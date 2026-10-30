"""
Run the SAST-gated pipeline over every sample, fully offline.

Per sample:
  1. Semgrep + Bandit on the whole file (cached; batched before the loop),
     keeping findings inside the target function.
  2. Comparison baselines (REALWORLD_BASELINES): the same model, one prompt,
     no static findings — the function alone, and the function plus the same
     context the board sees (same-file callers and callees, callers in other
     files, framework entry point). The LLM+context score also feeds the Soft
     LLM Screen when REALWORLD_LLM_SCREEN=1.
  3. One Joern session for taint flows on the static findings, when there
     are any. Files static analysis did not flag skip Joern.
  4. RAG definitions for those findings.
  5. One board debate for union-gated candidates: SAST findings, or (when the
     Soft LLM Screen is on) SAST-unflagged functions whose llm_context_p is at
     or above tau_recall. Functions failing both gates are SAFE (0 board tokens).
Fusion and calibrated thresholds are fitted on the dev split at report time.

Several workers run in parallel (REALWORLD_WORKERS), spread round-robin over
the Ollama servers in OLLAMA_BASE_URLS and the Joern servers in
JOERN_BASE_URLS. A Joern server holds one active project, so each is used by
one worker at a time. One checkpoint line is fsync'd per sample and finished
samples are skipped on restart. A worker pauses, instead of recording
failures, while its Ollama is down or on CPU, while its Joern is down, or
while the disk is nearly full.
"""

import copy
import hashlib
import logging
import os
import queue
import shutil
import signal
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from hackersec.evaluation.realworld import llm_screen, sast_cache, split, state

logger = logging.getLogger(__name__)

PIPELINE_VERSION = "v10-soft-llm-screen"
MIN_FREE_GB = float(os.getenv("REALWORLD_MIN_FREE_GB", "5"))
USE_CPG = os.getenv("REALWORLD_USE_CPG", "1") not in ("0", "false", "False")
# function = whole function, no findings; context = that plus the board's context.
# "0" records neither. Soft LLM Screen needs context scores when enabled.
_BASELINE_RAW = os.getenv("REALWORLD_BASELINES", "function,context").strip().lower()
BASELINES = set() if _BASELINE_RAW in ("", "0", "false", "off") else {p.strip() for p in _BASELINE_RAW.split(",") if p.strip()}
if llm_screen.ENABLED and "context" not in BASELINES:
    # Screen reuses llm_context_p; keep the context baseline on whenever the gate is on.
    BASELINES.add("context")
REQUIRE_GPU = os.getenv("REALWORLD_REQUIRE_GPU", "1") not in ("0", "false", "False")
MIN_TOKENS_PER_SEC = float(os.getenv("REALWORLD_MIN_TOKENS_PER_SEC", "3"))
# Ollama can reload a model onto CPU mid-run (e.g. after another user's job
# takes the GPU), so health is re-checked periodically, not only at start.
HEALTH_EVERY_SEC = float(os.getenv("REALWORLD_HEALTH_EVERY_SEC", "900"))
WORKERS = max(1, int(os.getenv("REALWORLD_WORKERS", "1")))
LLM_ATTEMPTS = 3
CPG_ATTEMPTS = 3
# Samples recorded while Joern was failing have no taint evidence; redo them
# on the next start instead of reporting them as normal results.
REDO_CPG_FAILED = os.getenv("REALWORLD_REDO_CPG_FAILED", "1") not in ("0", "false", "False")
_stop = False


class Stopped(Exception):
    pass


def _on_sigterm(signum, frame):
    global _stop
    _stop = True
    logger.warning("Stop requested — finishing the samples in flight, then exiting")


def _sleep(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if _stop:
            raise Stopped()
        time.sleep(min(1.0, end - time.time()))


def _urls(name: str, single: str, default: str) -> list[str]:
    raw = os.getenv(name) or os.getenv(single) or default
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def ollama_urls() -> list[str]:
    return _urls("OLLAMA_BASE_URLS", "OLLAMA_BASE_URL", "http://localhost:11434")


def joern_urls() -> list[str]:
    return _urls("JOERN_BASE_URLS", "JOERN_BASE_URL", "http://localhost:9000")


# ── Waiting on dependencies ─────────────────────────────────────────────────

def _wait_for_disk() -> None:
    delay = 60
    while shutil.disk_usage(state.ROOT).free / 1e9 < MIN_FREE_GB:
        free = shutil.disk_usage(state.ROOT).free / 1e9
        logger.error(f"Only {free:.1f} GB free (< {MIN_FREE_GB} GB). Paused — free disk space to continue.")
        state.update_status(waiting_for="disk_space", free_gb=round(free, 1))
        _sleep(delay)
        delay = min(delay * 2, 600)
    state.update_status(waiting_for=None)


def _wait_for_ollama(client, model: str) -> None:
    delay = 15
    started = time.time()
    while True:
        health = client.health(model, min_tokens_per_sec=MIN_TOKENS_PER_SEC, require_gpu=REQUIRE_GPU)
        if health["ok"]:
            if time.time() - started > 1:
                logger.info(f"Ollama at {client.base_url} usable again for {model}")
            state.update_status(
                waiting_for=None,
                waiting_context=None,
                llm_tokens_per_sec=health["tokens_per_sec"],
                llm_gpu_fraction=health["gpu_fraction"],
            )
            return
        waited = int(time.time() - started)
        logger.warning(f"Ollama at {client.base_url} not usable for {model}: {health['reason']}; waited {waited}s")
        state.update_status(waiting_for="ollama", waiting_context=f"{client.base_url}: {health['reason']}",
                            waited_seconds=waited)
        _sleep(delay)
        delay = min(delay * 2, 300)


def _wait_for_joern(client) -> None:
    delay = 15
    started = time.time()
    while not client.ready():
        waited = int(time.time() - started)
        logger.warning(f"Joern at {client.base_url} not answering queries; waited {waited}s")
        state.update_status(waiting_for="joern", waiting_context=f"{client.base_url} not ready", waited_seconds=waited)
        _sleep(delay)
        delay = min(delay * 2, 300)
    state.update_status(waiting_for=None, waiting_context=None)


# ── Per-sample helpers ──────────────────────────────────────────────────────

def _in_function(f, sample: dict) -> bool:
    return f.line_start <= sample["line_end"] and (f.line_end or f.line_start) >= sample["line_start"]


def _finding_summary(f) -> dict:
    from hackersec.analysis.dedup import has_tool

    cpg = f.cpg_context or {}
    taint_paths = cpg.get("taint_paths") or []
    return {
        "rule_id": f.rule_id,
        "tool": f.tool,
        "also_bandit": has_tool(f, "bandit") and f.tool != "bandit",
        "also_ast": has_tool(f, "ast_sink") and f.tool != "ast_sink",
        "also_codeql": has_tool(f, "codeql") and f.tool != "codeql",
        "severity": f.severity,
        "line": f.line_start,
        "cwe_ids": f.cwe_ids,
        "cpg_status": cpg.get("cpg_status"),
        "taint_paths": len(taint_paths),
        "unfiltered_flows": cpg.get("unfiltered_flows", len(cpg.get("unfiltered_taint_paths") or [])),
        "sanitized_flows": cpg.get("sanitized_flows", len(cpg.get("sanitized_taint_paths") or [])),
        "rag_hits": len(f.rag_docs or []),
    }


def _board_summary(res: dict) -> dict:
    attacker, defender = res.get("attacker") or {}, res.get("defender") or {}
    evidence = res.get("evidence_check") or {}
    votes = res.get("votes") or []
    first = next((v for v in votes if v.get("status") == "success"), {})
    return {
        "valid_votes": res.get("valid_votes"),
        "votes": [
            {"verdict": v.get("verdict"), "confidence": v.get("confidence"), "p_vulnerable": v.get("p_vulnerable")}
            for v in votes
        ],
        "verdict_source": res.get("verdict_source"),
        "gate_origin": res.get("gate_origin") or res.get("board_track"),
        "board_track": res.get("board_track") or res.get("gate_origin"),
        "attacker_confidence": attacker.get("exploitability_confidence"),
        "attacker_status": attacker.get("status"),
        "attacker_finding_ids": attacker.get("finding_ids"),
        "attacker_claim": (attacker.get("vulnerability") or "")[:300],
        "defender_safety": defender.get("safety_confidence"),
        "defender_status": defender.get("status"),
        "evidence_grounded": evidence.get("grounded"),
        "evidence_reason": evidence.get("reason"),
        "evidence_location": evidence.get("location", "function") if evidence.get("grounded") else None,
        "code_truncated": res.get("code_truncated"),
        "context_overflow": res.get("context_overflow"),
        "max_prompt_tokens": res.get("max_prompt_tokens"),
        "judge_reasoning": (first.get("reasoning") or "")[:400],
    }


def _context(sample: dict, source: str, start: int, end: int) -> tuple[str, dict]:
    """Prompt context shared by the board and the context baseline, and a
    summary of what it contains."""
    from hackersec.analysis.llm import repo_context
    from hackersec.analysis.llm.context import function_context
    from hackersec.evaluation.realworld import repo_snapshot

    same_file = function_context(source, start, end)
    if not repo_snapshot.ENABLED:
        return same_file, {"status": "disabled"}
    rec = repo_snapshot.lookup(sample["sample_id"])
    if rec and rec.get("status") == "ok":
        entry, callers = rec.get("entry_point"), rec
    else:
        entry, callers = repo_context.entry_point(source, start, end), None
    info = {
        "status": rec.get("status") if rec else "missing",
        "call_sites": (callers or {}).get("call_sites"),
        "caller_files": (callers or {}).get("caller_files"),
        "entry_point": (entry or {}).get("kind"),
    }
    text = "\n".join(p for p in (same_file, repo_context.render(entry, callers)) if p)
    return text, info


def _debate_fields(res: dict | None, pred: str, override: str, p: str, share: str, board: str) -> dict:
    """Record fields for one debate, under the given key names; `res` None
    means there was nothing to debate (predicted safe)."""
    if res is None:
        return {pred: 0, override: 0, p: None, share: None}
    grounded = bool((res.get("evidence_check") or {}).get("grounded"))
    return {
        # Majority of the Judge votes; the evidence check is only a signal.
        pred: res["prediction"],
        # Ablation: the citation rule as an override (a SAFE majority whose
        # sanitizer quote is not in the code is kept as vulnerable).
        override: int(res["prediction"] == 1 or not grounded),
        p: res.get("p_vulnerable"),
        share: res.get("vote_share"),
        board: _board_summary(res),
    }


class Shared:
    """Resources every worker uses: the RAG store and the Joern servers."""

    def __init__(self, tau_recall: float | None = None, llm_context_scores: dict | None = None):
        self.rag = None
        self.rag_lock = threading.Lock()
        # Soft LLM Screen threshold (DEV-tuned) and optional reused llm_context_p.
        self.tau_recall = tau_recall
        self.llm_context_scores = llm_context_scores or {}
        try:
            from hackersec.analysis.rag import LocalRAGStore

            self.rag = LocalRAGStore()
            if self.rag.index.ntotal == 0:
                logger.warning("RAG index is empty — findings will get no retrieved context")
        except Exception as e:
            logger.error(f"RAG store unavailable, continuing without it: {e}")

        self.joern = []
        if USE_CPG:
            from hackersec.analysis.joern.client import JoernClient

            self.joern = [(JoernClient(u), threading.Lock()) for u in joern_urls()]


class Evaluator:
    def __init__(self, index: int, shared: Shared):
        from hackersec.analysis.llm.board import AdversarialBoard
        from hackersec.analysis.llm.client import (
            MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE, OllamaClient,
        )

        urls = ollama_urls()
        self.client = OllamaClient(urls[index % len(urls)])
        self.model_judge = MODEL_JUDGE
        self.models = sorted({MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE})
        self.board = AdversarialBoard(client=self.client, mode="board")
        self.index = index
        self.shared = shared
        self.joern, self.joern_lock = shared.joern[index % len(shared.joern)] if shared.joern else (None, None)
        self._checked_at = 0.0

    def wait_ready(self) -> None:
        for m in self.models:
            _wait_for_ollama(self.client, m)
        if self.joern is not None:
            _wait_for_joern(self.joern)
        self._checked_at = time.time()

    def maybe_recheck(self) -> None:
        if time.time() - self._checked_at > HEALTH_EVERY_SEC:
            self.wait_ready()

    def _llm(self, call) -> dict:
        res = {}
        for _ in range(LLM_ATTEMPTS):
            res = call()
            if res.get("llm_status") == "success":
                return res
            logger.warning(f"LLM call failed ({res.get('error')}); waiting for Ollama")
            self.wait_ready()
        return res

    def _cpg(self, sample: dict, findings: list, extra, method_line: int | None = None) -> str:
        from hackersec.analysis.enrich import enrich_with_cpg

        # Per-worker project names: two workers may analyse the same file on
        # two Joern servers that share the workspace volume.
        job = f"rw{self.index}_" + hashlib.sha1(sample["file"].encode()).hexdigest()[:12]
        with self.joern_lock:
            for attempt in range(CPG_ATTEMPTS):
                if attempt:
                    # A failed import is nearly always the server (down, or
                    # still busy with a query the client gave up on), so wait
                    # until it answers again and redo this sample's CPG step.
                    _wait_for_joern(self.joern)
                    for f in findings:
                        f.cpg_context = None
                status = enrich_with_cpg(
                    findings, Path(sample["file"]), job_id=job, client=self.joern, extra=extra, method_line=method_line
                )
                if status != "failed":
                    break
                logger.warning(f"CPG import failed for {sample['sample_id']} on {self.joern.base_url} "
                               f"(attempt {attempt + 1}/{CPG_ATTEMPTS})")
        return status

    def _baseline(self, name: str, code: str, start: int, context: str) -> dict | None:
        """One no-SAST review. None means Ollama kept failing."""
        from hackersec.analysis.llm.baseline import review
        from hackersec.analysis.llm.function_prompter import MIN_CODE_CHARS, code_budget, fit_function_code

        budget = max(MIN_CODE_CHARS, code_budget(self.client.num_ctx) - len(context))
        code_text, _ = fit_function_code(code, start, [], budget)
        res = self._llm(lambda: review(self.client, self.model_judge, name, code_text, context))
        return res if res.get("llm_status") == "success" else None

    def evaluate(self, sample: dict, meta: dict) -> dict:
        from hackersec.analysis.dedup import has_tool
        from hackersec.analysis.enrich import enrich_with_rag

        started = time.time()
        record = {
            "sample_id": sample["sample_id"],
            "pair_id": sample["pair_id"],
            "dataset": sample["dataset"],
            "label": sample["label"],
            "kind": sample["kind"],
            "cwe": sample["cwe"],
            "split": meta.get("split"),
            "clean": meta.get("clean"),
            "pipeline": PIPELINE_VERSION,
        }

        if not Path(sample["file"]).exists():
            return {**record, "status": "file_missing", "seconds": 0}

        with open(sample["file"], "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        start, end = sample["line_start"], sample["line_end"]
        code = "\n".join(source.splitlines()[start - 1 : end])

        file_findings, sast_status = sast_cache.findings_for(sample["file"])
        sast = [copy.deepcopy(f) for f in file_findings if _in_function(f, sample)]
        record.update(
            file_findings=len(file_findings), n_findings=len(sast), sast_status=sast_status,
            sast_pred=int(bool(sast)),
            semgrep_pred=int(any(has_tool(f, "semgrep") for f in sast)),
            bandit_pred=int(any(has_tool(f, "bandit") for f in sast)),
            ast_pred=int(any(has_tool(f, "ast_sink") for f in sast)),
            codeql_pred=int(any(has_tool(f, "codeql") for f in sast)),
        )

        # Context for the board and the context baseline / soft screen score.
        need_context = bool(sast) or "context" in BASELINES or llm_screen.ENABLED
        context, repo_info = _context(sample, source, start, end) if need_context else ("", None)
        record["repo_context"] = repo_info

        # ── Baselines: same model, no static findings (outside the Joern lock)
        tokens = {"board": {"prompt": 0, "completion": 0, "calls": 0}}
        if BASELINES:
            for mode, ctx in (("function", ""), ("context", context)):
                if mode not in BASELINES:
                    continue
                key = "llm_only" if mode == "function" else "llm_context"
                # Soft screen: reuse llm_context_p from a prior / cached run when present.
                cached_p = self.shared.llm_context_scores.get(sample["sample_id"]) if key == "llm_context" else None
                requery = os.getenv("REALWORLD_LLM_SCREEN_REQUERY", "0") in ("1", "true", "True")
                if key == "llm_context" and cached_p is not None and not requery:
                    record[f"{key}_pred"] = int(float(cached_p) >= 0.5)
                    record[f"{key}_p"] = float(cached_p)
                    record[key] = {
                        "status": "reused",
                        "verdict": "VULNERABLE" if record[f"{key}_pred"] else "NOT_VULNERABLE",
                    }
                    tokens[key] = {"prompt": 0, "completion": 0, "calls": 0}
                    continue
                reviewed = self._baseline(sample["function"], code, start, ctx)
                if reviewed is None:
                    return {**record, "status": "llm_failed", "error": f"{key} baseline failed",
                            "seconds": round(time.time() - started, 1)}
                record[f"{key}_pred"] = reviewed["prediction"]
                record[f"{key}_p"] = reviewed.get("p_vulnerable")
                record[key] = {"status": reviewed.get("status"), "verdict": reviewed.get("verdict"),
                               "reasoning": reviewed.get("reasoning")}
                tokens[key] = reviewed.get("tokens") or {"prompt": 0, "completion": 0, "calls": 1}

        # Soft LLM Screen ∪ SAST → Board; failing both = SAFE (0 board tokens).
        llm_p = record.get("llm_context_p")
        if llm_p is None and sample["sample_id"] in self.shared.llm_context_scores:
            llm_p = self.shared.llm_context_scores[sample["sample_id"]]
            record["llm_context_p"] = llm_p
        origin = llm_screen.gate_origin(bool(sast), llm_p, self.shared.tau_recall)
        record["tau_recall"] = self.shared.tau_recall
        record["gate_origin"] = origin
        record["board_candidate"] = int(origin is not None)
        record["llm_screen_pred"] = int(origin == "llm_screen")

        # ── Joern + RAG only for functions static analysis flagged ──────────
        record["cpg_status"] = "skipped"
        if self.joern is not None and sast:
            record["cpg_status"] = self._cpg(sample, sast, None, method_line=start)
        if self.shared.rag is not None and sast:
            with self.shared.rag_lock:
                enrich_with_rag(sast, job_id="realworld", rag=self.shared.rag)

        # ── Shipped system: Board on union-gated candidates only ────────────
        res = None
        if origin is not None:
            suspicion = ((record.get("llm_context") or {}).get("reasoning") or "").strip()
            suspicion = suspicion.split(". ")[0][:240] if suspicion else None
            res = self._llm(lambda: self.board.deliberate_function(
                sample["function"], code, start, sast, context=context, gate_origin=origin,
                suspicion=suspicion, screen_p=llm_p,
            ))
            if res.get("llm_status") != "success":
                return {**record, "status": "llm_failed", "error": str(res.get("error"))[:300],
                        "seconds": round(time.time() - started, 1)}
            tokens["board"] = res.get("tokens") or tokens["board"]
        record.update(_debate_fields(res, "board_pred", "board_override_pred", "p_vulnerable", "vote_share", "board"))
        record["findings"] = [_finding_summary(f) for f in sast]
        record["context_chars"] = len(context)
        record["tokens"] = tokens

        record.update({
            "status": "ok",
            "seconds": round(time.time() - started, 1),
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return record


def _interleaved(samples: list[dict]) -> list[dict]:
    """Keep each pair together and alternate datasets, so a partial run still
    yields complete pairs from every dataset."""
    by_dataset: dict[str, list[list[dict]]] = {}
    index: dict[str, list[dict]] = {}
    for s in samples:
        if s["pair_id"] not in index:
            index[s["pair_id"]] = []
            by_dataset.setdefault(s["dataset"], []).append(index[s["pair_id"]])
        index[s["pair_id"]].append(s)
    queues = list(by_dataset.values())
    order = []
    while any(queues):
        for q in queues:
            if q:
                order.extend(sorted(q.pop(0), key=lambda s: s["kind"] != "vulnerable"))
    return order


def _error_record(s: dict, meta: dict, e: Exception) -> dict:
    return {"sample_id": s["sample_id"], "pair_id": s["pair_id"], "dataset": s["dataset"],
            "label": s["label"], "kind": s["kind"], "cwe": s["cwe"],
            "split": meta.get("split"), "clean": meta.get("clean"), "pipeline": PIPELINE_VERSION,
            "status": "error", "error": f"{e.__class__.__name__}: {e}"[:300]}


def run_evaluation(retry_failed: bool = False, limit: int | None = None) -> None:
    global _stop
    signal.signal(signal.SIGTERM, _on_sigterm)
    state.ensure_dirs()
    os.environ.setdefault("SEMGREP_RULES_DIR", str(state.RULES_DIR.resolve()))

    all_samples = state.load_samples()
    if not all_samples:
        raise RuntimeError(f"No samples in {state.SAMPLES_PATH}. Run the build phase first.")
    splits = split.load_or_create(all_samples)

    # Dev first: calibration and fusion only need dev, so a run cut short
    # can still be reported on whatever part of test it reached.
    samples = (
        _interleaved([s for s in all_samples if splits[s["pair_id"]]["split"] == "dev"])
        + _interleaved([s for s in all_samples if splits[s["pair_id"]]["split"] != "dev"])
    )
    if limit:
        samples = samples[: limit * 2]

    results = state.load_results()
    foreign = sorted({r.get("pipeline") for r in results.values()
                      if r.get("pipeline") and r.get("pipeline") != PIPELINE_VERSION})
    if foreign:
        raise RuntimeError(
            f"{state.RESULTS_PATH} already holds pipeline {foreign}, and this code is {PIPELINE_VERSION}. "
            "Point REALWORLD_RUN at a new directory so the two runs are not mixed."
        )
    cpg_failed = {sid for sid, r in results.items()
                  if REDO_CPG_FAILED and r.get("status") == "ok" and r.get("cpg_status") == "failed"}
    done = {sid for sid, r in results.items() if r.get("status") == "ok" or not retry_failed} - cpg_failed
    todo = [s for s in samples if s["sample_id"] not in done]
    if cpg_failed:
        logger.warning(f"Re-running {len(cpg_failed)} samples whose CPG step failed")
    logger.info(f"{len(samples)} samples, {len(samples) - len(todo)} already done, {len(todo)} to go; "
                f"{WORKERS} workers over {len(ollama_urls())} Ollama and {len(joern_urls()) if USE_CPG else 0} "
                f"Joern server(s); baselines {', '.join(sorted(BASELINES)) or 'off'}"
                f"{'; soft LLM screen on' if llm_screen.ENABLED else ''}")

    # Soft LLM Screen: reuse llm_context_p from disk and tune tau_recall on DEV.
    tau_meta = llm_screen.ensure_tau(splits, results) if llm_screen.ENABLED else None
    tau_recall = (tau_meta or {}).get("tau_recall")
    score_rows = llm_screen.collect_score_records(splits, results) if llm_screen.ENABLED else []
    llm_context_scores = {
        r["sample_id"]: float(r[llm_screen.SCORE_KEY])
        for r in score_rows if r.get(llm_screen.SCORE_KEY) is not None
    }
    if llm_screen.ENABLED:
        state.update_status(
            llm_screen=True,
            tau_recall=tau_recall,
            llm_screen_scores=len(llm_context_scores),
            llm_screen_meta=tau_meta,
        )

    try:
        state.update_status(phase="sast_prescan", detail=None, done=len(samples) - len(todo), total=len(samples),
                            workers=WORKERS, pipeline=PIPELINE_VERSION)
        scan = sast_cache.prescan(
            [s["file"] for s in todo],
            progress=lambda d, t: state.update_status(detail=f"SAST {d}/{t} files"),
        )
        logger.info(f"SAST prescan done: {scan}")
        state.update_status(sast_prescan=scan, detail=None)

        from hackersec.evaluation.realworld import repo_snapshot

        if repo_snapshot.ENABLED:
            missing = sum(repo_snapshot.lookup(s["sample_id"]) is None for s in todo)
            if missing:
                logger.warning(f"{missing}/{len(todo)} samples have no cached repo context; they get no "
                               "cross-file callers. Run the build phase (it needs internet) to fill the cache.")

        shared = Shared(tau_recall=tau_recall, llm_context_scores=llm_context_scores)
        evaluators = [Evaluator(i, shared) for i in range(WORKERS)]
        checked = set()
        for ev in evaluators:
            servers = (ev.client.base_url, ev.joern.base_url if ev.joern else None)
            if servers not in checked:
                ev.wait_ready()
                checked.add(servers)
            ev._checked_at = time.time()
    except Stopped:
        logger.warning("Stopped while waiting on a dependency")
        state.update_status(phase="stopped", waiting_for=None)
        return

    free: queue.Queue = queue.Queue()
    for ev in evaluators:
        free.put(ev)

    def job(s: dict) -> dict:
        ev = free.get()
        try:
            ev.maybe_recheck()
            return ev.evaluate(s, splits[s["pair_id"]])
        finally:
            free.put(ev)

    session_start = time.time()
    finished = 0
    pending: dict = {}
    remaining = iter(todo)
    state.update_status(phase="evaluate")

    def submit_next() -> None:
        if _stop:
            return
        s = next(remaining, None)
        if s is not None:
            pending[pool.submit(job, s)] = s

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        try:
            _wait_for_disk()
        except Stopped:
            pass
        for _ in range(WORKERS):
            submit_next()
        while pending:
            completed, _ = wait(list(pending), return_when=FIRST_COMPLETED)
            for fut in completed:
                s = pending.pop(fut)
                meta = splits[s["pair_id"]]
                try:
                    record = fut.result()
                except Stopped:
                    _stop = True
                    continue
                except Exception as e:  # one broken sample must not end an overnight run
                    logger.exception(f"Sample failed: {s['sample_id']}", exc_info=e)
                    record = _error_record(s, meta, e)
                state.append_jsonl(state.RESULTS_PATH, record)
                finished += 1
                rate = (time.time() - session_start) / finished
                left = len(todo) - finished
                state.update_status(
                    phase="evaluate",
                    detail=f"{meta['split']} {s['dataset']} {s['kind']} {s['function']}",
                    done=len(samples) - left,
                    total=len(samples),
                    sec_per_sample=round(rate, 1),
                    eta_hours=round(rate * left / 3600, 1),
                )
                logger.info(
                    f"[{len(samples) - left}/{len(samples)}] {record['status']} {record.get('split')} "
                    f"label={s['label']} sast={record.get('n_findings')} "
                    f"gate={record.get('gate_origin') or 'safe'} "
                    f"board={record.get('board_pred')} llm={record.get('llm_only_pred')} "
                    f"p={record.get('p_vulnerable')} "
                    f"({record.get('seconds')}s) {s['sample_id']}"
                )
                try:
                    _wait_for_disk()
                except Stopped:
                    pass
                submit_next()

    results = state.load_results()
    # Refresh tau_recall from whatever DEV llm_context_p the run produced (next start reuses it).
    if llm_screen.ENABLED and not _stop:
        tau_meta = llm_screen.ensure_tau(splits, results)
        if tau_meta:
            state.update_status(tau_recall=tau_meta.get("tau_recall"), llm_screen_meta=tau_meta)
    state.update_status(
        phase="stopped" if _stop else "evaluate_done",
        detail=None,
        waiting_for=None,
        done=sum(1 for s in samples if s["sample_id"] in results),
        total=len(samples),
        eta_hours=None,
    )
