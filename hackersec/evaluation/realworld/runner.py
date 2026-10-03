"""
Phase 2/3 — run the full pipeline over every sample, fully offline.

Per sample:
  1. Semgrep + Bandit on the whole file (cached; batched before the loop),
     keeping findings inside the target function.
  2. Phase 3 candidates (REALWORLD_PHASE3=1): an LLM auditor proposes
     vulnerabilities (GPTLens), and the LLM labels the function's calls as
     sources/sinks whose flows Joern then checks (IRIS).
  3. One Joern session: taint flows for every finding plus the labelled sinks.
  4. RAG definitions for every finding.
  5. Board debates; the Judge names the dangerous line and the check it
     needs before voting, and its quote of that check is verified against
     the code:
       sast debate  -- SAST findings only, no context (the Phase 2 system)
       full debate  -- SAST + taint + auditor candidates, with same-file
                       callers/callees (the Phase 3 system)
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

from hackersec.evaluation.realworld import sast_cache, split, state

logger = logging.getLogger(__name__)

PIPELINE_VERSION = "v5-guard-check"
MIN_FREE_GB = float(os.getenv("REALWORLD_MIN_FREE_GB", "5"))
USE_CPG = os.getenv("REALWORLD_USE_CPG", "1") not in ("0", "false", "False")
PHASE3 = os.getenv("REALWORLD_PHASE3", "1") not in ("0", "false", "False")
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
# Candidates shown in the full debate, per source.
MAX_SAST, MAX_TAINT, MAX_AUDITOR = 6, 3, 3

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
    cpg = f.cpg_context or {}
    return {
        "rule_id": f.rule_id,
        "tool": f.tool,
        "severity": f.severity,
        "line": f.line_start,
        "cwe_ids": f.cwe_ids,
        "cpg_status": cpg.get("cpg_status"),
        "taint_paths": len(cpg.get("taint_paths") or []),
        "rag_hits": len(f.rag_docs or []),
    }


def _board_summary(res: dict) -> dict:
    attacker, defender = res.get("attacker") or {}, res.get("defender") or {}
    evidence = res.get("evidence_check") or {}
    guard = res.get("guard_check") or {}
    votes = res.get("votes") or []
    first = next((v for v in votes if v.get("status") == "success"), {})
    return {
        "valid_votes": res.get("valid_votes"),
        "votes": [
            {"verdict": v.get("verdict"), "confidence": v.get("confidence"), "p_vulnerable": v.get("p_vulnerable")}
            for v in votes
        ],
        "verdict_source": res.get("verdict_source"),
        "attacker_confidence": attacker.get("exploitability_confidence"),
        "attacker_status": attacker.get("status"),
        "attacker_finding_ids": attacker.get("finding_ids"),
        "attacker_claim": (attacker.get("vulnerability") or "")[:300],
        "defender_safety": defender.get("safety_confidence"),
        "defender_status": defender.get("status"),
        "evidence_grounded": evidence.get("grounded"),
        "evidence_reason": evidence.get("reason"),
        "guard_grounded": guard.get("grounded"),
        "guard_reason": guard.get("reason"),
        "guard_grounded_share": res.get("guard_grounded_share"),
        "dangerous_operation": (first.get("dangerous_operation") or "")[:200],
        "required_check": (first.get("required_check") or "")[:200],
        "code_truncated": res.get("code_truncated"),
        "context_overflow": res.get("context_overflow"),
        "max_prompt_tokens": res.get("max_prompt_tokens"),
        "judge_reasoning": (first.get("reasoning") or "")[:400],
    }


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

    def __init__(self):
        self.rag = None
        self.rag_lock = threading.Lock()
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
            MODEL_ATTACKER, MODEL_DEFENDER, MODEL_HUNTER, MODEL_JUDGE, OllamaClient,
        )

        urls = ollama_urls()
        self.client = OllamaClient(urls[index % len(urls)])
        self.model_hunter = MODEL_HUNTER
        self.models = sorted({MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE} | ({MODEL_HUNTER} if PHASE3 else set()))
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

    def _cpg(self, sample: dict, findings: list, extra) -> str:
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
                status = enrich_with_cpg(findings, Path(sample["file"]), job_id=job, client=self.joern, extra=extra)
                if status != "failed":
                    break
                logger.warning(f"CPG import failed for {sample['sample_id']} on {self.joern.base_url} "
                               f"(attempt {attempt + 1}/{CPG_ATTEMPTS})")
        return status

    def _candidates(self, sample: dict, code: str, context: str) -> tuple[list, dict, list, dict] | None:
        """Auditor findings and IRIS sink sites; None if Ollama kept failing."""
        from hackersec.analysis.llm.function_prompter import MIN_CODE_CHARS, code_budget, fit_function_code
        from hackersec.analysis.llm.hunter import hunt
        from hackersec.analysis.llm.taint_specs import candidate_calls, infer_specs, sink_sites

        start, end, name = sample["line_start"], sample["line_end"], sample["function"]
        budget = max(MIN_CODE_CHARS, code_budget(self.client.num_ctx) - len(context))
        code_text, _ = fit_function_code(code, start, [], budget)

        h = self._llm(lambda: hunt(self.client, self.model_hunter, name, code_text, start, end, context))
        if h.get("llm_status") != "success":
            return None
        calls = candidate_calls(code, start)
        sp = self._llm(lambda: infer_specs(self.client, self.model_hunter, name, code_text, calls))
        if sp.get("llm_status") != "success":
            return None
        return h, sp, sink_sites(sp.get("sinks") or []), {"n_calls": len(calls)}

    def evaluate(self, sample: dict, meta: dict) -> dict:
        from hackersec.analysis.enrich import enrich_with_rag
        from hackersec.analysis.joern.queries import source_regex
        from hackersec.analysis.llm.context import function_context
        from hackersec.analysis.llm.hunter import hunter_findings
        from hackersec.analysis.llm.taint_specs import taint_findings

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
        file_lines = source.splitlines()
        start, end = sample["line_start"], sample["line_end"]
        code = "\n".join(file_lines[start - 1 : end])

        file_findings, sast_status = sast_cache.findings_for(sample["file"])
        sast = [copy.deepcopy(f) for f in file_findings if _in_function(f, sample)]
        record.update(file_findings=len(file_findings), n_findings=len(sast), sast_status=sast_status,
                      sast_pred=int(bool(sast)))

        # ── Phase 3 candidates (LLM calls happen outside the Joern lock) ────
        context, auditor, sites, spec, hunt_res = "", [], [], {}, {}
        if PHASE3:
            context = function_context(source, start, end)
            cand = self._candidates(sample, code, context)
            if cand is None:
                return {**record, "status": "llm_failed", "error": "candidate generation failed",
                        "seconds": round(time.time() - started, 1)}
            hunt_res, spec, sites, extra_info = cand
            spec = {**spec, **extra_info}
            auditor = hunter_findings(hunt_res.get("candidates") or [], sample["file"], file_lines, "realworld")

        # ── One Joern session: taint for every finding + labelled sinks ─────
        site_results = []
        src_regex = source_regex(spec.get("sources") or [])

        def spec_queries(client, project, rel):
            site_results.clear()
            for site in sites:
                site_results.append((site, client.query_taint(
                    project, rel, site["line"], sink_name=site["call_name"],
                    source_regex=src_regex, method_line=start,
                )))

        record["cpg_status"] = "skipped"
        if self.joern is not None and (sast or auditor or sites):
            record["cpg_status"] = self._cpg(sample, sast + auditor, spec_queries if sites else None)
        taint = taint_findings(site_results, sample["file"], file_lines, "realworld")
        seen, unique_taint = set(), []
        for f in taint:
            if f.line_start not in seen:
                seen.add(f.line_start)
                unique_taint.append(f)
        taint = unique_taint

        if self.shared.rag is not None and (sast or auditor or taint):
            with self.shared.rag_lock:
                enrich_with_rag(sast + auditor + taint, job_id="realworld", rag=self.shared.rag)

        # ── Phase 2 debate: SAST findings only, no context ──────────────────
        res = None
        if sast:
            res = self._llm(lambda: self.board.deliberate_function(sample["function"], code, start, sast))
            if res.get("llm_status") != "success":
                return {**record, "status": "llm_failed", "error": str(res.get("error"))[:300],
                        "seconds": round(time.time() - started, 1)}
        record.update(_debate_fields(res, "board_pred", "board_override_pred", "p_vulnerable", "vote_share", "board"))
        record["findings"] = [_finding_summary(f) for f in sast]

        # ── Phase 3 debate: every candidate, with same-file context ─────────
        if PHASE3:
            union = sast[:MAX_SAST] + taint[:MAX_TAINT] + auditor[:MAX_AUDITOR]
            full = None
            if union:
                full = self._llm(lambda: self.board.deliberate_function(
                    sample["function"], code, start, union, context=context))
                if full.get("llm_status") != "success":
                    return {**record, "status": "llm_failed", "error": str(full.get("error"))[:300],
                            "seconds": round(time.time() - started, 1)}
            record.update(_debate_fields(full, "full_pred", "full_override_pred", "full_p_vulnerable",
                                         "full_vote_share", "full_board"))
            record.update({
                "full_findings": [_finding_summary(f) for f in union],
                "hunter_pred": int(bool(auditor)),
                "taint_pred": int(bool(taint)),
                "union_pred": int(bool(union)),
                "n_candidates": {"sast": len(sast), "taint": len(taint), "auditor": len(auditor)},
                "auditor": {
                    "status": hunt_res.get("status"),
                    "verdict": hunt_res.get("verdict"),
                    "p_vulnerable": hunt_res.get("p_vulnerable"),
                    "candidates": [{"line": c["line"], "cwe": c["cwe"], "confidence": c["confidence"]}
                                   for c in hunt_res.get("candidates") or []],
                },
                "taint_spec": {
                    "status": spec.get("status"),
                    "n_calls": spec.get("n_calls"),
                    "sources": (spec.get("sources") or [])[:10],
                    "sinks": [{"callee": s["callee"], "cwe": s["cwe"]} for s in (spec.get("sinks") or [])][:10],
                    "sites_checked": len(site_results),
                    "flows": len(taint),
                },
                "context_chars": len(context),
            })

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
    cpg_failed = {sid for sid, r in results.items()
                  if REDO_CPG_FAILED and r.get("status") == "ok" and r.get("cpg_status") == "failed"}
    done = {sid for sid, r in results.items() if r.get("status") == "ok" or not retry_failed} - cpg_failed
    todo = [s for s in samples if s["sample_id"] not in done]
    if cpg_failed:
        logger.warning(f"Re-running {len(cpg_failed)} samples whose CPG step failed")
    logger.info(f"{len(samples)} samples, {len(samples) - len(todo)} already done, {len(todo)} to go; "
                f"{WORKERS} workers over {len(ollama_urls())} Ollama and {len(joern_urls()) if USE_CPG else 0} "
                f"Joern server(s); phase 3 {'on' if PHASE3 else 'off'}")

    try:
        state.update_status(phase="sast_prescan", detail=None, done=len(samples) - len(todo), total=len(samples),
                            workers=WORKERS, pipeline=PIPELINE_VERSION)
        scan = sast_cache.prescan(
            [s["file"] for s in todo],
            progress=lambda d, t: state.update_status(detail=f"SAST {d}/{t} files"),
        )
        logger.info(f"SAST prescan done: {scan}")
        state.update_status(sast_prescan=scan, detail=None)

        shared = Shared()
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
                    f"label={s['label']} sast={record.get('n_findings')} cand={record.get('n_candidates')} "
                    f"board={record.get('board_pred')} full={record.get('full_pred')} "
                    f"p={record.get('full_p_vulnerable', record.get('p_vulnerable'))} "
                    f"({record.get('seconds')}s) {s['sample_id']}"
                )
                try:
                    _wait_for_disk()
                except Stopped:
                    pass
                submit_next()

    results = state.load_results()
    state.update_status(
        phase="stopped" if _stop else "evaluate_done",
        detail=None,
        waiting_for=None,
        done=sum(1 for s in samples if s["sample_id"] in results),
        total=len(samples),
        eta_hours=None,
    )
