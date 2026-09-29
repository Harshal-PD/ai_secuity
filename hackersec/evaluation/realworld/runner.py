"""
Phase 2 — run the full production pipeline over every sample, fully offline.

Per sample: Semgrep + Bandit on the whole file (so imports and module context
are visible) -> keep findings inside the target function -> Joern CPG -> RAG
-> one Attacker/Defender/Judge debate over the whole function, with several
Judge votes. Fusion and the calibrated board threshold are fitted on the dev
split at report time, from the signals stored here.

SAST runs first for every pending file in batches (the rules are parsed once
per batch) and is cached on disk. One checkpoint line is fsync'd per sample,
and on restart finished samples are skipped. The run pauses, instead of
recording failures, while Ollama is down or has fallen back to CPU, while
Joern is down, or while the disk is nearly full.
"""

import copy
import hashlib
import logging
import os
import shutil
import signal
import time
from pathlib import Path

from hackersec.evaluation.realworld import sast_cache, split, state

logger = logging.getLogger(__name__)

PIPELINE_VERSION = "v2-function-board"
MIN_FREE_GB = float(os.getenv("REALWORLD_MIN_FREE_GB", "5"))
USE_CPG = os.getenv("REALWORLD_USE_CPG", "1") not in ("0", "false", "False")
REQUIRE_GPU = os.getenv("REALWORLD_REQUIRE_GPU", "1") not in ("0", "false", "False")
MIN_TOKENS_PER_SEC = float(os.getenv("REALWORLD_MIN_TOKENS_PER_SEC", "3"))
# Ollama can reload a model onto CPU mid-run (e.g. after another user's job
# takes the GPU), so health is re-checked periodically, not only at start.
HEALTH_EVERY_SEC = float(os.getenv("REALWORLD_HEALTH_EVERY_SEC", "900"))
LLM_ATTEMPTS = 3

_stop = False


class Stopped(Exception):
    pass


def _on_sigterm(signum, frame):
    global _stop
    _stop = True
    logger.warning("Stop requested — finishing the current sample, then exiting")


def _sleep(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if _stop:
            raise Stopped()
        time.sleep(min(1.0, end - time.time()))


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
                logger.info(f"Ollama usable again for {model}")
            state.update_status(
                waiting_for=None,
                waiting_context=None,
                llm_tokens_per_sec=health["tokens_per_sec"],
                llm_gpu_fraction=health["gpu_fraction"],
            )
            return
        waited = int(time.time() - started)
        logger.warning(f"Ollama not usable for {model}: {health['reason']}; waited {waited}s")
        state.update_status(waiting_for="ollama", waiting_context=health["reason"], waited_seconds=waited)
        _sleep(delay)
        delay = min(delay * 2, 300)


def _wait_for_joern(client) -> None:
    delay = 15
    started = time.time()
    while not client.ready():
        waited = int(time.time() - started)
        logger.warning(f"Joern not answering queries; waited {waited}s")
        state.update_status(waiting_for="joern", waiting_context="Joern server not ready", waited_seconds=waited)
        _sleep(delay)
        delay = min(delay * 2, 300)
    state.update_status(waiting_for=None, waiting_context=None)


# ── Per-sample work ─────────────────────────────────────────────────────────

def _in_function(f, sample: dict) -> bool:
    return f.line_start <= sample["line_end"] and (f.line_end or f.line_start) >= sample["line_start"]


def _function_code(sample: dict) -> str:
    with open(sample["file"], "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    return "\n".join(lines[sample["line_start"] - 1 : sample["line_end"]])


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
        "code_truncated": res.get("code_truncated"),
        "context_overflow": res.get("context_overflow"),
        "max_prompt_tokens": res.get("max_prompt_tokens"),
        "judge_reasoning": (first.get("reasoning") or "")[:400],
    }


class Evaluator:
    def __init__(self):
        from hackersec.analysis.llm.board import AdversarialBoard
        from hackersec.analysis.llm.client import MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE, OllamaClient

        self.client = OllamaClient()
        self.models = sorted({MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE})
        self.board = AdversarialBoard(client=self.client, mode="board")
        self.joern = None
        if USE_CPG:
            from hackersec.analysis.joern.client import JoernClient

            self.joern = JoernClient()
        self.rag = None
        try:
            from hackersec.analysis.rag import LocalRAGStore

            self.rag = LocalRAGStore()
            if self.rag.index.ntotal == 0:
                logger.warning("RAG index is empty — findings will get no retrieved context")
        except Exception as e:
            logger.error(f"RAG store unavailable, continuing without it: {e}")
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

    def _deliberate(self, sample: dict, code: str, findings: list) -> dict:
        res = {}
        for _ in range(LLM_ATTEMPTS):
            res = self.board.deliberate_function(sample["function"], code, sample["line_start"], findings)
            if res.get("llm_status") == "success":
                return res
            logger.warning(f"Board call failed ({res.get('error')}); waiting for Ollama")
            self.wait_ready()
        return res

    def _cpg(self, sample: dict, findings: list) -> str:
        from hackersec.analysis.enrich import enrich_with_cpg

        job = "rw_" + hashlib.sha1(sample["file"].encode()).hexdigest()[:12]
        status = enrich_with_cpg(findings, Path(sample["file"]), job_id=job, client=self.joern)
        if status == "failed" and not self.joern.ready():
            # Joern went down mid-run: wait, then redo this sample's CPG step.
            self.wait_ready()
            for f in findings:
                f.cpg_context = None
            status = enrich_with_cpg(findings, Path(sample["file"]), job_id=job, client=self.joern)
        return status

    def evaluate(self, sample: dict, meta: dict) -> dict:
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

        file_findings, sast_status = sast_cache.findings_for(sample["file"])
        findings = [copy.deepcopy(f) for f in file_findings if _in_function(f, sample)]
        record.update(file_findings=len(file_findings), n_findings=len(findings), sast_status=sast_status)

        if not findings:
            return {
                **record,
                "status": "ok",
                "sast_pred": 0,
                "board_pred": 0,
                "board_override_pred": 0,
                "p_vulnerable": None,
                "vote_share": None,
                "findings": [],
                "seconds": round(time.time() - started, 1),
                "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

        record["cpg_status"] = self._cpg(sample, findings) if self.joern is not None else "skipped"
        if self.rag is not None:
            enrich_with_rag(findings, job_id="realworld", rag=self.rag)

        res = self._deliberate(sample, _function_code(sample), findings)
        if res.get("llm_status") != "success":
            return {**record, "status": "llm_failed", "error": str(res.get("error"))[:300],
                    "seconds": round(time.time() - started, 1)}

        grounded = bool((res.get("evidence_check") or {}).get("grounded"))
        record.update({
            "status": "ok",
            "sast_pred": 1,
            # Majority of the Judge votes; the evidence check is only a signal.
            "board_pred": res["prediction"],
            # Ablation: the citation rule as an override (a SAFE majority whose
            # sanitizer quote is not in the code is kept as vulnerable).
            "board_override_pred": int(res["prediction"] == 1 or not grounded),
            "p_vulnerable": res.get("p_vulnerable"),
            "vote_share": res.get("vote_share"),
            "board": _board_summary(res),
            "findings": [_finding_summary(f) for f in findings],
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


def run_evaluation(retry_failed: bool = False, limit: int | None = None) -> None:
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
    done = {sid for sid, r in results.items() if r.get("status") == "ok" or not retry_failed}
    todo = [s for s in samples if s["sample_id"] not in done]
    logger.info(f"{len(samples)} samples, {len(samples) - len(todo)} already done, {len(todo)} to go")

    try:
        state.update_status(phase="sast_prescan", detail=None, done=len(samples) - len(todo), total=len(samples))
        scan = sast_cache.prescan(
            [s["file"] for s in todo],
            progress=lambda d, t: state.update_status(detail=f"SAST {d}/{t} files"),
        )
        logger.info(f"SAST prescan done: {scan}")
        state.update_status(sast_prescan=scan, detail=None)

        evaluator = Evaluator()
        evaluator.wait_ready()

        session_start = time.time()
        finished = 0
        for s in todo:
            if _stop:
                break
            _wait_for_disk()
            evaluator.maybe_recheck()

            remaining = len(todo) - finished
            rate = (time.time() - session_start) / finished if finished else None
            state.update_status(
                phase="evaluate",
                detail=f"{splits[s['pair_id']]['split']} {s['dataset']} {s['kind']} {s['function']}",
                done=len(samples) - remaining,
                total=len(samples),
                sec_per_sample=round(rate, 1) if rate else None,
                eta_hours=round(rate * remaining / 3600, 1) if rate else None,
            )

            try:
                record = evaluator.evaluate(s, splits[s["pair_id"]])
            except Stopped:
                raise
            except Exception as e:  # one broken sample must not end an overnight run
                logger.exception(f"Sample failed: {s['sample_id']}")
                record = {"sample_id": s["sample_id"], "pair_id": s["pair_id"], "dataset": s["dataset"],
                          "label": s["label"], "kind": s["kind"], "cwe": s["cwe"],
                          "split": splits[s["pair_id"]]["split"], "clean": splits[s["pair_id"]]["clean"],
                          "pipeline": PIPELINE_VERSION,
                          "status": "error", "error": f"{e.__class__.__name__}: {e}"[:300]}
            state.append_jsonl(state.RESULTS_PATH, record)
            finished += 1
            logger.info(
                f"[{len(samples) - len(todo) + finished}/{len(samples)}] {record['status']} "
                f"{record.get('split')} label={s['label']} findings={record.get('n_findings')} "
                f"board={record.get('board_pred')} p={record.get('p_vulnerable')} "
                f"({record.get('seconds')}s) {s['sample_id']}"
            )
    except Stopped:
        logger.warning("Stopped while waiting on a dependency")
        state.update_status(phase="stopped", waiting_for=None)
        return

    results = state.load_results()
    state.update_status(
        phase="evaluate_done" if not _stop else "stopped",
        detail=None,
        done=sum(1 for s in samples if s["sample_id"] in results),
        total=len(samples),
        eta_hours=None,
    )
