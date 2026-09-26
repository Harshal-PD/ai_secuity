"""
Phase 2 — run the full production pipeline over every sample, fully offline.

Per sample: Semgrep + Bandit on the whole file (so imports and module context
are visible) -> keep findings inside the target function -> Joern CPG -> RAG ->
Attacker/Defender/Judge board -> fusion classifier.

One checkpoint line is fsync'd per sample, and on restart finished samples are
skipped. An Ollama outage pauses the run instead of recording failures, and a
nearly full disk pauses it instead of crashing the DGX.
"""

import copy
import hashlib
import logging
import os
import shutil
import signal
import time
from pathlib import Path

from hackersec.evaluation.realworld import state

logger = logging.getLogger(__name__)

MIN_FREE_GB = float(os.getenv("REALWORLD_MIN_FREE_GB", "5"))
USE_CPG = os.getenv("REALWORLD_USE_CPG", "1") not in ("0", "false", "False")
LLM_ATTEMPTS = 3

_stop = False


def _on_sigterm(signum, frame):
    global _stop
    _stop = True
    logger.warning("Stop requested — finishing the current sample, then exiting")


# ── Waiting on dependencies ─────────────────────────────────────────────────

def _wait_for_disk() -> None:
    delay = 60
    while shutil.disk_usage(state.ROOT).free / 1e9 < MIN_FREE_GB:
        free = shutil.disk_usage(state.ROOT).free / 1e9
        logger.error(f"Only {free:.1f} GB free (< {MIN_FREE_GB} GB). Paused — free disk space to continue.")
        state.update_status(waiting_for="disk_space", free_gb=round(free, 1))
        time.sleep(delay)
        delay = min(delay * 2, 600)
    state.update_status(waiting_for=None)


def _wait_for_ollama(client, model: str) -> None:
    delay = 15
    started = time.time()
    while True:
        try:
            tags = client.client.get(f"{client.base_url}/api/tags", timeout=10).json()
            names = {m.get("name") for m in tags.get("models", [])}
            if model in names or f"{model}:latest" in names:
                if time.time() - started > 1:
                    logger.info(f"Ollama ready with {model}")
                state.update_status(waiting_for=None)
                return
            reason = f"model {model} not pulled yet"
        except Exception as e:
            reason = f"Ollama unreachable ({e.__class__.__name__})"
        waited = int(time.time() - started)
        logger.warning(f"{reason}; waited {waited}s")
        state.update_status(waiting_for="ollama", waiting_context=reason, waited_seconds=waited)
        time.sleep(delay)
        delay = min(delay * 2, 300)


# ── Per-sample work ─────────────────────────────────────────────────────────

def _in_function(f, sample: dict) -> bool:
    return f.line_start <= sample["line_end"] and (f.line_end or f.line_start) >= sample["line_start"]


def _finding_summary(f) -> dict:
    analysis = f.llm_analysis or {}
    board = analysis.get("board") or {}
    evidence = board.get("evidence_check") or {}
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
        "llm_status": analysis.get("llm_status"),
        "board_verdict": analysis.get("board_verdict"),
        "judge_verdict": (board.get("judge") or {}).get("verdict"),
        "verdict_source": board.get("verdict_source"),
        "confidence": analysis.get("confidence"),
        "attacker_confidence": (board.get("attacker") or {}).get("exploitability_confidence"),
        "defender_safety": (board.get("defender") or {}).get("safety_confidence"),
        "evidence_grounded": evidence.get("grounded"),
        "evidence_reason": evidence.get("reason"),
        "judge_reasoning": ((board.get("judge") or {}).get("reasoning") or "")[:400],
        "fusion": f.fusion_verdict,
    }


class Evaluator:
    def __init__(self):
        from hackersec.analysis.llm.board import AdversarialBoard
        from hackersec.analysis.llm.client import MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE, OllamaClient
        from hackersec.analysis.ml.inference import FusionClassifier

        self.client = OllamaClient()
        self.models = sorted({MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE})
        self.board = AdversarialBoard(client=self.client, mode="board")
        self.classifier = FusionClassifier()
        self.rag = None
        try:
            from hackersec.analysis.rag import LocalRAGStore

            self.rag = LocalRAGStore()
            if self.rag.index.ntotal == 0:
                logger.warning("RAG index is empty — findings will get no retrieved context")
        except Exception as e:
            logger.error(f"RAG store unavailable, continuing without it: {e}")
        self._scan_cache: dict[str, list] = {}

    def wait_ready(self) -> None:
        for m in self.models:
            _wait_for_ollama(self.client, m)

    def _scan(self, file: str) -> list:
        from hackersec.analysis.dedup import dedup_findings
        from hackersec.analysis.static import run_static_analysis

        if file not in self._scan_cache:
            if len(self._scan_cache) > 8:
                self._scan_cache.clear()
            self._scan_cache[file] = dedup_findings(run_static_analysis(Path(file), job_id="realworld"))
        return self._scan_cache[file]

    def _deliberate(self, finding) -> dict:
        res = {}
        for _ in range(LLM_ATTEMPTS):
            res = self.board.deliberate(finding)
            if res.get("llm_status") == "success":
                return res
            logger.warning(f"Board call failed ({res.get('error')}); waiting for Ollama")
            self.wait_ready()
        return res

    def evaluate(self, sample: dict) -> dict:
        from hackersec.analysis.enrich import enrich_with_cpg, enrich_with_rag

        started = time.time()
        record = {
            "sample_id": sample["sample_id"],
            "pair_id": sample["pair_id"],
            "dataset": sample["dataset"],
            "label": sample["label"],
            "kind": sample["kind"],
            "cwe": sample["cwe"],
        }

        if not Path(sample["file"]).exists():
            return {**record, "status": "file_missing", "seconds": 0}

        file_findings = self._scan(sample["file"])
        findings = [copy.deepcopy(f) for f in file_findings if _in_function(f, sample)]
        record["file_findings"] = len(file_findings)
        record["n_findings"] = len(findings)

        if findings:
            if USE_CPG:
                job = "rw_" + hashlib.sha1(sample["file"].encode()).hexdigest()[:12]
                enrich_with_cpg(findings, Path(sample["file"]), job_id=job)
            if self.rag is not None:
                enrich_with_rag(findings, job_id="realworld", rag=self.rag)

            for f in findings:
                f.llm_analysis = self._deliberate(f)
            if any((f.llm_analysis or {}).get("llm_status") != "success" for f in findings):
                return {**record, "status": "llm_failed", "seconds": round(time.time() - started, 1)}

            for f in findings:
                try:
                    f.fusion_verdict = self.classifier.predict(f)["prediction"]
                except Exception as e:
                    logger.warning(f"Fusion failed: {e}")
                    f.fusion_verdict = "true_positive"

        record.update({
            "status": "ok",
            "sast_pred": int(bool(findings)),
            "board_pred": int(any(f.llm_analysis.get("board_verdict") == "TRUE_POSITIVE" for f in findings)),
            "fusion_pred": int(any(f.fusion_verdict == "true_positive" for f in findings)),
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

    samples = _interleaved(state.load_samples())
    if limit:
        samples = samples[: limit * 2]
    if not samples:
        raise RuntimeError(f"No samples in {state.SAMPLES_PATH}. Run the build phase first.")

    results = state.load_results()
    done = {sid for sid, r in results.items() if r.get("status") == "ok" or not retry_failed}
    todo = [s for s in samples if s["sample_id"] not in done]
    logger.info(f"{len(samples)} samples, {len(samples) - len(todo)} already done, {len(todo)} to go")

    evaluator = Evaluator()
    evaluator.wait_ready()

    session_start = time.time()
    finished = 0
    for s in todo:
        if _stop:
            break
        _wait_for_disk()

        remaining = len(todo) - finished
        rate = (time.time() - session_start) / finished if finished else None
        state.update_status(
            phase="evaluate",
            detail=f"{s['dataset']} {s['kind']} {s['function']}",
            done=len(samples) - remaining,
            total=len(samples),
            sec_per_sample=round(rate, 1) if rate else None,
            eta_hours=round(rate * remaining / 3600, 1) if rate else None,
        )

        try:
            record = evaluator.evaluate(s)
        except Exception as e:  # one broken sample must not end an overnight run
            logger.exception(f"Sample failed: {s['sample_id']}")
            record = {"sample_id": s["sample_id"], "pair_id": s["pair_id"], "dataset": s["dataset"],
                      "label": s["label"], "kind": s["kind"], "cwe": s["cwe"],
                      "status": "error", "error": f"{e.__class__.__name__}: {e}"[:300]}
        state.append_jsonl(state.RESULTS_PATH, record)
        finished += 1
        logger.info(
            f"[{len(samples) - len(todo) + finished}/{len(samples)}] {record['status']} "
            f"label={s['label']} findings={record.get('n_findings')} "
            f"board={record.get('board_pred')} ({record.get('seconds')}s) {s['sample_id']}"
        )

    state.update_status(
        phase="evaluate_done" if not _stop else "stopped",
        detail=None,
        done=len(samples) - len(todo) + finished,
        total=len(samples),
        eta_hours=None,
    )
