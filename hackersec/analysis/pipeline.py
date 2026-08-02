"""Shared enrichment pipeline.

Single source of truth for the CPG → RAG → LLM → Fusion → Patch → Verify
stages. Both the Celery worker (`worker/tasks.py`) and the evaluation harness
(`evaluation/runner.py`) call `analyze_findings` so the eval exercises the
*real* pipeline instead of mocked stages.

Each stage fails gracefully: an exception in one stage marks its findings and
lets the rest continue.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Ordered pipeline stages — the frontend renders these as a live progress stepper.
STAGES = ["static", "cpg", "rag", "llm", "fusion", "verify", "patch"]


def _stage(job_id: str, name: str):
    """Record live progress. No-op for non-job callers (e.g. eval)."""
    try:
        from hackersec.db import store
        store.update_job(job_id, status="running", stage=name)
    except Exception:
        pass


def analyze_findings(
    findings: list,
    target_path,
    job_id: str = "standalone",
    *,
    enable_cpg: bool = True,
    enable_llm: bool = True,
    enable_verify: bool = False,
) -> list:
    """Enrich deduped findings in place and return them.

    Args:
        findings: deduped `Finding` list from static analysis.
        target_path: path Joern imports for CPG (file or dir).
        job_id: log correlation id.
        enable_cpg/enable_llm: toggle heavyweight stages (LLM+CPG dominate runtime).
        enable_verify: run the dynamic exploit-verification sandbox stage.
    """
    target_path = Path(target_path)

    # ── CPG Enrichment ────────────────────────────────────────────────────
    if enable_cpg:
        _stage(job_id, "cpg")
        from hackersec.analysis.joern.client import JoernClient
        from hackersec.analysis.joern.exceptions import JoernConnectionError, JoernQueryError

        try:
            joern_client = JoernClient()
            cpg_workspace = f"job_{job_id}"
            logger.info(f"[{job_id}] Initializing CPG on workspace {cpg_workspace}")

            joern_client.create_workspace(cpg_workspace)
            joern_client.import_code(target_path, cpg_workspace)

            for f in findings:
                logger.info(f"[{job_id}] Taint flow query: {f.file_path}:{f.line_start}")
                cpg_res = joern_client.query_taint(cpg_workspace, str(f.file_path), f.line_start)
                f.cpg_context = cpg_res

            logger.info(f"[{job_id}] CPG augmentation complete")

        except (JoernConnectionError, JoernQueryError) as e:
            logger.warning(f"[{job_id}] Joern CPG pipeline failed gracefully: {e}")
            for f in findings:
                if not f.cpg_context:
                    f.cpg_context = {"cpg_status": "failed", "error": str(e)}

    # ── RAG Enrichment ────────────────────────────────────────────────────
    _stage(job_id, "rag")
    try:
        from hackersec.analysis.rag import LocalRAGStore
        rag = LocalRAGStore()
        for f in findings:
            query_str = f"Security vulnerability {f.rule_id} "
            if f.cwe_ids:
                query_str += " ".join(f.cwe_ids)
            if f.owasp_category:
                query_str += f" {f.owasp_category}"

            logger.info(f"[{job_id}] RAG query: {query_str}")
            f.rag_docs = rag.search(query_str, top_k=2)

        logger.info(f"[{job_id}] RAG enrichment complete")
    except Exception as e:
        logger.error(f"[{job_id}] RAG augmentation failed: {e}", exc_info=True)
        for f in findings:
            if not f.rag_docs:
                f.rag_docs = []

    # ── LLM Reasoning ─────────────────────────────────────────────────────
    if enable_llm:
        _stage(job_id, "llm")
        from hackersec.analysis.llm.client import OllamaClient
        from hackersec.analysis.llm.prompter import build_analysis_prompt
        from hackersec.analysis.llm.parser import parse_llm_response

        try:
            llm_client = OllamaClient()
            for f in findings:
                prompt = build_analysis_prompt(f)
                logger.info(f"[{job_id}] Evaluating findings against Ollama for {f.file_path}:{f.line_start}")

                llm_res = llm_client.generate(prompt)

                if llm_res["llm_status"] == "success":
                    f.llm_analysis = parse_llm_response(llm_res["response"])
                else:
                    f.llm_analysis = {"llm_status": llm_res["llm_status"], "error": llm_res.get("error")}

            logger.info(f"[{job_id}] LLM structured mapping complete")

        except Exception as e:
            logger.error(f"[{job_id}] LLM pipeline gracefully bounded exceptions: {e}")
            for f in findings:
                if not getattr(f, "llm_analysis", None):
                    f.llm_analysis = {"llm_status": "failed_connection", "error": str(e)}

    # ── ML Fusion Inference ───────────────────────────────────────────────
    _stage(job_id, "fusion")
    try:
        from hackersec.analysis.ml.inference import FusionClassifier
        classifier = FusionClassifier()
        for f in findings:
            res = classifier.predict(f)
            f.fusion_verdict = res["prediction"]
            if res.get("shap_values"):
                if f.llm_analysis is None:
                    f.llm_analysis = {}
                f.llm_analysis["shap_values"] = res["shap_values"]

        logger.info(f"[{job_id}] ML Classifier fusion completion")

    except Exception as e:
        logger.error(f"[{job_id}] ML Inference crashed gracefully: {e}")
        for f in findings:
            if not f.fusion_verdict:
                f.fusion_verdict = "uncertain"

    # ── Dynamic Exploit Verification ──────────────────────────────────────
    if enable_verify:
        _stage(job_id, "verify")
        from hackersec.analysis.verify import verify_finding

        for f in findings:
            try:
                verify_finding(f, job_id=job_id)
            except Exception as e:
                logger.error(f"[{job_id}] Verification errored for {f.file_path}:{f.line_start}: {e}")
                if f.reproduced is None and f.repro_evidence is None:
                    f.repro_evidence = {"status": "error", "error": str(e)}

    # ── Patch Generation ──────────────────────────────────────────────────
    if enable_llm:
        _stage(job_id, "patch")
        from hackersec.analysis.llm.client import OllamaClient
        from hackersec.analysis.patch import build_patch_prompt, parse_patch, compute_diff, validate_patch

        try:
            llm_client = OllamaClient()
            for f in findings:
                if f.fusion_verdict == "true_positive" and f.code_snippet:
                    logger.info(f"[{job_id}] Generating patch for true positive at {f.file_path}:{f.line_start}")

                    prompt = build_patch_prompt(f)
                    llm_res = llm_client.generate(prompt)

                    if llm_res["llm_status"] == "success":
                        raw_patch = parse_patch(llm_res["response"])
                        f.patch = compute_diff(f.code_snippet, raw_patch)
                        f.patch_status = validate_patch(f, raw_patch)
                    else:
                        f.patch_status = "failed_generation"

            logger.info(f"[{job_id}] Patching validation loops complete")

        except Exception as e:
            logger.error(f"[{job_id}] Patch generation failed elegantly: {e}")
            for f in findings:
                if f.fusion_verdict == "true_positive" and not f.patch_status:
                    f.patch_status = "error"

    return findings
