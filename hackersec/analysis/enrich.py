"""
Shared CPG and RAG enrichment.

The Celery worker and the evaluation harness both call these functions, so a
reported metric reflects the same enrichment the live pipeline performs. Each
function mutates the findings in place and never raises: a missing Joern or
FAISS index degrades the finding, it does not fail the run.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def enrich_with_cpg(findings: list, target_path: Path, job_id: str = "standalone") -> str:
    """Attach Joern taint flows to each finding. Returns a status string."""
    from hackersec.analysis.joern.client import JoernClient
    from hackersec.analysis.joern.exceptions import (
        JoernConnectionError,
        JoernQueryError,
    )

    if not findings:
        return "skipped_no_findings"

    try:
        joern_client = JoernClient()
        cpg_workspace = f"job_{job_id}"
        logger.info(f"[{job_id}] Initializing CPG on workspace {cpg_workspace}")

        joern_client.create_workspace(cpg_workspace)
        joern_client.import_code(target_path, cpg_workspace)

        for f in findings:
            logger.info(f"[{job_id}] Taint flow query: {f.file_path}:{f.line_start}")
            f.cpg_context = joern_client.query_taint(
                cpg_workspace, str(f.file_path), f.line_start
            )

        logger.info(f"[{job_id}] CPG augmentation complete")
        return "success"

    except (JoernConnectionError, JoernQueryError) as e:
        logger.warning(f"[{job_id}] Joern CPG pipeline failed gracefully: {e}")
        for f in findings:
            if not f.cpg_context:
                f.cpg_context = {"cpg_status": "failed", "error": str(e)}
        return "failed"


def enrich_with_rag(findings: list, job_id: str = "standalone", rag=None) -> str:
    """
    Attach retrieved OWASP/CWE definitions to each finding.

    Pass an existing `LocalRAGStore` to avoid reloading the sentence-transformer
    for every file during an evaluation sweep.
    """
    if not findings:
        return "skipped_no_findings"

    try:
        if rag is None:
            from hackersec.analysis.rag import LocalRAGStore

            rag = LocalRAGStore()
        store = rag
        for f in findings:
            query_str = f"Security vulnerability {f.rule_id} "
            if f.cwe_ids:
                query_str += " ".join(f.cwe_ids)
            if f.owasp_category:
                query_str += f" {f.owasp_category}"

            logger.info(f"[{job_id}] RAG query: {query_str}")
            f.rag_docs = store.search(query_str, top_k=2)

        logger.info(f"[{job_id}] RAG enrichment complete")
        return "success"

    except Exception as e:
        logger.error(f"[{job_id}] RAG augmentation failed: {e}", exc_info=True)
        for f in findings:
            if not f.rag_docs:
                f.rag_docs = []
        return "failed"
