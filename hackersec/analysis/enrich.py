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


def _relative_to(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).name


def enrich_with_cpg(findings: list, target_path: Path, job_id: str = "standalone", client=None) -> str:
    """
    Attach Joern taint flows to each finding. Returns a status string.

    `target_path` may be a file or a directory; a file's directory is imported
    so the CPG stays small. Joern resolves the path itself, so it must be on a
    volume the Joern container shares.
    """
    from hackersec.analysis.joern.client import JoernClient
    from hackersec.analysis.joern.exceptions import (
        JoernConnectionError,
        JoernQueryError,
    )

    if not findings:
        return "skipped_no_findings"

    target = Path(target_path)
    root = target if target.is_dir() else target.parent
    project = f"hs_{job_id}"
    joern_client = client or JoernClient()

    try:
        logger.info(f"[{job_id}] Building CPG for {root}")
        methods = joern_client.import_project(root, project)
        logger.info(f"[{job_id}] CPG ready ({methods} methods)")
    except (JoernConnectionError, JoernQueryError) as e:
        logger.warning(f"[{job_id}] Joern CPG pipeline failed gracefully: {e}")
        for f in findings:
            if not f.cpg_context:
                f.cpg_context = {"cpg_status": "failed", "error": str(e)[:300]}
        return "failed"

    failed = 0
    try:
        for f in findings:
            rel = _relative_to(f.file_path, root)
            try:
                f.cpg_context = joern_client.query_taint(project, rel, f.line_start)
            except (JoernConnectionError, JoernQueryError) as e:
                failed += 1
                f.cpg_context = {"cpg_status": "failed", "error": str(e)[:300]}
            logger.info(
                f"[{job_id}] Taint {rel}:{f.line_start} -> {f.cpg_context.get('cpg_status')} "
                f"({len(f.cpg_context.get('taint_paths') or [])} flows)"
            )
    finally:
        joern_client.delete_project(project)

    logger.info(f"[{job_id}] CPG augmentation complete")
    return "success" if not failed else "partial"


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
