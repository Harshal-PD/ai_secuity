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


def enrich_with_cpg(
    findings: list,
    target_path: Path,
    job_id: str = "standalone",
    client=None,
    extra=None,
    method_line: int | None = None,
    root: Path | None = None,
) -> str:
    """
    Attach Joern taint flows to each finding. Returns a status string.

    `target_path` may be a file or a directory; a file's directory is imported
    so the CPG stays small, unless `root` names a directory that contains the
    target (a version root with companion files), which is imported instead so
    cross-file imports resolve. Joern resolves the path itself, so it must be on
    a volume the Joern container shares. `extra(client, project, rel_path)` runs
    further queries against the same imported project before it is deleted.
    """
    from hackersec.analysis.joern.client import JoernClient
    from hackersec.analysis.joern.exceptions import (
        JoernConnectionError,
        JoernQueryError,
    )

    if not findings and extra is None:
        return "skipped_no_findings"

    target = Path(target_path)
    root = Path(root) if root else (target if target.is_dir() else target.parent)
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
    file_lines_cache: dict[str, list[str]] = {}
    try:
        from hackersec.analysis.joern.queries import classify_taint_paths

        for f in findings:
            rel = _relative_to(f.file_path, root)
            try:
                f.cpg_context = joern_client.query_taint(
                    project, rel, f.line_start, method_line=method_line, line_end=f.line_end
                )
                flows = f.cpg_context.get("taint_paths") or []
                if flows:
                    fp = str(f.file_path)
                    if fp not in file_lines_cache:
                        try:
                            file_lines_cache[fp] = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
                        except OSError:
                            file_lines_cache[fp] = []
                    unfiltered, sanitized = classify_taint_paths(flows, file_lines_cache.get(fp))
                    f.cpg_context["unfiltered_taint_paths"] = unfiltered
                    f.cpg_context["sanitized_taint_paths"] = sanitized
                    f.cpg_context["unfiltered_flows"] = len(unfiltered)
                    f.cpg_context["sanitized_flows"] = len(sanitized)
            except (JoernConnectionError, JoernQueryError) as e:
                failed += 1
                f.cpg_context = {"cpg_status": "failed", "error": str(e)[:300]}
            logger.info(
                f"[{job_id}] Taint {rel}:{f.line_start} -> {f.cpg_context.get('cpg_status')} "
                f"({len(f.cpg_context.get('taint_paths') or [])} flows: "
                f"{f.cpg_context.get('unfiltered_flows', 0)} unfiltered, "
                f"{f.cpg_context.get('sanitized_flows', 0)} sanitized)"
            )
        if extra is not None:
            try:
                extra(joern_client, project, _relative_to(str(target), root))
            except (JoernConnectionError, JoernQueryError) as e:
                failed += 1
                logger.warning(f"[{job_id}] Extra CPG queries failed: {e}")
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
            logger.info(f"[{job_id}] RAG lookup: {f.rule_id} {f.cwe_ids}")
            f.rag_docs = store.retrieve_for_finding(
                f.rule_id, f.cwe_ids, f.owasp_category, f.message or "", top_k=2
            )

        logger.info(f"[{job_id}] RAG enrichment complete")
        return "success"

    except Exception as e:
        logger.error(f"[{job_id}] RAG augmentation failed: {e}", exc_info=True)
        for f in findings:
            if not f.rag_docs:
                f.rag_docs = []
        return "failed"
