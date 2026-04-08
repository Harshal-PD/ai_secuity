import shutil
import tempfile
import logging
from pathlib import Path

from hackersec.worker.celery_app import celery_app
from hackersec.db import store
from hackersec.analysis.static import run_static_analysis
from hackersec.analysis.dedup import dedup_findings, summarize_findings
from hackersec.ingestion.git_clone import clone_repo

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="hackersec.worker.tasks.run_analysis", max_retries=0)
def run_analysis(self, job_id: str, target: str, target_type: str):
    """Main analysis pipeline task. Orchestrates static analysis pipeline."""
    logger.info(f"[{job_id}] Starting analysis — target_type={target_type}")
    store.update_job(job_id, status="running")
    tmpdir = Path(tempfile.mkdtemp(prefix="hackersec_"))

    try:
        # ── Step 1: Prepare target path ──────────────────────────────────
        if target_type == "git_url":
            logger.info(f"[{job_id}] Cloning {target}")
            target_path = clone_repo(target, tmpdir / "repo")
        else:
            target_path = Path(target)
            if not target_path.exists():
                raise FileNotFoundError(f"Uploaded file not found: {target}")

        # ── Step 2: Static analysis ───────────────────────────────────────
        logger.info(f"[{job_id}] Running static analysis on {target_path}")
        raw_findings = run_static_analysis(target_path, job_id=job_id)
        logger.info(f"[{job_id}] Raw findings: {len(raw_findings)}")

        # ── Step 3: Deduplication ─────────────────────────────────────────
        findings = dedup_findings(raw_findings)
        logger.info(f"[{job_id}] After dedup: {len(findings)} findings")

        # ── Step 3.5: CPG Enrichment ──────────────────────────────────────
        from hackersec.analysis.joern.client import JoernClient
        from hackersec.analysis.joern.exceptions import JoernConnectionError, JoernQueryError
        
        try:
            joern_client = JoernClient()
            cpg_workspace = f"job_{job_id}"
            logger.info(f"[{job_id}] Initializing CPG on workspace {cpg_workspace}")
            
            # Joern API convention handling
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

        # ── Step 4: Store results ─────────────────────────────────────────
        store.save_findings(job_id, findings)
        store.update_job(job_id, status="complete", finding_count=len(findings))
        logger.info(f"[{job_id}] Analysis complete")

    except Exception as exc:
        logger.error(f"[{job_id}] Analysis failed: {exc}", exc_info=True)
        store.update_job(job_id, status="failed", error=str(exc))
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
