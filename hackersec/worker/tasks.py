import shutil
import tempfile
import logging
from pathlib import Path

from hackersec.worker.celery_app import celery_app
from hackersec.db import store
# from hackersec.analysis.static import run_static_analysis
# from hackersec.analysis.dedup import dedup_findings, summarize_findings
# from hackersec.ingestion.git_clone import clone_repo

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="hackersec.worker.tasks.run_analysis", max_retries=0)
def run_analysis(self, job_id: str, target: str, target_type: str):
    """Main analysis pipeline task. Orchestrates static analysis pipeline."""
    logger.info(f"[{job_id}] Starting analysis — target_type={target_type}")
    store.update_job(job_id, status="running")
    tmpdir = Path(tempfile.mkdtemp(prefix="hackersec_"))

    try:
        # Stub implementation for Wave 1 testing
        logger.info(f"[{job_id}] Stub analysis on {target}")
        
        # Step 4: Store results
        findings = []
        store.save_findings(job_id, findings)
        store.update_job(job_id, status="complete", finding_count=len(findings))
        logger.info(f"[{job_id}] Analysis complete")

    except Exception as exc:
        logger.error(f"[{job_id}] Analysis failed: {exc}", exc_info=True)
        store.update_job(job_id, status="failed", error=str(exc))
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
