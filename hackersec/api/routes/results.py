from fastapi import APIRouter, HTTPException
from hackersec.db import store

router = APIRouter(prefix="/api", tags=["results"])


@router.get("/status/{job_id}")
def get_status(job_id: str):
    """Get job status: pending | running | complete | failed"""
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@router.get("/results/{job_id}")
def get_results(job_id: str):
    """Get analysis findings for a completed job."""
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job["status"] != "complete":
        return {"job_id": job_id, "status": job["status"], "findings": []}

    findings = store.get_findings(job_id)
    return {
        "job_id": job_id,
        "status": "complete",
        "finding_count": len(findings),
        "findings": findings,
    }
