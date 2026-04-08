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


import os
import json
import glob

@router.get("/metrics")
def get_metrics():
    """Retrieve the latest evaluation metrics snapshot."""
    eval_dir = "eval_results"
    if not os.path.exists(eval_dir):
        # Return empty safe defaults if benchmarking skipped
        return {
            "baseline_metrics": {"precision": 0, "recall": 0, "f1": 0, "fpr": 0},
            "hackersec_metrics": {"precision": 0, "recall": 0, "f1": 0, "fpr": 0},
            "raw_counts": {}
        }
        
    jsons = glob.glob(f"{eval_dir}/*.json")
    if not jsons:
        return {
            "baseline_metrics": {"precision": 0, "recall": 0, "f1": 0, "fpr": 0},
            "hackersec_metrics": {"precision": 0, "recall": 0, "f1": 0, "fpr": 0},
            "raw_counts": {}
        }
        
    # Sort by datestring, get latest
    latest_file = sorted(jsons)[-1]
    with open(latest_file, "r") as f:
         return json.load(f)
