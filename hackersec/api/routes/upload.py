import uuid
import tempfile
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from hackersec.db import store
from hackersec.worker.tasks import run_analysis

router = APIRouter(prefix="/api", tags=["analysis"])


class AnalyzeRequest(BaseModel):
    repo_url: str


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a source file for analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    job_id = str(uuid.uuid4())
    # Save uploaded file to temp location
    tmpdir = Path(tempfile.mkdtemp())
    dest = tmpdir / file.filename
    content = await file.read()
    dest.write_bytes(content)

    store.create_job(job_id, target=str(dest), target_type="file")
    run_analysis.delay(job_id, str(dest), "file")

    return {"job_id": job_id, "status": "pending", "filename": file.filename}


@router.post("/analyze")
async def analyze_repo(request: AnalyzeRequest):
    """Trigger analysis of a public git repository."""
    if not request.repo_url.startswith(("http://", "https://", "git@")):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    job_id = str(uuid.uuid4())
    store.create_job(job_id, target=request.repo_url, target_type="git_url")
    run_analysis.delay(job_id, request.repo_url, "git_url")

    return {"job_id": job_id, "status": "pending", "repo_url": request.repo_url}
