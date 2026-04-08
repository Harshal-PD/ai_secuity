import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from hackersec.main import app

client = TestClient(app)
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vuln_sample.py"


@pytest.mark.integration
def test_upload_file():
    """Test the POST /api/upload endpoint."""
    with open(FIXTURE_PATH, "rb") as f:
        files = {"file": ("vuln_sample.py", f, "text/x-python")}
        response = client.post("/api/upload", files=files)
    
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "pending"
    assert data["filename"] == "vuln_sample.py"


@pytest.mark.integration
def test_analyze_repo():
    """Test the POST /api/analyze endpoint."""
    payload = {"repo_url": "https://github.com/PyCQA/bandit.git"}
    response = client.post("/api/analyze", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "pending"
    assert data["repo_url"] == payload["repo_url"]


@pytest.mark.integration
def test_status_and_results_endpoints():
    """Test the GET /api/status/{job_id} and GET /api/results/{job_id} endpoints."""
    # Since we are not running a live Celery worker, we inject a job to test the GET endpoints.
    from hackersec.db import store
    store.init_db()
    
    job_id = "test-job-123"
    store.create_job(job_id, target="test", target_type="file")
    
    # Check status (pending)
    res = client.get(f"/api/status/{job_id}")
    assert res.status_code == 200
    assert res.json()["status"] == "pending"
    
    # Check results (pending status overrides finding list logic)
    res2 = client.get(f"/api/results/{job_id}")
    assert res2.status_code == 200
    assert res2.json()["status"] == "pending"
    
    # Mark as complete and save dummy findings
    from hackersec.analysis.schema import Finding
    store.update_job(job_id, status="complete", finding_count=1)
    f1 = Finding(job_id=job_id, file_path="app.py", line_start=1, line_end=1, rule_id="1", tool="semgrep", severity="high", message="test")
    store.save_findings(job_id, [f1])
    
    res3 = client.get(f"/api/results/{job_id}")
    assert res3.status_code == 200
    assert res3.json()["status"] == "complete"
    assert res3.json()["finding_count"] == 1
    assert len(res3.json()["findings"]) == 1
