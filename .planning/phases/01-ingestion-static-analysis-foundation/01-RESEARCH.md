# Phase 1 Research: Ingestion & Static Analysis Foundation

## RESEARCH COMPLETE

**Phase:** 1 — Ingestion & Static Analysis Foundation
**Goal:** FastAPI + Celery + Semgrep/Bandit pipeline that accepts code, runs SAST, deduplicates findings, returns normalized JSON

---

## 1. FastAPI + Celery + Redis Architecture

### Recommended Structure

```
hackersec/
├── main.py              # FastAPI app entry point
├── api/
│   ├── routes/
│   │   ├── upload.py    # POST /upload, POST /analyze
│   │   └── results.py   # GET /status/{job_id}, GET /results/{job_id}
├── worker/
│   ├── celery_app.py    # Celery app + broker config
│   └── tasks.py         # @celery.task: run_analysis()
├── analysis/
│   ├── static.py        # Semgrep + Bandit runners
│   ├── dedup.py         # Finding deduplication
│   └── schema.py        # Normalized finding dataclass
├── db/
│   └── store.py         # SQLite job + findings store
└── ingestion/
    ├── git_clone.py     # GitPython clone
    ├── file_upload.py   # Multipart upload handler
    └── detector.py      # Language detection
```

### Key Implementation Patterns

**FastAPI endpoint returning job ID immediately:**
```python
@app.post("/analyze")
async def analyze_repo(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    # Store pending job
    db.create_job(job_id, status="pending")
    # Dispatch to Celery (non-blocking)
    run_analysis.delay(job_id, request.repo_url)
    return {"job_id": job_id, "status": "pending"}
```

**Celery task structure:**
```python
@celery.task(bind=True, max_retries=2)
def run_analysis(self, job_id: str, target: str):
    db.update_job(job_id, status="running")
    try:
        findings = pipeline.run(target)
        db.save_findings(job_id, findings)
        db.update_job(job_id, status="complete")
    except Exception as exc:
        db.update_job(job_id, status="failed", error=str(exc))
```

### Celery + Redis Config
- Broker: `redis://localhost:6379/0`
- Backend: `redis://localhost:6379/1`
- Worker concurrency: 2 (Semgrep + Joern are CPU-bound)
- Task timeout: 300 seconds (large repos need headroom)

---

## 2. Semgrep Integration

### Correct Rule Sets for Security Focus (NOT `--config=auto`)
```bash
semgrep --config p/security-audit \
        --config p/owasp-top-ten \
        --config p/python \
        --json \
        --timeout 60 \
        /path/to/target
```

### Parsing Semgrep JSON Output
```python
import subprocess, json

def run_semgrep(target_path: str) -> list[dict]:
    result = subprocess.run(
        ["semgrep", "--config", "p/security-audit",
         "--config", "p/owasp-top-ten",
         "--json", "--timeout", "60", str(target_path)],
        capture_output=True, text=True, timeout=120
    )
    if result.returncode not in (0, 1):  # 1 = findings found (not error)
        raise RuntimeError(f"Semgrep failed: {result.stderr}")
    data = json.loads(result.stdout)
    return data.get("results", [])
```

### Semgrep Finding Fields to Extract
- `check_id` → rule_id
- `path` → file path
- `start.line` → line number
- `extra.severity` → severity (ERROR=Critical, WARNING=High, INFO=skip)
- `extra.message` → human-readable message
- `extra.metadata.cwe` → CWE list (may be absent — handle gracefully)
- `extra.metadata.owasp` → OWASP category

### Filter INFO-Level
```python
KEEP_SEVERITIES = {"ERROR", "WARNING"}  # Skip INFO

findings = [f for f in raw if f["extra"]["severity"] in KEEP_SEVERITIES]
```

---

## 3. Bandit Integration

### Bandit CLI + JSON Output
```bash
bandit -r /path/to/target -f json -ll  # -ll = medium severity and above
```

### Parsing Bandit Output
```python
def run_bandit(target_path: str) -> list[dict]:
    result = subprocess.run(
        ["bandit", "-r", str(target_path), "-f", "json", "-ll"],
        capture_output=True, text=True, timeout=60
    )
    # Bandit exits 1 when issues found — that's not an error
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return data.get("results", [])
```

### Bandit Fields to Extract
- `test_id` → rule_id (e.g. "B608")
- `filename` → file path
- `line_number` → line
- `issue_severity` → HIGH/MEDIUM/LOW (map to Critical/High/Medium)
- `issue_text` → message
- `issue_cwe.id` → CWE number (Bandit ≥1.7.5 includes CWE)

---

## 4. Normalized Finding Schema

### Dataclass Definition
```python
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Finding:
    id: str                        # UUID, generated on creation
    job_id: str
    file_path: str
    line_start: int
    line_end: int
    rule_id: str
    tool: str                      # "semgrep" | "bandit"
    severity: str                  # "critical" | "high" | "medium" | "low"
    message: str
    cwe_ids: list[str] = field(default_factory=list)   # ["CWE-89", "CWE-20"]
    owasp_category: Optional[str] = None               # "A03:2021"
    code_snippet: Optional[str] = None                 # raw source lines
    # Enrichment fields (filled by later phases)
    cpg_context: Optional[dict] = None
    rag_docs: Optional[list] = None
    llm_analysis: Optional[dict] = None
    fusion_verdict: Optional[str] = None
    patch: Optional[str] = None
```

### Severity Mapping
```python
SEMGREP_SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": None,         # Filtered out
}
BANDIT_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
```

---

## 5. Deduplication Strategy

### Dedup Key
Two findings are duplicates if they share the same `(file_path, line_start, cwe_category)`:

```python
def get_cwe_category(cwe_ids: list[str]) -> str:
    """Extract primary CWE for grouping — CWE-89 → '89'"""
    return cwe_ids[0].replace("CWE-", "") if cwe_ids else "unknown"

def dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen = {}
    for f in findings:
        key = (f.file_path, f.line_start, get_cwe_category(f.cwe_ids))
        if key not in seen:
            seen[key] = f
        else:
            # Keep the higher-severity finding
            if severity_rank(f.severity) > severity_rank(seen[key].severity):
                seen[key] = f
    return list(seen.values())

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
severity_rank = lambda s: SEVERITY_RANK.get(s, 0)
```

---

## 6. Language Detection

### Using `pygments` or simple extension mapping
```python
LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
}

def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return LANGUAGE_MAP.get(ext, "unknown")
```

---

## 7. SQLite Store

### Schema
```sql
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,  -- pending|running|complete|failed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    target TEXT,
    error TEXT
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    job_id TEXT REFERENCES jobs(id),
    file_path TEXT,
    line_start INTEGER,
    severity TEXT,
    rule_id TEXT,
    tool TEXT,
    message TEXT,
    cwe_ids TEXT,  -- JSON array
    code_snippet TEXT,
    cpg_context TEXT,  -- JSON, filled in Phase 2
    rag_docs TEXT,     -- JSON, filled in Phase 3
    llm_analysis TEXT, -- JSON, filled in Phase 4
    fusion_verdict TEXT,
    patch TEXT
);
```

---

## 8. Git Clone via GitPython

```python
import git

def clone_repo(url: str, dest: Path) -> Path:
    """Clone repo to temp directory. Returns path to cloned dir."""
    try:
        git.Repo.clone_from(url, str(dest), depth=1)  # Shallow clone for speed
        return dest
    except git.GitCommandError as e:
        raise ValueError(f"Failed to clone {url}: {e}")
```

---

## 9. File Upload Handling

```python
from fastapi import UploadFile
import shutil

async def save_upload(file: UploadFile, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return dest
```

---

## 10. Key Pitfall Reminders (from project research)

- **Semgrep exit code 1** = findings found (not error). Handle correctly or analysis silently fails.
- **Bandit on non-Python files** will error. Guard with language detection before running.
- **Celery task timeout** needed — set both `soft_time_limit` and `time_limit`.
- **INFO findings** must be filtered BEFORE storing — don't let them reach the DB.
- **UTF-8 decode errors** from subprocess output — always use `errors='replace'` or encode check.

---

## Validation Architecture

### Test Approach for Phase 1

| Test Target | Method | Success Signal |
|-------------|--------|----------------|
| `/upload` endpoint | curl multipart POST | Returns `{"job_id": "...", "status": "pending"}` in <500ms |
| `/analyze` endpoint | curl POST with git URL | Returns job_id; status transitions to `complete` |
| `/status/{id}` | Poll until `complete` | No infinite loop; correct status values |
| `/results/{id}` | GET after complete | Returns list of findings with all schema fields |
| Semgrep integration | Known-vuln Python file | SQL injection finding returned at High/Critical |
| Bandit integration | `os.system()` call in code | B605 finding returned |
| Deduplication | File with same vuln reported by 2 tools | Only 1 finding in results |
| INFO filter | File with only INFO findings | Empty results list |
