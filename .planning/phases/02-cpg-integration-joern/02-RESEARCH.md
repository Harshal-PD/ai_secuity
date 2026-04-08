# Phase 2 Research: CPG Integration (Joern)

## RESEARCH COMPLETE

**Phase:** 2 — CPG Integration (Joern)
**Goal:** Integrate Joern server to generate CPGs and execute taint flow queries for static findings. Attach structured graph context to the `Finding` dataclass.

---

## 1. Joern Architecture & Integration Pattern

### Joern Server Mode
Joern takes significant time (5–10s) to boot the JVM and load its Scala environment. To satisfy Success Criteria 1 ("Joern server starts and stays alive"), we must run Joern as a persistent background process.

However, standard Joern (cpgman / joern --server) often has poor Python client support. The most robust research-grade patterns use one of the following:

**Pattern A (Subprocess Server):**
Run `joern --server` and communicate via its internal REST API (typically on port 9000).
*API Flow:*
1. Call `/workspace/create` with path to code.
2. Call `/workspace/query` with Scala Ocular/Joern dialect strings.
3. Parse JSON response.

**Pattern B (Batch Mode via CPG format):**
1. Run `joern-parse /path/to/code -o cpg.bin` (this is relatively fast, bypassing the REPL).
2. Run `joern --script taint_query.sc --params cpgFile=cpg.bin,line=X` and parse output.
Wait, since cold start is a concern, running scripts repeatedly incurs the boot penalty.
Server mode REST API is the required path.

*Validation check (from STACK.md): "Joern ≥2.0 ... server mode integration".*

### Recommended Architecture: Python Joern Client
```python
import httpx
import uuid
from pathlib import Path

class JoernClient:
    def __init__(self, base_url: str = "http://localhost:9000"):
        self.base_url = base_url
    
    def generate_cpg(self, source_path: Path, workspace_name: str) -> None:
        """Triggers CPG generation in Joern server."""
        pass
        
    def query_taint(self, workspace_name: str, file_name: str, line_num: int) -> dict:
        """Executes Scala query to find paths to the given sink line."""
        pass
```

---

## 2. Joern Scala Query Formatting

Constructing the right taint flow query in Joern's Scala DSL is critical. When Semgrep flags line X as SQL injection, that line is our **sink**. We want the CPG context showing where the taint originated (the **source**).

A robust generic query:
```scala
val sink = cpg.call.lineNumber({line}).l
val source = cpg.identifier.l // very broad, but usually we just want reaching definitions
sink.reachableByFlows(source).p
```
*Note for implementation*: Parsing Joern's raw string output for `reachableByFlows` is notoriously complex because it returns an ASCII-art graph.
Alternatively, request JSON formatting inside the scala script:
```scala
sink.reachableByFlows(source).map(f => f.elements.map(n => Map("line" -> n.lineNumber, "code" -> n.code))).toJson
```

---

## 3. Data Structure: CPG Context

The extracted CPG context should be compact. Large AST/CFG dumps will exceed the LLM context window in Phase 4. Keep it to a trace of lines.

```python
{
    "cpg_status": "success",  # or "failed"
    "taint_paths": [
        [
            {"line": 15, "code": "user = request.args.get('user')"},
            {"line": 20, "code": "query = f'SELECT * FROM t WHERE u={user}'"},
            {"line": 25, "code": "cursor.execute(query)"}
        ]
    ]
}
```

---

## 4. Pipeline Integration & Graceful Failure (CPG-04)

`tasks.py` from Phase 1 will be updated:

```python
# Step 2: Static analysis
raw_findings = run_static_analysis(target_path, job_id=job_id)

# Step 3: Deduplication
findings = dedup_findings(raw_findings)

# Step 3.5: CPG Enrichment
try:
    cpg_workspace = f"job_{job_id}"
    joern.generate_cpg(target_path, cpg_workspace)
    for f in findings:
        f.cpg_context = joern.query_taint(cpg_workspace, f.file_path, f.line_start)
except Exception as e:
    logger.warning(f"Joern failed gracefully: {e}")
    for f in findings:
        f.cpg_context = {"cpg_status": "failed", "error": str(e)}
```

---

## 5. Pitfalls
1. **Memory Exhaustion:** Joern requires significant JVM heap for large repositories (e.g. `export _JAVA_OPTIONS="-Xmx8G"`).
2. **Server Availability:** We need to check if the Joern REST API is actually up before sending files; timeout is necessary.
3. **Scala Output Parsing:** Relying on `toJson` is much safer than parsing Joern's stdout string formats. Ensure `io.circe.syntax._` is available or use native Joern JSON dumps if newer version.

---

## Validation Architecture

| Test Target | Method | Success Signal |
|-------------|--------|----------------|
| Joern server status | GET /health or local TCP socket check | Port 9000 is open and responding |
| CPG generation | Local vulnerable file | Workspace created in Joern successfully |
| Taint flow extraction | Supply mock SQLi line number | JSON response containing source->sink lines |
| Graceful degradation | Shut down Joern server prior to pipeline run | Findings still land in DB, marked `cpg_status: failed` |
