# Architecture Research — HackerSec

## Domain: AI-Driven Security Code Review & Vulnerability Analysis

---

## System Architecture Overview

### Component Map

```
┌─────────────────────────────────────────────────────┐
│                   CLIENT / WEB UI                   │
│          (React/Streamlit dashboard)                 │
└───────────────────────┬─────────────────────────────┘
                        │ REST API
┌───────────────────────▼─────────────────────────────┐
│              FASTAPI INGESTION LAYER                 │
│   - /upload endpoint (file)                          │
│   - /analyze endpoint (git URL)                      │
│   - Language detection                               │
│   - Celery task dispatch                             │
└───────────────────────┬─────────────────────────────┘
                        │ Celery Job
          ┌─────────────▼──────────────┐
          │      CELERY WORKER          │
          │  Orchestrates pipeline:     │
          │  1. Static Analysis         │
          │  2. CPG Generation          │
          │  3. RAG Retrieval           │
          │  4. LLM Reasoning           │
          │  5. Fusion Decision         │
          │  6. Patch Generation        │
          └────────┬────────────────────┘
                   │
    ┌──────────────┼──────────────────────┐
    │              │                      │
    ▼              ▼                      ▼
┌───────┐    ┌──────────┐         ┌───────────┐
│SEMGREP│    │  JOERN   │         │  OLLAMA   │
│BANDIT │    │  (CPG)   │         │  (LOCAL   │
│FLAWFND│    │  Engine  │         │   LLM)    │
└───┬───┘    └────┬─────┘         └─────┬─────┘
    │             │                     │
    ▼             ▼                     ▼
┌───────────────────────────────────────────────────┐
│              FINDINGS AGGREGATOR                   │
│  - Normalize all findings to common schema         │
│  - Deduplicate by (file, line, rule_id)            │
│  - Enrich with CPG context + RAG docs              │
└──────────────────────┬────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │     FAISS RAG STORE     │
          │  OWASP + CWE + NVD      │
          │  sentence-transformers  │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │    FUSION CLASSIFIER    │
          │  (scikit-learn)         │
          │  Inputs:                │
          │  - static confidence    │
          │  - LLM confidence       │
          │  - graph features       │
          │  Output: verdict + SHAP │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │   PATCH GENERATOR       │
          │  LLM → diff → validate  │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │     RESULTS STORE       │
          │  SQLite / JSON file     │
          └─────────────────────────┘
```

---

## Data Flow

### Per-Finding Enrichment Flow

```
Static finding (file, line, rule_id, message)
    │
    ├─► CPG Query: "what are the data flows reaching this line?"
    │       → Returns: taint sources, sinks, control flow context
    │
    ├─► RAG Query: embed(finding.message) → FAISS → top-3 CWE docs
    │       → Returns: CWE description, exploitability, OWASP category
    │
    └─► LLM Prompt:
          System: "You are a security expert."
          User: {finding} + {cpg_context} + {cwe_docs}
          → Returns: explanation, root cause, fix, confidence (0-1)
```

### Fusion Decision Flow

```
Feature vector:
  [static_confidence, llm_confidence, cpg_taint_depth,
   cwe_severity_score, line_complexity, rule_category_weight]
    │
    ▼
GradientBoostingClassifier (pretrained on Big-Vul labels)
    │
    ▼
verdict: {true_positive, false_positive, uncertain}
SHAP values: which features drove the decision
```

---

## Component Boundaries

| Component | Responsibility | Owns | Does NOT own |
|-----------|---------------|------|--------------|
| FastAPI | HTTP API, job dispatch | /upload, /analyze, /status, /results | Analysis logic |
| Celery | Async pipeline orchestration | Job state, worker routing | HTTP concerns |
| Semgrep/Bandit | Known-pattern vulnerability detection | Static findings JSON | Semantic reasoning |
| Joern | CPG generation + graph queries | AST, CFG, PDG, taint flows | LLM prompting |
| FAISS + sentence-transformers | Semantic retrieval from CWE/OWASP corpus | Vector embeddings, similarity search | LLM reasoning |
| Ollama | Local LLM inference | Model serving, GPU routing | Prompt construction |
| Fusion classifier | FP/TP decision | Final verdict, SHAP explanation | Individual tool scores |
| Dashboard | Visualization | UI, user interaction | Backend logic |

---

## Build Order (Phase Dependencies)

```
Phase 1: Ingestion + Static Analysis    (no deps — standalone)
Phase 2: CPG integration                (depends on Phase 1 findings schema)
Phase 3: RAG Knowledge Base            (no deps — standalone, parallelizable with Phase 2)
Phase 4: LLM Reasoning                 (depends on Phase 2 CPG + Phase 3 RAG)
Phase 5: Fusion Classifier             (depends on Phase 4 outputs for feature construction)
Phase 6: Patch Generation              (depends on Phase 4 LLM)
Phase 7: Evaluation                    (depends on Phases 1-6 complete)
Phase 8: Dashboard                     (depends on all pipeline phases)
```

---

## Key Architectural Decisions

### Why Celery + Redis for job queue?
- Joern CPG generation blocks for 30–120 seconds on medium repos
- FastAPI should return job IDs immediately; worker processes async
- Redis is lightweight and runs locally without external infrastructure

### Why SQLite for results store?
- Single-file database, no server, perfect for research reproducibility
- Enough for demo + evaluation datasets (not millions of findings)
- Easy to export to JSON/CSV for paper tables

### Why subprocess for Semgrep/Joern?
- Both tools have CLI interfaces; subprocess is simplest integration
- Avoids library version conflicts
- JSON output is stable across versions

### Why direct FAISS (not LangChain)?
- LangChain adds 3+ abstraction layers — masks behavior from graders
- Direct pipeline = clear research contribution, reproducible experiments
- Fewer dependencies = fewer failure modes

---

## Performance Considerations

| Bottleneck | Expected Latency | Mitigation |
|------------|-----------------|------------|
| Joern CPG startup | 5–10 seconds | Keep Joern server alive between analyses |
| Joern CPG parse (large repo) | 30–120 seconds | Async Celery job, stream status to UI |
| Ollama LLM inference | 5–30 seconds per finding | Batch findings, parallel workers |
| FAISS vector search | < 10ms | No concern |
| Semgrep scan | 1–10 seconds | No concern |
