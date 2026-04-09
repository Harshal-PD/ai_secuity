# Requirements: HackerSec

**Defined:** 2026-04-08
**Core Value:** Accurate, context-aware vulnerability detection with actionable remediation — grounded in security standards, not hallucination.

---

## v1 Requirements

### Ingestion

- [ ] **INGT-01**: User can upload a source code file (Python) via web UI or REST API and receive a job ID
- [ ] **INGT-02**: User can provide a public git repository URL and the system clones and analyzes it
- [ ] **INGT-03**: System automatically detects programming language of each submitted file
- [ ] **INGT-04**: System splits multi-file repos into individual file units for per-file analysis
- [ ] **INGT-05**: User can query job status (pending / running / complete / failed) via API

### Static Analysis

- [ ] **STAT-01**: System runs Semgrep with security-focused rule sets (`p/security-audit`, `p/owasp-top-ten`) on submitted code
- [ ] **STAT-02**: System runs Bandit on Python files and parses JSON output
- [ ] **STAT-03**: System deduplicates findings from multiple tools by `(file, line, CWE category)` — one finding per unique location+class
- [ ] **STAT-04**: Each finding includes: file path, line number, rule ID, severity (Critical/High/Medium/Low), raw message
- [ ] **STAT-05**: System filters out INFO-level and non-security stylistic findings before LLM analysis

### CPG (Code Property Graph)

- [ ] **CPG-01**: System generates a Code Property Graph (CPG) for submitted code using Joern
- [ ] **CPG-02**: System queries Joern for taint flows (sources → sinks) relevant to each static finding
- [ ] **CPG-03**: CPG context (taint paths, AST excerpt) is extracted and structured for LLM prompt injection
- [ ] **CPG-04**: System handles Joern parse failures gracefully — pipeline continues with empty CPG context if Joern errors

### RAG Knowledge Base

- [ ] **RAG-01**: System embeds OWASP Top 10 descriptions using `sentence-transformers/all-MiniLM-L6-v2` and stores in FAISS index
- [ ] **RAG-02**: System embeds MITRE CWE list (top 25 + common) and stores in the same FAISS index
- [ ] **RAG-03**: FAISS index is persisted to disk and loaded on startup (not rebuilt each run)
- [ ] **RAG-04**: For each finding, system performs semantic search to retrieve top-3 most relevant CWE/OWASP documents
- [ ] **RAG-05**: Retrieved documents are injected into the LLM prompt as grounding context

### LLM Reasoning

- [ ] **LLM-01**: System sends each enriched finding (static result + CPG context + RAG docs) to DeepSeek-Coder-V2 via Ollama
- [ ] **LLM-02**: LLM prompt strictly instructs model to use only provided CWE context — never cite CVE/CWE IDs from memory
- [ ] **LLM-03**: Code snippets in prompts are wrapped in explicit delimiters with instruction to treat as untrusted data (anti-prompt-injection)
- [ ] **LLM-04**: LLM returns: plain-English explanation of vulnerability, root cause, suggested fix, confidence score (0.0–1.0)
- [ ] **LLM-05**: System handles Ollama timeout / failure gracefully — finding is marked `llm_status: failed` and pipeline continues

### Fusion / Decision Layer

- [ ] **FUSE-01**: System constructs a feature vector per finding: static confidence, LLM confidence, CPG taint depth, CWE severity score, rule category weight
- [ ] **FUSE-02**: A trained scikit-learn GradientBoostingClassifier produces a verdict: `true_positive`, `false_positive`, or `uncertain`
- [ ] **FUSE-03**: Classifier is trained with `class_weight='balanced'` on labeled findings from Big-Vul dataset
- [ ] **FUSE-04**: SHAP values are computed per finding to explain which features drove the fusion verdict
- [ ] **FUSE-05**: Final verdict and SHAP explanation are stored alongside the finding in results

### Patch Generation

- [ ] **PATC-01**: For each confirmed vulnerability (verdict: `true_positive`), LLM generates a corrected code snippet
- [ ] **PATC-02**: System shows a diff view of original vs. patched code
- [ ] **PATC-03**: System re-runs Semgrep on the patched snippet to validate the fix removes the finding
- [ ] **PATC-04**: Patch validation result (fixed / still vulnerable / unverified) is stored with the finding

### Evaluation

- [ ] **EVAL-01**: System can run in batch evaluation mode against the Juliet Test Suite (Python subset)
- [ ] **EVAL-02**: System can run in batch evaluation mode against the Big-Vul dataset (real CVE commits)
- [ ] **EVAL-03**: System computes and reports: Precision, Recall, F1-score, False Positive Rate for each evaluation run
- [ ] **EVAL-04**: System computes baseline metrics (Semgrep-only, no AI) for comparison
- [ ] **EVAL-05**: Evaluation results are stored in structured JSON for inclusion in research paper/report

### Dashboard

- [ ] **DASH-01**: User can submit code (file upload or git URL) from the web dashboard
- [ ] **DASH-02**: Dashboard shows real-time analysis status with progress indicator
- [ ] **DASH-03**: Dashboard displays a findings list filterable by severity and verdict
- [ ] **DASH-04**: User can click any finding to see: explanation, root cause, CWE reference, confidence score, SHAP features, and patch diff
- [ ] **DASH-05**: Dashboard shows an overall risk summary for the analyzed codebase (total findings by severity)
- [ ] **DASH-06**: Dashboard has an Evaluation Metrics panel showing Precision/Recall/F1/FPR comparisons (baseline vs. HackerSec)

---

## v2 Requirements

### Extended Language Support

- **LANG-01**: System supports JavaScript/TypeScript analysis (Semgrep JS rules + Joern JS frontend)
- **LANG-02**: System supports Go analysis

### CI/CD Integration

- **CICD-01**: GitHub Action that triggers HackerSec analysis on pull requests
- **CICD-02**: PR comment with vulnerability summary

### Advanced Features

- **ADV-01**: Multi-turn LLM conversation — user can ask follow-up questions about a finding
- **ADV-02**: Incremental analysis — only re-analyze files changed since last scan
- **ADV-03**: Private git repository support (SSH key auth)
- **ADV-04**: PDF/JSON report export

### IDE Integration

- **IDE-01**: VS Code extension for real-time scan on save

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| Runtime / DAST analysis | Requires deployed app infrastructure — separate research domain |
| Cloud-hosted LLM (OpenAI/Anthropic) | Breaks local-only reproducibility requirement; privacy concern |
| Commercial SAST (Fortify, Checkmarx, Coverity) | Licensing cost; not available in research setting |
| SonarQube integration | Server-based, heavyweight; Semgrep covers the use case |
| LangChain / LlamaIndex | Abstraction layer masks pipeline logic; direct FAISS preferred for research control |
| Mobile app | Out of scope entirely |
| Fuzzing / DAST | Separate research sub-domain |

---

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INGT-01 | Phase 1 | Pending |
| INGT-02 | Phase 1 | Pending |
| INGT-03 | Phase 1 | Pending |
| INGT-04 | Phase 1 | Pending |
| INGT-05 | Phase 1 | Pending |
| STAT-01 | Phase 1 | Pending |
| STAT-02 | Phase 1 | Pending |
| STAT-03 | Phase 1 | Pending |
| STAT-04 | Phase 1 | Pending |
| STAT-05 | Phase 1 | Pending |
| CPG-01 | Phase 2 | Pending |
| CPG-02 | Phase 2 | Pending |
| CPG-03 | Phase 2 | Pending |
| CPG-04 | Phase 2 | Pending |
| RAG-01 | Phase 3 | Pending |
| RAG-02 | Phase 3 | Pending |
| RAG-03 | Phase 3 | Pending |
| RAG-04 | Phase 3 | Pending |
| RAG-05 | Phase 3 | Pending |
| LLM-01 | Phase 4 | Pending |
| LLM-02 | Phase 4 | Pending |
| LLM-03 | Phase 4 | Pending |
| LLM-04 | Phase 4 | Pending |
| LLM-05 | Phase 4 | Pending |
| FUSE-01 | Phase 5 | Pending |
| FUSE-02 | Phase 5 | Pending |
| FUSE-03 | Phase 5 | Pending |
| FUSE-04 | Phase 5 | Pending |
| FUSE-05 | Phase 5 | Pending |
| PATC-01 | Phase 6 | Pending |
| PATC-02 | Phase 6 | Pending |
| PATC-03 | Phase 6 | Pending |
| PATC-04 | Phase 6 | Pending |
| EVAL-01 | Phase 7 | Pending |
| EVAL-02 | Phase 7 | Pending |
| EVAL-03 | Phase 7 | Pending |
| EVAL-04 | Phase 7 | Pending |
| EVAL-05 | Phase 7 | Pending |
| DASH-01 | Phase 8 | Pending |
| DASH-02 | Phase 8 | Pending |
| DASH-03 | Phase 8 | Pending |
| DASH-04 | Phase 8 | Pending |
| DASH-05 | Phase 8 | Pending |
| DASH-06 | Phase 8 | Pending |

**Coverage:**
- v1 requirements: 44 total
- Mapped to phases: 44
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-08*
*Last updated: 2026-04-08 after initial definition*
