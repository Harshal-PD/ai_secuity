# Features Research — HackerSec

## Domain: AI-Driven Security Code Review & Vulnerability Analysis

---

## Feature Categories

### 1. Code Ingestion

#### Table Stakes (users leave without these)
- [ ] Accept single-file upload (Python, JS, Go)
- [ ] Accept git repository URL (public repos via clone)
- [ ] Detect programming language automatically
- [ ] Show analysis progress/status indicator
- [ ] Return results in structured JSON format

#### Differentiators (competitive advantage for research)
- [ ] Private/local repo support (no remote URL required)
- [ ] Incremental analysis — only re-analyze changed files
- [ ] Zip/archive upload support

#### Anti-features (deliberately exclude in v1)
- Real-time IDE streaming (complexity cost)
- Browser extension (scope creep)

---

### 2. Vulnerability Detection

#### Table Stakes
- [ ] Detect OWASP Top 10 vulnerability classes
- [ ] Report findings with file + line number precision
- [ ] Assign severity labels (Critical / High / Medium / Low / Info)
- [ ] Show confidence score per finding
- [ ] Deduplicate overlapping findings from multiple tools

#### Differentiators
- [ ] Taint flow analysis (source → sink tracing via CPG)
- [ ] Context-aware classification (LLM distinguishes real vs. false positive)
- [ ] CWE mapping for each finding
- [ ] CVE cross-reference where applicable
- [ ] Data flow visualization (CPG graph excerpt)

#### Anti-features
- Runtime/DAST analysis (different infrastructure)
- Fuzzing (separate research domain)

---

### 3. LLM-Powered Reasoning

#### Table Stakes
- [ ] Explain what the vulnerability is (plain English)
- [ ] Explain root cause (why the code is vulnerable)
- [ ] Rate confidence: is this a real vulnerability or false positive?
- [ ] Suggest a code fix

#### Differentiators
- [ ] Include CWE-grounded explanation (from RAG, not hallucination)
- [ ] CPG-informed reasoning (control/data flow context in prompt)
- [ ] Multi-turn explanation (follow-up questions support)
- [ ] Explain potential attack vector / exploitability

#### Anti-features
- Automatic commit of patches (high risk)
- Hallucinated CVE references (RAG must ground this)

---

### 4. False Positive Reduction (Fusion Layer)

#### Table Stakes
- [ ] Combine static + LLM scores into a single verdict
- [ ] Output final: Vulnerable / Likely Vulnerable / Uncertain / False Positive
- [ ] Show reasoning for fusion decision

#### Differentiators (core research contribution)
- [ ] ML classifier trained on labeled findings (precision over heuristics)
- [ ] SHAP feature importance — which signals drove the decision
- [ ] Configurable threshold (tune FPR vs. recall tradeoff)

---

### 5. Patch Generation

#### Table Stakes
- [ ] Generate corrected code snippet for each confirmed vulnerability
- [ ] Show diff view (original vs. patched)

#### Differentiators
- [ ] Re-run Semgrep on patched code to validate fix
- [ ] Explain why the patch fixes the vulnerability
- [ ] Multiple fix options when pattern is ambiguous

---

### 6. Evaluation & Metrics

#### Table Stakes (required for research grade)
- [ ] Run against Juliet Test Suite → report Precision/Recall/F1/FPR
- [ ] Run against OWASP Benchmark
- [ ] Compare baseline (Semgrep-only) vs. full pipeline

#### Differentiators
- [ ] Per-CWE breakdown of metrics
- [ ] False positive rate comparison: static-only vs. AI-augmented
- [ ] ROC curve visualization

---

### 7. Dashboard / UI

#### Table Stakes
- [ ] Upload code / enter repo URL in web UI
- [ ] View findings list with severity filter
- [ ] Click finding → see explanation + suggested fix
- [ ] See overall risk score for analyzed codebase

#### Differentiators
- [ ] CPG visualization (interactive graph for a finding)
- [ ] Evaluation metrics panel (Precision/Recall/F1 charts)
- [ ] Export report as PDF/JSON
- [ ] Finding history across analysis runs

---

## Feature Priority Matrix

| Feature | v1 (Must Ship) | v2 (Future) | Why deferred |
|---------|---------------|-------------|--------------|
| OWASP Top 10 detection | ✅ | | Core requirement |
| CWE mapping | ✅ | | Research grounding |
| CPG taint flow | ✅ | | Research contribution |
| RAG-grounded explanation | ✅ | | Anti-hallucination |
| Fusion ML classifier | ✅ | | Research contribution |
| Patch generation | ✅ | | Developer value |
| Evaluation metrics | ✅ | | Research validity |
| Web dashboard | ✅ (basic) | | Demonstration |
| Multi-language support (JS/Go) | | ✅ | Python first |
| IDE extension | | ✅ | Scope |
| DAST/runtime analysis | | ✅ | Different infra |
| CI/CD GitHub Action | | ✅ | Post-research |
| Incremental analysis | | ✅ | Optimization |
