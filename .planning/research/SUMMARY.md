# Research Summary — HackerSec

## Domain: AI-Driven Security Code Review & Vulnerability Analysis

---

## Key Findings

### Stack
- **FastAPI + Celery + Redis** for the ingestion/async pipeline (Joern is too slow for sync calls)
- **Semgrep** is the strongest primary SAST — targeted rule sets (`p/security-audit`, `p/owasp-top-ten`), not `--config=auto`
- **Joern ≥2.0** is the only viable open-source CPG engine; must run in server mode to avoid cold-start latency
- **DeepSeek-Coder-V2 via Ollama** is the recommended LLM — SOTA on code benchmarks, runs locally, Apache 2.0
- **FAISS + sentence-transformers (`all-MiniLM-L6-v2`)** is the right RAG stack — lightweight, offline, reproducible
- **scikit-learn GradientBoostingClassifier** for fusion — interpretable, fast to train, SHAP-explainable
- **DO NOT use LangChain** — direct RAG pipeline is cleaner for research, fewer abstraction layers

### Table Stakes Features (v1 must-haves)
- Code ingestion: file upload + git URL clone
- Language detection + per-file splitting
- OWASP Top 10 + CWE-mapped vulnerability detection
- Line-level finding precision (file + line number)
- Severity labels: Critical / High / Medium / Low
- LLM plain-English explanation + root cause + fix suggestion
- Confidence score per finding (static + LLM combined)
- Fusion classifier verdict (TP / FP / Uncertain)
- Evaluation metrics: Precision / Recall / F1 / FPR on Juliet + Big-Vul
- Web dashboard: upload → view findings → see explanations + patches

### Watch Out For (Top Pitfalls)
1. 🔴 **LLM hallucinating CVE/CWE IDs** — RAG must provide all CWE context; never let LLM cite from memory
2. 🔴 **Prompt injection via analyzed code** — wrap code in strict delimiters, instruct LLM to treat as data
3. 🔴 **Imbalanced fusion training data** — use stratified sampling + `class_weight='balanced'` + optimize F1 not accuracy
4. 🔴 **Evaluation metric inflation** — 3-way split; test on BOTH Juliet (synthetic) AND Big-Vul (real)
5. 🟠 **Joern blocking FastAPI** — async Celery queue essential from day 1; Joern in server mode
6. 🟠 **Duplicate findings** — deduplicate by `(file, line, cwe_category)` before LLM analysis
7. 🟡 **Semgrep rule noise** — use targeted rule sets only; discard INFO-level findings
8. 🟡 **FAISS index not persisted** — save/load index; rebuild is expensive (30–60s)

---

## Architecture Decision Summary

The pipeline is a **sequential, enrichment-based architecture**:

```
Code Input → Static Analysis → CPG → RAG Retrieval → LLM Reasoning → Fusion → Patch → Dashboard
```

Each finding is enriched incrementally:
1. **Static tools** provide ground-truth pattern matches (fast, high recall, high FP rate)
2. **CPG (Joern)** adds taint flow and structural context (converts local to inter-procedural analysis)
3. **RAG (FAISS)** retrieves relevant CWE/OWASP docs (grounds LLM, prevents hallucination)
4. **LLM (DeepSeek)** reasons about whether it's a real vulnerability (high precision, semantic understanding)
5. **Fusion classifier** combines all signals into a final verdict (research contribution: FP reduction)
6. **Patch generator** proposes fixes and validates them with Semgrep re-run

**Build order by dependency**:
Phase 1 (Ingestion + Static) → Phase 2 (CPG) → Phase 3 (RAG) → Phase 4 (LLM) → Phase 5 (Fusion) → Phase 6 (Patch) → Phase 7 (Evaluation) → Phase 8 (Dashboard)

Phases 2 and 3 are independent of each other — can be parallelized in development.

---

## Research Positioning

**Core contribution**: The **fusion layer** (Phase 5) — an ML classifier that combines static confidence, LLM confidence, and CPG graph features to reduce false positives. Baseline comparison (Semgrep-only vs. full pipeline) is the primary research result.

**Expected outcome**: 15–40% improvement in F1 score over Semgrep-only baseline, based on LLMxCPG literature. Paper-quality evaluation requires Big-Vul (real-world) results, not just Juliet (synthetic).

**Differentiating factor from prior work**: Most systems use either static OR LLM. HackerSec's 3-signal fusion (static + graph + LLM) with explicit CWE grounding is the research novelty.
