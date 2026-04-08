# STATE.md — HackerSec

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-08)

**Core value:** Accurate, context-aware vulnerability detection with actionable remediation — grounded in security standards, not hallucination.
**Current focus:** Not started — ready for Phase 1

---

## Current Status

**Phase:** Pre-execution (project initialized)
**Milestone:** v1.0 — Research-grade pipeline
**Last action:** Roadmap created (8 phases, 44 requirements)
**Next action:** `/gsd-plan-phase 1` — Ingestion & Static Analysis Foundation

---

## Phase Progress

| Phase | Name | Status |
|-------|------|--------|
| 1 | Ingestion & Static Analysis Foundation | ⬜ Not Started |
| 2 | CPG Integration (Joern) | ⬜ Not Started |
| 3 | RAG Knowledge Base | ⬜ Not Started |
| 4 | LLM Reasoning Layer | ⬜ Not Started |
| 5 | Fusion / Decision Classifier | ⬜ Not Started |
| 6 | Patch Generation | ⬜ Not Started |
| 7 | Evaluation & Benchmarking | ⬜ Not Started |
| 8 | Dashboard & Polish | ⬜ Not Started |

---

## Key Context

- **Language**: Python (primary), extensible to JS/Go in v2
- **LLM Runtime**: Ollama (local) — DeepSeek-Coder-V2
- **SAST**: Semgrep (`p/security-audit`, `p/owasp-top-ten`) + Bandit
- **CPG**: Joern ≥2.0 in server mode
- **Vector Store**: FAISS + sentence-transformers (all-MiniLM-L6-v2)
- **Fusion**: scikit-learn GradientBoostingClassifier + SHAP
- **Evaluation datasets**: Juliet Test Suite (Python subset) + Big-Vul

## Critical Pitfall Reminders

1. 🔴 Never let LLM cite CVE/CWE from memory — RAG must provide all context
2. 🔴 Wrap analyzed code in strict delimiters — prompt injection prevention
3. 🔴 Use `class_weight='balanced'` in fusion classifier — dataset is imbalanced
4. 🔴 3-way split for evaluation — never tune on test set
5. 🟠 Joern must run in server mode — async Celery queue mandatory

---
*State initialized: 2026-04-08*
