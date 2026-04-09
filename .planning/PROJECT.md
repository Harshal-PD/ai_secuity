# HackerSec

## What This Is

HackerSec is a research-grade, AI-driven security code reviewer and vulnerability analysis system. It ingests source code (via file upload or git clone), runs multi-layer static and semantic analysis, and uses a local LLM (DeepSeek-Coder via Ollama) grounded by a RAG knowledge base (OWASP/CWE/NVD) to reason about real vulnerabilities, reduce false positives, and generate patch suggestions. It is designed as a publishable research system with quantitative evaluation metrics.

## Core Value

Accurate, context-aware vulnerability detection with actionable remediation — grounded in security standards, not hallucination.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — ship to validate)

### Active

<!-- Current scope. Building toward these. -->

- [ ] Ingestion Layer: Accept file uploads and git repo URLs via FastAPI; detect language; split files for analysis
- [ ] Static Analysis Layer: Run Semgrep, Bandit, and Flawfinder; parse JSON output into normalized findings
- [ ] Program Representation Layer (CPG): Use Joern to generate Code Property Graphs; extract taint flows and AST features
- [ ] RAG Knowledge Base: Embed OWASP, MITRE CWE, and NIST NVD data with FAISS + sentence-transformers
- [ ] LLM Reasoning Layer: Use DeepSeek-Coder (via Ollama) with CPG context + RAG retrieval to reason about each finding
- [ ] Fusion / Decision Layer: ML classifier (scikit-learn) combining static score + LLM confidence + graph features to reduce false positives
- [ ] Patch Generation Layer: LLM-generated code fixes with Semgrep re-run validation
- [ ] Evaluation Layer: Benchmark against Juliet Test Suite, OWASP Benchmark, Big-Vul; report Precision/Recall/F1/FPR
- [ ] Dashboard: Web UI showing findings, severity, confidence scores, patches, and evaluation metrics

### Out of Scope

- Runtime / dynamic analysis (DAST) — complexity out of scope for v1; may add in future milestone
- Cloud-hosted LLM inference — system uses local Ollama models only for privacy and reproducibility
- IDE extension or VS Code plugin — CLI + web dashboard is the primary interface for v1
- CI/CD GitHub Action integration — deferred to post-research milestone

## Context

- **Research Project**: This is a semester 6 AI Security project with a research + implementation mandate. Quantitative evaluation (F1, FPR) is required for the final submission.
- **Architecture Philosophy**: Layered pipeline — static tools provide ground-truth baseline, CPG adds structural reasoning, RAG grounds LLM with known vulnerability patterns, fusion layer reduces noise.
- **Key Research Insight**: Static tools alone produce high false-positive rates. The fusion of CPG graph context + RAG-grounded LLM reasoning is the core research contribution targeting 15–40% improvement over baseline.
- **Local-first**: All LLM inference runs locally via Ollama (DeepSeek-Coder or CodeLlama) for reproducibility.
- **Language Focus**: Initial support for Python; extensible to JavaScript and Go in later phases.
- **Existing codebase**: Directory was fresh at project start — greenfield build.

## Constraints

- **Tech Stack**: Python (FastAPI backend), Joern (Scala/JVM for CPG), Ollama (local LLM runtime), FAISS (vector search), scikit-learn (fusion classifier)
- **LLM**: Local models only via Ollama — no OpenAI/Anthropic API keys required
- **Evaluation**: Must produce measurable metrics (Precision/Recall/F1/FPR) on standard benchmarks for research validity
- **Performance**: Joern CPG generation is heavyweight — async processing queue required for large repos
- **Timeline**: Semester 6 deadline — 8 phases, prioritize core pipeline over polish

## Current State
**v1.0 Deployed (2026-04-09)**: The full pipeline (Ingestion ➔ Joern CPG ➔ FAISS/OWASP ➔ DeepSeek LLM ➔ ML Fusion ➔ Auto-Patching) operates natively mapped cleanly against evaluation metrics bridging into the React/Vite UI.

## Next Milestone Goals
1. Optimization & Scale (Larger AST representations).
2. Distributed Architectures for Ollama execution clusters.
## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DeepSeek-Coder as primary LLM | Strong code understanding, runs locally via Ollama, SOTA on code benchmarks | — Pending |
| Joern for CPG generation | Only open-source tool producing full CPG (AST + CFG + PDG); research literature uses it | — Pending |
| FAISS for vector store | Lightweight, no server required, works offline — ideal for research reproducibility | — Pending |
| Semgrep as primary SAST | JSON output, broad rule library, integrates cleanly as subprocess | — Pending |
| Fusion layer as ML classifier | Rule-based thresholds are brittle; trained classifier is the research contribution | — Pending |
| FastAPI as ingestion layer | Async, lightweight, clean REST API for pipeline orchestration | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-07 after initialization*
