<!-- GSD:project-start source:PROJECT.md -->
## Project

**HackerSec**

HackerSec is a research-grade, AI-driven security code reviewer and vulnerability analysis system. It ingests source code (via file upload or git clone), runs multi-layer static and semantic analysis, and uses a local LLM (DeepSeek-Coder via Ollama) grounded by a RAG knowledge base (OWASP/CWE/NVD) to reason about real vulnerabilities, reduce false positives, and generate patch suggestions. It is designed as a publishable research system with quantitative evaluation metrics.

**Core Value:** Accurate, context-aware vulnerability detection with actionable remediation — grounded in security standards, not hallucination.

### Constraints

- **Tech Stack**: Python (FastAPI backend), Joern (Scala/JVM for CPG), Ollama (local LLM runtime), FAISS (vector search), scikit-learn (fusion classifier)
- **LLM**: Local models only via Ollama — no OpenAI/Anthropic API keys required
- **Evaluation**: Must produce measurable metrics (Precision/Recall/F1/FPR) on standard benchmarks for research validity
- **Performance**: Joern CPG generation is heavyweight — async processing queue required for large repos
- **Timeline**: Semester 6 deadline — 8 phases, prioritize core pipeline over polish
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Domain: AI-Driven Security Code Review & Vulnerability Analysis
## Recommended 2025 Stack
### Ingestion Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| Web Framework | **FastAPI** | ≥0.111 | Async-native, OpenAPI docs auto-generated, ideal for pipeline orchestration | ⭐⭐⭐ High |
| Git Integration | **GitPython** | ≥3.1 | Mature, Pythonic git API — clone, walk history, diff blobs | ⭐⭐⭐ High |
| File Chunking | **tree-sitter** | ≥0.21 | Language-aware file splitting (preserves AST boundaries, not arbitrary line cuts) | ⭐⭐ Medium |
| Language Detection | **linguist (via pygments)** | latest | Robust language detection from file extension + content heuristics | ⭐⭐ Medium |
| Task Queue | **Celery + Redis** | Celery 5.x | Async job processing for large repos — avoid blocking FastAPI workers | ⭐⭐⭐ High |
### Static Analysis Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| Primary SAST | **Semgrep** | ≥1.70 | JSON output, 3000+ rules, subprocess-safe, community rules for OWASP Top 10 | ⭐⭐⭐ High |
| Advanced SAST | **CodeQL** | 2.x | GitHub-maintained, inter-procedural analysis, catches complex data flows | ⭐⭐ Medium |
| Python-specific | **Bandit** | ≥1.7.8 | Lightweight, 60+ Python security checks, fast | ⭐⭐⭐ High |
| C/C++ | **Flawfinder** | ≥2.0.19 | Pattern-based for C/C++ unsafe functions | ⭐⭐ Medium |
### CPG / Program Representation Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| CPG Engine | **Joern** | ≥2.0 | Only open-source tool producing full CPG (AST+CFG+PDG+CG); used in LLMxCPG research | ⭐⭐⭐ High |
| CPG Query | **Joern Scala scripts** | — | Built-in query language for taint flow traversal | ⭐⭐⭐ High |
| Alternative | **CodeQL QL** | — | Can produce similar graph queries but requires GitHub licensing for advanced features | ⭐⭐ Medium |
### RAG Knowledge Base Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| Embeddings | **sentence-transformers** | ≥2.6 | `all-MiniLM-L6-v2` (384-dim) — fast, lightweight, good semantic similarity | ⭐⭐⭐ High |
| Vector Store | **FAISS** | ≥1.8 | Local, no server, sub-millisecond search — ideal for offline research | ⭐⭐⭐ High |
| Alternative Vector | **ChromaDB** | ≥0.5 | Easier API, persistent by default, slightly slower | ⭐⭐ Medium |
| Data Sources | OWASP Top 10 (JSON), MITRE CWE list (XML), NVD CVE feeds (JSON) | — | Ground truth for vulnerability taxonomy | ⭐⭐⭐ High |
### LLM Reasoning Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| Primary Model | **DeepSeek-Coder-V2** | via Ollama | SOTA on code benchmarks, instruction-tuned, Apache 2.0, runs on 16GB VRAM | ⭐⭐⭐ High |
| Fallback Model | **CodeLlama-34b-Instruct** | via Ollama | Proven on security tasks, Meta license | ⭐⭐ Medium |
| Lightweight | **Phi-3-mini-128k** | via Ollama | 4GB VRAM — for classification subtasks | ⭐⭐ Medium |
| Runtime | **Ollama** | ≥0.3 | REST API, model management, GPU acceleration, local-only | ⭐⭐⭐ High |
### Fusion Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| ML Framework | **scikit-learn** | ≥1.4 | GradientBoostingClassifier or RandomForest — interpretable, fast to train | ⭐⭐⭐ High |
| Feature Store | **pandas + numpy** | latest | Feature matrix construction | ⭐⭐⭐ High |
| Explainability | **SHAP** | ≥0.44 | Feature importance for fusion decisions — research value | ⭐⭐ Medium |
### Evaluation Layer
| Component | Recommended | Rationale |
|-----------|-------------|-----------|
| Primary Dataset | **Juliet Test Suite (C/C++/Java/Python)** | NIST-maintained, labeled — 100K+ test cases |
| Secondary Dataset | **OWASP Benchmark** | Java, precision-tracked |
| Third Dataset | **Big-Vul (GitHub CVE commits)** | Real-world CVEs with patches |
| Metrics | Precision, Recall, F1, FPR | Standard research metrics |
### Dashboard
| Component | Recommended | Rationale |
|-----------|-------------|-----------|
| Frontend | **React + Vite** or **Streamlit** | Streamlit for rapid research demo; React for production-quality UI |
| Charts | **Recharts** (React) or **Altair** (Streamlit) | Visualize finding heatmaps, F1 curves |
## What NOT to Build With
| Tool | Reason to Avoid |
|------|----------------|
| Docker for Joern | Adds complexity; install natively on dev machine |
| OpenAI/Anthropic APIs | Network dependency, privacy, reproducibility cost |
| SonarQube | Server-based, heavy, not research-friendly |
| Elasticsearch | Overkill for FAISS use case |
| LangChain | Heavy abstraction — build direct RAG pipeline for research control |
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.agent/skills/`, `.agents/skills/`, `.cursor/skills/`, or `.github/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
