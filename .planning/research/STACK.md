# Stack Research — HackerSec

## Domain: AI-Driven Security Code Review & Vulnerability Analysis

---

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

**DO NOT USE**: SonarQube (requires server), Fortify (commercial), Checkmarx (commercial)

### CPG / Program Representation Layer
| Component | Recommended | Version | Rationale | Confidence |
|-----------|-------------|---------|-----------|------------|
| CPG Engine | **Joern** | ≥2.0 | Only open-source tool producing full CPG (AST+CFG+PDG+CG); used in LLMxCPG research | ⭐⭐⭐ High |
| CPG Query | **Joern Scala scripts** | — | Built-in query language for taint flow traversal | ⭐⭐⭐ High |
| Alternative | **CodeQL QL** | — | Can produce similar graph queries but requires GitHub licensing for advanced features | ⭐⭐ Medium |

**Note**: Joern requires JVM 11+. Integration via subprocess (`joern-parse`, `joern --script`). Startup latency ~5–10 seconds per analysis — use async task queue.

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

**DO NOT USE**: OpenAI API (network dependency), Anthropic API (no local option) — breaks reproducibility requirement.

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

---

## What NOT to Build With

| Tool | Reason to Avoid |
|------|----------------|
| Docker for Joern | Adds complexity; install natively on dev machine |
| OpenAI/Anthropic APIs | Network dependency, privacy, reproducibility cost |
| SonarQube | Server-based, heavy, not research-friendly |
| Elasticsearch | Overkill for FAISS use case |
| LangChain | Heavy abstraction — build direct RAG pipeline for research control |

---

*Confidence: ⭐⭐⭐ = Verified in research literature / production systems | ⭐⭐ = Commonly used, minor caveats | ⭐ = Experimental*
