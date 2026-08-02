# HackerSec — Project Overview & Deep Dive

> Read this first. It explains **what HackerSec is, the problem it solves, how every stage
> works, how to run and evaluate it, and the research it builds on**. Written so a newcomer,
> a professor, or a new contributor can understand the whole system without reading the code.
>
> Companion docs: `STATE.md` (current status + how to run + known issues),
> `PROGRESS.md` (phase-by-phase done/left), `DECISIONS.md` (why), `CHANGELOG.md` (what changed).

---

## 1. What HackerSec is (in one paragraph)

HackerSec is a **research-grade, fully-local AI security code reviewer**. You give it source
code (a file or a git repo); it finds vulnerabilities using layered static + semantic analysis,
uses a local LLM (via Ollama) grounded by a security knowledge base to reason about each finding,
and — the part that makes it different — **actually executes the suspected vulnerability inside a
hardened sandbox to prove it is real** before reporting it. No cloud APIs, no data leaves the machine.

## 2. The problem it solves

Static analysis tools (SAST) and even LLM-based detectors produce **too many false positives** —
they flag code that *looks* dangerous but isn't exploitable. The whole field (SASTBench, RealVuln,
CASTLE) is now a fight against false positives, and LLM "triage" only guesses which findings are real.

**HackerSec's thesis:** stop guessing. A finding is only called a true vulnerability when the system
can **reproduce it by execution** — run the flagged code with a malicious input and observe it fire.
This turns a probabilistic verdict into an evidence-backed one.

## 3. The novel contribution

**Reproduction-Gated, Program-Analysis-Guided Vulnerability Detection.** Three ideas combine:

1. **Reproduction gating** — a positive verdict requires a sandbox to actually trigger the bug.
   We report a new metric, **precision@reproduced** (a.k.a. verified-F1), that detection benchmarks
   don't, because they have no execution stage.
2. **Anti-hardcoding differential oracle** — a proof-of-concept can *cheat* by printing the "success"
   marker regardless of input (a failure mode named by POC-GYM). HackerSec runs the exploit payload
   **and** a benign control input; it only counts as reproduced if the marker fires under the payload
   and **not** under the control. Fake/hardcoded PoCs are rejected.
3. **Program-analysis-guided PoC** — the exploit driver is built from the **CPG taint path** (Joern
   source→sink) the system already computed, not a blind LLM guess (planned Phase 1b).

## 4. How it works — the pipeline, stage by stage

The whole pipeline is orchestrated by one function, `hackersec/analysis/pipeline.py::analyze_findings`,
called by both the async worker (`worker/tasks.py`) and the evaluation harness (so benchmarks measure
the real system). Each stage fails gracefully — an error in one marks its findings and the rest continue.

| # | Stage | Module | Input → Output | Why it exists |
|---|-------|--------|----------------|---------------|
| 0 | **Ingestion** | `ingestion/` | file/zip/git URL → source files; language detected | Normalizes input; `detect_language` drives language-aware rules |
| 1 | **Static analysis** | `analysis/static.py` | source → raw findings (file, line, CWE, severity) | Cheap, deterministic "points of interest." Semgrep (language-aware packs) + Bandit (Python) |
| — | **Dedup** | `analysis/dedup.py` | raw findings → deduped by (file, line, CWE) | Removes duplicate hits |
| 2 | **CPG taint flow** | `analysis/joern/` | finding + file → taint path (source→sink) | Joern builds a Code Property Graph (AST+CFG+PDG); shows whether tainted input reaches the sink. Grounds the LLM in real data flow |
| 3 | **RAG grounding** | `analysis/rag.py` | finding → top-k CWE/OWASP docs | FAISS + `all-MiniLM-L6-v2` retrieve the real weakness definition so the LLM doesn't hallucinate CWEs |
| 4 | **LLM reasoning** | `analysis/llm/` | code + CPG + RAG → structured verdict (explanation, root cause, fix, confidence) | Local LLM (Ollama) acts as a senior reviewer making a *binary* decision, not blind discovery |
| 5 | **ML fusion** | `analysis/ml/` | features (static/LLM confidence, taint depth, CWE severity) → `true_positive`/`false_positive`/`uncertain` + SHAP | A scikit-learn classifier combines signals; SHAP explains each decision |
| 6 | **Dynamic verify** | `analysis/verify/` | candidate finding → `reproduced ∈ {True,False,None}` + evidence | **The differentiator.** Executes the flagged code against a payload in a hardened Docker sandbox; differential control run rejects fakes |
| 7 | **Patch generation** | `analysis/patch/` | confirmed finding → patched code + diff + validation | LLM writes a fix; re-run Semgrep (and, planned, re-run the exploit) to confirm it's fixed |

Result: each finding carries its static evidence, taint path, RAG grounding, LLM reasoning, fusion
verdict + SHAP, reproduction evidence, and a candidate patch.

## 5. The dynamic-verification innovation (in depth)

Location: `analysis/verify/` — `sandbox.py`, `oracles.py`, `__init__.py`.

- **Sandbox (`sandbox.py`)** runs attacker-controlled payloads, so isolation is a hard security
  boundary: `--network none`, non-root, read-only rootfs + tmpfs, `--cap-drop ALL`,
  `no-new-privileges`, CPU/memory/PID caps, hard timeout, `--rm`. If Docker is unavailable it
  returns `sandbox_unavailable` and **never** runs payloads on the host.
- **Oracles (`oracles.py`)** build a per-CWE probe for the injection/RCE family (CWE-78/77/94/95):
  a driver that imports the **real flagged function** and calls it with a payload crafted to print a
  unique sentinel marker *iff* the sink executes it. Also builds a **control probe** with benign input.
- **Differential decision (`__init__.py`)** — `reproduced = payload_fired AND NOT control_fired`.
  This is what defeats the "hardcoded PoC" cheat: a driver that prints the marker regardless of input
  fires under both runs → rejected (`hardcoded_rejected`). CWE classes with no code-level oracle →
  `reproduced=None` ("not dynamically checkable"), never a false negative.

## 6. Architecture & code map

```
hackersec/
  api/routes/        FastAPI endpoints (upload, analyze git URL, status, results, metrics)
  worker/            Celery task — async pipeline execution
  analysis/
    pipeline.py      analyze_findings() — the single enrichment path (STAGES + live progress)
    static.py        Semgrep (language-aware) + Bandit; select_semgrep_configs()
    dedup.py         finding dedup
    joern/           CPG client + taint-flow queries
    rag.py           FAISS retrieval
    llm/             Ollama client, prompt builder, response parser
    ml/              fusion classifier (features, inference, train) + SHAP
    verify/          dynamic exploit verification (sandbox, oracles, differential)
    patch/           patch prompt, diff, validator
    schema.py        Finding dataclass (the object every stage enriches)
  ingestion/         file upload, git clone, language detection, CWE ingest, KB seed
  evaluation/        dataset loaders (mock + HuggingFace), runner, metrics
  db/store.py        SQLite (jobs + findings), stage progress, verify persistence
hackersec-web/       React 19 + Vite dashboard (live pipeline timeline, findings, metrics)
eval_run.py          CLI: run the real pipeline over a labeled dataset → metrics
test_*.py            assert-based self-checks (verify, static-lang)
docs/                STATE / PROGRESS / OVERVIEW / DECISIONS / CHANGELOG
```

## 7. Frontend (observability dashboard)

`hackersec-web/` (React 19 + Vite + Recharts). Submit a file or git URL, then **watch the pipeline
run stage-by-stage** on a live timeline (driven by the job's `stage` field via a 2s poll). Findings
show severity/verdict, an **"Exploit Confirmed" badge** when reproduced, LLM analysis, RAG references,
SHAP decision factors, and a red/green patch diff. A headline **"Confirmed Exploitable"** stat and a
3-way metrics chart (Baseline vs HackerSec vs HackerSec+Verify) surface the core claim.

## 8. How to run

```bash
# Full stack (needs Redis, Ollama, Joern, Docker) — via compose
docker compose up            # backend :8000, worker, frontend :3000, ollama, joern, redis

# Or locally
uvicorn hackersec.main:app --reload --port 8000
celery -A hackersec.worker.celery_app worker --loglevel=info
cd hackersec-web && npm install && npm run dev     # dashboard

# Evaluation (real pipeline, no mocks)
python eval_run.py --dataset bigvul --limit 50 --verify   # → eval_results/YYYY-MM-DD_run.json
python eval_run.py --dataset mock --no-cpg --no-llm        # fast offline smoke

# Self-checks (no external services needed)
python test_verify.py          # dynamic-verification differential oracle
python test_static_lang.py     # language-aware Semgrep config selection
```

## 9. Evaluation methodology & metrics

- **Datasets:** mock (3 offline files, smoke) or real benchmarks via `evaluation/huggingface_loader.py`
  (Big-Vul, DiverseVul, Juliet), stratified so the set has real negatives (for FPR).
- **Three systems compared** (`evaluation/metrics.py`, `eval_run.py`):
  1. **Baseline** — Semgrep-only (any finding = positive).
  2. **HackerSec** — fusion verdict (`true_positive`).
  3. **HackerSec+Verify** — positive only if reproduced in the sandbox (**precision@reproduced**).
- **Metrics:** Precision, Recall, F1, FPR per system + per-CWE breakdown; results persisted to
  `eval_results/` for reproducibility.
- **The headline claim to demonstrate:** reproduction-gating raises precision (kills false positives)
  over both baselines, at a measured recall cost.

## 10. Research context & citations

> ⚠️ arXiv IDs below were collected from literature search, not opened one-by-one — **verify each ID
> and author list before formal submission.** Titles are the reliable key.

**CPG + LLM detection (the reasoning backbone)**
- *LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided LLMs* — USENIX
  Security 2025 (arXiv 2507.16585). LLM-generated CPGQL slices, +15-40% F1. HackerSec adopts this in Phase 4.
- Yamaguchi et al., *Modeling and Discovering Vulnerabilities with Code Property Graphs* — IEEE S&P 2014
  (the original CPG; basis for Joern).

**PoC generation / execution-verified reproduction (the differentiator)**
- *POC-GYM: Towards More Reliable LLM-Assisted Proof-of-Concept Exploit Generation* — names the
  hardcoded-outcome false-positive class HackerSec's differential oracle defeats.
- *Program Analysis Guided LLM Agent for PoC Generation (PAGENT)* — program-analysis-guided PoC beats
  blind LLM PoC (motivates CPG-guided synthesis).
- *PoCGen: Generating Proof-of-Concept Exploits for Vulnerabilities in npm Packages* (arXiv 2506.04962).
- *LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet?* (arXiv 2510.14700) —
  documents the execution→trigger gap and service-scenario failures (motivates Phase 5 DAST).

**SAST + LLM triage / false-positive filtering (the baseline landscape)**
- *SASTBench: A Benchmark for Testing Agentic SAST Triage.*
- *RealVuln: Benchmarking Rule-Based, General-Purpose LLM, and Security-Specialized Scanners.*
- *CASTLE* micro-benchmark suite; PrimeVul; Datadog's LLM FP-filtering work.

**Agentic remediation / self-healing patches (Phase 3)**
- *EvoRepair: Enhancing Vulnerability Repair Agents Through Experience-Based Self-Evolution.*
- *Fixing Security Vulnerabilities with Agentic AI in OSS-Fuzz* — ICSE 2026 SEIP (validators re-run
  PoV + regression).

**Agentic security surveys / benchmarks (context, Phase 5)**
- *A Survey on Agentic Security: Applications, Threats and Defenses* (arXiv 2510.06445).
- CVE-Bench, AutoPenBench — agents exploiting real web-app vulnerabilities.

**Foundational tools & data**
- Semgrep (registry rule packs); Bandit; Joern; FAISS; sentence-transformers `all-MiniLM-L6-v2`;
  scikit-learn + SHAP; Ollama (DeepSeek-Coder / CodeLlama); MITRE CWE; OWASP Top 10; Big-Vul,
  DiverseVul, Juliet Test Suite datasets.

## 11. Limitations & honest status

- Dynamic verification currently covers the **injection/RCE family** (CWE-78/77/94/95) at the code
  level; classes without a cheap oracle return `None`. Web/service (DAST) verification is Phase 5.
- Full numbers require the DGX (Semgrep/Bandit/Joern/Ollama/Docker) — most self-checks here are unit-level.
- Open blockers and their status live in `STATE.md`; execution progress in `PROGRESS.md`.

## 12. Glossary

- **SAST** — Static Application Security Testing (analyze code without running it).
- **DAST** — Dynamic AST (test a running application).
- **CPG** — Code Property Graph (AST + control-flow + data-dependence in one graph).
- **RAG** — Retrieval-Augmented Generation (ground the LLM with retrieved documents).
- **PoC** — Proof of Concept (an input/script that demonstrates a vulnerability).
- **CWE / OWASP** — standard vulnerability taxonomies.
- **precision@reproduced** — precision when only sandbox-reproduced findings count as positive.
