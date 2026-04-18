# Scaling HackerSec to Real-World Research Evaluation

This plan shifts HackerSec from a localized mock-test environment into a rigorous, research-grade pipeline capable of evaluating real-world vulnerability datasets and mapping semantic flaws using massive unstructured knowledge.

## Proposed Changes

### 1. Massive RAG Database Ingestion (MITRE CWE Dictionary)
We will expand the RAG (Retrieval-Augmented Generation) layer from a hardcoded list of 5 vulnerabilities to a comprehensive copy of the MITRE CWE database.

#### [NEW] `hackersec/ingestion/cwe_ingest.py`
- Writes a script to download the official MITRE CWE dictionary (JSON/XML).
- Parses descriptions, mitigation strategies, and attack vectors for over 1000+ weaknesses.
- Chunks and stores them into the FAISS `LocalRAGStore`.

---

### 2. HuggingFace Research Dataset Loader
Instead of using locally mocked python files (`vuln_eval.py`), we will integrate the HuggingFace `datasets` library. This allows benchmarking HackerSec against standard datasets mentioned in research papers (e.g., *DiverseVul*, *Big-Vul*, or *Juliet* subsets).

#### [NEW] `hackersec/evaluation/huggingface_loader.py`
- Connects to HuggingFace to pull real-world coding datasets.
- Maps dataset features (e.g., `func` -> code snippet, `target` -> 1 for vulnerable / 0 for safe, `cwe` -> CWE ID).
- Saves local caches to `data/eval_set` so tests run offline seamlessly.

#### [MODIFY] `hackersec/evaluation/dataset.py`
- Upgrades `generate_test_suite` to use the new HF loader natively.

---

### 3. Asynchronous Pipeline Integration for Evaluation
Currently, `runner.py` mocks the LLM out of the evaluation loop for speed. We need the evaluation harness to use the *real* pipeline (Semgrep -> Joern -> RAG -> CodeLlama -> ML Fusion). 

#### [MODIFY] `hackersec/evaluation/runner.py`
- Wraps the analysis loop to call the active Celery worker queue or runs the components synchronously in batch mode.
- Validates the complete pipeline efficiency.

#### [MODIFY] `eval_run.py`
- Adds CLI arguments like `--dataset diversevul` or `--samples 100` to let you quickly configure what scale of research paper benchmarking you want to run.

## ⚠️ User Review Required

> [!WARNING]
> Running the full LLM and Joern CPG extraction on hundreds of real-world files from HuggingFace will take **a long time** (potentially hours), even on a DGX. I will add a `--limit 50` parameter by default to bound the execution. Does this sound acceptable?

> [!IMPORTANT]
> The RAG dataset builder will pull directly from MITRE/HuggingFace upon the initial boot. Ensure the DGX has external internet access during this initialization phase (which you clearly currently do based on previous successful model pulls).

## Verification Plan
1. **Automated Mappings**: Run `python -m hackersec.ingestion.cwe_ingest` to verify FAISS populates with ~1,000+ docs.
2. **Dataset Load**: Run the HuggingFace loader to verify it securely pulls and formats real-world vulnerable functions into our local `data/eval_set`.
3. **Execution**: Run `python eval_run.py --limit 10` to verify precision, recall, and F1 calculations using the *actual* HackerSec pipeline on real data.
