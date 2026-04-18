# HackerSec Architecture & Data Flow

This document outlines the detailed architecture and end-to-end data flow of the HackerSec AI-Driven Security Code Reviewer. It is designed to document how the different microservices interact within the isolated DGX server environment.

---

## 🏗️ 1. High-Level System Architecture

HackerSec relies on a multi-container Docker infrastructure to asynchronously process and evaluate massive codebases using Machine Learning and Static Analysis, without relying on external network calls for inference or vector searching.

### Microservices Setup (`docker-compose.yml`)
- **Frontend (Nginx/React)**: Serves the Web UI on Port 3000. Proxies all `/api` requests internally to the Backend across the secure Docker bridge.
- **Backend (FastAPI)**: Hands out jobs, monitors status, and serves the dashboard REST endpoints.
- **Message Broker (Redis)**: Manages the asynchronous task queues (Celery) and temporarily stores execution results.
- **Celery Worker**: The heavyweight processor. It coordinates the static analysis engines, orchestrates the FAISS vector searches, queries Joern, and communicates with the LLM. 
- **Joern CPG Server**: A JVM-based Server exposing Port 8080. It maps the Abstract Syntax Tree (AST), Control Flow (CFG), and Data Dependencies of the source code.
- **Ollama (LLM Engine)**: GPU-isolated runtime running Meta's `codellama` (7B parameters). Explicitly bound to **GPU 7** (via Compose deploy specs) to avoid out-of-memory kernel panics caused by adjacent DGX cluster jobs.

---

## 🌊 2. End-to-End Pipeline Data Flow

When a user submits a file (e.g., `test_vuln.py`) for evaluation through the Web UI, the pipeline follows a strict, sequential 5-phase analytical process:

### Phase 1: Ingestion & Queuing
1. The file is POSTed to the **FastAPI Backend**.
2. The Backend physically saves the file to the active Docker Volume (`app_data/uploads/<uuid>/`).
3. The Backend creates a Celery Task identifying the file path and hands it to **Redis**.
4. The **Celery Worker** pulls the task from Redis and begins processing.

### Phase 2: Static Analysis (The "Trigger" Layer)
Instead of forcing the LLM to blindly search thousands of lines of code, HackerSec uses traditional SBR (Signature-Based Rulers) to find "Points of Interest":
1. **Semgrep**: Scans the file using `p/secrets`, `p/owasp-top-ten`, and `p/python` rules.
2. **Bandit**: Secondary Python-specific AST scanner testing for misconfigurations.
*Result*: A deduplicated list of potential vulnerabilities (e.g., "Found os.system() use at Line 42").

### Phase 3: CPG Taint Extraction (The "Trace" Layer)
To determine if a "Point of Interest" is actually exploitable, the LLM needs to know where the data originated.
1. The Worker sends a POST request to the **Joern Server**.
2. Joern constructs a **Code Property Graph (CPG)** for the entire file.
3. Joern tracks the vulnerable variable backward in time across functions to see if it touches a user-controlled source (like an HTTP Request).
*Result*: A trace path (e.g., `Line 12 -> Line 40 -> Line 42`).

### Phase 4: RAG Knowledge Base (The "Context" Layer)
Because CodeLlama is an LLM, its inherent knowledge about specific vulnerabilities can drift. We ground its reasoning against formal MITRE databases.
1. The error string (e.g., "Improper Neutralization of OS Commands") is encoded into a 384-dimensional mathematical vector using the lightweight CPU model `all-MiniLM-L6-v2`.
2. This vector is compared against thousands of CWE definitions residing in the **FAISS Vector Database** (`kb.faiss`).
3. FAISS instantly returns the `top_k = 2` paragraphs physically describing the exact weakness methodology.

### Phase 5: LLM Reasoning (The "Decision" Layer)
The Worker merges all the gathered intelligence into a colossal prompt and queries **Ollama**.

**Prompt Ingredients transmitted to CodeLlama:**
- The Exact Source Code (so it can inspect manual developer sanitization)
- The Static Rule Name (e.g., `eval-injection`)
- The Joern CPG Taint Track (Path data travels)
- The MITRE RAG Definition (Mathematical context)

CodeLlama runs this through its internal layers loaded on the isolated Tesla V100 GPU (GPU 7). It analyzes the context and is strictly constrained by a JSON output schema. It returns a final verdict (`True Positive` or `False Positive`), overriding the naive Static Analysis tools.

---

## ⚙️ 3. Hardware Constraint Handling

Running Large Language Models on a shared DGX Server (where multiple researchers are saturating CUDA cores) is notoriously difficult. HackerSec circumvents timeouts:

- **Tensor Splitting**: A `16384` context-window requires ~8.2 GB of VRAM. If GPU 7 falls beneath 11 GB of total free threshold (due to other scripts), Ollama intentionally "splits" the AI across `libggml-cuda.so` and `libggml-cpu-haswell.so` (the PCIe/CPU). Performance slows to ~40 seconds per file, but effectively prevents fatal CUDA `OOM (Out Of Memory)` exceptions.
- **httpx Impatience Bounding**: The internal python LLM Client (`client.py`) sets a highly aggressive `timeout=300.0s`. Standard python routines crash at 60s, but HackerSec allows deep, un-terminated context reasoning windows due to the potential hybrid PCIe penalty.
