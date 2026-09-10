---
marp: true
theme: default
paginate: true
header: "HackerSec: AI-Driven Security Code Reviewer"
footer: "Semester 6 Research Project"
style: |
  section {
    font-family: 'Inter', sans-serif;
  }
  table {
    font-size: 0.8em;
  }
---

# HackerSec: A Research-Grade AI-Driven Security Code Reviewer 🛡️
**Context-Aware Vulnerability Detection with Actionable Remediation**

---

# 1. Motivation
* **The Alert Fatigue Crisis:** Traditional Static Application Security Testing (SAST) tools (e.g., SonarQube, Fortify) generate overwhelming volumes of False Positives.
* **LLM Hallucinations:** Generative AI solutions exist, but often lack formal semantic understanding, leading to fabricated "phantom" vulnerabilities or missing deep logical flaws.
* **Data Privacy:** Cloud-based APIs (OpenAI/Anthropic) require transmitting proprietary source code off-premise, violating strict enterprise compliance protocols.
* **The Need:** A fully offline, deterministic, and graph-grounded agentic system capable of reasoning like a human security engineer.

---

# 2. Literature Survey

| Year | Author / System | Findings / Approach | Remarks / Limitations |
|------|-----------------|---------------------|-----------------------|
| 2021 | VulDeePecker | Deep Learning for VR using code gadgets | High setup overhead; limited context memory. |
| 2022 | Devign / Graph | utilized Graph Neural Networks over ASTs | Black-box models; no actionable patch generation. |
| 2023 | GPT-4 for SAST | Direct prompt-based vulnerability scanning | High token cost; prone to hallucination; privacy risks. |
| 2024 | LLMxCPG / Hybrid | Combined Code Property Graphs with LLMs | Often relies on cloud APIs; lacks adversarial verification. |

---

# 3. Literature Survey (Continued)
* Early methodologies relied entirely on **Signature-Based Rules (SBR)**, which fail to understand custom developer sanitization strategies.
* Machine Learning shifted toward **Graph Neural Networks (GNN)**, establishing the Code Property Graph (CPG) as the gold standard for tracking data flow.
* Modern efforts attempt to inject source code directly into **Large Language Models (LLMs)**. However, without directing the model's attention using strict heuristic anchors or RAG contexts, models suffer from catastrophic context loss in large files. 

---

# 4. Research Gap
1. **Lack of Grounding:** Existing LLM reviewers analyze code blindly. They are not intrinsically grounded in formal security classifications (MITRE CWE/OWASP).
2. **Missing Directed Taint Tracking:** Most AI tools ignore the mathematical traversal of data from untrusted sources to execution sinks, failing to recognize when data is pre-sanitized.
3. **No Multi-Agent Verification:** Current approaches typically use a single LLM pass, lacking an internal "Devil's Advocate" mechanism to robustly challenge the vulnerability's existence.
4. **Cloud Dependency:** Existing high-performance systems prohibit offline, air-gapped utilization due to reliance on proprietary APIs.

---

# 5. Problem Statement
To design and implement **HackerSec**, a purely localized, multi-layered AI security pipeline that overcomes traditional SAST false positives. 

The system must programmatically combine **heuristic static triggers**, **Code Property Graph (CPG) taint analysis**, and **RAG-grounded MITRE knowledge bases**, feeding precisely bounded context into a localized LLM (CodeLlama/DeepSeek) orchestrating an adversarial verification panel to evaluate real-world vulnerabilities and generate autonomous patches.

---

# 6. System Architecture (The 6-Phase Pipeline)
*HackerSec processes raw source code through a sequential, multi-layered asynchronous pipeline.*

**Phase 1: Deterministic Static Triggers**
Rather than feeding an entire codebase to an LLM, HackerSec uses lightweight static analyzers to scout for dangerous "sinks" (e.g., `eval()`, `subprocess.call()`, `cursor.execute()`).
* **Engines:** Semgrep (broad multi-language rules) and Bandit (Python-native AST inspection).
* **Output:** A deduplicated list of specific line numbers containing potentially dangerous execution points.

---

# 7. Architecture: Taint Path & RAG Grounding

**Phase 2: CPG Augmentation & Directed Taint Analysis**
The static triggers are passed to a semantic graph engine to verify if user-controlled data can actually reach the dangerous sink.
* **Engine:** Joern.
* **Process:** The source code is compiled into a Code Property Graph. Custom Scala queries execute a backward taint analysis from the triggered sink to any untrusted input source.
* **Output:** A mathematical proof of the data flow (Taint Path), isolating the variable's journey.

**Phase 3: RAG Knowledge Grounding**
To prevent hallucination, the pipeline retrieves textbook facts.
* **Engine:** Local FAISS + `all-MiniLM-L6-v2`.
* **Output:** The top paragraphs detailing theoretical exploit mechanics/mitigations.

---

# 8. Architecture: The LLM Evaluation Board

**Phase 4: Adversarial Multi-Agent Reasoning Board**
The raw code, Joern taint path, and RAG definitions are injected into a local LLM orchestrating three distinct agent personas:
1. **The Attacker (Red Team):** Analyzes the graph to theorize an exploit path.
2. **The Defender (Blue Team):** Analyzes the graph for sanitization logic (e.g., type-casting) to argue the input is neutralized.
3. **The Judge (Arbitrator):** Evaluates arguments grounded strictly by RAG definitions.
* **Output:** A deterministic JSON payload (TRUE_POSITIVE or FALSE_POSITIVE) and confidence score.

---

# 9. Architecture: Remediation & Fusion

**Phase 5: Auto-Remediation (Patcher LLM)**
If the Judge issues a TRUE_POSITIVE verdict, a specialized patching prompt is triggered.
* **Process:** The Patcher LLM evaluates the vulnerable code segment to rewrite the syntax securely.
* **Output:** A unified diff Git patch and a developer explanation.

**Phase 6: ML Fusion Classifier**
To provide normalized metrics for evaluation, a Scikit-Learn RandomForest classifier ingests the initial SAST severity, the Judge's Boolean verdict, and the confidence score.
* **Output:** A final probability score (0.0 to 1.0) of the vulnerability's reality.

---

# 10. Technology Stack
* **Ingestion & Orchestration:** FastAPI (Backend API), Celery & Redis (Asynchronous task queues for heavy CPG generation).
* **Static & Semantic Analysis:** Semgrep, Bandit, Joern (Scala/JVM).
* **AI/LLM Runtime:** Ollama orchestrating local models (DeepSeek-Coder-V2 / CodeLlama) to ensure 100% offline data privacy.
* **Vector Retrieval (RAG):** FAISS (Facebook AI Similarity Search), `sentence-transformers` for embeddings.
* **Machine Learning:** Scikit-Learn, Pandas.

---

# 11. Code Snippets: Extracted Triggers
**Example of vulnerable code bounded for the LLM Prompt:**
```python
===== UNTRUSTED SOURCE CODE =====
[UNTRUSTED_CODE_START]
def execute_ping(request):
    # Developer taking user input
    target = request.GET.get('ip')
    
    # Passing un-sanitized data to an OS execute sink
    os.system(f"ping -c 4 {target}")
[UNTRUSTED_CODE_END]
```
The architecture strips out surrounding white noise, padding precisely 3 context lines above and below the triggered sink to prevent LLM context-window saturation.

---

# 12. Code Snippets: Joern CPG Taint Output
**Example of a semantic mathematical proof fed to the LLM:**
```json
===== CPG TRACE (Syntax Flows) =====
Flow 0: "request.GET.get('ip')" (Line 3) -> "target" (Line 3)
Flow 1: "target" (Line 3) -> "f'ping -c 4 {target}'" (Line 6)
Flow 2: "f'ping -c 4 {target}'" (Line 6) -> "os.system" (Line 6)

===== RAG CONTEXT (OWASP/CWE Base) =====
- [CWE-78] Improper Neutralization of Special Elements used in an OS Command.
```
By providing physical flow proofs, the LLM stops guessing and deterministically evaluates if `target` encountered integer casting or regex sanitization on its journey.

---

# 13. Evaluation Methodology & Results
To validate the pipeline's effectiveness as a research system, HackerSec is benchmarked against standard industry datasets:
* **Datasets:** The NIST Juliet Test Suite (focusing on Python/C/C++ cases) and the OWASP Benchmark.

**Key Performance Indicators (KPIs):**
1. **Precision:** Ensuring findings marked as positive are genuinely exploitable (minimizing the alert fatigue problem).
2. **Recall:** Measuring the system's ability to identify all hidden vulnerabilities.
3. **F1 Score:** The harmonic mean of precision and recall, serving as the ultimate benchmark for the system's reliability.

---

# 14. Future Work
1. **Cross-File Taint Tracking Expansion:** Enhancing Joern's traversal to accurately trace variables passed deeply across multiple `.import` files and network microservices.
2. **Dynamic Application Security Testing (DAST) Integration:** Augmenting the pipeline with active payloads injected into live running containers to mathematically confirm the LLM patches.
3. **Fine-Tuning Local Models:** Transitioning from prompt-engineered CodeLlama limits to mathematically Fine-Tuning LoRA adapters specifically trained on RAG-augmented AST security graphs.

---

# 15. Conclusion & References
**Conclusion:** HackerSec represents a significant shift in automated code review. By restricting naive LLM analysis and replacing it with deterministic triggers, directed taint analysis, and adversarial AI reasoning, the system eliminates hallucination. By mandating an offline-only architecture, it ensures a high-fidelity, zero-trust solution capable of scaling.

**References:**
1. Yamaguchi, F., et al. (2014) *Modeling and Discovering Vulnerabilities with Code Property Graphs*. IEEE Symposium on Security and Privacy.
2. MITRE Corporation (2025). *Common Weakness Enumeration (CWE)*.
3. Meta AI. (2023). *Code Llama: Open Foundation Models for Code*.
4. OWASP Foundation (2021). *OWASP Top 10 Application Security Risks*.
