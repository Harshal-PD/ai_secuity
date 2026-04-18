# HackerSec Analytical Architecture & Pipeline

This document details the deep conceptual architecture of HackerSec's analytical pipeline. It explains exactly what inputs and outputs are passed between the analytical engines (Static Analysis, CPG, RAG, LLM, and ML Fusion) and the technical philosophy behind *why* they are structured this way.

## 🎯 The Philosophy: Grounded AI Security
Modern LLMs are prone to extreme hallucination when asked to "find security bugs" in large codebases. HackerSec solves this by using **Deterministic Static Analysis** to generate hard evidence (triggers), **Code Property Graphs (CPG)** to map the data flow, and **RAG** to establish definitions. The LLM is then used exclusively for *binary reasoning* rather than blind discovery.

---

## 🔍 Phase 1: Static Analysis (The "Trigger" Generation)
Rather than feeding thousands of lines of arbitrary code to the LLM, we use AST (Abstract Syntax Tree) parsers to find mathematically definitive "Points of Interest."

- **Input:** Raw Source Code (e.g., `test_vuln.py`).
- **Concept:** We use `Semgrep` (equipped with `p/owasp-top-ten` and `p/secrets` rules) and `Bandit`. These engines tokenize the code and execute regex and graph-based rule matching to find traditionally dangerous function calls (like `eval()` or `os.system()`).
- **Output:** A deduplicated list of **Raw Findings**.
  ```json
  {
    "line_number": 42,
    "rule_id": "eval-injection",
    "cwe_id": "CWE-95",
    "code_snippet": "eval(request.GET['data'])"
  }
  ```

---

## 🕸️ Phase 2: Code Property Graph (CPG) Augmentation
Static analysis tells us *where* a dangerous function is used, but it does not know if the input is sanitized elsewhere in the file. We use Joern to trace the data backward.

- **Input:** The offending Line Number (from Phase 1) + Source File.
- **Concept:** Joern parses the file into a multi-dimensional graph combining the AST, the CFG (Control Flow Graph), and the PDG (Program Dependence Graph). We inject Scala query scripts into Joern that execute **Taint Flow Analysis**. This mathematically traces how a variable flows from its declaration (the source) to its execution (the sink).
- **Output:** A String representation of the data's journey (Taint Path).
  ```text
  Line 10: user_input = request.GET['data']
  Line 25: sanitized = strip_tags(user_input)
  Line 42: eval(sanitized)
  ```

---

## 📚 Phase 3: RAG Grounding (The Knowledge Retrieval)
Because the internal knowledge weights of models like CodeLlama deteriorate or confuse specific CVEs/CWEs, we ground the LLM with physical definitions before it thinks.

- **Input:** The Static rule string (e.g., `CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code`).
- **Concept:** We process the rule string through the `all-MiniLM-L6-v2` transformer model to convert it into a dense 384-dimensional mathematical vector. We perform an **L2 Distance Similarity Search** against our offline FAISS database (which physically holds over 1,000 MITRE dictionary vulnerabilities).
- **Output:** The Top 2 most mathematically relevant paragraphs detailing how the attack actually works, what mitigations exist, and theoretical exploitation vectors.

---

## 🧠 Phase 4: LLM Evaluation (The Reasoning Engine)
We merge all gathered intelligence and force the LLM to act as a **Senior Security Reviewer** making a logical decision.

- **Input:** A highly structured mega-prompt injected with:
  1. Full Source Code
  2. The flagged Line segment
  3. The CPG Taint Flow Array
  4. The 2 MITRE RAG Paragraphs
- **Concept:** The CodeLlama 7B model (running entirely in VRAM) processes the prompt. Because it is given the CPG, it can read: *"Ah, I see `eval` is used on Line 42, but the CPG shows the data was explicitly cast to an integer on Line 25."* Because it is given the RAG, it knows: *"CWE-95 explicitly states that integer-casted variables cannot be leveraged for arbitrary execution."*
- **Output:** A rigid, deterministic JSON object overriding the naive static analysis.
  ```json
  {
    "reasoning": "The tainted variable is sanitized via int() casting prior to the eval() sink, neutralizing the CWE-95 threat.",
    "is_true_positive": false,
    "confidence_score": 0.95
  }
  ```

---

## 🧬 Phase 5: ML Fusion (The Confidence Classifier)
*Research Roadmap Phase: To be finalized for HuggingFace Dataset Benchmarking.*

- **Input:** The LLM's Boolean output (`is_true_positive`), The LLM's raw Confidence Score, and the Static Analyzer's original Severity Rating (Low/Medium/High).
- **Concept:** LLMs occasionally output uncertain probabilities. We map these results into numerical feature vectors. A lightweight Machine Learning classifier (like Scikit-Learn's `RandomForest` or `GradientBoostingClassifier`) evaluates these combined features against historically trained data distributions to calculate a final mathematical probability.
- **Output:** A final, normalized metric (0.0 to 1.0 probability) representing the ultimate reality of the vulnerability, establishing the final `Precision`, `Recall`, and `F1 Score` of the HackerSec research pipeline.
