# Phase 3 Research: RAG Knowledge Base

## RESEARCH COMPLETE

**Phase:** 3 — RAG Knowledge Base
**Goal:** Build and persist a FAISS vector index composed of OWASP/CWE/CVE documentation to augment the DeepSeek-Coder LLM prompt later in the pipeline.

---

## 1. Vector Database Architecture

### Technology Selection
Based on HackerSec project constraints (STACK.md), the system strictly requires:
- **Embeddings:** `sentence-transformers` using `all-MiniLM-L6-v2` (384-dimensional). Lightweight and local.
- **Index:** `FAISS` (Facebook AI Similarity Search) CPU version. Local, stateless memory mapping, no network socket overhead compared to Chroma/Qdrant.

### Ingestion Data
For research-grade vulnerability evaluation, the LLM needs ground truth definitions of flaws.
We map:
1. **CWE Descriptions:** MITRE Top 25 and general software engineering weaknesses.
2. **OWASP Definitions:** Standard context surrounding exploit vectors.
3. *Phase 3 Scope:* Pre-load standard dictionary JSONs into FAISS vectors using localized scripts.

---

## 2. FAISS Store Implementation

We avoid heavy abstractions like LangChain (per PITFALLS.md) to maintain research reproducibility and lower footprint.

```python
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

class LocalRAGStore:
    def __init__(self, index_path: str = "data/faiss.index"):
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.index_path = index_path
        self.index = None
        self.metadata = []

    def populate(self, documents: list[dict]):
        # texts = [d["text"] for d in documents]
        # embeddings = self.model.encode(texts)
        # self.index = faiss.IndexFlatL2(384)
        # self.index.add(np.array(embeddings))
        pass

    def search(self, query: str, top_k: int = 3) -> list:
        # returns metadata of closest vectors
        pass
```

---

## 3. Data Integration for findings

Static analysis provides CWE IDs and generic rule hints. The FAISS database will query:
`f"Explain {finding.cwe_ids} and {finding.owasp_category} vulnerabilities and secure coding patterns"`

The returned textual documentation will be packed into the `Finding.rag_docs` array attribute.

---

## 4. Pitfalls & Performance
1. **FAISS Persistence:** Store FAISS index as `.bin` alongside a JSON array mapping relative positions (IDs) strictly to text strings to return textual info without a secondary database.
2. **Model Download on Boot (Cold Start):** `sentence_transformers` downloads models via HuggingFace by default. For the API, the model MUST strictly exist locally preventing internet blockages or downloading 100 times. We dictate local cache utilization configuration within the class `__init__`.

---

## Validation Strategy
1. Unit test ensuring vector dimensionalities map uniformly (`384` for all-MiniLM) and FAISS inserts don't throw bounds mismatch exceptions.
2. Functional mock confirming that semantic similarity works (e.g. querying "SQL Injection" surfaces the CWE-89 document first).
