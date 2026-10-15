import json
import re
from pathlib import Path
from typing import List, Dict

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

_CWE_ID = re.compile(r"CWE-\d+", re.I)
_OWASP_ID = re.compile(r"A\d{2}:\d{4}", re.I)


class LocalRAGStore:
    """Local FAISS vector store mapped to sentence-transformers."""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.index_path = self.data_dir / "kb.faiss"
        self.meta_path = self.data_dir / "kb_meta.json"
        
        # Load offline-safe model
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.embedding_dim = 384
        
        self.metadata: List[Dict] = []
        self.index = faiss.IndexFlatL2(self.embedding_dim)
        
        self._load()

    def _load(self):
        """Restore index and metadata if available."""
        if self.index_path.exists() and self.meta_path.exists():
            self.index = faiss.read_index(str(self.index_path))
            with open(self.meta_path, 'r', encoding='utf-8') as f:
                self.metadata = json.load(f)

    def _save(self):
        """Persist index and metadata."""
        faiss.write_index(self.index, str(self.index_path))
        with open(self.meta_path, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f)

    def add_documents(self, documents: List[Dict[str, str]]) -> None:
        """
        Add items. Expects JSON dicts: {"id": "CWE-89", "text": "SQL Injection details..."}
        """
        if not documents:
            return
            
        texts = [doc.get("text", "") for doc in documents]
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        
        self.index.add(np.array(embeddings, dtype=np.float32))
        self.metadata.extend(documents)
        
        self._save()

    def search(self, query: str, top_k: int = 2) -> List[Dict]:
        """Query finding string to retrieve nearest semantic text chunks."""
        if self.index.ntotal == 0:
            return []
            
        query_vector = self.model.encode([query], convert_to_numpy=True)
        distances, indices = self.index.search(np.array(query_vector, dtype=np.float32), top_k)
        
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx != -1 and idx < len(self.metadata):
                results.append({
                    "id": self.metadata[idx].get("id"),
                    "text": self.metadata[idx].get("text"),
                    "distance": float(dist)
                })
        return results

    def retrieve_for_finding(
        self,
        rule_id: str,
        cwe_ids: List[str] | None = None,
        owasp: str | None = None,
        message: str = "",
        top_k: int = 2,
    ) -> List[Dict]:
        """Exact CWE/OWASP metadata lookup first, then semantic search with the finding message."""
        wanted: List[str] = []
        for raw in cwe_ids or []:
            for m in _CWE_ID.findall(str(raw)):
                cid = m.upper()
                if cid not in wanted:
                    wanted.append(cid)
        if owasp:
            for m in _OWASP_ID.findall(str(owasp)):
                oid = m.upper()
                if oid not in wanted:
                    wanted.append(oid)

        matched: List[Dict] = []
        seen_ids: set[str] = set()
        for target_id in wanted:
            if len(matched) >= top_k:
                break
            candidates = [d for d in self.metadata if str(d.get("id", "")).upper() == target_id]
            if not candidates:
                continue
            # Prefer a doc whose text begins with its own ID (avoids mislabelled duplicates).
            chosen = next((d for d in candidates if str(d.get("text", "")).upper().startswith(target_id)), candidates[0])
            seen_ids.add(target_id)
            matched.append({"id": chosen.get("id"), "text": chosen.get("text"), "distance": 0.0})

        if len(matched) < top_k and self.index.ntotal > 0:
            parts = [f"Security vulnerability {rule_id}"]
            if wanted:
                parts.append(" ".join(wanted))
            if message:
                parts.append(str(message)[:200])
            for doc in self.search(" ".join(parts), top_k=top_k + len(matched)):
                doc_id = str(doc.get("id") or "")
                if doc_id not in seen_ids:
                    seen_ids.add(doc_id)
                    matched.append(doc)
                    if len(matched) >= top_k:
                        break
        return matched
