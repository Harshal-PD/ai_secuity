import pytest
from pathlib import Path
from hackersec.analysis.rag import LocalRAGStore

@pytest.fixture
def temp_rag_store(tmp_path):
    # Setup isolated memory store without writing to global data/ arrays
    store = LocalRAGStore(data_dir=str(tmp_path))
    yield store

def test_rag_embedding_size_and_injection(temp_rag_store):
    assert temp_rag_store.embedding_dim == 384
    assert temp_rag_store.index.ntotal == 0
    
    docs = [{"id": "CWE-123", "text": "This is a random test issue regarding SQL maps."}]
    temp_rag_store.add_documents(docs)
    
    assert temp_rag_store.index.ntotal == 1
    assert len(temp_rag_store.metadata) == 1

def test_rag_semantic_search_retrieves_nearest(temp_rag_store):
    docs = [
        {"id": "CWE-999", "text": "Something about buffer overflows and memory blocks."},
        {"id": "CWE-89", "text": "SQL Injection vulnerability in database queries."}
    ]
    temp_rag_store.add_documents(docs)
    
    # "database sql" is semantically much closer to CWE-89
    results = temp_rag_store.search("database sql", top_k=1)
    assert len(results) == 1
    assert results[0]["id"] == "CWE-89"
    assert "SQL" in results[0]["text"]
