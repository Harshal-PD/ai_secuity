import csv
import io
import zipfile
import httpx
import logging
import sys
from pathlib import Path

# Add project root to path so we can import from hackersec
sys.path.insert(0, str(Path(__file__).parent.parent.parent.absolute()))

from hackersec.analysis.rag import LocalRAGStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cwe-ingress")

CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

def fetch_and_ingest_cwes():
    logger.info(f"Downloading CWE Database from {CWE_CSV_URL}...")
    
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        res = client.get(CWE_CSV_URL)
        res.raise_for_status()
        
    logger.info("Extracting ZIP payload...")
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        csv_filename = [name for name in z.namelist() if name.endswith('.csv')][0]
        # MITRE strings might sometimes contain windows-1252 anomalies, utf-8 replace is safe
        with z.open(csv_filename) as f:
            csv_text = f.read().decode("utf-8", errors="replace")
            
    logger.info("Parsing CSV columns...")
    # Skip any potential BOM or MITRE prologue, though 1000.csv is usually clean
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    
    documents = []
    
    for row in reader:
        cwe_id = row.get("CWE-ID", "")
        if not cwe_id:
            continue
            
        cwe_str = f"CWE-{cwe_id}"
        name = row.get("Name", "")
        desc = row.get("Description", "")
        mitigations = row.get("Potential Mitigations", "")
        
        # Build semantic chunk for RAG
        text_chunk = f"{cwe_str}: {name}. Description: {desc}."
        if mitigations:
            # Mitigation string can be long and messy (colon separated), capture top 250 logic chars
            clean_mit = mitigations.replace("::", "; ")
            text_chunk += f" Mitigations: {clean_mit[:250]}..."
            
        documents.append({
            "id": cwe_str,
            "text": text_chunk
        })
        
    logger.info(f"Parsed {len(documents)} valid CWE records from MITRE.")
    
    rag_store = LocalRAGStore()
    
    # Check if we already loaded them
    if len(rag_store.metadata) > 100:
        logger.info(f"FAISS Database already contains {len(rag_store.metadata)} docs. Skipping.")
        return
        
    logger.info("Injecting CWEs into FAISS LocalRAGStore (Computing embeddings)...")
    rag_store.add_documents(documents)
    
    logger.info(f"✅ RAG Build Complete! Database has {len(rag_store.metadata)} total embedded records.")

if __name__ == "__main__":
    fetch_and_ingest_cwes()
