import sys
import logging
from hackersec.analysis.rag import LocalRAGStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

INITIAL_KB_SEED = [
    {
        "id": "CWE-89",
        "text": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command."
    },
    {
        "id": "CWE-78",
        "text": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command."
    },
    {
        "id": "CWE-79",
        "text": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."
    },
    {
        "id": "CWE-22",
        "text": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
    },
    {
        "id": "CWE-327",
        "text": "Use of a Broken or Risky Cryptographic Algorithm. The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information."
    },
    {
        "id": "CWE-259",
        "text": "Use of Hard-coded Password. The software contains a hard-coded password, which makes it significantly easier for attackers to bypass authentication."
    }
]

def main():
    logger.info("Initializing baseline RAG Vector Store with CWE seeds...")
    store = LocalRAGStore(data_dir="data")
    
    # If index already has items, we skip seeding to avoid duplicates
    if store.index and store.index.ntotal > 0:
        logger.info(f"Store already populated with {store.index.ntotal} vectors. Skipping seed.")
        sys.exit(0)
        
    store.add_documents(INITIAL_KB_SEED)
    logger.info(f"Successfully seeded {len(INITIAL_KB_SEED)} CWE records into FAISS.")

if __name__ == "__main__":
    main()
