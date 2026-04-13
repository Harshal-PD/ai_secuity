import logging
import os
import httpx

logger = logging.getLogger(__name__)

_DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

class OllamaClient:
    def __init__(self, base_url: str = _DEFAULT_OLLAMA_URL):
        self.base_url = base_url.rstrip("/")
        # Provide aggressive timeouts to prevent blocking inference loops mapping large batches
        self.client = httpx.Client(timeout=60.0)

    def ping(self) -> bool:
        """Check if local Ollama Server is reachable."""
        try:
            res = self.client.get(self.base_url, timeout=5.0)
            return res.status_code == 200
        except httpx.RequestError:
            return False

    def generate(self, prompt: str, model: str = "deepseek-coder-v2") -> dict:
        """
        Invokes Ollama text generation endpoint sequentially.
        DeepSeek variants usually yield strict boundaries via format constraints.
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        try:
            res = self.client.post(f"{self.base_url}/api/generate", json=payload)
            res.raise_for_status()
            
            # The returned schema from Ollama has "response" nested string 
            data = res.json()
            return {"llm_status": "success", "response": data.get("response", "")}
            
        except httpx.RequestError as e:
            logger.error(f"Failed to query Ollama backend: {e}")
            return {"llm_status": "failed_connection", "error": str(e)}
