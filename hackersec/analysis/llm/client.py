import logging
import os
import httpx

logger = logging.getLogger(__name__)

_DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Single place to change the served model. Roles may override individually so the
# board can run a different family for the judge without touching the code.
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")
MODEL_ATTACKER = os.getenv("OLLAMA_MODEL_ATTACKER", DEFAULT_MODEL)
MODEL_DEFENDER = os.getenv("OLLAMA_MODEL_DEFENDER", DEFAULT_MODEL)
MODEL_JUDGE = os.getenv("OLLAMA_MODEL_JUDGE", DEFAULT_MODEL)
MODEL_PATCHER = os.getenv("OLLAMA_MODEL_PATCHER", DEFAULT_MODEL)

_DEFAULT_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))


class OllamaClient:
    def __init__(self, base_url: str = _DEFAULT_OLLAMA_URL):
        self.base_url = base_url.rstrip("/")
        # Provide aggressive timeouts to prevent blocking inference loops mapping large batches
        self.client = httpx.Client(timeout=300.0)

    def ping(self) -> bool:
        """Check if local Ollama Server is reachable."""
        try:
            res = self.client.get(self.base_url, timeout=5.0)
            return res.status_code == 200
        except httpx.RequestError:
            return False

    def generate(
        self,
        prompt: str,
        model: str | None = None,
        temperature: float = 0.2,
        json_mode: bool = True,
        num_ctx: int | None = None,
        seed: int | None = 42,
    ) -> dict:
        """
        Invokes Ollama text generation endpoint sequentially.

        `json_mode` must be disabled for the patcher, which returns raw source
        rather than a JSON object.
        """
        options = {
            "num_ctx": num_ctx or _DEFAULT_NUM_CTX,
            "temperature": temperature,
        }
        if seed is not None:
            options["seed"] = seed

        payload = {
            "model": model or DEFAULT_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if json_mode:
            payload["format"] = "json"

        try:
            res = self.client.post(f"{self.base_url}/api/generate", json=payload)
            res.raise_for_status()

            # The returned schema from Ollama has "response" nested string 
            data = res.json()
            return {"llm_status": "success", "response": data.get("response", "")}

        except httpx.HTTPStatusError as e:
            logger.error(f"Ollama backend returned status {e.response.status_code}: {e.response.text}")
            return {"llm_status": "failed_connection", "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except httpx.RequestError as e:
            logger.error(f"Failed to query Ollama backend: {e}")
            return {"llm_status": "failed_connection", "error": str(e)}
