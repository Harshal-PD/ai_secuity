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
_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "300"))


class OllamaClient:
    def __init__(self, base_url: str = _DEFAULT_OLLAMA_URL):
        self.base_url = base_url.rstrip("/")
        # Provide aggressive timeouts to prevent blocking inference loops mapping large batches
        self.client = httpx.Client(timeout=_TIMEOUT)
        self.num_ctx = _DEFAULT_NUM_CTX

    def health(self, model: str, min_tokens_per_sec: float = 3.0, require_gpu: bool = True) -> dict:
        """
        Can `model` actually generate at a usable speed right now?

        Listing the model in /api/tags only proves the server is up; a model
        that fell back to CPU on a busy host still lists fine but takes longer
        than the request timeout per call. This runs a tiny generation, then
        reads /api/ps to see how much of the model sits in GPU memory.
        """
        out = {"ok": False, "model": model, "tokens_per_sec": None, "gpu_fraction": None, "reason": ""}
        try:
            res = self.client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": "Reply with the single word: ready",
                    "stream": False,
                    "options": {"num_ctx": self.num_ctx, "num_predict": 8, "temperature": 0},
                },
                timeout=min(_TIMEOUT, 240.0),
            )
            res.raise_for_status()
            data = res.json()
        except httpx.HTTPStatusError as e:
            out["reason"] = f"HTTP {e.response.status_code}: {e.response.text[:120]}"
            return out
        except httpx.RequestError as e:
            out["reason"] = f"generation probe failed ({e.__class__.__name__})"
            return out

        count, duration_ns = data.get("eval_count") or 0, data.get("eval_duration") or 0
        tps = count / (duration_ns / 1e9) if count and duration_ns else None
        out["tokens_per_sec"] = round(tps, 2) if tps else None

        try:
            ps = self.client.get(f"{self.base_url}/api/ps", timeout=10).json()
            for m in ps.get("models", []):
                if m.get("name") in (model, f"{model}:latest") or m.get("model") in (model, f"{model}:latest"):
                    size, vram = m.get("size") or 0, m.get("size_vram") or 0
                    out["gpu_fraction"] = round(vram / size, 3) if size else None
        except (httpx.HTTPError, ValueError):
            pass

        if require_gpu and out["gpu_fraction"] is not None and out["gpu_fraction"] < 0.95:
            out["reason"] = f"model is {100 * (1 - out['gpu_fraction']):.0f}% on CPU"
        elif tps is not None and tps < min_tokens_per_sec:
            out["reason"] = f"generation too slow ({tps:.2f} tokens/s)"
        else:
            out["ok"] = True
        return out

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
            return {
                "llm_status": "success",
                "response": data.get("response", ""),
                # Ollama silently drops the start of a prompt longer than
                # num_ctx; this lets callers detect that.
                "prompt_tokens": data.get("prompt_eval_count"),
                "num_ctx": options["num_ctx"],
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Ollama backend returned status {e.response.status_code}: {e.response.text}")
            return {"llm_status": "failed_connection", "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except httpx.RequestError as e:
            logger.error(f"Failed to query Ollama backend: {e}")
            return {"llm_status": "failed_connection", "error": str(e)}
