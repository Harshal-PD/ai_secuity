import logging
import os

from hackersec.analysis.schema import Finding
from hackersec.analysis.llm.client import (
    OllamaClient,
    MODEL_ATTACKER,
    MODEL_DEFENDER,
    MODEL_JUDGE,
)
from hackersec.analysis.llm.prompter import (
    build_attacker_prompt,
    build_defender_prompt,
    build_judge_prompt,
    build_analysis_prompt,
)
from hackersec.analysis.llm.parser import (
    parse_attacker_response,
    parse_defender_response,
    parse_judge_response,
    parse_llm_response,
)

logger = logging.getLogger(__name__)

# Set to "0" to fall back to the original single-pass reasoning call. Kept as a
# baseline so the board can be measured against it during evaluation.
BOARD_ENABLED = os.getenv("LLM_BOARD_ENABLED", "1") not in ("0", "false", "False")

# The adversaries need room to theorize; the judge must be reproducible.
TEMP_ATTACKER = float(os.getenv("LLM_TEMP_ATTACKER", "0.6"))
TEMP_DEFENDER = float(os.getenv("LLM_TEMP_DEFENDER", "0.5"))
TEMP_JUDGE = float(os.getenv("LLM_TEMP_JUDGE", "0.0"))


class AdversarialBoard:
    """
    Three-seat reasoning board: Attacker argues exploitability, Defender argues
    neutralization and rebuts, Judge arbitrates on the evidence.

    Seats run sequentially because the Defender needs the Attacker's claim and
    the Judge needs both. Findings are processed one at a time by the Celery
    worker, so only one generation is ever in flight against Ollama.
    """

    def __init__(self, client: OllamaClient | None = None):
        self.client = client or OllamaClient()

    def deliberate(self, finding: Finding) -> dict:
        if not BOARD_ENABLED:
            return self._single_pass(finding)

        # ── Seat 1: Attacker ────────────────────────────────────────────────
        res = self.client.generate(
            build_attacker_prompt(finding),
            model=MODEL_ATTACKER,
            temperature=TEMP_ATTACKER,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        attacker = parse_attacker_response(res["response"])

        # ── Seat 2: Defender (sees the Attacker's claim) ────────────────────
        res = self.client.generate(
            build_defender_prompt(finding, attacker),
            model=MODEL_DEFENDER,
            temperature=TEMP_DEFENDER,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        defender = parse_defender_response(res["response"])

        # ── Seat 3: Judge (sees both) ───────────────────────────────────────
        res = self.client.generate(
            build_judge_prompt(finding, attacker, defender),
            model=MODEL_JUDGE,
            temperature=TEMP_JUDGE,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        judge = parse_judge_response(res["response"])

        return self._assemble(attacker, defender, judge)

    # ── Result shaping ──────────────────────────────────────────────────────

    def _assemble(self, attacker: dict, defender: dict, judge: dict) -> dict:
        """
        Flattens the debate into the `llm_analysis` contract the fusion layer,
        patcher, and dashboard already consume.
        """
        return {
            "llm_status": "success",
            "mode": "adversarial_board",
            # Judge's answer is the finding's analysis.
            "explanation": judge["explanation"],
            "root_cause": judge["root_cause"],
            "fix_suggestion": judge["fix_suggestion"],
            # P(vulnerability is real), already inverted for FALSE_POSITIVE.
            "confidence": judge["confidence"],
            "board_verdict": judge["verdict"],
            "board": {
                "attacker": attacker,
                "defender": defender,
                "judge": {
                    "verdict": judge["verdict"],
                    "verdict_confidence": judge["verdict_confidence"],
                    "reasoning": judge["reasoning"],
                    "status": judge["status"],
                },
                "models": {
                    "attacker": MODEL_ATTACKER,
                    "defender": MODEL_DEFENDER,
                    "judge": MODEL_JUDGE,
                },
            },
        }

    def _transport_failure(self, res: dict) -> dict:
        logger.warning(f"Board seat unreachable: {res.get('error')}")
        return {
            "llm_status": res["llm_status"],
            "mode": "adversarial_board",
            "error": res.get("error"),
        }

    def _single_pass(self, finding: Finding) -> dict:
        """Original one-shot reasoning call, retained as the ablation baseline."""
        res = self.client.generate(build_analysis_prompt(finding))
        if res["llm_status"] != "success":
            return self._transport_failure(res)

        parsed = parse_llm_response(res["response"])
        parsed["mode"] = "single_pass"
        return parsed
