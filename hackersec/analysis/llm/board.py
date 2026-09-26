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
from hackersec.analysis.llm.evidence import check_sanitizer_evidence

logger = logging.getLogger(__name__)

# Set to "0" to fall back to the original single-pass reasoning call. Kept as a
# baseline so the board can be measured against it during evaluation.
BOARD_ENABLED = os.getenv("LLM_BOARD_ENABLED", "1") not in ("0", "false", "False")

# Enforce citation-required neutralization. Disable only to ablate the rule.
EVIDENCE_RULE_ENABLED = os.getenv("LLM_EVIDENCE_RULE", "1") not in ("0", "false", "False")

# The adversaries need room to theorize; the judge must be reproducible.
TEMP_ATTACKER = float(os.getenv("LLM_TEMP_ATTACKER", "0.6"))
TEMP_DEFENDER = float(os.getenv("LLM_TEMP_DEFENDER", "0.5"))
TEMP_JUDGE = float(os.getenv("LLM_TEMP_JUDGE", "0.0"))

# Confidence floor applied when the evidence rule overturns a FALSE_POSITIVE.
OVERRIDE_CONFIDENCE_FLOOR = 0.5


class AdversarialBoard:
    """
    Three-seat reasoning board: Attacker argues exploitability, Defender argues
    neutralization and rebuts, Judge arbitrates on the evidence.

    Seats run sequentially because the Defender needs the Attacker's claim and
    the Judge needs both. Findings are processed one at a time by the Celery
    worker, so only one generation is ever in flight against Ollama.

    `mode`, `models`, and `use_evidence_rule` exist so the evaluation harness
    can hold the dataset fixed and vary exactly one factor at a time.
    """

    def __init__(
        self,
        client: OllamaClient | None = None,
        *,
        mode: str | None = None,
        models: dict | None = None,
        use_evidence_rule: bool | None = None,
    ):
        self.client = client or OllamaClient()
        if mode is None:
            mode = "board" if BOARD_ENABLED else "single"
        if mode not in ("board", "single"):
            raise ValueError(f"mode must be 'board' or 'single', got {mode!r}")
        self.mode = mode

        models = models or {}
        self.model_attacker = models.get("attacker", MODEL_ATTACKER)
        self.model_defender = models.get("defender", MODEL_DEFENDER)
        self.model_judge = models.get("judge", MODEL_JUDGE)

        self.use_evidence_rule = (
            EVIDENCE_RULE_ENABLED if use_evidence_rule is None else use_evidence_rule
        )

    def deliberate(self, finding: Finding) -> dict:
        if self.mode == "single":
            return self._single_pass(finding)

        # ── Seat 1: Attacker ────────────────────────────────────────────────
        res = self.client.generate(
            build_attacker_prompt(finding),
            model=self.model_attacker,
            temperature=TEMP_ATTACKER,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        attacker = parse_attacker_response(res["response"])

        # ── Seat 2: Defender (sees the Attacker's claim) ────────────────────
        res = self.client.generate(
            build_defender_prompt(finding, attacker),
            model=self.model_defender,
            temperature=TEMP_DEFENDER,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        defender = parse_defender_response(res["response"])

        # Verify the Defender's quote against the code before the Judge's
        # ruling is allowed to dismiss the finding.
        evidence = check_sanitizer_evidence(
            finding.code_snippet, defender.get("sanitization_evidence")
        )

        # ── Seat 3: Judge (sees both) ───────────────────────────────────────
        res = self.client.generate(
            build_judge_prompt(finding, attacker, defender),
            model=self.model_judge,
            temperature=TEMP_JUDGE,
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)
        judge = parse_judge_response(res["response"])

        return self._assemble(attacker, defender, judge, evidence)

    # ── Result shaping ──────────────────────────────────────────────────────

    def _assemble(
        self, attacker: dict, defender: dict, judge: dict, evidence: dict
    ) -> dict:
        """
        Flattens the debate into the `llm_analysis` contract the fusion layer,
        patcher, and dashboard already consume.
        """
        verdict = judge["verdict"]
        confidence = judge["confidence"]
        verdict_source = "judge"

        # Citation-required neutralization: a dismissal needs a sanitizer that
        # is actually in the code.
        if (
            self.use_evidence_rule
            and verdict == "FALSE_POSITIVE"
            and not evidence["grounded"]
        ):
            verdict = "TRUE_POSITIVE"
            confidence = max(confidence, OVERRIDE_CONFIDENCE_FLOOR)
            verdict_source = "evidence_rule"

        return {
            "llm_status": "success",
            "mode": "adversarial_board",
            # Judge's answer is the finding's analysis.
            "explanation": judge["explanation"],
            "root_cause": judge["root_cause"],
            "fix_suggestion": judge["fix_suggestion"],
            # P(vulnerability is real), already inverted for FALSE_POSITIVE.
            "confidence": confidence,
            "board_verdict": verdict,
            "board": {
                "attacker": attacker,
                "defender": defender,
                "judge": {
                    "verdict": judge["verdict"],
                    "verdict_confidence": judge["verdict_confidence"],
                    "reasoning": judge["reasoning"],
                    "status": judge["status"],
                },
                # Everything needed to audit an override without an LLM.
                "evidence_check": evidence,
                "verdict_source": verdict_source,
                "final_verdict": verdict,
                "evidence_rule_enabled": self.use_evidence_rule,
                "models": {
                    "attacker": self.model_attacker,
                    "defender": self.model_defender,
                    "judge": self.model_judge,
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
        res = self.client.generate(
            build_analysis_prompt(finding), model=self.model_judge
        )
        if res["llm_status"] != "success":
            return self._transport_failure(res)

        parsed = parse_llm_response(res["response"])
        parsed["mode"] = "single_pass"
        return parsed
