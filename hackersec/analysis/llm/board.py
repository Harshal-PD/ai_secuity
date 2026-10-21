import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

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
    parse_function_attacker_response,
    parse_judge_response,
    parse_llm_response,
    parse_vote_response,
)
from hackersec.analysis.llm.evidence import check_sanitizer_evidence
from hackersec.analysis.llm.function_prompter import (
    DEFENDER_CODE_CHARS,
    MIN_CODE_CHARS,
    build_function_attacker_prompt,
    build_function_defender_prompt,
    build_function_judge_prompt,
    code_budget,
    fit_function_code,
    synthesize_sast_attacker,
)

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

# Function-level review: with more than one vote the Judge is sampled at
# TEMP_JUDGE_VOTE and the share of VULNERABLE votes is the score
# (self-consistency, Wang et al. 2023). Sampled votes on this model almost
# always agree, so the default is one vote at TEMP_JUDGE.
JUDGE_VOTES = int(os.getenv("LLM_JUDGE_VOTES", "1"))
TEMP_JUDGE_VOTE = float(os.getenv("LLM_JUDGE_VOTE_TEMP", "0.7"))
# By default, the SAST + Joern finding packet acts as the Challenger claim
# (0 LLM tokens), and the 2-seat board runs Defender -> Judge. Set
# LLM_USE_ATTACKER=1 to run a separate Attacker LLM seat.
USE_LLM_ATTACKER = os.getenv("LLM_USE_ATTACKER", "0") in ("1", "true", "True")
# signal   -- the evidence check is recorded as a feature, never flips a vote
# override -- a SAFE majority whose sanitizer quote is not in the code is
#             overturned to VULNERABLE (the per-finding rule, for ablation)
# off      -- not applied
EVIDENCE_MODE = os.getenv("LLM_EVIDENCE_MODE", "signal").strip().lower()
# Answer caps for the function-level seats. A capped, unfinished JSON answer
# is parsed as a failed vote rather than stalling a parallel slot.
SEAT_MAX_TOKENS = 400
VOTE_MAX_TOKENS = 350


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

    # ── Function-level review ───────────────────────────────────────────────

    def deliberate_function(
        self,
        function_name: str,
        code: str,
        start_line: int,
        findings: list[Finding],
        *,
        votes: int | None = None,
        evidence_mode: str | None = None,
        context: str = "",
    ) -> dict:
        """
        One debate over a whole function and all of its candidate findings.

        Attacker and Defender argue once; the Judge then votes `votes` times,
        at TEMP_JUDGE_VOTE with different seeds when there is more than one
        vote. `p_vulnerable` is the mean of the votes' P(vulnerable), and
        `prediction` is the majority vote
        (after the evidence rule, when that is set to override). `context`
        (same-file callers and callees) is shown to every seat and takes its
        room from the code budget.
        """
        votes = votes or JUDGE_VOTES
        mode = (evidence_mode or EVIDENCE_MODE).lower()
        if mode not in ("signal", "override", "off"):
            raise ValueError(f"evidence_mode must be signal, override or off, got {mode!r}")

        num_ctx = getattr(self.client, "num_ctx", 4096)
        focus_lines = [f.line_start for f in findings]
        full_budget = max(MIN_CODE_CHARS, code_budget(num_ctx) - len(context))
        code_text, code_truncated = fit_function_code(code, start_line, focus_lines, full_budget)
        def_code_text, _ = fit_function_code(code, start_line, focus_lines, min(DEFENDER_CODE_CHARS, full_budget))
        prompt_tokens = []
        usage = {"prompt": 0, "completion": 0, "calls": 0}
        usage_lock = threading.Lock()

        def call(prompt: str, model: str, temperature: float, seed: int = 42, max_tokens: int = SEAT_MAX_TOKENS) -> dict:
            res = self.client.generate(prompt, model=model, temperature=temperature, seed=seed, max_tokens=max_tokens)
            with usage_lock:
                if res.get("prompt_tokens") is not None:
                    prompt_tokens.append(res["prompt_tokens"])
                    usage["prompt"] += int(res["prompt_tokens"] or 0)
                if res.get("completion_tokens") is not None:
                    usage["completion"] += int(res["completion_tokens"] or 0)
                if res.get("llm_status") == "success":
                    usage["calls"] += 1
            return res

        # 2-seat Challenger -> Defender -> Judge by default: the SAST + Joern
        # packet is the Challenger claim (0 LLM tokens), the Defender directly
        # rebuts it on a compact window around the flagged lines, and the Judge
        # rules on [SAST+Joern Alert + Defender Quote + Automated Quote Check].
        if USE_LLM_ATTACKER:
            atk_prompt = build_function_attacker_prompt(function_name, def_code_text, findings, "")
            res_atk = call(atk_prompt, self.model_attacker, TEMP_ATTACKER)
            if res_atk["llm_status"] != "success":
                return self._transport_failure(res_atk)
            attacker = parse_function_attacker_response(res_atk["response"])
        else:
            attacker = synthesize_sast_attacker(findings)

        def_prompt = build_function_defender_prompt(
            function_name, def_code_text, findings, attacker, "", include_rag=False
        )
        res_def = call(def_prompt, self.model_defender, TEMP_DEFENDER)
        if res_def["llm_status"] != "success":
            return self._transport_failure(res_def)
        defender = parse_defender_response(res_def["response"])

        evidence = check_sanitizer_evidence(code, defender.get("sanitization_evidence"))

        judge_prompt = build_function_judge_prompt(
            function_name, code_text, findings, attacker, defender, context, evidence=evidence
        )
        ballots = []
        vote_temp = TEMP_JUDGE_VOTE if votes > 1 else TEMP_JUDGE
        for i in range(votes):
            res = call(judge_prompt, self.model_judge, vote_temp, seed=1000 + i, max_tokens=VOTE_MAX_TOKENS)
            if res["llm_status"] != "success":
                return self._transport_failure(res)
            ballots.append(parse_vote_response(res["response"]))

        valid = [b for b in ballots if b["status"] == "success"]
        if valid:
            vote_share = sum(b["verdict"] == "VULNERABLE" for b in valid) / len(valid)
            p_vuln = sum(b["p_vulnerable"] for b in valid) / len(valid)
            prediction = int(vote_share >= 0.5)
            verdict_source = "judge_votes"
        else:
            # No readable vote: keep the static finding rather than dismiss it.
            vote_share, p_vuln, prediction, verdict_source = None, None, 1, "unparseable_votes"

        if mode == "override" and prediction == 0 and not evidence["grounded"]:
            prediction, verdict_source = 1, "evidence_rule"

        max_prompt = max(prompt_tokens) if prompt_tokens else None
        return {
            "llm_status": "success",
            "mode": "function_board",
            "prediction": prediction,
            "vote_share": None if vote_share is None else round(vote_share, 4),
            "p_vulnerable": None if p_vuln is None else round(p_vuln, 4),
            "votes": ballots,
            "valid_votes": len(valid),
            "attacker": attacker,
            "defender": defender,
            "evidence_check": evidence,
            "evidence_mode": mode,
            "verdict_source": verdict_source,
            "tokens": usage,
            "code_truncated": code_truncated,
            "max_prompt_tokens": max_prompt,
            # Ollama keeps only the last num_ctx tokens of an oversized prompt.
            "context_overflow": bool(max_prompt and max_prompt >= num_ctx - 8),
            "models": {
                "attacker": self.model_attacker,
                "defender": self.model_defender,
                "judge": self.model_judge,
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
