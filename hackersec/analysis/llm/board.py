import ast
import logging
import os
import re
import textwrap
import threading
from concurrent.futures import ThreadPoolExecutor

from hackersec.analysis.dedup import has_tool
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
    parse_prosecutor_rebuttal,
    parse_vote_response,
)
from hackersec.analysis.llm.context import context_code
from hackersec.analysis.llm.evidence import check_sanitizer_evidence
from hackersec.analysis.llm.function_prompter import (
    DEFENDER_CODE_CHARS,
    MIN_CODE_CHARS,
    TRACK_LLM_SCREEN,
    build_function_attacker_prompt,
    build_function_defender_prompt,
    build_function_judge_prompt,
    build_prosecutor_rebuttal_prompt,
    code_budget,
    fit_function_code,
    resolve_board_track,
    synthesize_sast_attacker,
    synthesize_screen_indictment,
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
# Prior-aware adjudication. SAST-flagged candidates are ~56% vulnerable, SAST-missed
# ones far fewer, so the two tracks do not share one conviction rule.
#   Track 1: a CodeQL finding the Prosecutor rests on convicts without the Judge's vote.
#   Track 2: a conviction stands only if the Prosecutor cites a real parameter and a real line.
CODEQL_AUTOCONVICT = os.getenv("LLM_CODEQL_AUTOCONVICT", "1") not in ("0", "false", "False")
TRACK2_STRICT = os.getenv("LLM_TRACK2_STRICT", "1") not in ("0", "false", "False")
# Defender -> grounded Prosecutor rebuttal -> Judge. "0" restores the earlier
# Attacker-first board (Track 1: Defender -> Judge; Track 2: Attacker -> Defender -> Judge).
PROSECUTOR_REBUTTAL = os.getenv("LLM_PROSECUTOR_REBUTTAL", "1") not in ("0", "false", "False")
TEMP_REBUTTAL = float(os.getenv("LLM_TEMP_REBUTTAL", "0.2"))


def _function_params(code: str) -> set[str]:
    """Parameter names from the function's signature (self/cls excluded)."""
    try:
        tree = ast.parse(textwrap.dedent(code))
        fn = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
        a = fn.args
        names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
        names += [x.arg for x in (a.vararg, a.kwarg) if x]
    except (SyntaxError, StopIteration, ValueError):
        header = code.split(":\n", 1)[0]
        names = re.findall(r"[A-Za-z_]\w*", header.split("(", 1)[-1])
    return {n for n in names if n not in ("self", "cls")}


def _track2_cited(attacker: dict, code: str) -> bool:
    """The Prosecutor named a real input parameter and quoted a real body line."""
    param = (attacker.get("input_parameter") or "").strip()
    line = (attacker.get("state_line") or "").strip()
    if not param or not line or param not in _function_params(code):
        return False
    body = "\n".join(code.splitlines()[1:])  # the signature line is not a state change
    return check_sanitizer_evidence(body, line, 0.9)["grounded"]


def _codeql_agrees(findings: list[Finding], attacker: dict, llm_attacker: bool) -> bool:
    """A CodeQL finding backs the Prosecutor. The default Prosecutor is the SAST
    packet itself, so it agrees by construction; an Attacker LLM must name it."""
    idx = [f"F{i}" for i, f in enumerate(findings, start=1) if has_tool(f, "codeql")]
    if not idx:
        return False
    return (not llm_attacker) or bool(set(idx) & set(attacker.get("finding_ids") or []))
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
        gate_origin: str | None = None,
        suspicion: str | None = None,
        screen_p: float | None = None,
    ) -> dict:
        """
        One debate over a whole function and all of its candidate findings.

        Attacker and Defender argue once; the Judge then votes `votes` times,
        at TEMP_JUDGE_VOTE with different seeds when there is more than one
        vote. `p_vulnerable` is the mean of the votes' P(vulnerable), and
        `prediction` is the majority vote
        (after the evidence rule, when that is set to override). `context`
        (callers and callees from this file and the repository) is shown to
        every seat and takes its room from the code budget; a Defender quote
        found there instead of in the function counts as grounded, with
        location "context".

        `gate_origin` selects the Board track: "sast" (Track 1 — sink & taint)
        or "llm_screen" (Track 2 — semantic invariant / missing guard). When
        omitted, non-empty `findings` map to Track 1 and empty to Track 2.
        """
        votes = votes or JUDGE_VOTES
        mode = (evidence_mode or EVIDENCE_MODE).lower()
        if mode not in ("signal", "override", "off"):
            raise ValueError(f"evidence_mode must be signal, override or off, got {mode!r}")
        track = resolve_board_track(gate_origin, findings)

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

        # Rebuttal mode: Static Indictment (0 tokens) -> Defender -> grounded
        # Prosecutor rebuttal -> Judge. Track 1's indictment is the SAST + Joern
        # packet; Track 2's is the Soft LLM Screen's 1-line suspicion trace.
        # Legacy mode: Track 1 uses the SAST packet, Track 2 an Attacker LLM.
        use_attacker_llm = not PROSECUTOR_REBUTTAL and (USE_LLM_ATTACKER or track == TRACK_LLM_SCREEN)
        if PROSECUTOR_REBUTTAL and track == TRACK_LLM_SCREEN:
            attacker = synthesize_screen_indictment(suspicion, screen_p, findings)
        elif use_attacker_llm:
            atk_prompt = build_function_attacker_prompt(
                function_name, def_code_text, findings, "", track=track
            )
            res_atk = call(atk_prompt, self.model_attacker, TEMP_ATTACKER)
            if res_atk["llm_status"] != "success":
                return self._transport_failure(res_atk)
            attacker = parse_function_attacker_response(res_atk["response"])
        else:
            attacker = synthesize_sast_attacker(findings)

        def_prompt = build_function_defender_prompt(
            function_name, def_code_text, findings, attacker if PROSECUTOR_REBUTTAL else None, context,
            include_rag=False, track=track,
        )
        res_def = call(def_prompt, self.model_defender, TEMP_DEFENDER)
        if res_def["llm_status"] != "success":
            return self._transport_failure(res_def)
        defender = parse_defender_response(res_def["response"])

        evidence = check_sanitizer_evidence(code, defender.get("sanitization_evidence"))
        if evidence["reason"] == "no_span_match" and context:
            # A caller's validation is a real defence too, but only if it is
            # verbatim in the context the Defender was shown.
            in_context = check_sanitizer_evidence(context_code(context), defender.get("sanitization_evidence"))
            if in_context["grounded"]:
                evidence = {**in_context, "location": "context"}

        rebuttal = None
        if PROSECUTOR_REBUTTAL:
            reb_prompt = build_prosecutor_rebuttal_prompt(
                function_name, def_code_text, findings, attacker, defender, context,
                evidence=evidence, track=track,
            )
            res_reb = call(reb_prompt, self.model_attacker, TEMP_REBUTTAL)
            if res_reb["llm_status"] != "success":
                return self._transport_failure(res_reb)
            rebuttal = parse_prosecutor_rebuttal(res_reb["response"])
            if track == TRACK_LLM_SCREEN:
                # Track 2's strict citation rule reads the cites from the rebuttal.
                attacker = {**attacker, "input_parameter": rebuttal["input_parameter"],
                            "state_line": rebuttal["state_line"]}

        judge_prompt = build_function_judge_prompt(
            function_name, code_text, findings, attacker, defender, context,
            evidence=evidence, track=track, rebuttal=rebuttal,
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

        if track == TRACK_LLM_SCREEN:
            if TRACK2_STRICT and prediction == 1 and not _track2_cited(attacker, code):
                prediction, verdict_source = 0, "track2_uncited"
        elif (
            CODEQL_AUTOCONVICT and prediction == 0
            and not (rebuttal and rebuttal["patch_verified"])  # the Prosecutor itself conceded the patch
            and _codeql_agrees(findings, attacker, use_attacker_llm)
        ):
            prediction, verdict_source = 1, "codeql_agrees"

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
            "prosecutor_rebuttal": rebuttal,
            "evidence_check": evidence,
            "evidence_mode": mode,
            "gate_origin": track,
            "board_track": track,
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
