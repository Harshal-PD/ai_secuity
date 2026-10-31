"""
v11 board refinements: gate split (3 static tools gate, AST/Joern/RAG enrich),
Track 2 reaching Fusion, calibration floor, and the refined board prompts.
"""

import pytest

from hackersec.analysis.schema import Finding


def _finding(tool="semgrep", line=10, cwe="CWE-89", severity="high", rule="r", message="m"):
    return Finding(
        job_id="t", file_path="/x/a.py", line_start=line, line_end=line, rule_id=rule,
        tool=tool, severity=severity, message=message, cwe_ids=[cwe] if cwe else [],
    )


# ── Fix 3: Fusion keeps Track 2 candidates ──────────────────────────────────

class TestFusionTrack2:
    def _board(self):
        return {"defender_safety": 0.3, "evidence_grounded": False}

    def test_empty_findings_with_board_still_scored(self):
        from hackersec.evaluation.realworld import fusion

        record = {"findings": [], "board": self._board(), "p_vulnerable": 0.8, "llm_context_p": 0.9}
        x = fusion.features(record)
        assert x is not None
        assert x[0] == 0.8 and x[1] == 0.3 and x[2] == 0.0
        # No static leads: strength falls back to the screen's own score, never above 0.25.
        assert x[3] == pytest.approx(0.25 * 0.9)

    def test_fallback_without_screen_score_uses_neutral_prior(self):
        from hackersec.evaluation.realworld import fusion

        record = {"findings": [], "board": self._board(), "p_vulnerable": 0.5}
        assert fusion.features(record)[3] == pytest.approx(0.25 * 0.5)

    def test_no_board_means_no_features(self):
        from hackersec.evaluation.realworld import fusion

        assert fusion.features({"findings": [_finding().__dict__], "board": None}) is None
        assert fusion.features({"findings": []}) is None

    def test_findings_still_drive_static_strength(self):
        from hackersec.evaluation.realworld import fusion

        record = {
            "findings": [{"tool": "semgrep", "severity": "high"}],
            "board": self._board(), "p_vulnerable": 0.6, "semgrep_pred": 1, "bandit_pred": 1,
        }
        x = fusion.features(record)
        assert x[3] == pytest.approx(0.5 * 0.75 + 0.5 * 1.0)


# ── Fix 4: calibrated board threshold cannot drop below the Judge's 0.5 ─────

class TestBoardThresholdFloor:
    def test_floor_blocks_low_threshold(self):
        from hackersec.evaluation.realworld import fusion

        # Low scores happen to be positives on dev; an unconstrained argmax picks 0.2.
        scores = [0.2, 0.2, 0.2, 0.9, 0.9, 0.3, 0.3, 0.8]
        labels = [1, 1, 1, 0, 0, 1, 0, 1]
        assert fusion.best_threshold(scores, labels) <= 0.3
        floored = fusion.best_threshold(scores, labels, min_threshold=0.5)
        assert floored >= 0.5

    def test_floor_when_no_score_reaches_it(self):
        from hackersec.evaluation.realworld import fusion

        t = fusion.best_threshold([0.1, 0.2, 0.3], [1, 0, 1], min_threshold=0.5)
        assert t == 0.5

    def test_none_scores_still_none(self):
        from hackersec.evaluation.realworld import fusion

        assert fusion.best_threshold([None, None], [1, 0], min_threshold=0.5) is None

    def test_defaults_are_configured(self):
        from hackersec.evaluation.realworld import fusion

        assert fusion.BOARD_MIN_THRESHOLD == 0.5
        assert 0.0 < fusion.BOARD_MIN_PRECISION < 1.0


# ── Fix 1: three static tools gate; AST is enrichment ───────────────────────

class TestGateSplit:
    def _entry(self):
        def tool(name, findings):
            return {"status": "ok", "findings": [f.__dict__ | {"file_path": "/x/a.py"} for f in findings]}

        return {
            "semgrep": tool("semgrep", [_finding("semgrep", 10)]),
            "bandit": tool("bandit", []),
            "ast_sink": tool("ast_sink", [_finding("ast_sink", 12, "CWE-22", "low")]),
            "codeql": tool("codeql", [_finding("codeql", 14, "CWE-78")]),
        }

    def test_gate_tools_exclude_ast(self):
        from hackersec.evaluation.realworld import sast_cache

        assert sast_cache.GATE_TOOLS == ("semgrep", "bandit", "codeql")
        assert "ast_sink" not in sast_cache.GATE_TOOLS

    def test_split_findings(self, monkeypatch):
        from hackersec.evaluation.realworld import sast_cache

        monkeypatch.setattr(sast_cache, "_signature", lambda: "sig")
        monkeypatch.setattr(sast_cache, "_load", lambda f, s: self._entry())
        gate, ast_findings, status = sast_cache.split_findings_for("/x/a.py")
        assert {f.tool for f in gate} == {"semgrep", "codeql"}
        assert [f.tool for f in ast_findings] == ["ast_sink"]
        assert status["ast_sink"] == "ok"

    def test_ast_only_function_is_not_gated(self, monkeypatch):
        from hackersec.evaluation.realworld import sast_cache

        entry = self._entry()
        entry["semgrep"]["findings"] = []
        entry["codeql"]["findings"] = []
        monkeypatch.setattr(sast_cache, "_signature", lambda: "sig")
        monkeypatch.setattr(sast_cache, "_load", lambda f, s: entry)
        gate, ast_findings, _ = sast_cache.split_findings_for("/x/a.py")
        assert gate == [] and len(ast_findings) == 1

    def test_findings_for_unchanged(self, monkeypatch):
        from hackersec.evaluation.realworld import sast_cache

        monkeypatch.setattr(sast_cache, "_signature", lambda: "sig")
        monkeypatch.setattr(sast_cache, "_load", lambda f, s: self._entry())
        findings, _ = sast_cache.findings_for("/x/a.py")
        assert {f.tool for f in findings} == {"semgrep", "codeql", "ast_sink"}


# ── Fix 2: every Board candidate gets AST + Joern + RAG leads ───────────────

class TestActiveFindings:
    SAMPLE = {"sample_id": "s1", "function": "handler", "file": "/x/a.py", "line_start": 5, "line_end": 20}

    def test_sast_origin_merges_ast_into_gate_findings(self):
        from hackersec.evaluation.realworld import enrich_stage

        gate = [_finding("semgrep", 10, "CWE-89")]
        ast_f = [_finding("ast_sink", 10, "CWE-89", "low"), _finding("ast_sink", 12, "CWE-22", "low")]
        active = enrich_stage.active_findings("sast", gate, ast_f, self.SAMPLE, None)
        assert {f.line_start for f in active} == {10, 12}
        assert not any(f.tool == "llm_screen" for f in active)

    def test_screen_origin_uses_ast_when_present(self):
        from hackersec.evaluation.realworld import enrich_stage

        ast_f = [_finding("ast_sink", 12, "CWE-22", "low")]
        active = enrich_stage.active_findings("llm_screen", [], ast_f, self.SAMPLE, "path handling")
        assert [f.tool for f in active] == ["ast_sink"]

    def test_screen_origin_without_ast_gets_a_lead(self):
        from hackersec.evaluation.realworld import enrich_stage

        active = enrich_stage.active_findings("llm_screen", [], [], self.SAMPLE, "missing owner check")
        assert len(active) == 1
        lead = active[0]
        assert lead.tool == "llm_screen" and lead.severity == "low"
        assert lead.line_start == 5 and lead.line_end == 20
        assert "missing owner check" in lead.message
        assert lead.cwe_ids == []

    def test_no_origin_means_no_findings(self):
        from hackersec.evaluation.realworld import enrich_stage

        assert enrich_stage.active_findings(None, [], [_finding("ast_sink")], self.SAMPLE, None) == []

    def test_inputs_are_not_mutated(self):
        from hackersec.evaluation.realworld import enrich_stage

        gate = [_finding("semgrep", 10)]
        ast_f = [_finding("ast_sink", 10, "CWE-89", "low")]
        enrich_stage.active_findings("sast", gate, ast_f, self.SAMPLE, None)
        assert len(gate) == 1 and len(ast_f) == 1
        assert "also flagged" not in gate[0].message


# ── Track 2 indictment carries the Stage-2 leads ────────────────────────────

class TestScreenIndictment:
    def test_without_findings_is_the_old_indictment(self):
        from hackersec.analysis.llm.function_prompter import synthesize_screen_indictment

        ind = synthesize_screen_indictment("no authz check", 0.7)
        assert ind["finding_ids"] == [] and ind["source"] == "llm_screen"
        assert "no authz check" in ind["vulnerability"]
        assert ind["exploitability_confidence"] == 0.7

    def test_real_findings_are_included(self):
        from hackersec.analysis.llm.function_prompter import synthesize_screen_indictment

        ind = synthesize_screen_indictment("no authz check", 0.7, [_finding("ast_sink", 12, "CWE-22", "low")])
        assert ind["finding_ids"] == ["F1"]
        assert "no authz check" in ind["vulnerability"] and "ast_sink" in ind["vulnerability"]
        assert ind["source"] == "llm_screen"

    def test_synthetic_lead_is_not_echoed_as_a_finding(self):
        from hackersec.analysis.llm.function_prompter import synthesize_screen_indictment

        lead = _finding("llm_screen", 5, None, "low", "llm_screen-lead", "suspicion")
        ind = synthesize_screen_indictment("suspicion", 0.7, [lead])
        assert ind["finding_ids"] == []
        assert "llm_screen-lead" not in ind["vulnerability"]


# ── Fix 5: prompts ──────────────────────────────────────────────────────────

CODE = "   5| def f(uid):\n   6|     cur.execute('SELECT 1 WHERE id=%s', (uid,))"


class TestPrompts:
    def test_defender_names_safe_api_and_constant_cases(self):
        from hackersec.analysis.llm.function_prompter import build_function_defender_prompt

        p = build_function_defender_prompt("f", CODE, [_finding()])
        assert "SAFE API" in p and "NO TAINTED INPUT" in p
        assert "ONE single contiguous line" in p
        assert "ONLY when untrusted input" in p

    def test_defender_track2_also_refined(self):
        from hackersec.analysis.llm.function_prompter import build_function_defender_prompt

        p = build_function_defender_prompt("f", CODE, [], track="llm_screen")
        assert "ONE single contiguous line" in p

    def test_concession_does_not_anchor_the_judge(self):
        from hackersec.analysis.llm.function_prompter import _format_evidence_status

        msg = _format_evidence_status({"grounded": False, "reason": "conceded"})
        assert "NO QUOTE CITED" in msg
        assert "reachable by untrusted input" in msg
        assert "NONE —" not in msg

    def test_rebuttal_requires_taint_and_bypass(self):
        from hackersec.analysis.llm.function_prompter import build_prosecutor_rebuttal_prompt

        ind = {"finding_ids": ["F1"], "vulnerability": "v", "exploit_path": "p"}
        p = build_prosecutor_rebuttal_prompt("f", CODE, [_finding()], ind, {"sanitization_evidence": "x"})
        assert "ONLY if BOTH" in p and "MUST be \"NO\"" in p
        assert "REFERENCE DEFINITIONS" in p

    def test_rebuttal_track2_keeps_cite_fields(self):
        from hackersec.analysis.llm.function_prompter import build_prosecutor_rebuttal_prompt

        ind = {"finding_ids": [], "vulnerability": "v", "exploit_path": "p"}
        p = build_prosecutor_rebuttal_prompt("f", CODE, [], ind, {}, track="llm_screen")
        assert "input_parameter" in p and "state_line" in p

    def _judge(self, track):
        from hackersec.analysis.llm.function_prompter import build_function_judge_prompt

        return build_function_judge_prompt(
            "f", CODE, [_finding()] if track == "sast" else [], {"finding_ids": []}, {}, track=track,
        )

    def test_judge_three_element_test_and_safe_patterns(self):
        for track in ("sast", "llm_screen"):
            p = self._judge(track)
            assert "SOURCE" in p and "SINK" in p and "MISSING NEUTRALIZATION" in p
            assert "SAFE-PATTERN CHECK" in p and "parameterized" in p

    def test_judge_weighs_joern_outcomes(self):
        for track in ("sast", "llm_screen"):
            p = self._judge(track)
            assert "UNFILTERED FLOW" in p and "GUARDED/SANITIZED FLOW" in p
            assert "no direct flow found" in p

    def test_judge_confidence_tiers(self):
        p = self._judge("sast")
        assert "0.90" in p and "0.75" in p and "0.55" in p

    def test_judge_track2_mentions_stage2_evidence(self):
        p = self._judge("llm_screen")
        assert "Soft LLM Screen" in p and "Joern" in p

    def test_judge_rules_are_numbered_consecutively(self):
        import re

        p = self._judge("sast")
        rules = p.split("Rules:\n", 1)[1].split("{", 1)[0]
        numbers = [int(n) for n in re.findall(r"^(\d+)\. ", rules, flags=re.M)]
        assert numbers == list(range(1, len(numbers) + 1))


# -- Smoke: a Track 2 candidate runs the whole Board and reaches Fusion ------

class _FakeClient:
    num_ctx = 4096

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, model=None, temperature=0.0, seed=42, max_tokens=400):
        import json

        self.prompts.append(prompt)
        if "You are the DEFENDER" in prompt:
            body = {"sanitization_evidence": "none found", "mitigating_controls": "none",
                    "rebuttal": "concede", "safety_confidence": 0.2}
        elif "You are the PROSECUTOR" in prompt:
            body = {"raw_path": "YES", "patch_verified": "NO", "input_parameter": "uid",
                    "state_line": "cur.execute('SELECT 1 WHERE id=%s', (uid,))", "rebuttal": "reaches"}
        else:
            body = {"verdict": "VULNERABLE", "confidence": 0.8, "finding_ids": [], "reasoning": "r"}
        return {"llm_status": "success", "response": json.dumps(body), "prompt_tokens": 10, "completion_tokens": 5}


class TestTrack2Smoke:
    SAMPLE = {"sample_id": "s1", "function": "f", "file": "/x/a.py", "line_start": 5, "line_end": 6}

    def test_screen_candidate_runs_board_and_is_scored_by_fusion(self):
        from hackersec.analysis.llm.board import AdversarialBoard
        from hackersec.evaluation.realworld import enrich_stage, fusion

        active = enrich_stage.active_findings("llm_screen", [], [], self.SAMPLE, "no ownership check")
        client = _FakeClient()
        res = AdversarialBoard(client=client, mode="board").deliberate_function(
            "f", "def f(uid):\n    cur.execute('SELECT 1 WHERE id=%s', (uid,))", 5, active,
            gate_origin="llm_screen", suspicion="no ownership check", screen_p=0.7,
        )
        assert res["llm_status"] == "success" and res["gate_origin"] == "llm_screen"
        assert res["tokens"]["calls"] == 3
        judge_prompt = client.prompts[-1]
        assert "Soft LLM Screen" in judge_prompt and "HS-LLM-SCREEN" in judge_prompt
        record = {
            "findings": [{"tool": f.tool, "severity": f.severity} for f in active],
            "board": {"defender_safety": 0.2, "evidence_grounded": False},
            "p_vulnerable": res["p_vulnerable"], "llm_context_p": 0.7,
        }
        assert fusion.features(record) is not None


class TestCalibrationIntegration:
    def _rows(self):
        import random

        rnd = random.Random(3)
        rows = []
        for i in range(60):
            label = i % 2
            screen_only = i % 5 == 0
            p = round(min(0.95, max(0.05, (0.55 if label else 0.45) + rnd.uniform(-0.35, 0.35))), 2)
            rows.append({
                "split": "dev", "label": label, "p_score": p,
                "findings": [] if screen_only else [{"tool": "semgrep", "severity": "high"}],
                "board": {"defender_safety": 1 - p, "evidence_grounded": False},
                "p_vulnerable": p, "llm_context_p": 0.6, "semgrep_pred": 0 if screen_only else 1,
            })
        return rows

    def test_calibrate_respects_floor_and_trains_on_screen_rows(self):
        from hackersec.evaluation.realworld import report

        rows = self._rows()
        out = report._calibrate(rows)
        assert out["board_threshold"] >= 0.5
        assert out["fusion_model"]["n_train"] == 60  # screen-only rows are included
        assert all("fusion_pred" in r for r in rows)
