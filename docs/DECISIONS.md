# Decision Log

Dated decisions, why, and what each rules out. Newest first.

## 2026-08-02 — Add dynamic exploit-verification; validate static pipeline first

**Context:** The static pipeline (Semgrep→CPG→RAG→LLM→fusion→patch) was fully wired
but (a) never honestly validated — `evaluation/runner.py` mocked the CPG/LLM and imported
a non-existent `run_sast`, so the eval could not even run — and (b) could only *reason*
about findings, never *prove* exploitability. 2025-26 research (CVE-Bench, AutoPenBench,
Automation-Exploit, SASTBench, RealVuln) shows SAST+LLM triage is crowded/solved-ish;
the live frontier is execution-confirmed vulnerability discovery.

**Decisions:**
1. **Extract `analyze_findings()` into `hackersec/analysis/pipeline.py`** as the single
   enrichment path used by BOTH `worker/tasks.py` and `evaluation/runner.py`.
   *Rules out:* the eval and production drifting apart; benchmark numbers that don't
   reflect the real pipeline.
2. **De-mock the eval** and add a real HuggingFace dataset loader (Big-Vul/DiverseVul/Juliet)
   + CLI flags (`--dataset/--samples/--limit/--verify`). Validate static *before* leaning
   on the new dynamic layer (user's call). *Rules out:* publishing unverified metrics.
3. **New `hackersec/analysis/verify/` stage** reproduces injection/RCE findings by running
   the real flagged function against a payload in a hardened Docker sandbox; verdict gated
   on a sentinel marker. `reproduced ∈ {True, False, None}`; `None` = not dynamically
   checkable (never a false negative). *Rules out:* a full autonomous pentest-agent pivot
   and browser-driving DAST for now — those are deferred Part C, reusing the same
   sandbox+oracle contract.
4. **Sandbox isolation is a hard security boundary:** `--network none`, non-root,
   read-only rootfs + tmpfs, `--cap-drop ALL`, no-new-privileges, resource caps, `--rm`.
   No host-side fallback for running payloads. *Rules out:* executing attacker payloads
   unsandboxed if Docker is missing (returns `None` instead).

**Deferred (Part C):** LLM-synthesized PoCs for multi-arg / non-function sinks; browser
agent clicking buttons/forms against a running DVWA/Juice-Shop/WebGoat.
