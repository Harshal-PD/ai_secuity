# Phase 6 Research: Patch Generation & Validation

## RESEARCH COMPLETE

**Phase:** 6 — Patch Generation
**Goal:** Hook into `true_positive` ML predictions. Query DeepSeek to output patched implementations. Construct `diff` wrappers ensuring valid execution and string comparisons. Launch `semgrep` recursively validating the patches eliminate the offending rule locally.

---

## 1. DeepSeek Patch Generator

Ollama provides robust text completion arrays. Using the existing `hackersec.analysis.llm.client`, we can execute a specific prompt generator `build_patch_prompt()`:
- Bound the vulnerable snippet alongside the extracted LLM explanation / fix.
- Demand pure text without conversational scaffolding or markdown wrappers, directly outputting substitution elements masking the exact line limits.

## 2. Diff Computation (Python Difflib)

Python's built-in `difflib.unified_diff` safely represents additions `+` and deletions `-` without requiring external diff implementations or binary requirements natively.
These patches are stored inside SQLite under `finding.patch` schema values mapping the literal strings.

## 3. Semgrep Re-validation Loop

To validate a patched string, we securely write the snippet to a `.tmp` file containing the precise patched wrapper simulating local states. 
- Invoke `semgrep --config {finding.rule_id} .tmp`
- Assert finding arrays equal `0` mapped against rule strings. 
- Assign validation string mapping `fixed` or `still_vulnerable`.

## 4. Concurrency Bounds

`semgrep` requires IO disk constraints. Using `tempfile.NamedTemporaryFile()` generates concurrent-safe boundaries mitigating Celery worker race conditions blocking the same rule outputs locally.

## Validation Strategy
1. **End-to-End Simulation Testing:** Inject mocked `true_positive` instances generating patches and mock a patched snippet executing Semgrep simulating an eliminated dependency output array.
2. **Regex Filter Protections:** Confirm prompt constraints preventing markdown wrapper anomalies.
