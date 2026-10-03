"""
Citation-required neutralization.

The Defender may only win the debate if the sanitizer it quotes actually exists
in the analyzed snippet. This turns "the input looks validated" into a
mechanically checkable claim: the quoted evidence must share a contiguous
character span with the code under review.

The check is deterministic and model-independent, so a reviewer can reproduce
every verdict override from the stored JSON without re-running any LLM.
"""

import re
from difflib import SequenceMatcher

# Minimum contiguous span (whitespace-stripped characters) shared between the
# Defender's quote and the snippet. 8 chars is long enough to cover a real
# sanitizing expression (`int(port)`, `shell=False`, `literal_eval`) while
# rejecting incidental overlap like `data` or `(x)`.
MIN_SPAN = 8

# Explicit concessions. The Defender is instructed to emit one of these when it
# cannot find a sanitizer, so they are treated as "not grounded" without
# attempting a span match.
_CONCESSIONS = {
    "none",
    "none found",
    "none stated",
    "not found",
    "no evidence",
    "no sanitization",
    "no sanitizer",
    "no sanitization found",
    "nothing",
    "n/a",
    "na",
    "unknown",
    "unparseable",
}

_STRIP_CHARS = re.compile(r"[\s`'\"]+")


def _normalize(text: str) -> str:
    """Lowercase and drop whitespace/quotes so spacing and quote style do not
    decide whether a real sanitizer counts as quoted."""
    return _STRIP_CHARS.sub("", text.lower())


def check_sanitizer_evidence(snippet: str | None, evidence: str | None, min_coverage: float = 0.0) -> dict:
    """
    Verify the Defender's quoted sanitizer against the analyzed snippet.

    `min_coverage` is the share of the (normalized) quote that must be one
    contiguous span of the snippet. 0 accepts prose that contains a real code
    span; a quote that is supposed to be copied code should use a high value,
    or `x.startswith(ROOT)` would be grounded by any `.startswith(`.

    Returns a record that is stored verbatim on the finding so the override is
    auditable:
        grounded       -- whether the quote was located in the code
        reason         -- conceded | span_match | no_span_match | no_snippet | empty
        matched_span   -- the longest shared span, for the paper's examples
        span_length    -- length of that span
        required_span  -- threshold applied to this particular quote
    """
    record = {
        "grounded": False,
        "reason": "empty",
        "matched_span": "",
        "span_length": 0,
        "required_span": 0,
    }

    if not evidence or not evidence.strip():
        return record

    if evidence.strip().lower().rstrip(".") in _CONCESSIONS:
        record["reason"] = "conceded"
        return record

    if not snippet or not snippet.strip():
        record["reason"] = "no_snippet"
        return record

    norm_evidence = _normalize(evidence)
    norm_snippet = _normalize(snippet)

    if not norm_evidence or not norm_snippet:
        record["reason"] = "empty"
        return record

    # Short quotes must match almost entirely; long prose quotes only need to
    # contain one real code span.
    required = max(min(MIN_SPAN, len(norm_evidence)), int(min_coverage * len(norm_evidence) + 0.999))
    record["required_span"] = required

    match = SequenceMatcher(None, norm_evidence, norm_snippet).find_longest_match(
        0, len(norm_evidence), 0, len(norm_snippet)
    )
    record["span_length"] = match.size
    record["matched_span"] = norm_evidence[match.a:match.a + match.size]

    if match.size >= required:
        record["grounded"] = True
        record["reason"] = "span_match"
    else:
        record["reason"] = "no_span_match"

    return record
