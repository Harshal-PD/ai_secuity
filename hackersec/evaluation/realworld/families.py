"""
CWE families for the per-family breakdown.

Semgrep and Bandit match code patterns, so they can only report weakness
classes that have a recognisable sink (a shell call, a SQL string, pickle,
a weak hash). Access-control, resource-exhaustion and information-exposure
bugs are about what the code fails to do and have no such sink; the first
run flagged almost none of them (e.g. CWE-863 0/26, CWE-400 0/24). Reporting
the two groups separately shows where the pipeline is limited by static
analysis rather than by the board.
"""

import re

FAMILIES: dict[str, set[int]] = {
    "injection": {74, 75, 77, 78, 79, 80, 88, 89, 90, 91, 93, 94, 95, 96, 97, 113, 116, 117, 643, 644, 917, 943, 1336},
    "path_traversal": {22, 23, 24, 25, 26, 27, 28, 29, 30, 32, 35, 36, 37, 38, 39, 40, 59, 61, 73, 434},
    "deserialization": {502, 915},
    "crypto_secrets": {259, 261, 295, 296, 297, 310, 311, 312, 319, 321, 322, 323, 326, 327, 328, 329, 330, 331, 335,
                       338, 347, 522, 759, 760, 798, 916},
    "xml": {611, 776, 827},
    "ssrf_redirect": {601, 918},
    "access_control": {250, 264, 266, 269, 276, 281, 282, 284, 285, 287, 288, 290, 294, 302, 305, 306, 307, 345, 346,
                       352, 384, 425, 441, 613, 639, 640, 648, 732, 862, 863, 1021, 1220},
    "resource_dos": {399, 400, 401, 404, 405, 407, 409, 674, 690, 770, 772, 834, 835, 1050, 1333},
    "info_exposure": {200, 201, 203, 208, 209, 212, 359, 497, 532, 538, 548, 552, 668, 669},
    "input_validation": {20, 129, 166, 172, 176, 179, 180, 697, 703, 704, 707, 754, 755, 838, 843, 1284, 1287},
    "memory_numeric": {119, 120, 125, 131, 190, 191, 369, 476, 682, 787, 824},
}

SAST_REACHABLE = {"injection", "path_traversal", "deserialization", "crypto_secrets", "xml", "ssrf_redirect"}

_BY_CWE = {}
for _family, _ids in FAMILIES.items():
    for _id in _ids:
        _BY_CWE.setdefault(_id, _family)

_CWE_NUM = re.compile(r"CWE-(\d+)")


def family(cwe: str | None) -> str:
    m = _CWE_NUM.search(cwe or "")
    if not m:
        return "unknown"
    return _BY_CWE.get(int(m.group(1)), "other")


def group(cwe: str | None) -> str:
    """"sast_reachable" or "logic_semantic" (unknown CWEs count as the latter)."""
    return "sast_reachable" if family(cwe) in SAST_REACHABLE else "logic_semantic"
