"""
Repo-disjoint dev/test split and a PrimeVul-style clean subset.

Anything tuned on the data (the calibrated board threshold, the fusion model)
is fitted on `dev` and reported on `test`. Whole repositories go to one side,
so a model can never score well on test by recognising a project it saw on
dev. The split is made per dataset, so both halves keep the CVEfixes/VUDENC
mix, and it is persisted so the run and every later report agree.

`clean` marks pairs whose fixing commit changed exactly one function in the
eligible files. Multi-function commits often touch helpers that were never
vulnerable, which is the main source of label noise in commit-mined datasets
(Croft et al., ICSE 2023; PrimeVul, Ding et al., ICSE 2025).
"""

import logging
import os
import random
from collections import Counter, defaultdict

from hackersec.evaluation.realworld import state

logger = logging.getLogger(__name__)

DEV_FRACTION = float(os.getenv("REALWORLD_DEV_FRACTION", "0.2"))
SEED = int(os.getenv("REALWORLD_SPLIT_SEED", "13"))
SPLITS_PATH = state.ROOT / "splits.json"


def _origin(pair_id: str) -> tuple[str, str, str]:
    """(dataset, repo slug, commit) from `dataset:slug:sha12:path:function`,
    so samples and result records always produce the same split."""
    dataset, slug, sha12 = pair_id.split(":", 3)[:3]
    return dataset, slug, sha12


def compute(samples: list[dict]) -> dict:
    """`samples` may be sample or result records; only `pair_id` is read."""
    pairs: dict[str, tuple] = {}
    for s in samples:
        pairs.setdefault(s["pair_id"], _origin(s["pair_id"]))
    per_commit = Counter(pairs.values())

    by_dataset: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for pid, (dataset, repo, _) in pairs.items():
        by_dataset[dataset][repo].append(pid)

    rng = random.Random(SEED)
    assignment, summary = {}, {}
    for dataset in sorted(by_dataset):
        repos = sorted(by_dataset[dataset])
        rng.shuffle(repos)
        total = sum(len(v) for v in by_dataset[dataset].values())
        target = round(total * DEV_FRACTION)
        dev_pairs, dev_repos = 0, 0
        for repo in repos:
            n = len(by_dataset[dataset][repo])
            # Repos that would overshoot the target go to test, so large
            # projects cannot make the dev side much bigger than intended.
            side = "dev" if dev_pairs + n <= target else "test"
            if side == "dev":
                dev_pairs += n
                dev_repos += 1
            for pid in by_dataset[dataset][repo]:
                assignment[pid] = {"split": side, "clean": per_commit[pairs[pid]] == 1}
        summary[dataset] = {
            "pairs": total,
            "dev_pairs": dev_pairs,
            "test_pairs": total - dev_pairs,
            "dev_repos": dev_repos,
            "test_repos": len(repos) - dev_repos,
            "clean_pairs": sum(1 for pid in pairs if pairs[pid][0] == dataset and per_commit[pairs[pid]] == 1),
        }

    return {"seed": SEED, "dev_fraction": DEV_FRACTION, "summary": summary, "pairs": assignment}


def load_or_create(samples: list[dict]) -> dict[str, dict]:
    """{pair_id: {"split", "clean"}}, reusing the saved split when it covers
    every pair and was made with the same seed and fraction."""
    saved = state.read_json(SPLITS_PATH)
    wanted = {s["pair_id"] for s in samples}
    if (
        saved
        and saved.get("seed") == SEED
        and saved.get("dev_fraction") == DEV_FRACTION
        and wanted <= set(saved.get("pairs", {}))
    ):
        return saved["pairs"]

    split = compute(samples)
    state.write_json_atomic(SPLITS_PATH, split)
    for dataset, s in split["summary"].items():
        logger.info(
            f"Split {dataset}: {s['dev_pairs']} dev / {s['test_pairs']} test pairs "
            f"({s['dev_repos']} / {s['test_repos']} repos), {s['clean_pairs']} clean"
        )
    return split["pairs"]


def summary() -> dict:
    return (state.read_json(SPLITS_PATH) or {}).get("summary", {})
