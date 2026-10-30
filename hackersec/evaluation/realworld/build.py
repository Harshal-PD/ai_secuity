"""
Phase 1 — everything that needs the internet.

  1. Vendor the Semgrep rule packs so scanning works offline.
  2. Cache the embedding model and seed the RAG knowledge base.
  3. Build the labeled function-pair dataset from fix commits.
  4. Find each sample's callers in the rest of its repository
     (repo_snapshot.py).

Commits are visited in a CWE-stratified round-robin order (seeded), so the
first N pairs are spread across weakness classes instead of being dominated by
whichever CWE is most common. Progress is saved after every commit.
"""

import logging
import os
import random
import time
from collections import Counter, defaultdict
from pathlib import Path

from hackersec.analysis.static import SEMGREP_CONFIGS as SEMGREP_PACKS
from hackersec.evaluation.realworld import gitfetch, state
from hackersec.evaluation.realworld.functions import extract_pairs, skip_reason
from hackersec.evaluation.realworld.gitfetch import GitFetcher, Unavailable, _slug
from hackersec.evaluation.realworld.net import with_network_retry
from hackersec.evaluation.realworld.sources import LOADERS, _download, _net_guard, local_file_pair

logger = logging.getLogger(__name__)

# A fix commit that edits many functions is usually a refactor bundled with
# the fix; labeling all of them vulnerable would flood the set with noise.
MAX_FUNCS_PER_COMMIT = int(os.getenv("REALWORLD_MAX_FUNCS_PER_COMMIT", "4"))
MAX_PATHS_PER_COMMIT = 15

DEFAULT_TARGETS = {
    "cvefixes": int(os.getenv("REALWORLD_TARGET_CVEFIXES", "500")),
    "vudenc": int(os.getenv("REALWORLD_TARGET_VUDENC", "250")),
    # ~800 test pairs after the 20% dev split: enough to detect a difference
    # of about 0.065 in TPR - FPR between two systems (80% power, alpha 0.05).
    "reposvul": int(os.getenv("REALWORLD_TARGET_REPOSVUL", "1000")),
}
SEED = int(os.getenv("REALWORLD_SEED", "42"))


# ── Offline assets ──────────────────────────────────────────────────────────

def prepare_offline_assets() -> None:
    state.update_status(phase="prepare", detail="semgrep rules + embedding model")

    for pack in SEMGREP_PACKS:
        dest = state.RULES_DIR / f"{pack.replace('/', '_')}.yml"
        _download(f"https://semgrep.dev/c/{pack}", dest)
    logger.info(f"Semgrep rules vendored to {state.RULES_DIR}")

    # Seeding downloads the embedding model into the Hugging Face cache, which
    # is what lets the evaluation phase load it with HF_HUB_OFFLINE=1.
    if not Path("data/kb.faiss").exists():
        logger.info("Seeding the RAG knowledge base (downloads the embedding model once)")
        from hackersec.ingestion import seed_kb

        _net_guard(seed_kb.main, "seed RAG knowledge base")


# ── Dataset build ───────────────────────────────────────────────────────────

def _stratified_order(commits: list[dict], seed: int) -> list[dict]:
    rng = random.Random(seed)
    buckets = defaultdict(list)
    for c in commits:
        buckets[c["cwe"]].append(c)
    for b in buckets.values():
        rng.shuffle(b)
    names = sorted(buckets)
    rng.shuffle(names)
    order = []
    while any(buckets[n] for n in names):
        for n in names:
            if buckets[n]:
                order.append(buckets[n].pop())
    return order


def _process_commit(c: dict, fetcher: GitFetcher) -> tuple[list, Counter]:
    drops = Counter()
    paths = []
    for p in c["paths"]:
        reason = skip_reason(p)
        if reason:
            drops[reason] += 1
        else:
            paths.append(p)
    if not paths:
        drops["no_eligible_files"] += 1
        return [], drops

    local = bool(c.get("local"))
    if not local:
        try:
            fetcher._ensure_commit(fetcher._repo(c["repo_url"]), c["sha"])
        except Unavailable as e:
            logger.info(f"  unavailable: {e}")
            drops["commit_unavailable"] += 1
            return [], drops

    collected = []
    for path in paths[:MAX_PATHS_PER_COMMIT]:
        try:
            if local:
                before, after = local_file_pair(c, path)
            else:
                before, after = fetcher.file_pair(c["repo_url"], c["sha"], path)
        except Unavailable as e:
            logger.info(f"  {path}: {e}")
            drops["file_unavailable"] += 1
            continue
        if before is None or after is None:
            drops["file_added_or_deleted"] += 1
            continue
        pairs, reason = extract_pairs(before, after)
        if reason:
            drops[reason] += 1
            continue
        collected.extend((path, pair, before, after) for pair in pairs)

    if len(collected) > MAX_FUNCS_PER_COMMIT:
        drops["tangled_commit"] += 1
        return [], drops
    return collected, drops


def _write(path: Path, text: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _emit(c: dict, collected: list) -> list[dict]:
    slug, sha12 = _slug(c["repo_url"]), c["sha"][:12]
    base_dir = state.FILES_DIR / c["dataset"] / slug / sha12
    samples = []
    for path, pair, before, after in collected:
        before_file = base_dir / "before" / path
        after_file = base_dir / "after" / path
        _write(before_file, before)
        _write(after_file, after)

        pair_id = f"{c['dataset']}:{slug}:{sha12}:{path}:{pair.qualname}"
        common = {
            "pair_id": pair_id,
            "dataset": c["dataset"],
            "repo_url": c["repo_url"],
            "sha": c["sha"],
            "path": path,
            "function": pair.qualname,
            "cwe": c["cwe"],
            "cwe_name": c["cwe_name"],
            "cve": c["cve"],
        }
        if "static_check" in c:
            # ReposVul's own Semgrep/RATS agreement for this file (1/0), so the
            # report can show how much SAST gains from that selection.
            common["dataset_static_check"] = c["static_check"].get(path)
        samples.append({
            **common,
            "sample_id": f"{pair_id}#before",
            "label": 1,
            "kind": "vulnerable",
            "file": before_file.as_posix(),
            "line_start": pair.before.start,
            "line_end": pair.before.end,
        })
        samples.append({
            **common,
            "sample_id": f"{pair_id}#after",
            "label": 0,
            "kind": "fixed",
            "file": after_file.as_posix(),
            "line_start": pair.after.start,
            "line_end": pair.after.end,
        })
    return samples


def _emit_companions(c: dict, collected: list, fetcher: GitFetcher) -> int:
    """Store the local files each target file imports next to it, in the same
    before/after tree, so Joern and CodeQL can resolve its imports. Targets
    already on disk are never overwritten. Returns the number of files written."""
    if c.get("local") or not collected or gitfetch.MAX_COMPANIONS <= 0:
        return 0
    base_dir = state.FILES_DIR / c["dataset"] / _slug(c["repo_url"]) / c["sha"][:12]
    written = 0
    for path in dict.fromkeys(p for p, _, _, _ in collected):
        before = next(b for p, _, b, _ in collected if p == path)
        after = next(a for p, _, _, a in collected if p == path)
        try:
            before_comp, after_comp = fetcher.companion_files(c["repo_url"], c["sha"], path, before, after)
        except Unavailable as e:
            logger.info(f"  {path}: companions unavailable: {e}")
            continue
        for side, files in (("before", before_comp), ("after", after_comp)):
            for rel, text in files.items():
                dest = base_dir / side / rel
                if not dest.exists():
                    _write(dest, text)
                    written += 1
    return written


def build_dataset(name: str, target: int, seed: int = SEED) -> dict:
    state.update_status(phase="build", dataset=name, detail="loading commit list")
    commits = LOADERS[name]()
    order = _stratified_order(commits, seed)

    progress = state.read_json(state.BUILD_PROGRESS_PATH, {}) or {}
    dp = progress.setdefault(name, {
        "done": [], "pairs": 0, "commits_used": 0,
        "per_cwe": {}, "drops": {}, "exhausted": False,
    })
    dp["target"] = target
    dp["commits_total"] = len(commits)
    done = set(dp["done"])
    fetcher = GitFetcher()
    started = time.time()

    for idx, c in enumerate(order, start=1):
        if dp["pairs"] >= target:
            break
        key = f"{c['repo_url']}@{c['sha']}"
        if key in done:
            continue

        logger.info(f"[{name}] {dp['pairs']}/{target} pairs | commit {idx}/{len(order)} {key} ({c['cwe']})")
        collected, drops = with_network_retry(lambda c=c: _process_commit(c, fetcher), key)

        # Room left under the target: never overshoot by a whole commit's worth.
        collected = collected[: max(0, target - dp["pairs"])]
        samples = _emit(c, collected)
        with_network_retry(lambda c=c, collected=collected: _emit_companions(c, collected, fetcher), f"{key} companions")
        for s in samples:
            state.append_jsonl(state.SAMPLES_PATH, s)

        dp["pairs"] += len(collected)
        if collected:
            dp["commits_used"] += 1
            dp["per_cwe"][c["cwe"]] = dp["per_cwe"].get(c["cwe"], 0) + len(collected)
        for reason, n in drops.items():
            dp["drops"][reason] = dp["drops"].get(reason, 0) + n
        dp["done"].append(key)
        done.add(key)
        state.write_json_atomic(state.BUILD_PROGRESS_PATH, progress)

        state.update_status(
            phase="build", dataset=name, detail="fetching fix commits",
            pairs=dp["pairs"], target=target,
            commits_tried=len(done), commits_total=len(commits),
            elapsed_min=round((time.time() - started) / 60, 1),
        )

    dp["exhausted"] = dp["pairs"] < target
    state.write_json_atomic(state.BUILD_PROGRESS_PATH, progress)
    if dp["exhausted"]:
        logger.warning(f"[{name}] only {dp['pairs']} pairs available (target {target})")
    logger.info(f"[{name}] build complete: {dp['pairs']} pairs from {dp['commits_used']} commits")
    return dp


def build_all(datasets: list[str], targets: dict | None = None) -> None:
    state.ensure_dirs()
    targets = {**DEFAULT_TARGETS, **(targets or {})}
    plan = {name: targets[name] for name in datasets}

    # After a reboot during an outage, a finished build must not wait for internet.
    marker = state.ROOT / "BUILD_COMPLETE.json"
    if (state.read_json(marker) or {}).get("plan") == plan:
        logger.info("Dataset already built; skipping the download phase")
    else:
        prepare_offline_assets()
        for name, target in plan.items():
            build_dataset(name, target)
        state.write_json_atomic(marker, {"plan": plan, "seed": SEED})

    # Its own checkpoint: samples already in the cache need no network.
    from hackersec.evaluation.realworld import repo_snapshot

    summary = repo_snapshot.prepare()
    state.update_status(phase="build_done", detail="dataset ready", repo_context=summary)
