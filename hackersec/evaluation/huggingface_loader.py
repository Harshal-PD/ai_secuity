"""Load real labeled vulnerability datasets from HuggingFace into local files.

Writes one source file per sample to `data/eval_set/<dataset>/` and a
`metadata.json` mapping absolute path → {label, cwe}, matching the shape
`evaluation.dataset.load_dataset` already expects. This lets the eval harness
run over real research benchmarks instead of the 3 hand-written mock files.
"""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Each config maps a benchmark to the fields we need. `label`: 1=vulnerable.
# ponytail: add a row here to support another dataset — no code change needed.
DATASET_CONFIGS = {
    "bigvul": {
        "hf_name": "bstee615/bigvul",
        "split": "train",
        "code_field": "func_before",
        "label_field": "vul",
        "cwe_field": "CWE ID",
        "ext": ".c",
    },
    "diversevul": {
        "hf_name": "bstee615/diversevul",
        "split": "train",
        "code_field": "func",
        "label_field": "target",
        "cwe_field": "cwe",
        "ext": ".c",
    },
    "juliet": {
        "hf_name": "google/code_x_glue_cc_defect_detection",
        "split": "train",
        "code_field": "func",
        "label_field": "target",
        "cwe_field": None,
        "ext": ".c",
    },
}


def _norm_cwe(raw) -> str:
    if raw is None:
        return "UNKNOWN"
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
        if raw is None:
            return "UNKNOWN"
    s = str(raw).strip()
    if not s or s.lower() in ("none", "nan"):
        return "UNKNOWN"
    return s if s.startswith("CWE-") else f"CWE-{s}"


def load_hf_dataset(dataset: str = "bigvul", samples: int = 100,
                    out_dir: str = "data/eval_set") -> str:
    """Download `samples` rows, write source files, return metadata.json path."""
    if dataset not in DATASET_CONFIGS:
        raise ValueError(f"Unknown dataset '{dataset}'. Choose from {list(DATASET_CONFIGS)}")

    try:
        from datasets import load_dataset as hf_load
    except ImportError as e:
        raise ImportError(
            "The 'datasets' package is required for HF datasets. "
            "Install it: pip install datasets"
        ) from e

    cfg = DATASET_CONFIGS[dataset]
    base = Path(out_dir) / dataset
    base.mkdir(parents=True, exist_ok=True)

    logger.info(f"[eval] Loading {cfg['hf_name']} (streaming, {samples} samples, stratified)")
    ds = hf_load(cfg["hf_name"], split=cfg["split"], streaming=True)

    # Stratify: fill a per-label quota so the set has real negatives (FPR needs
    # them). Datasets are often label-sorted, so a raw first-N head can be one class.
    per_label = max(1, samples // 2)
    quota = {0: per_label, 1: samples - per_label}
    seen = {0: 0, 1: 0}
    metadata = {}
    written = 0
    scanned = 0
    scan_cap = samples * 200  # bound the stream walk if a class is rare

    for row in ds:
        scanned += 1
        if written >= samples or scanned > scan_cap:
            break
        code = row.get(cfg["code_field"])
        if not code or not str(code).strip():
            continue

        label = int(bool(row.get(cfg["label_field"], 0)))
        if seen[label] >= quota[label]:
            continue  # this class is full
        seen[label] += 1

        cwe = _norm_cwe(row.get(cfg["cwe_field"]) if cfg["cwe_field"] else None)
        path = base / f"sample_{written}{cfg['ext']}"
        path.write_text(str(code), encoding="utf-8", errors="replace")
        metadata[str(path.resolve())] = {"label": label, "cwe": cwe}
        written += 1

    logger.info(f"[eval] Stratified counts: vulnerable={seen[1]} safe={seen[0]} (scanned {scanned})")
    meta_path = base / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2))
    logger.info(f"[eval] Wrote {written} samples to {base}")
    return str(meta_path)
