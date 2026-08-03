"""Phase 0 self-check: Semgrep configs adapt to the target's language(s).

Tests config SELECTION (pure logic) — no semgrep binary required. The actual
scan run is verified separately on a box with semgrep installed.

Run: python test_static_lang.py
"""
import tempfile
from pathlib import Path

from hackersec.analysis.static import (
    select_semgrep_configs, SEMGREP_BASE_CONFIGS, SEMGREP_LANG_CONFIGS,
)


def _write(dirpath, name, content="x = 1\n"):
    p = Path(dirpath) / name
    p.write_text(content)
    return p


def test_python_file_selects_python_pack():
    with tempfile.TemporaryDirectory() as d:
        cfgs = select_semgrep_configs(_write(d, "a.py"))
        assert "p/python" in cfgs
        assert "p/c" not in cfgs and "p/java" not in cfgs
        assert all(b in cfgs for b in SEMGREP_BASE_CONFIGS)


def test_c_file_selects_c_not_python():
    with tempfile.TemporaryDirectory() as d:
        cfgs = select_semgrep_configs(_write(d, "a.c", "int main(){return 0;}"))
        assert "p/c" in cfgs
        assert "p/python" not in cfgs, "regression: C scan must not carry p/python"
        assert all(b in cfgs for b in SEMGREP_BASE_CONFIGS)


def test_mixed_dir_unions_language_packs():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "a.py"); _write(d, "b.c", "int x;"); _write(d, "c.go", "package main")
        cfgs = select_semgrep_configs(Path(d))
        for pack in ("p/python", "p/c", "p/golang"):
            assert pack in cfgs, f"missing {pack} for mixed repo"


def test_unknown_language_falls_back_to_base_only():
    with tempfile.TemporaryDirectory() as d:
        cfgs = select_semgrep_configs(_write(d, "notes.txt", "hello"))
        assert cfgs == SEMGREP_BASE_CONFIGS  # nothing language-specific added


def test_no_duplicate_configs():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "a.c", "int x;"); _write(d, "b.cpp", "int y;")  # both map to p/c
        cfgs = select_semgrep_configs(Path(d))
        assert len(cfgs) == len(set(cfgs)), "duplicate configs would waste a scan pass"


def test_lang_map_slugs_wellformed():
    for packs in SEMGREP_LANG_CONFIGS.values():
        for p in packs:
            assert p.startswith("p/"), f"bad registry slug: {p}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} checks passed.")
