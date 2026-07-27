"""Provenance invariant: a completed arm persists an artifact inventory.

The benchmark's arms reset the workspace between runs, and a control arm carries no
genuine-target oracle of its own. If what a build produced is not recorded while it
still exists, artifact identity can only be recovered by rebuilding afterwards —
which is exactly what the H2a v2 paired run had to do (H2a_V2_RESULTS.md §9).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parents[1] / "benchmarks" / "onboard_suite"
if str(SUITE) not in sys.path:
    sys.path.insert(0, str(SUITE))

run_suite = pytest.importorskip("run_suite")


def _repo(tmp_path, monkeypatch, build_dir: str | None):
    """A RepoRun whose config points at `build_dir` (None = no build_dir key)."""
    root = tmp_path / "nemesis"
    (root / "config" / "targets").mkdir(parents=True)
    if build_dir is not None:
        (root / "config" / "targets" / "proj.yaml").write_text(
            f"target:\n  name: proj\n  build_dir: {build_dir}\n", encoding="utf-8")
    monkeypatch.setattr(run_suite, "NEMESIS_ROOT", root)
    return run_suite.RepoRun({"full_name": "owner/proj", "commit": "0" * 40},
                             tmp_path / "work")


def test_no_config_yields_empty_inventory(tmp_path, monkeypatch):
    inv = _repo(tmp_path, monkeypatch, None)._artifact_inventory()
    assert inv["exists"] is False
    assert inv["artifacts"] == []
    assert inv["artifact_count"] == 0


def test_missing_build_dir_is_recorded_not_silently_empty(tmp_path, monkeypatch):
    # "the directory was not there" and "there was nothing to record" are different
    # facts, and only one of them is a finding
    missing = tmp_path / "nowhere" / "build_fuzz"
    inv = _repo(tmp_path, monkeypatch, str(missing))._artifact_inventory()
    assert inv["build_dir"] == str(missing)
    assert inv["exists"] is False


def test_artifacts_are_recorded_with_sizes_largest_first(tmp_path, monkeypatch):
    bd = tmp_path / "work" / "build_fuzz"
    (bd / "dep" / "glfw" / "src").mkdir(parents=True)
    (bd / "libastera.a").write_bytes(b"\x00" * 300)
    (bd / "dep" / "glfw" / "src" / "libglfw3.a").write_bytes(b"\x00" * 100)
    (bd / "notalib.txt").write_text("ignored")

    inv = _repo(tmp_path, monkeypatch, str(bd))._artifact_inventory()

    assert inv["exists"] is True
    assert inv["artifact_count"] == 2
    assert inv["truncated"] is False
    assert [a["path"] for a in inv["artifacts"]] == [
        "libastera.a", str(Path("dep/glfw/src/libglfw3.a")),
    ]
    assert inv["artifacts"][0]["bytes"] == 300
    # the vendored artifact is recorded, not filtered: the inventory reports what was
    # produced, and deciding what it means is the oracle's job, not the recorder's
    assert "glfw" in inv["artifacts"][1]["path"]


def test_environment_variables_in_build_dir_are_expanded(tmp_path, monkeypatch):
    bd = tmp_path / "expanded" / "build_fuzz"
    bd.mkdir(parents=True)
    (bd / "libp.a").write_bytes(b"\x00" * 10)
    monkeypatch.setenv("TESTROOT", str(tmp_path / "expanded"))
    inv = _repo(tmp_path, monkeypatch, "$TESTROOT/build_fuzz")._artifact_inventory()
    assert inv["exists"] is True
    assert inv["artifact_count"] == 1


def test_large_trees_are_capped_and_flagged(tmp_path, monkeypatch):
    bd = tmp_path / "work" / "build_fuzz"
    bd.mkdir(parents=True)
    for i in range(105):
        (bd / f"lib{i:03d}.a").write_bytes(b"\x00" * (i + 1))
    inv = _repo(tmp_path, monkeypatch, str(bd))._artifact_inventory()
    assert inv["artifact_count"] == 105          # the true count is never lost
    assert len(inv["artifacts"]) == 100
    assert inv["truncated"] is True
    assert inv["artifacts"][0]["path"] == "lib104.a"


def test_inventory_is_attached_to_the_repository_record(tmp_path, monkeypatch):
    # the invariant is about the record, not about a helper existing
    bd = tmp_path / "work" / "build_fuzz"
    bd.mkdir(parents=True)
    (bd / "libp.a").write_bytes(b"\x00" * 5)
    repo = _repo(tmp_path, monkeypatch, str(bd))
    monkeypatch.setattr(repo, "t0_acquire", lambda: False)   # stop after tier 0
    rec = repo.run()
    assert rec["artifact_inventory"]["artifact_count"] == 1
