"""triage_all must collect crashes from EVERY AFL instance (main + slave_*),
not just findings/main/crashes (audit Batch 1)."""
import os
from pathlib import Path

import pytest

from nemesis.config import load_config
from nemesis.fuzzing import CrashTriager

# AFL crash files are named `id:NNNNNN,sig:...` — the colon is invalid in a
# Windows filename, so this test only runs on the POSIX hosts AFL targets.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="AFL `id:` filenames need POSIX fs")


def _make_crash(dirpath: Path, name: str):
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / name).write_bytes(b"crashinput")


def test_triage_collects_main_and_secondary_crashes(tmp_path, monkeypatch):
    cfg = load_config()
    cfg.engine.work_dir = tmp_path
    triager = CrashTriager(cfg)

    findings = tmp_path / "findings"
    triager.crashes_dir = findings / "main" / "crashes"

    # main + two secondaries each with one unique crash, plus an autoresume archive
    _make_crash(findings / "main" / "crashes", "id:000000,sig:06")
    _make_crash(findings / "main" / "crashes.1700000000", "id:000001,sig:06")
    _make_crash(findings / "slave_1" / "crashes", "id:000000,sig:11")
    _make_crash(findings / "slave_2" / "crashes", "id:000000,sig:06")

    seen: list[str] = []

    def fake_analyze(self, crash_file):
        seen.append(Path(crash_file).parent.parent.name + "/" + Path(crash_file).name)
        return None  # skip real ASAN analysis

    monkeypatch.setattr(CrashTriager, "_analyze_crash", fake_analyze, raising=True)
    monkeypatch.setattr(CrashTriager, "_run_afl_cmin",
                        lambda self, d: d, raising=True)

    triager.triage_all()

    # one crash from each instance + the archive must all be visited
    instances_seen = {s.split("/")[0] for s in seen}
    assert "main" in instances_seen
    assert "slave_1" in instances_seen, "secondary crashes must be triaged"
    assert "slave_2" in instances_seen
    assert len(seen) == 4, f"expected 4 crash files, got {seen}"
