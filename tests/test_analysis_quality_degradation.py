"""
Tests that a missing analysis binary is reported, not silently absorbed.

`analysis_binary()` returning None means per-input coverage cannot be measured.
Callers used to fall back to the AFL fuzzing binary, which in persistent mode
receives nothing offline and reports one identical map for every input — so
afl-cmin kept zero seeds and logged an ordinary-looking empty result. On libnmea
that stayed invisible for an entire campaign, and nothing downstream could tell
that corpus minimisation had not happened.

The invariant: when the probe is unavailable, the run must say so in a form a
report or benchmark can read, and steps that depend on it must be skipped rather
than executed against a binary that cannot answer.
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.fuzzing import AFLOrchestrator


@pytest.fixture
def orch(tmp_path: Path) -> AFLOrchestrator:
    cfg = NemesisConfig()
    cfg.engine.work_dir = str(tmp_path / "ws")
    cfg.target.build_dir = str(tmp_path / "build_fuzz")
    cfg.target.library_name = "libnmea.a"
    return AFLOrchestrator(cfg)


def test_quality_is_ok_before_any_failure(orch: AFLOrchestrator):
    assert orch.analysis_quality == {
        "analysis_quality": "ok",
        "probe_available": True,
        "degraded_reason": None,
    }


def test_missing_harness_source_marks_degraded(orch: AFLOrchestrator):
    """build_dir has no fuzz_nemesis.c — the probe cannot even be attempted."""
    assert orch.analysis_binary() is None
    q = orch.analysis_quality
    assert q["analysis_quality"] == "degraded"
    assert q["probe_available"] is False
    assert q["degraded_reason"] == "no_harness_source"


def test_degraded_reason_is_specific(orch: AFLOrchestrator):
    """A generic 'degraded' is not actionable — the reason must survive."""
    orch._mark_analysis_degraded("probe_build_failed", "library=None")
    assert orch.analysis_quality["degraded_reason"] == "probe_build_failed"


def test_degradation_is_logged_with_impact(orch: AFLOrchestrator, capsys):
    """The warning must state the consequence, not just the fact. This is the
    line that would have flagged the libnmea run.

    structlog renders to stdout rather than through stdlib logging, so this
    reads captured output, not caplog.
    """
    orch._mark_analysis_degraded("probe_build_failed", "undefined reference")
    text = capsys.readouterr().out.lower()
    assert "degraded" in text
    assert "cmin" in text or "minimis" in text
    assert "probe_build_failed" in text


def test_quality_dict_is_json_serialisable(orch: AFLOrchestrator):
    """Consumed by benchmark artifacts (input_influence.json), so it must be
    plain data — no Paths, no exceptions."""
    import json
    orch._mark_analysis_degraded("build_error", "boom")
    assert json.loads(json.dumps(orch.analysis_quality))["analysis_quality"] == "degraded"
