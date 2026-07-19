"""The dashboard was blind while a run was in flight: results.json only lands
at the end, and AFL statistics only exist once Stage 4 starts. The heartbeat
file closes that gap, so it has to be accurate about what is happening and
honest when a run dies without finishing.
"""
import json
import os
import time

from fastapi.testclient import TestClient

from nemesis.api.app import create_app
from nemesis.run_status import (
    STALE_AFTER_SECONDS,
    NullRunStatus,
    RunStatusWriter,
    read_status,
    status_path,
)


def test_reports_nothing_before_any_run(tmp_path):
    assert read_status(tmp_path) is None


def test_tracks_stage_and_target_progress(tmp_path):
    w = RunStatusWriter(tmp_path, "abc123", "cjson")
    w.target_started("cJSON_Parse", 3, 20)
    w.stage(2, "neural", func="cJSON_Parse", detail="generating a harness")

    st = read_status(tmp_path)
    assert st["run_id"] == "abc123" and st["target"] == "cjson"
    assert st["stage"] == "neural" and st["stage_num"] == 2
    assert st["targets_done"] == 3 and st["targets_total"] == 20
    assert st["finished"] is False and st["status"] == "running"


def test_finish_marks_the_run_inactive(tmp_path):
    w = RunStatusWriter(tmp_path, "abc123", "cjson")
    w.finish(status="success", crashes=2)
    st = read_status(tmp_path)
    assert st["finished"] is True and st["crashes"] == 2


def test_a_killed_run_is_reported_stale_not_running(tmp_path):
    """Without this the UI would show a run in progress forever."""
    w = RunStatusWriter(tmp_path, "abc123", "cjson")
    w.stage(1, "recon")
    old = time.time() - (STALE_AFTER_SECONDS + 60)
    os.utime(status_path(tmp_path), (old, old))

    assert read_status(tmp_path)["status"] == "stale"


def test_writes_are_atomic_and_leave_no_partial_file(tmp_path):
    w = RunStatusWriter(tmp_path, "abc123", "cjson")
    for i in range(20):
        w.update(detail=f"step {i}")
        json.loads(status_path(tmp_path).read_text(encoding="utf-8"))   # always parseable
    assert not list(tmp_path.glob("*.tmp"))


def test_writer_never_raises_when_the_path_is_unusable(tmp_path):
    """Telemetry must not be able to fail a fuzzing run."""
    blocker = tmp_path / "ws"
    blocker.write_text("not a directory", encoding="utf-8")
    w = RunStatusWriter(blocker, "abc123", "cjson")     # must not raise
    w.stage(1, "recon")
    w.finish()


def test_null_writer_is_a_safe_noop():
    n = NullRunStatus()
    n.stage(1, "recon"); n.target_started("f", 1, 2); n.update(x=1); n.finish()


# ── API ──────────────────────────────────────────────────────


def test_endpoint_reports_active_run_then_goes_quiet(tmp_path):
    c = TestClient(create_app(workspace=str(tmp_path), serve_frontend=False))

    assert c.get("/api/runs/current").json()["active"] is False

    w = RunStatusWriter(tmp_path, "abc123", "cjson")
    w.stage(3, "symbolic", func="cJSON_Parse", detail="building")
    body = c.get("/api/runs/current").json()
    assert body["active"] is True
    assert body["stage"] == "symbolic" and body["func"] == "cJSON_Parse"

    w.finish(status="success")
    assert c.get("/api/runs/current").json()["active"] is False


def test_current_is_not_shadowed_by_the_run_id_route(tmp_path):
    """`/api/runs/current` must not be parsed as a run id."""
    c = TestClient(create_app(workspace=str(tmp_path), serve_frontend=False))
    assert c.get("/api/runs/current").status_code == 200
