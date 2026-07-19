"""A heartbeat file describing what the engine is doing right now.

Until this existed the dashboard was blind for the first several minutes of a
run: `results.json` is only written when the run ends, and AFL's `fuzzer_stats`
only appears once Stage 4 starts. Everything before that — recon, harness
generation, the instrumented build — produced no observable state at all, so a
run in progress was indistinguishable from nothing happening.

The pipeline updates this file as it moves; the API serves it at
`/api/runs/current`. It is advisory: a stale or missing file never affects a
run, and writes are best-effort so a full disk cannot fail the pipeline.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATUS_FILENAME = "current_run.json"

# A run whose heartbeat is older than this is treated as dead — the process was
# killed, so nothing will ever mark it finished.
STALE_AFTER_SECONDS = 180


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def status_path(workspace: str | Path) -> Path:
    return Path(workspace) / STATUS_FILENAME


class RunStatusWriter:
    """Records pipeline progress. Every write is best-effort."""

    def __init__(self, workspace: str | Path, run_id: str, target: str) -> None:
        self._path = status_path(workspace)
        self._state: dict[str, Any] = {
            "run_id": run_id,
            "target": target,
            "started_at": _now(),
            "updated_at": _now(),
            "stage": "starting",
            "stage_num": 0,
            "func": "",
            "detail": "",
            "targets_done": 0,
            "targets_total": 0,
            "crashes": 0,
            "finished": False,
            "status": "running",
        }
        self._write()

    def update(self, **fields: Any) -> None:
        self._state.update(fields)
        self._state["updated_at"] = _now()
        self._write()

    def stage(self, num: int | str, name: str, func: str = "", detail: str = "") -> None:
        self.update(stage_num=num, stage=name, func=func, detail=detail)

    def target_started(self, func: str, index: int, total: int) -> None:
        self.update(func=func, targets_done=index, targets_total=total)

    def finish(self, status: str = "completed", crashes: int = 0) -> None:
        self.update(finished=True, status=status, crashes=crashes,
                    stage="finished", func="", detail="")

    def _write(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)      # atomic: readers never see a partial file
        except OSError:
            pass                              # never let telemetry break a run


def read_status(workspace: str | Path) -> dict[str, Any] | None:
    """Current run state, or None when nothing has run yet.

    A run whose heartbeat stopped without being marked finished is reported as
    ``status="stale"`` — the process died, and callers should not show it as
    still running forever.
    """
    p = status_path(workspace)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    if not data.get("finished"):
        try:
            age = time.time() - p.stat().st_mtime
        except OSError:
            age = 0.0
        if age > STALE_AFTER_SECONDS:
            data["status"] = "stale"
            data["stale_seconds"] = int(age)
    return data


class NullRunStatus:
    """Stand-in used before a run starts, so entry points that never call
    `execute()` cannot trip over a missing attribute."""

    def update(self, **fields: Any) -> None: ...
    def stage(self, num: int | str, name: str, func: str = "", detail: str = "") -> None: ...
    def target_started(self, func: str, index: int, total: int) -> None: ...
    def finish(self, status: str = "completed", crashes: int = 0) -> None: ...
