"""GET /api/live/targets + WS /ws/live — live AFL stats."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect

from nemesis.api.models import LiveSnapshot, LiveTargetStats

router = APIRouter(tags=["live"])


# ── Fuzzer stats parsing ─────────────────────────────────────


def _parse_fuzzer_stats(stats_file: Path) -> dict[str, str]:
    """Parse AFL++ fuzzer_stats key:value file."""
    data: dict[str, str] = {}
    try:
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                data[k.strip()] = v.strip()
    except OSError:
        pass
    return data


def _is_pid_running(pid_str: str) -> bool:
    try:
        pid = int(pid_str)
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        return False


def _build_target_stats(target_name: str, fuzz_dir: Path) -> LiveTargetStats:
    """Read AFL fuzzer_stats from the main fuzzer instance."""
    stats_file = fuzz_dir / "main" / "fuzzer_stats"
    if not stats_file.exists():
        return LiveTargetStats(target_name=target_name, is_running=False)

    stats = _parse_fuzzer_stats(stats_file)

    fuzzer_pid = stats.get("fuzzer_pid", "0")
    is_running = _is_pid_running(fuzzer_pid)

    # AFL++ 4.x renamed paths_total → corpus_count
    total_paths = int(stats.get("corpus_count", stats.get("paths_total", 0)))

    map_density_raw = stats.get("bitmap_cvg", "0%").rstrip("%")
    try:
        map_density = float(map_density_raw)
    except ValueError:
        map_density = 0.0

    stability_raw = stats.get("stability", "0%").rstrip("%")
    try:
        stability = float(stability_raw)
    except ValueError:
        stability = 0.0

    last_updated = stats.get("last_update", "")

    return LiveTargetStats(
        target_name=target_name,
        is_running=is_running,
        exec_per_sec=float(stats.get("execs_per_sec", 0.0)),
        total_paths=total_paths,
        unique_crashes=int(stats.get("saved_crashes", stats.get("unique_crashes", 0))),
        unique_hangs=int(stats.get("saved_hangs", stats.get("unique_hangs", 0))),
        map_density_pct=map_density,
        stability_pct=stability,
        duration_seconds=int(stats.get("run_time", 0)),
        last_updated=last_updated,
    )


def _get_live_snapshot(workspace: str) -> LiveSnapshot:
    findings_root = Path(workspace) / "fuzzing" / "findings"
    # Prefer run-scoped `current/` symlink (set by pipeline at run start)
    current = findings_root / "current"
    fuzz_findings = current if current.exists() else findings_root
    targets: list[LiveTargetStats] = []

    if fuzz_findings.exists():
        for target_dir in sorted(fuzz_findings.iterdir()):
            if target_dir.is_dir() and target_dir.name != "current":
                stats = _build_target_stats(target_dir.name, target_dir)
                targets.append(stats)

    active = sum(1 for t in targets if t.is_running)
    now = datetime.now(UTC).isoformat()

    return LiveSnapshot(
        timestamp=now,
        active_count=active,
        targets=targets,
    )


# ── REST endpoint ────────────────────────────────────────────


@router.get("/api/live/targets", response_model=LiveSnapshot)
def get_live_targets(request: Request) -> LiveSnapshot:
    return _get_live_snapshot(request.app.state.workspace)


# ── WebSocket endpoint ───────────────────────────────────────


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    await websocket.accept()
    workspace = websocket.app.state.workspace
    try:
        while True:
            snapshot = _get_live_snapshot(workspace)
            await websocket.send_text(snapshot.model_dump_json())
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()
