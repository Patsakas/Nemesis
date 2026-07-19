"""POST /api/scans — launch new scans."""

from __future__ import annotations

import subprocess
import sys

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Track running scan processes
_active_scans: dict[str, subprocess.Popen] = {}


class ScanRequest(BaseModel):
    target: str
    max_targets: int = 10
    scan: bool = True
    strategy: str = "harness"
    deep: bool = False
    deep_top: int = 3
    deep_hours: float = 4.0
    timeout_hours: float = 0.0   # 0 = keep the scan/deep preset


class ScanResponse(BaseModel):
    status: str
    message: str
    target: str


class ActiveScan(BaseModel):
    target: str
    pid: int
    is_running: bool


def _run_scan(request: ScanRequest) -> None:
    """Run nemesis scan in a subprocess."""
    cmd = [
        sys.executable, "-m", "nemesis.cli", "run",
        "-t", request.target,
        "--max-targets", str(request.max_targets),
        "--strategy", request.strategy,
    ]
    if request.scan:
        cmd.append("--scan")
    if request.deep:
        cmd.extend(["--deep", "--deep-top", str(request.deep_top),
                     "--deep-hours", str(request.deep_hours)])
    if request.timeout_hours and request.timeout_hours > 0:
        cmd.extend(["--timeout-hours", str(request.timeout_hours)])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    _active_scans[request.target] = proc


@router.post("", response_model=ScanResponse)
def launch_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    """Launch a new scan for a target library."""
    # Check if already running
    if request.target in _active_scans:
        proc = _active_scans[request.target]
        if proc.poll() is None:
            raise HTTPException(
                status_code=409,
                detail=f"Scan for {request.target} already running (PID {proc.pid})",
            )
        else:
            del _active_scans[request.target]

    background_tasks.add_task(_run_scan, request)

    return ScanResponse(
        status="launched",
        message=f"Scan launched for {request.target}",
        target=request.target,
    )


@router.get("/active", response_model=list[ActiveScan])
def list_active_scans() -> list[ActiveScan]:
    """List currently running scans."""
    result = []
    to_remove = []
    for target, proc in _active_scans.items():
        is_running = proc.poll() is None
        result.append(ActiveScan(
            target=target,
            pid=proc.pid,
            is_running=is_running,
        ))
        if not is_running:
            to_remove.append(target)

    # Clean up finished scans
    for t in to_remove:
        del _active_scans[t]

    return result


@router.delete("/{target}")
def stop_scan(target: str) -> ScanResponse:
    """Stop a running scan."""
    if target not in _active_scans:
        raise HTTPException(status_code=404, detail=f"No active scan for {target}")

    proc = _active_scans[target]
    if proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=10)

    del _active_scans[target]
    return ScanResponse(
        status="stopped",
        message=f"Scan for {target} stopped",
        target=target,
    )
