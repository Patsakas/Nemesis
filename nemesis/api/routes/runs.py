"""GET /api/runs — pipeline run history routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from nemesis.api.models import RunDetail, RunSummary, TargetResultSummary

router = APIRouter(prefix="/api/runs", tags=["runs"])


class CurrentRun(BaseModel):
    """What the engine is doing right now. `active` is False when no run has
    started, when the last one finished, or when its heartbeat went stale."""

    active: bool = False
    run_id: str = ""
    target: str = ""
    stage: str = ""
    stage_num: int | str = 0
    func: str = ""
    detail: str = ""
    targets_done: int = 0
    targets_total: int = 0
    crashes: int = 0
    status: str = ""
    started_at: str = ""
    updated_at: str = ""


@router.get("/current", response_model=CurrentRun)
def get_current_run(request: Request) -> CurrentRun:
    """Live progress for the run in flight.

    Reads the heartbeat the pipeline writes, so this works for runs started
    from the CLI as well as from the dashboard — and it reports the stages
    that happen long before AFL produces any statistics.
    """
    from nemesis.run_status import read_status  # noqa: PLC0415

    data = read_status(request.app.state.workspace)
    if not data:
        return CurrentRun()
    return CurrentRun(
        active=not data.get("finished") and data.get("status") != "stale",
        run_id=data.get("run_id", ""),
        target=data.get("target", ""),
        stage=data.get("stage", ""),
        stage_num=data.get("stage_num", 0),
        func=data.get("func", ""),
        detail=data.get("detail", ""),
        targets_done=int(data.get("targets_done", 0)),
        targets_total=int(data.get("targets_total", 0)),
        crashes=int(data.get("crashes", 0)),
        status=data.get("status", ""),
        started_at=data.get("started_at", ""),
        updated_at=data.get("updated_at", ""),
    )


def _load_run(run_dir: Path) -> dict:
    results_file = run_dir / "results.json"
    if not results_file.exists():
        return {}
    with open(results_file) as fh:
        return json.load(fh)


def _to_summary(data: dict) -> RunSummary:
    return RunSummary(
        run_id=data.get("run_id", ""),
        started_at=str(data.get("started_at", "")),
        finished_at=str(data.get("finished_at", "")) if data.get("finished_at") else None,
        targets_processed=int(data.get("targets_processed", 0)),
        targets_successful=int(data.get("targets_successful", 0)),
        total_crashes=int(data.get("total_crashes", 0)),
        total_cves=int(data.get("total_cves", 0)),
        total_llm_cost_usd=float(data.get("total_llm_cost_usd", 0.0)),
    )


def _to_target_summary(r: dict) -> TargetResultSummary:
    target = r.get("target", {})
    crashes = r.get("crashes", [])
    return TargetResultSummary(
        func_name=target.get("func_name", ""),
        file_path=target.get("file_path", ""),
        status=r.get("status", "unknown"),
        crashes=len(crashes),
        has_patch=r.get("patch") is not None,
        has_analysis=r.get("analysis") is not None,
        feedback_iterations=int(r.get("feedback_iterations", 0)),
        duration_seconds=float(r.get("duration_seconds", 0.0)),
    )


def _list_run_dirs(workspace: Path) -> list[Path]:
    """Return run dirs (hex IDs, contain results.json), sorted newest first."""
    if not workspace.exists():
        return []
    dirs = []
    for p in workspace.iterdir():
        if p.is_dir() and (p / "results.json").exists():
            dirs.append(p)
    # Sort by modification time of results.json, newest first
    dirs.sort(key=lambda p: (p / "results.json").stat().st_mtime, reverse=True)
    return dirs


@router.get("", response_model=list[RunSummary])
def list_runs(request: Request) -> list[RunSummary]:
    workspace = Path(request.app.state.workspace)
    run_dirs = _list_run_dirs(workspace)
    result = []
    for d in run_dirs:
        data = _load_run(d)
        if data:
            result.append(_to_summary(data))
    return result


@router.get("/{run_id}", response_model=RunDetail)
def get_run(run_id: str, request: Request) -> RunDetail:
    workspace = Path(request.app.state.workspace)
    run_dir = workspace / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    data = _load_run(run_dir)
    if not data:
        raise HTTPException(status_code=404, detail=f"Run {run_id} has no results")

    target_results = [_to_target_summary(r) for r in data.get("results", [])]

    return RunDetail(
        run_id=data.get("run_id", run_id),
        started_at=str(data.get("started_at", "")),
        finished_at=str(data.get("finished_at", "")) if data.get("finished_at") else None,
        targets_processed=int(data.get("targets_processed", 0)),
        targets_successful=int(data.get("targets_successful", 0)),
        total_crashes=int(data.get("total_crashes", 0)),
        total_cves=int(data.get("total_cves", 0)),
        total_llm_cost_usd=float(data.get("total_llm_cost_usd", 0.0)),
        results=target_results,
    )
