"""GET /api/runs — pipeline run history routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from nemesis.api.models import RunDetail, RunSummary, TargetResultSummary

router = APIRouter(prefix="/api/runs", tags=["runs"])


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
