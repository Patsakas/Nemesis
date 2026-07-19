"""GET /api/coverage — coverage data for a specific target library."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


class TargetCoverage(BaseModel):
    func_name: str
    source_coverage_pct: float = -1.0
    function_coverage_pct: float = -1.0
    harness_quality_score: float = -1.0
    status: str = "unknown"


class CoverageSummary(BaseModel):
    target_name: str
    run_id: str = ""
    targets: list[TargetCoverage] = []
    avg_source_coverage: float = 0.0
    targets_with_coverage: int = 0


_SRC_EXTS = (".cxx", ".cpp", ".hpp", ".cc", ".hh", ".c", ".h")


def _norm(name: str) -> str:
    """Normalize a library/source token for matching: lowercase, drop a source
    extension, drop a leading ``lib`` (so ``libpng`` and ``png`` compare equal)."""
    s = name.strip().lower()
    for ext in _SRC_EXTS:
        if s.endswith(ext):
            s = s[: -len(ext)]
            break
    if s.startswith("lib"):
        s = s[3:]
    return s


def _run_matches_target(data: dict[str, Any], target_name: str) -> bool:
    """Does this run's results.json belong to ``target_name``?

    Prefers the explicit ``target_name`` field written by the pipeline. Legacy
    runs predate that field, so fall back to the source path prefix of the
    results (a run is homogeneous — every result comes from one library).
    """
    req = _norm(target_name)
    if not req:
        return False

    explicit = str(data.get("target_name") or "").strip()
    if explicit:
        return _norm(explicit) == req

    for r in data.get("results", []):
        fp = str(r.get("target", {}).get("file_path", "")).replace("\\", "/")
        if not fp:
            continue
        prefix = _norm(fp.split("/")[0])
        if prefix and (prefix == req or (len(req) >= 3 and prefix.startswith(req))):
            return True
    return False


def _build_summary(target_name: str, data: dict[str, Any], run_dir_name: str) -> CoverageSummary:
    targets: list[TargetCoverage] = []
    covered = 0
    total_cov = 0.0

    for r in data.get("results", []):
        src_cov = float(r.get("source_coverage_pct", -1.0))
        targets.append(TargetCoverage(
            func_name=r.get("target", {}).get("func_name", ""),
            source_coverage_pct=src_cov,
            function_coverage_pct=float(r.get("function_coverage_pct", -1.0)),
            harness_quality_score=float(r.get("harness_quality_score", -1.0)),
            status=r.get("status", "unknown"),
        ))
        if src_cov >= 0:
            covered += 1
            total_cov += src_cov

    avg = total_cov / covered if covered > 0 else 0.0
    return CoverageSummary(
        target_name=target_name,
        run_id=data.get("run_id", run_dir_name),
        targets=targets,
        avg_source_coverage=round(avg, 2),
        targets_with_coverage=covered,
    )


@router.get("/{target_name}", response_model=CoverageSummary)
def get_coverage(target_name: str, request: Request) -> CoverageSummary:
    """Coverage for ``target_name`` from its most recent run.

    Runs are scanned newest-first and the first one belonging to this target is
    returned — not merely the newest run overall, which may target a different
    library.
    """
    workspace = Path(request.app.state.workspace)

    run_dirs: list[tuple[Path, float]] = []
    if workspace.exists():
        for p in workspace.iterdir():
            results_file = p / "results.json"
            if p.is_dir() and results_file.exists():
                run_dirs.append((p, results_file.stat().st_mtime))

    run_dirs.sort(key=lambda x: x[1], reverse=True)

    for run_dir, _ in run_dirs:
        try:
            data = json.loads((run_dir / "results.json").read_text())
        except (json.JSONDecodeError, OSError):
            continue

        if not data.get("results"):
            continue
        if not _run_matches_target(data, target_name):
            continue

        return _build_summary(target_name, data, run_dir.name)

    raise HTTPException(status_code=404, detail=f"No run data found for {target_name}")
