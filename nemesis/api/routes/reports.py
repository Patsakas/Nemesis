"""GET /api/reports — CVE Markdown report routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from nemesis.api.models import ReportMeta

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _list_reports(reports_dir: Path) -> list[Path]:
    if not reports_dir.exists():
        return []
    return sorted(reports_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)


@router.get("", response_model=list[ReportMeta])
def list_reports(request: Request) -> list[ReportMeta]:
    reports_dir = Path(request.app.state.reports_dir)
    result = []
    for p in _list_reports(reports_dir):
        finding_id = p.stem  # filename without .md
        result.append(
            ReportMeta(
                id=finding_id,
                filename=p.name,
                finding_id=finding_id,
                size_bytes=p.stat().st_size,
            )
        )
    return result


@router.get("/{report_id}", response_class=PlainTextResponse)
def get_report(report_id: str, request: Request) -> str:
    reports_dir = Path(request.app.state.reports_dir)
    # Strip .md suffix if user included it
    report_id = report_id.removesuffix(".md")
    report_path = reports_dir / f"{report_id}.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return report_path.read_text()
