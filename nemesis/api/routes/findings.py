"""GET /api/findings — findings database routes."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from nemesis.api.models import FindingDetail, FindingSummary, ReproductionInfo, CVEAssessmentInfo
from nemesis.reporter import load_findings

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _to_summary(f: dict[str, Any]) -> FindingSummary:
    return FindingSummary(
        id=f.get("id", ""),
        status=f.get("status", "unknown"),
        cve_worthy=bool(f.get("cve_worthy", False)),
        cve_status=f.get("cve_status", ""),
        cve_id=f.get("cve_id"),
        library=f.get("library", "unknown"),
        function=f.get("function", ""),
        file=f.get("file", ""),
        cwe=f.get("cwe", "CWE-unknown"),
        cwe_name=f.get("cwe_name", "Unknown"),
        severity=f.get("severity", "unknown"),
        crash_type=f.get("crash_type", "UNKNOWN"),
        discovered_date=str(f.get("discovered_date", "")),
        run_id=f.get("run_id"),
        patch_induced=f.get("patch_induced"),
        cvss_estimate=f.get("cvss_estimate"),
    )


def _to_detail(f: dict[str, Any]) -> FindingDetail:
    repro_raw = f.get("reproduction")
    repro = None
    if isinstance(repro_raw, dict):
        repro = ReproductionInfo(
            direct=repro_raw.get("direct", ""),
            bsdtar=repro_raw.get("bsdtar", ""),
            note=repro_raw.get("note", ""),
        )

    cve_raw = f.get("cve_assessment")
    cve_assess = None
    if isinstance(cve_raw, dict):
        cve_assess = CVEAssessmentInfo(
            is_known_cve=cve_raw.get("is_known_cve", False),
            cve_id=cve_raw.get("cve_id", ""),
            cve_confidence=cve_raw.get("cve_confidence", 0.0),
            rationale=cve_raw.get("rationale", ""),
            cvss_estimate=cve_raw.get("cvss_estimate", 0.0),
            similar_cves=cve_raw.get("similar_cves", []),
            suggested_mitigation=cve_raw.get("suggested_mitigation", ""),
        )

    call_chain = f.get("call_chain") or []
    crash_files = f.get("crash_files") or []

    return FindingDetail(
        id=f.get("id", ""),
        status=f.get("status", "unknown"),
        cve_worthy=bool(f.get("cve_worthy", False)),
        cve_status=f.get("cve_status", ""),
        cve_id=f.get("cve_id"),
        library=f.get("library", "unknown"),
        function=f.get("function", ""),
        file=f.get("file", ""),
        line=int(f.get("line", 0) or 0),
        crash_location=f.get("crash_location", ""),
        call_chain=[str(c) for c in call_chain],
        cwe=f.get("cwe", "CWE-unknown"),
        cwe_name=f.get("cwe_name", "Unknown"),
        severity=f.get("severity", "unknown"),
        crash_type=f.get("crash_type", "UNKNOWN"),
        asan_error=f.get("asan_error", ""),
        description=f.get("description", ""),
        root_cause=f.get("root_cause", ""),
        trigger=f.get("trigger", ""),
        discovered_date=str(f.get("discovered_date", "")),
        discovered_by=f.get("discovered_by", ""),
        run_id=f.get("run_id"),
        patch_induced=f.get("patch_induced"),
        patch_verdict=f.get("patch_verdict", ""),
        crash_files=[str(c) for c in crash_files],
        notes=f.get("notes", ""),
        reproduction=repro,
        cve_assessment=cve_assess,
        cvss_estimate=f.get("cvss_estimate"),
    )


@router.get("", response_model=list[FindingSummary])
def list_findings(
    request: Request,
    library: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    cwe: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    cve_worthy: Optional[bool] = Query(None),
) -> list[FindingSummary]:
    findings = load_findings(request.app.state.findings_yaml)
    result = []
    for f in findings:
        if library and f.get("library", "").lower() != library.lower():
            continue
        if severity and f.get("severity", "").lower() != severity.lower():
            continue
        if cwe and f.get("cwe", "").lower() != cwe.lower():
            continue
        if status and f.get("status", "").lower() != status.lower():
            continue
        if cve_worthy is not None and bool(f.get("cve_worthy")) != cve_worthy:
            continue
        result.append(_to_summary(f))
    return result


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, request: Request) -> FindingDetail:
    findings = load_findings(request.app.state.findings_yaml)
    for f in findings:
        if f.get("id") == finding_id:
            return _to_detail(f)
    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
