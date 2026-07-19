"""Pydantic response schemas for the NEMESIS Web API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


# ── Findings ─────────────────────────────────────────────────


class FindingSummary(BaseModel):
    id: str
    status: str
    cve_worthy: bool
    cve_status: str
    cve_id: Optional[str]
    library: str
    function: str
    file: str
    cwe: str
    cwe_name: str
    severity: str
    crash_type: str
    discovered_date: str
    run_id: Optional[str]
    patch_induced: Optional[bool]
    cvss_estimate: Optional[float] = None


class ReproductionInfo(BaseModel):
    direct: str = ""
    bsdtar: str = ""
    note: str = ""


class CVEAssessmentInfo(BaseModel):
    is_known_cve: bool = False
    cve_id: str = ""
    cve_confidence: float = 0.0
    rationale: str = ""
    cvss_estimate: float = 0.0
    similar_cves: list[str] = []
    suggested_mitigation: str = ""


class FindingDetail(BaseModel):
    id: str
    status: str
    cve_worthy: bool
    cve_status: str
    cve_id: Optional[str]
    library: str
    function: str
    file: str
    line: int = 0
    crash_location: str = ""
    call_chain: list[str] = []
    cwe: str
    cwe_name: str
    severity: str
    crash_type: str
    asan_error: str = ""
    description: str = ""
    root_cause: str = ""
    trigger: str = ""
    discovered_date: str
    discovered_by: str = ""
    run_id: Optional[str]
    patch_induced: Optional[bool]
    patch_verdict: str = ""
    crash_files: list[str] = []
    notes: str = ""
    reproduction: Optional[ReproductionInfo] = None
    cve_assessment: Optional[CVEAssessmentInfo] = None
    cvss_estimate: Optional[float] = None


# ── Runs ─────────────────────────────────────────────────────


class RunSummary(BaseModel):
    run_id: str
    started_at: str
    finished_at: Optional[str]
    targets_processed: int
    targets_successful: int
    total_crashes: int
    total_cves: int
    total_llm_cost_usd: float


class TargetResultSummary(BaseModel):
    func_name: str
    file_path: str
    status: str
    crashes: int
    has_patch: bool
    has_analysis: bool
    feedback_iterations: int
    duration_seconds: float


class RunDetail(BaseModel):
    run_id: str
    started_at: str
    finished_at: Optional[str]
    targets_processed: int
    targets_successful: int
    total_crashes: int
    total_cves: int
    total_llm_cost_usd: float
    results: list[TargetResultSummary]


# ── Reports ──────────────────────────────────────────────────


class ReportMeta(BaseModel):
    id: str
    filename: str
    finding_id: str
    size_bytes: int


# ── Live ─────────────────────────────────────────────────────


class LiveTargetStats(BaseModel):
    target_name: str
    is_running: bool
    exec_per_sec: float = 0.0
    total_paths: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    map_density_pct: float = 0.0
    stability_pct: float = 0.0
    duration_seconds: int = 0
    last_updated: str = ""


class LiveSnapshot(BaseModel):
    timestamp: str
    active_count: int
    targets: list[LiveTargetStats]
