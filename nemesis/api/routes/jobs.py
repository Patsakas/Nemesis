"""POST /api/jobs — run the long-lived CLI operations from the dashboard.

`onboard`, `setup`, `recon`, `scout` and `verify-crashes` all shell out to the
same CLI the terminal uses, so the dashboard never grows a second implementation
of the pipeline. Each job is a subprocess whose output is tailed into memory so
the UI can follow along.

Security note: the command line is *built here* from a fixed whitelist
(`_BUILDERS`) — request fields are only ever passed as separate argv entries,
never concatenated into a shell string, and `shell=False` throughout. Combined
with binding to loopback by default (`nemesis serve --host`), that keeps this
from being a remote-code-execution surface.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/jobs", tags=["jobs"])

_MAX_OUTPUT_LINES = 400
_MAX_JOBS = 50


class JobRequest(BaseModel):
    kind: str
    target: str = ""
    # onboard
    source_root: str = ""
    project_name: str = ""
    oss_fuzz_project: str = ""
    # setup
    url: str = ""
    skip_build: bool = False
    # scout
    top: int = 25
    round_trip_only: bool = False
    # run
    scan: bool = True
    deep: bool = False
    max_targets: int = 0
    timeout_hours: float = 0.0
    strategy: str = ""
    auto_sanitizer: bool = False


class JobInfo(BaseModel):
    id: str
    kind: str
    argv: list[str]
    status: str                 # running | succeeded | failed | stopped
    started_at: str
    finished_at: str | None = None
    exit_code: int | None = None
    output: list[str] = Field(default_factory=list)


class _Job:
    def __init__(self, kind: str, argv: list[str]) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.argv = argv
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.finished_at: str | None = None
        self.exit_code: int | None = None
        self.stopped = False
        self.lines: deque[str] = deque(maxlen=_MAX_OUTPUT_LINES)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "nemesis.cli", *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            shell=False,
        )
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))
        self.exit_code = self.proc.wait()
        self.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def status(self) -> str:
        if self.proc.poll() is None:
            return "running"
        if self.stopped:
            return "stopped"
        return "succeeded" if self.exit_code == 0 else "failed"

    def info(self, with_output: bool = False) -> JobInfo:
        return JobInfo(
            id=self.id, kind=self.kind, argv=self.argv, status=self.status,
            started_at=self.started_at, finished_at=self.finished_at,
            exit_code=self.exit_code,
            output=list(self.lines) if with_output else [],
        )


_jobs: dict[str, _Job] = {}


# ── argv builders (the whitelist) ────────────────────────────


def _need(value: str, field: str) -> str:
    if not value:
        raise HTTPException(status_code=400, detail=f"`{field}` is required for this job")
    return value


def _onboard(r: JobRequest) -> list[str]:
    argv = ["onboard",
            "--source-root", _need(r.source_root, "source_root"),
            "--project-name", _need(r.project_name, "project_name")]
    if r.oss_fuzz_project:
        argv += ["--oss-fuzz-project", r.oss_fuzz_project]
    return argv


def _setup(r: JobRequest) -> list[str]:
    argv = ["setup", "-t", _need(r.target, "target")]
    if r.url:
        argv += ["--url", r.url]
    if r.skip_build:
        argv.append("--skip-build")
    return argv


def _recon(r: JobRequest) -> list[str]:
    return ["recon", "-t", _need(r.target, "target")]


def _scout(r: JobRequest) -> list[str]:
    argv = ["scout", "-n", str(max(1, min(200, r.top)))]
    if r.round_trip_only:
        argv.append("--round-trip-only")
    return argv


def _verify_crashes(r: JobRequest) -> list[str]:
    return ["verify-crashes", "-t", _need(r.target, "target")]


def _run(r: JobRequest) -> list[str]:
    argv = ["run", "-t", _need(r.target, "target")]
    if r.deep:
        argv.append("--deep")
    elif r.scan:
        argv.append("--scan")
    if r.max_targets:
        argv += ["--max-targets", str(max(0, min(500, r.max_targets)))]
    if r.timeout_hours and r.timeout_hours > 0:
        argv += ["--timeout-hours", str(min(72.0, max(0.01, r.timeout_hours)))]
    if r.strategy in ("patch", "harness"):
        argv += ["--strategy", r.strategy]
    if r.auto_sanitizer:
        argv.append("--auto-sanitizer")
    return argv


_BUILDERS: dict[str, Callable[[JobRequest], list[str]]] = {
    "onboard": _onboard,
    "setup": _setup,
    "recon": _recon,
    "scout": _scout,
    "verify-crashes": _verify_crashes,
    "run": _run,
}


# ── routes ───────────────────────────────────────────────────


@router.get("/kinds", response_model=list[str])
def list_kinds() -> list[str]:
    """The operations this endpoint is allowed to launch."""
    return sorted(_BUILDERS)


@router.post("", response_model=JobInfo)
def create_job(req: JobRequest) -> JobInfo:
    builder = _BUILDERS.get(req.kind)
    if builder is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown job kind {req.kind!r}. Allowed: {', '.join(sorted(_BUILDERS))}",
        )

    # One running job per (kind, target) — re-running the same thing concurrently
    # would have two processes fighting over the same workspace.
    key = (req.kind, req.target)
    for j in _jobs.values():
        if (j.kind, _target_of(j)) == key and j.status == "running":
            raise HTTPException(status_code=409, detail=f"{req.kind} already running for {req.target or 'this'}")

    argv = builder(req)
    try:
        job = _Job(req.kind, argv)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not start job: {exc}") from exc

    _jobs[job.id] = job
    _prune()
    return job.info()


@router.get("", response_model=list[JobInfo])
def list_jobs() -> list[JobInfo]:
    return [j.info() for j in sorted(_jobs.values(), key=lambda j: j.started_at, reverse=True)]


@router.get("/{job_id}", response_model=JobInfo)
def get_job(job_id: str) -> JobInfo:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No job {job_id}")
    return job.info(with_output=True)


@router.delete("/{job_id}", response_model=JobInfo)
def stop_job(job_id: str) -> JobInfo:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No job {job_id}")
    if job.proc.poll() is None:
        job.stopped = True
        job.proc.terminate()
        try:
            job.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            job.proc.kill()
    return job.info()


def _target_of(job: _Job) -> str:
    """Recover the -t/--project-name value so we can detect duplicate work."""
    for flag in ("-t", "--project-name"):
        if flag in job.argv:
            i = job.argv.index(flag)
            if i + 1 < len(job.argv):
                return job.argv[i + 1]
    return ""


def _prune() -> None:
    """Drop the oldest finished jobs so the table does not grow without bound."""
    if len(_jobs) <= _MAX_JOBS:
        return
    finished = sorted(
        (j for j in _jobs.values() if j.status != "running"),
        key=lambda j: j.started_at,
    )
    for job in finished[: len(_jobs) - _MAX_JOBS]:
        _jobs.pop(job.id, None)
