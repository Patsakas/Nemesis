"""FastAPI application factory for NEMESIS Web Dashboard."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from nemesis.api.routes import (
    findings, runs, reports, live, targets, scans, coverage, functions, jobs,
)


def create_app(
    workspace: str = "workspace",
    findings_yaml: str = "findings.yaml",
    reports_dir: str = "workspace/reports",
    serve_frontend: bool = True,
) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        workspace:      Path to workspace directory (contains run dirs + fuzzing/).
        findings_yaml:  Path to findings.yaml.
        reports_dir:    Path to workspace/reports/ (CVE .md files).
        serve_frontend: If True and frontend/dist/ exists, mount it at /.
    """
    app = FastAPI(
        title="NEMESIS Dashboard",
        description="Neuro-Symbolic Exploit Mining Engine — Web Dashboard",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS — allow Vite dev server (port 5173) to talk to FastAPI (port 8000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Store paths in app.state (no globals)
    app.state.workspace = str(Path(workspace).resolve())
    app.state.findings_yaml = str(Path(findings_yaml).resolve())
    app.state.reports_dir = str(Path(reports_dir).resolve())

    # API routers
    app.include_router(findings.router)
    app.include_router(runs.router)
    app.include_router(reports.router)
    app.include_router(live.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(coverage.router)
    app.include_router(functions.router)
    app.include_router(jobs.router)

    # Serve built React app at / (production mode)
    frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
    if serve_frontend and frontend_dist.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app


# Module-level app for uvicorn --reload (import string mode).
# Reads paths from env vars set by `nemesis serve`.
app = create_app(
    workspace=os.environ.get("NEMESIS_WORKSPACE", "workspace"),
    findings_yaml=os.environ.get("NEMESIS_FINDINGS", "findings.yaml"),
    reports_dir=os.environ.get("NEMESIS_REPORTS_DIR", "workspace/reports"),
)
