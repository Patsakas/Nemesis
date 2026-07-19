"""The jobs endpoint shells out to the CLI, so its argv whitelist is the security
boundary: only known operations, and request values only ever as separate argv."""
import time

import pytest
from fastapi.testclient import TestClient

from nemesis.api.app import create_app
from nemesis.api.routes import jobs as jobs_mod


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    jobs_mod._jobs.clear()
    return TestClient(create_app(workspace=str(tmp_path / "ws"), serve_frontend=False))


def test_only_whitelisted_kinds_are_offered(client):
    kinds = client.get("/api/jobs/kinds").json()
    assert set(kinds) == {"onboard", "setup", "recon", "scout", "verify-crashes", "run"}


def test_unknown_kind_is_rejected(client):
    r = client.post("/api/jobs", json={"kind": "rm-rf"})
    assert r.status_code == 400
    assert "Unknown job kind" in r.json()["detail"]


def test_missing_required_field_is_rejected(client):
    r = client.post("/api/jobs", json={"kind": "recon"})       # no target
    assert r.status_code == 400
    assert "target" in r.json()["detail"]


def test_request_values_never_become_shell_syntax():
    """A hostile target name must land as one argv entry, not a shell fragment."""
    req = jobs_mod.JobRequest(kind="recon", target="libfoo; rm -rf /")
    argv = jobs_mod._BUILDERS["recon"](req)
    assert argv == ["recon", "-t", "libfoo; rm -rf /"]         # single argv entry


def test_scout_top_is_clamped():
    argv = jobs_mod._BUILDERS["scout"](jobs_mod.JobRequest(kind="scout", top=99999))
    assert argv[argv.index("-n") + 1] == "200"
    argv = jobs_mod._BUILDERS["scout"](jobs_mod.JobRequest(kind="scout", top=-5))
    assert argv[argv.index("-n") + 1] == "1"


def test_run_builder_maps_flags():
    argv = jobs_mod._BUILDERS["run"](jobs_mod.JobRequest(
        kind="run", target="libfoo", deep=True, strategy="harness", auto_sanitizer=True))
    assert argv[:3] == ["run", "-t", "libfoo"]
    assert "--deep" in argv and "--auto-sanitizer" in argv
    assert argv[argv.index("--strategy") + 1] == "harness"
    # an invalid strategy is dropped rather than passed through
    argv = jobs_mod._BUILDERS["run"](jobs_mod.JobRequest(
        kind="run", target="libfoo", strategy="evil"))
    assert "--strategy" not in argv


def test_fuzz_budget_is_forwarded_and_clamped():
    argv = jobs_mod._BUILDERS["run"](jobs_mod.JobRequest(
        kind="run", target="libfoo", timeout_hours=2))
    assert argv[argv.index("--timeout-hours") + 1] == "2.0"

    # 0 means "keep the scan/deep preset" — the flag is not passed at all
    argv = jobs_mod._BUILDERS["run"](jobs_mod.JobRequest(kind="run", target="libfoo"))
    assert "--timeout-hours" not in argv

    # absurd values are clamped rather than handed to the fuzzer
    argv = jobs_mod._BUILDERS["run"](jobs_mod.JobRequest(
        kind="run", target="libfoo", timeout_hours=99999))
    assert argv[argv.index("--timeout-hours") + 1] == "72.0"


def test_job_lifecycle_is_tracked(client):
    """Launch something that fails fast and confirm status/exit code/output land."""
    r = client.post("/api/jobs", json={"kind": "recon", "target": "does-not-exist"})
    assert r.status_code == 200
    job_id = r.json()["id"]
    assert r.json()["status"] == "running"

    for _ in range(100):                       # it exits quickly: no such config
        detail = client.get(f"/api/jobs/{job_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.1)

    assert detail["status"] in ("failed", "succeeded")
    assert detail["exit_code"] is not None
    assert client.get("/api/jobs").json()[0]["id"] == job_id


def test_unknown_job_is_404(client):
    assert client.get("/api/jobs/nope").status_code == 404
    assert client.delete("/api/jobs/nope").status_code == 404
