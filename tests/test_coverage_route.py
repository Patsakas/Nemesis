"""The /api/coverage/{target} route must return the latest run for THAT target,
not the newest run overall (which may belong to a different library)."""
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from nemesis.api.app import create_app


def _write_run(ws: Path, run_id: str, mtime: float, *, target_name=None,
               file_prefix: str, funcs: list[tuple[str, float]]) -> None:
    d = ws / run_id
    d.mkdir(parents=True)
    data = {
        "run_id": run_id,
        "results": [
            {
                "target": {"func_name": fn, "file_path": f"{file_prefix}/{fn}.c"},
                "source_coverage_pct": cov,
                "function_coverage_pct": cov,
                "harness_quality_score": 0.5,
                "status": "success",
            }
            for fn, cov in funcs
        ],
    }
    if target_name is not None:
        data["target_name"] = target_name
    f = d / "results.json"
    f.write_text(json.dumps(data))
    os.utime(f, (mtime, mtime))


def _client(ws: Path) -> TestClient:
    return TestClient(create_app(workspace=str(ws), serve_frontend=False))


def test_returns_this_targets_run_not_the_newest_overall(tmp_path):
    # older run for libfoo, NEWER run for libbar
    _write_run(tmp_path, "aaa", 1000.0, target_name="libfoo",
               file_prefix="libfoo", funcs=[("foo_parse", 40.0)])
    _write_run(tmp_path, "bbb", 2000.0, target_name="libbar",
               file_prefix="libbar", funcs=[("bar_read", 90.0)])
    c = _client(tmp_path)

    r = c.get("/api/coverage/libfoo")
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] == "aaa"                       # not the newer bbb
    assert body["avg_source_coverage"] == 40.0
    assert [t["func_name"] for t in body["targets"]] == ["foo_parse"]

    r = c.get("/api/coverage/libbar")
    assert r.json()["run_id"] == "bbb"


def test_legacy_run_without_target_name_matches_by_path_prefix(tmp_path):
    # No target_name field (older schema) — must match via file_path prefix.
    _write_run(tmp_path, "leg", 1000.0, target_name=None,
               file_prefix="libtiff", funcs=[("TIFFReadDirectory", 82.5)])
    c = _client(tmp_path)

    r = c.get("/api/coverage/libtiff")
    assert r.status_code == 200
    assert r.json()["run_id"] == "leg"


def test_lib_prefix_is_normalized(tmp_path):
    # Root-layout project: source files sit at the top with no lib/ dir.
    _write_run(tmp_path, "png", 1000.0, target_name=None,
               file_prefix="pngrutil", funcs=[("png_handle_iCCP", 91.2)])
    c = _client(tmp_path)

    assert c.get("/api/coverage/libpng").status_code == 200


def test_unknown_target_is_404(tmp_path):
    _write_run(tmp_path, "aaa", 1000.0, target_name="libfoo",
               file_prefix="libfoo", funcs=[("foo_parse", 40.0)])
    c = _client(tmp_path)

    assert c.get("/api/coverage/doesnotexist").status_code == 404
