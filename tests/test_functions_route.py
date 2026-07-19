"""Pinning from the dashboard must not damage hand-written target configs, and
the Introspector payload must be normalized into real source symbol names."""
import os

import pytest
from fastapi.testclient import TestClient

from nemesis.api.app import create_app
from nemesis.api.routes.functions import _from_introspector

CONFIG_WITH_COMMENTS = """\
# libfoo target config — hand written, comments must survive
target:
  name: libfoo
  oss_fuzz_project: libfoo
  # Functions pinned by hand, with tuning we must not lose
  pinned_funcs:
    - func_name: foo_parse_header
      file_path: parse.c
      line: 120
      indirect_reach: true
      # NOTE: reached only via the public API, do not call directly
  build:
    make: "make -j4"   # keep this inline comment
"""


def _mk(tmp_path, text=CONFIG_WITH_COMMENTS):
    (tmp_path / "config" / "targets").mkdir(parents=True)
    (tmp_path / "config" / "targets" / "libfoo.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "config" / "default.yaml").write_text("engine: {}\n", encoding="utf-8")
    return tmp_path / "config" / "targets" / "libfoo.yaml"


@pytest.fixture()
def client_in(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return TestClient(create_app(workspace=str(tmp_path / "ws"), serve_frontend=False))


# ── Introspector normalization ───────────────────────────────


def test_strips_oss_fuzz_prefix_and_drops_foreign_files():
    raw = [
        {"function_name": "OSS_FUZZ_foo_parse", "function_filename": "/src/libfoo/parse.c",
         "runtime_coverage_percent": 42.0, "source_line_begin": 10},
        {"function_name": "std::length_error", "function_filename": "/usr/include/c++/stdexcept",
         "runtime_coverage_percent": 0.0},
    ]
    out = _from_introspector(raw, "libfoo")
    assert [f.func_name for f in out] == ["foo_parse"]     # prefix stripped
    assert out[0].file_path == "parse.c"                    # /src/libfoo/ trimmed
    assert out[0].oss_fuzz_coverage_pct == 42.0


def test_excludes_the_projects_own_fuzz_harness():
    """OSS-Fuzz ships its harness inside the project tree; it must not be offered
    as a fuzz target (same exclusions recon applies)."""
    raw = [
        {"function_name": "png_handle_iCCP", "function_filename": "/src/libpng/pngrutil.c",
         "runtime_coverage_percent": 91.0},
        {"function_name": "PngObjectHandler", "runtime_coverage_percent": 0.0,
         "function_filename": "/src/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc"},
        {"function_name": "helper", "function_filename": "/src/libpng/test/harness.c",
         "runtime_coverage_percent": 0.0},
    ]
    out = _from_introspector(raw, "libpng", {"test", "contrib", "build"}, ["fuzz_*.c"])
    assert [f.func_name for f in out] == ["png_handle_iCCP"]


def test_prefixed_and_unprefixed_twins_keep_the_better_coverage():
    raw = [
        {"function_name": "foo_x", "function_filename": "/src/libfoo/a.c",
         "runtime_coverage_percent": 10.0},
        {"function_name": "OSS_FUZZ_foo_x", "function_filename": "/src/libfoo/a.c",
         "runtime_coverage_percent": 90.0},
    ]
    out = _from_introspector(raw, "libfoo")
    assert len(out) == 1 and out[0].oss_fuzz_coverage_pct == 90.0


# ── Pin writing ──────────────────────────────────────────────


def test_pinning_preserves_comments_and_existing_tuning(tmp_path, client_in):
    cfg = _mk(tmp_path)
    before = cfg.read_text(encoding="utf-8")

    r = client_in.put("/api/targets/libfoo/pins", json={"pins": [
        {"func_name": "foo_parse_header", "file_path": "parse.c", "line": 120},
        {"func_name": "foo_read_chunk", "file_path": "read.c", "line": 55},
    ]})
    assert r.status_code == 200, r.text
    assert r.json()["pinned_count"] == 2

    after = cfg.read_text(encoding="utf-8")
    # every comment survives
    assert "# libfoo target config" in after
    assert "# Functions pinned by hand" in after
    assert "# NOTE: reached only via the public API" in after
    assert "keep this inline comment" in after
    assert before.count("#") == after.count("#")
    # the pre-existing entry keeps its hand-tuned field
    assert "indirect_reach: true" in after
    # the new pin was added
    assert "foo_read_chunk" in after


def test_unpinning_removes_only_that_entry(tmp_path, client_in):
    cfg = _mk(tmp_path)
    client_in.put("/api/targets/libfoo/pins", json={"pins": [
        {"func_name": "foo_parse_header"},
        {"func_name": "foo_read_chunk", "file_path": "read.c", "line": 55},
    ]})
    r = client_in.put("/api/targets/libfoo/pins", json={"pins": [
        {"func_name": "foo_read_chunk", "file_path": "read.c", "line": 55},
    ]})
    assert r.status_code == 200 and r.json()["pinned_count"] == 1

    after = cfg.read_text(encoding="utf-8")
    assert "foo_read_chunk" in after
    assert "foo_parse_header" not in after
    assert "# libfoo target config" in after      # comments still intact


def test_unpinning_everything_leaves_an_empty_list(tmp_path, client_in):
    cfg = _mk(tmp_path)
    r = client_in.put("/api/targets/libfoo/pins", json={"pins": []})
    assert r.status_code == 200 and r.json()["pinned_count"] == 0
    assert "foo_parse_header" not in cfg.read_text(encoding="utf-8")


def test_config_without_pinned_funcs_gets_the_key_created(tmp_path, client_in):
    cfg = _mk(tmp_path, "# no pins yet\ntarget:\n  name: libfoo\n")
    r = client_in.put("/api/targets/libfoo/pins",
                      json={"pins": [{"func_name": "foo_new", "file_path": "a.c", "line": 1}]})
    assert r.status_code == 200
    text = cfg.read_text(encoding="utf-8")
    assert "pinned_funcs:" in text and "foo_new" in text
    assert "# no pins yet" in text


def test_advanced_options_are_written_and_cleared(tmp_path, client_in):
    cfg = _mk(tmp_path)
    # set a few knobs
    r = client_in.put("/api/targets/libfoo/pins", json={"pins": [{
        "func_name": "foo_read_chunk", "file_path": "read.c", "line": 55,
        "differential_oracle": True, "harness_hint": "feed it a full frame",
        "needed_headers": ["foo.h", "foo_internal.h"],
    }]})
    assert r.status_code == 200
    after = cfg.read_text(encoding="utf-8")
    assert "differential_oracle: true" in after
    assert "feed it a full frame" in after
    assert "foo_internal.h" in after
    # defaults are not written as noise
    assert "threaded_oracle" not in after

    # explicitly turning it back off removes the key again
    r = client_in.put("/api/targets/libfoo/pins", json={"pins": [{
        "func_name": "foo_read_chunk", "file_path": "read.c", "line": 55,
        "differential_oracle": False, "harness_hint": "",
    }]})
    assert r.status_code == 200
    after = cfg.read_text(encoding="utf-8")
    assert "differential_oracle" not in after
    assert "feed it a full frame" not in after
    assert "foo_internal.h" in after      # untouched key survives


def test_bare_pin_does_not_wipe_hand_tuned_options(tmp_path, client_in):
    """A client that PUTs only {func_name} must not clear existing YAML tuning."""
    cfg = _mk(tmp_path)
    client_in.put("/api/targets/libfoo/pins",
                  json={"pins": [{"func_name": "foo_parse_header"}]})
    after = cfg.read_text(encoding="utf-8")
    assert "indirect_reach: true" in after
    assert "# NOTE: reached only via the public API" in after


def test_pin_options_are_reported_for_functions_absent_from_introspector(tmp_path, client_in):
    """Static/internal functions never appear in the Introspector payload; they are
    appended from the config and must still carry their tuning to the UI."""
    _mk(tmp_path)
    r = client_in.get("/api/targets/libfoo/functions")
    assert r.status_code == 200
    pinned = [f for f in r.json()["functions"] if f["pinned"]]
    assert pinned, "the configured pin should be surfaced even with no Introspector data"
    assert pinned[0]["func_name"] == "foo_parse_header"
    assert pinned[0]["pin_options"]["indirect_reach"] is True


def test_unknown_target_is_404(tmp_path, client_in):
    _mk(tmp_path)
    assert client_in.put("/api/targets/nope/pins", json={"pins": []}).status_code == 404
    assert client_in.get("/api/targets/nope/functions").status_code == 404
