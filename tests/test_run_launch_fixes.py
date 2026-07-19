"""Three failures seen in a real cjson run, each with a regression test:

1. The `current` findings symlink aborted the whole pipeline on Windows.
2. An unset `coverage_build_dir` became `Path(".")`, so the coverage build ran
   cmake against whatever the cwd happened to be and line coverage was never
   measured.
3. The seedgen prompt invited "any stdlib import" while the sandbox allowed ten
   modules — a JSON generator for a JSON parser was rejected for `import json`.
"""
from pathlib import Path

from nemesis.recon.seedgen import (
    _SCRIPT_ALLOWED_IMPORTS,
    _render_system_prompt,
    _script_ast_is_safe,
)

# ── 2. coverage build directory ──────────────────────────────


def test_empty_path_is_not_a_usable_build_dir():
    """The trap: Path("") is Path("."), which is truthy as a string."""
    assert str(Path("")) == "."
    assert bool(str(Path("")))          # why the old `not str(...)` guard never fired


def test_coverage_build_is_skipped_when_unconfigured(tmp_path, monkeypatch):
    """An unset coverage_build_dir must skip the build, not run cmake in the cwd."""
    from nemesis.symbolic import SymbolicStage

    class _Build:
        coverage_configure = "cmake .. -DCMAKE_BUILD_TYPE=Debug"
        coverage_make = "make"
        debug_make = "make"

    class _Target:
        coverage_build_dir = Path("")     # unset in the target YAML
        build = _Build()

    class _Cfg:
        target = _Target()

    builder = SymbolicStage.__new__(SymbolicStage)
    builder.config = _Cfg()

    calls = []

    class _Log:
        def info(self, *a, **k): calls.append(("info", a, k))
        def error(self, *a, **k): calls.append(("error", a, k))
        def warning(self, *a, **k): calls.append(("warning", a, k))
        def debug(self, *a, **k): calls.append(("debug", a, k))

    builder.log = _Log()

    monkeypatch.chdir(tmp_path)
    assert builder.build_coverage_library() is False
    # skipped cleanly — no error, and no cmake was attempted
    assert any(a and a[0] == "coverage.not_configured" for _, a, _ in calls)
    assert not any(lvl == "error" for lvl, _, _ in calls)


# ── 3. seedgen sandbox vs prompt ─────────────────────────────


def test_json_generator_is_accepted():
    ok, why = _script_ast_is_safe("import sys, random, json\nprint(json.dumps({'a': 1}))")
    assert ok, why


def test_sandbox_still_blocks_dangerous_imports_and_calls():
    for script, needle in [
        ("import os\nos.system('id')", "os"),
        ("import subprocess", "subprocess"),
        ("import socket", "socket"),
        ("x = eval('1')", "eval"),
        ("y = ().__class__", "dunder"),
    ]:
        ok, why = _script_ast_is_safe(script)
        assert not ok, f"{script!r} should be rejected"
        assert needle in why


def test_prompt_advertises_exactly_what_the_sandbox_allows():
    """The mismatch is what wasted the LLM call, so keep the two in lockstep."""
    rendered = _render_system_prompt()
    assert "{allowed_imports}" not in rendered      # placeholder was filled
    for mod in _SCRIPT_ALLOWED_IMPORTS:
        assert mod in rendered, f"{mod} missing from the prompt"
    # and it no longer promises the whole standard library
    assert "any other stdlib imports" not in rendered
