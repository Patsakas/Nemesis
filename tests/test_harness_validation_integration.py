"""
Integration guard: the validator must sit ON the execution path, not beside it.

`tests/test_variadic_arity_gate.py` proved the checker works when called. It
passed 23 of 23 while the real pipeline logged **zero** validation events,
because the gate had been wired into `_compile_harness_with_repair` and the
harness-variant path calls `InstrumentedBuilder.build_harness` directly. Unit
correctness without integration correctness: the component was right and
unreachable.

These tests assert the property the unit tests cannot — that an unsound harness
cannot become a binary by any route — by driving the real `build_harness` and
checking both the refusal and the fact that the gate was consulted at all.
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.models import HarnessSpec
from nemesis.symbolic import InstrumentedBuilder

VARIADIC_HEADER = """\
#ifndef LIBFOO_H
#define LIBFOO_H
bool foo_scan(const char *sentence, const char *format, ...);
int  foo_parse(const char *sentence, size_t len);
#endif
"""

UNSOUND = """\
#include "libfoo.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        char *buf = (char *)__AFL_FUZZ_TESTCASE_BUF;
        const char *formats[] = {"t", "tciiiiiiiiiiiiifff"};
        for (int i = 0; i < 2; i++)
            foo_scan(buf, formats[i], &a, &b, &c);
    }
    return 0;
}
"""

SOUND = """\
#include "libfoo.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        char *buf = (char *)__AFL_FUZZ_TESTCASE_BUF;
        foo_scan(buf, "tcf", &a, &b, &c);
    }
    return 0;
}
"""


@pytest.fixture
def builder(tmp_path: Path) -> InstrumentedBuilder:
    src = tmp_path / "src"
    src.mkdir()
    (src / "libfoo.h").write_text(VARIADIC_HEADER)
    (src / "libfoo.c").write_text("int foo_parse(const char *s, size_t n) { return 0; }\n")
    cfg = NemesisConfig()
    cfg.target.source_root = str(src)
    cfg.target.build_dir = str(tmp_path / "build")
    return InstrumentedBuilder(cfg)


def _spec(code: str, func: str = "foo_scan") -> HarnessSpec:
    return HarnessSpec(target_func=func, input_format="text", c_code=code)


# ── the property that was violated ──────────────────────────


def test_unsound_harness_never_becomes_a_binary(builder, tmp_path, capsys):
    """Refusal happens *before* anything is compiled.

    Checking only the False return would pass for the wrong reason — this
    harness would fail to compile anyway — so it also asserts no compile was
    attempted. Verified by removing the gate: without it this assertion is the
    one that fires.
    """
    build_dir = tmp_path / "build"
    assert builder.build_harness(_spec(UNSOUND), build_dir) is False
    assert not (build_dir / "fuzz_nemesis").exists()
    out = capsys.readouterr().out
    assert "harness.compile.start" not in out, \
        "rejected before compiling, not after a failed compile"


def test_gate_is_consulted_by_the_real_build_path(builder, tmp_path, monkeypatch):
    """Asserts the *call*, not the checker. This is the assertion whose absence
    let a fully-tested gate sit unreachable for an entire run."""
    calls = []
    original = builder._variadic_arity_ok
    monkeypatch.setattr(builder, "_variadic_arity_ok",
                        lambda h: calls.append(h.target_func) or original(h))
    builder.build_harness(_spec(UNSOUND), tmp_path / "build")
    assert calls == ["foo_scan"]


def test_rejection_states_the_reason(builder, tmp_path, capsys):
    builder.build_harness(_spec(UNSOUND), tmp_path / "build")
    out = capsys.readouterr().out
    assert "variadic_arity_rejected" in out
    assert "false positive" in out          # the impact, not just the fact


# ── guards against over-blocking ────────────────────────────


def test_sound_variadic_harness_is_not_rejected_by_the_gate(builder):
    assert builder._variadic_arity_ok(_spec(SOUND)) is True


def test_non_variadic_target_is_not_gated(builder):
    """foo_parse takes a fixed argument list; the gate must not touch it."""
    code = SOUND.replace("foo_scan(buf, \"tcf\", &a, &b, &c);",
                         "foo_parse(buf, len);")
    assert builder._variadic_arity_ok(_spec(code, "foo_parse")) is True


def test_unknown_target_is_not_gated(builder):
    """No declaration found means no basis to reject."""
    assert builder._variadic_arity_ok(_spec(SOUND, "not_in_this_project")) is True


# ── single source of truth for the declaration ──────────────


def test_symbolic_stage_delegates_declaration_lookup(tmp_path):
    """Two implementations of "where does this live" is what cost a whole
    libnmea campaign when the library resolvers diverged. The stage must
    delegate to the builder, not keep a copy."""
    from nemesis.symbolic import SymbolicStage
    src = tmp_path / "src"
    src.mkdir()
    (src / "libfoo.h").write_text(VARIADIC_HEADER)
    cfg = NemesisConfig()
    cfg.target.source_root = str(src)
    stage = SymbolicStage(cfg)
    assert stage._target_declaration("foo_scan") is \
        stage.builder.target_declaration("foo_scan")
    assert "..." in stage._target_declaration("foo_scan")


def test_declaration_lookup_is_cached(builder):
    first = builder.target_declaration("foo_scan")
    assert builder.target_declaration("foo_scan") is first
