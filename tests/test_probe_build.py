"""
Tests for probe-binary construction.

The probe binary is what makes offline analysis possible at all: the fuzzing
harness is AFL++ persistent mode with shared-memory test cases and receives no
input outside afl-fuzz, so probing it reports that no byte matters — a
plausible-looking zero rather than an error.

Most of these are source-level checks, because the two failure modes that cost
real time are both source/flag issues rather than logic:
  - a stub that only #defines the AFL macros loses to afl-clang-fast's own
    definitions and the binary quietly reverts to shared-memory mode;
  - omitting the library's sanitizer flags from the link line produces
    `undefined reference to __asan_report_load4`, which reads like an AFL
    problem and is not.

The compile test runs only where afl-clang-fast exists (i.e. the Linux/WSL
environment NEMESIS actually runs in).
"""

import shutil

import pytest

from nemesis.recon.probe_build import (
    PROBE_SANITIZER_FLAGS,
    PROBE_STUB_HEADER,
    _fingerprint,
    _is_cpp_harness,
    build_probe_binary,
    probe_source_for,
)

HARNESS = """\
#include <stdint.h>
#include <stdlib.h>
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        if (len > 0 && buf[0] == 'A') return 0;
    }
    return 0;
}
"""


# ── Stub header contents ────────────────────────────────────


@pytest.mark.parametrize("macro", [
    "__AFL_FUZZ_INIT", "__AFL_INIT", "__AFL_LOOP",
    "__AFL_FUZZ_TESTCASE_LEN", "__AFL_FUZZ_TESTCASE_BUF",
])
def test_every_afl_macro_is_undefd_before_redefinition(macro):
    """CRITICAL: afl-clang-fast defines these itself. A stub that only #defines
    them loses, and the binary silently goes back to shared-memory mode — which
    looks like "no bytes are influential" rather than like a build problem."""
    undef_at = PROBE_STUB_HEADER.index(f"#undef {macro}")
    define_at = PROBE_STUB_HEADER.index(f"#define {macro}")
    assert undef_at < define_at, f"{macro} redefined before being undef'd"


def test_stub_reads_stdin_once():
    """Persistent mode loops; a probe must consume its input exactly once and
    then let __AFL_LOOP go false, or showmap never terminates."""
    assert "fread" in PROBE_STUB_HEADER
    assert "stdin" in PROBE_STUB_HEADER
    assert "__nm_probe_called++ == 0" in PROBE_STUB_HEADER


def test_stub_symbols_do_not_collide_with_the_reproduction_stub():
    """symbolic/__init__.py ships a similar stub using __afl_stub_* names. If
    both headers ever land in one TU, identical names would be a redefinition
    error, so this one is deliberately prefixed differently."""
    assert "__afl_stub_buf" not in PROBE_STUB_HEADER
    assert "__nm_probe_buf" in PROBE_STUB_HEADER


def test_sanitizer_flags_are_present():
    """Linking against the ASan-built library without these yields
    `undefined reference to __asan_report_load4`."""
    assert "-fsanitize=address" in PROBE_SANITIZER_FLAGS


# ── probe_source_for ────────────────────────────────────────


def test_probe_source_prepends_stub_and_keeps_harness():
    out = probe_source_for(HARNESS)
    assert out.startswith("/* NEMESIS probe stub")
    assert "__AFL_FUZZ_INIT();" in out          # original harness body intact
    assert out.index("#undef __AFL_LOOP") < out.index("int main(void)")


def test_probe_source_does_not_edit_the_harness_body():
    """The fuzz harness is not modified — the probe is a second artifact built
    from the same source, so the two cannot drift."""
    out = probe_source_for(HARNESS)
    assert HARNESS in out


# ── C++ detection ───────────────────────────────────────────


@pytest.mark.parametrize("source", [
    "std::string s;", "namespace foo {}", '#include <vector>',
])
def test_cpp_harness_detected(source):
    assert _is_cpp_harness(source) is True


def test_plain_c_harness_not_detected_as_cpp():
    assert _is_cpp_harness(HARNESS) is False


def test_cpp_detected_from_extra_flags():
    assert _is_cpp_harness("int main(void){}", extra_flags="-std=c++17") is True


# ── Build caching ───────────────────────────────────────────


def test_fingerprint_changes_with_source(tmp_path):
    a = _fingerprint("int main(){}", None, "")
    b = _fingerprint("int main(){return 1;}", None, "")
    assert a != b


def test_fingerprint_changes_when_library_is_rebuilt(tmp_path):
    """A rebuilt library with unchanged harness source is still a different
    program — a cached probe would measure the previous one."""
    lib = tmp_path / "lib.a"
    lib.write_bytes(b"v1")
    first = _fingerprint("src", lib, "")
    lib.write_bytes(b"version two, longer")
    assert _fingerprint("src", lib, "") != first


def test_fingerprint_changes_with_link_line(tmp_path):
    assert _fingerprint("src", None, "-lm") != _fingerprint("src", None, "-lz")


def test_fingerprint_is_stable_for_identical_inputs(tmp_path):
    lib = tmp_path / "lib.a"
    lib.write_bytes(b"same")
    assert _fingerprint("src", lib, "-lm") == _fingerprint("src", lib, "-lm")


# ── build_probe_binary failure handling ─────────────────────
#
# Probing is an optimisation over the LLM path; every failure must return None
# rather than raise, or a build problem costs the run its seeds.


def test_missing_harness_source_returns_none(tmp_path):
    assert build_probe_binary(tmp_path / "nope.c", None, tmp_path / "out") is None


def test_missing_compiler_returns_none(tmp_path, monkeypatch):
    src = tmp_path / "h.c"
    src.write_text(HARNESS)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert build_probe_binary(src, None, tmp_path / "out") is None


def test_compile_failure_returns_none(tmp_path):
    if shutil.which("afl-clang-fast") is None:
        pytest.skip("afl-clang-fast not installed")
    src = tmp_path / "bad.c"
    src.write_text("this is not C at all ((( \n")
    assert build_probe_binary(src, None, tmp_path / "out") is None


# ── Real compile ────────────────────────────────────────────

needs_afl = pytest.mark.skipif(
    shutil.which("afl-clang-fast") is None, reason="afl-clang-fast not installed"
)


@needs_afl
def test_builds_a_working_probe(tmp_path):
    src = tmp_path / "h.c"
    src.write_text(HARNESS)
    binary = build_probe_binary(src, None, tmp_path / "out")
    assert binary is not None and binary.exists()


@needs_afl
def test_second_build_is_cached(tmp_path):
    src = tmp_path / "h.c"
    src.write_text(HARNESS)
    first = build_probe_binary(src, None, tmp_path / "out")
    assert first is not None
    mtime = first.stat().st_mtime_ns
    second = build_probe_binary(src, None, tmp_path / "out")
    assert second == first
    assert second.stat().st_mtime_ns == mtime      # not recompiled


@needs_afl
def test_changed_harness_forces_a_rebuild(tmp_path):
    src = tmp_path / "h.c"
    src.write_text(HARNESS)
    first = build_probe_binary(src, None, tmp_path / "out")
    src.write_text(HARNESS.replace("'A'", "'B'"))
    second = build_probe_binary(src, None, tmp_path / "out")
    assert first is not None and second is not None
    assert second != first


@needs_afl
def test_probe_discriminates_inputs_under_showmap(tmp_path):
    """The whole point. The persistent binary reports the same map for every
    input; the probe must not. Without this the algorithm silently measures
    nothing — which is exactly what happened on cJSON before probe binaries
    existed."""
    import subprocess

    if shutil.which("afl-showmap") is None:
        pytest.skip("afl-showmap not installed")

    src = tmp_path / "h.c"
    src.write_text(HARNESS)
    binary = build_probe_binary(src, None, tmp_path / "out")
    assert binary is not None

    def edges(data: bytes) -> set[str]:
        inp = tmp_path / "in.bin"
        inp.write_bytes(data)
        out_map = tmp_path / "m.map"
        with open(inp, "rb") as fh:
            subprocess.run(
                ["afl-showmap", "-o", str(out_map), "-q", "--", str(binary)],
                stdin=fh, capture_output=True, timeout=30,
            )
        if not out_map.exists():
            return set()
        return {ln.split(":", 1)[0] for ln in
                out_map.read_text(errors="replace").splitlines() if ":" in ln}

    # The harness branches on buf[0] == 'A'.
    assert edges(b"AAAA") != edges(b"BBBB"), (
        "probe binary reports identical coverage for different inputs — "
        "it is not receiving the test case"
    )
