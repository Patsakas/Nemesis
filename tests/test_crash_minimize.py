"""Tests for per-input crash minimization (CrashTriager.minimize_crash + helpers).

The delta-debug core (_ddmin) and signature fingerprint (_crash_signature) are
exercised without a real binary; the integration test monkeypatches _run_input to
simulate a target that crashes iff a marker byte-sequence is present.
"""
from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.fuzzing import CrashTriager
from nemesis.models import CWE, CrashReport, Severity

# ── _ddmin (pure delta-debug) ────────────────────────────────────────────────


def test_ddmin_reduces_to_marker():
    """Removes every byte not needed to keep the predicate true."""
    data = b"AAAABUGBBBBCCCC"

    def still(cand: bytes) -> bool:
        return b"BUG" in cand

    result = CrashTriager._ddmin(data, still)
    assert result == b"BUG"
    assert still(result)


def test_ddmin_no_reduction_when_all_needed():
    """If every byte matters, nothing is removed."""
    data = b"BUG"

    def still(cand: bytes) -> bool:
        return b"BUG" in cand

    assert CrashTriager._ddmin(data, still) == b"BUG"


def test_ddmin_respects_deadline():
    """A deadline already in the past returns the input unchanged."""
    data = b"AAAABUGBBBB"

    def still(cand: bytes) -> bool:
        return b"BUG" in cand

    # deadline in the past → no work performed
    assert CrashTriager._ddmin(data, still, deadline=1.0) == data


# ── _crash_signature (site fingerprint) ──────────────────────────────────────


def test_signature_none_on_clean_exit():
    assert CrashTriager._crash_signature(0, "") is None


def test_signature_extracts_class_and_frame():
    stderr = (
        "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50 ...\n"
        "READ of size 1 at 0x50 thread T0\n"
        "    #0 0xdead in parse_string /home/u/cjson_clean/cJSON.c:786:9\n"
        "    #1 0xbeef in parse_object /home/u/cjson_clean/cJSON.c:1665:14\n"
    )
    sig = CrashTriager._crash_signature(134, stderr)
    assert sig == ("heap-buffer-overflow", "cJSON.c:786:9")


def test_signature_skips_machinery_frames():
    """The abort/sanitizer machinery frames must not become the fault site."""
    stderr = (
        "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x00 ...\n"
        "    #0 0x1 in __asan_report_load1 /asan/asan_rtl.cpp:1\n"
        "    #1 0x2 in rpng_chunk_read_from_memory /home/u/rpng/src/rpng.h:1639:42\n"
    )
    sig = CrashTriager._crash_signature(139, stderr)
    assert sig == ("SEGV", "rpng.h:1639:42")


def test_signature_differs_across_sites():
    a = CrashTriager._crash_signature(
        134, "ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in f /a/x.c:10\n"
    )
    b = CrashTriager._crash_signature(
        134, "ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in g /a/x.c:20\n"
    )
    assert a != b


# ── minimize_crash (integration, monkeypatched binary) ───────────────────────


_FAKE_ASAN = (
    "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 ...\n"
    "    #0 0xabc in parse /home/u/lib/foo.c:42:5\n"
)


def _make_triager(tmp_path: Path) -> CrashTriager:
    cfg = NemesisConfig()
    cfg.target.minimize_crashes = True
    cfg.target.minimize_max_bytes = 65536
    cfg.target.minimize_timeout_s = 0  # no wall-clock cap in tests
    tri = CrashTriager(cfg)
    tri.crashes_dir = tmp_path / "crashes"
    tri.crashes_dir.mkdir(parents=True, exist_ok=True)
    # minimize_crash only checks the binary path exists; _run_input is patched.
    fake_bin = tmp_path / "fuzz_nemesis_debug"
    fake_bin.write_bytes(b"\x7fELF-fake")
    tri.unpatched_binary = fake_bin
    return tri


def test_minimize_crash_writes_minimized_and_sets_field(tmp_path, monkeypatch):
    tri = _make_triager(tmp_path)

    # Fake target: crashes (same site) iff the marker survives.
    def fake_run(data: bytes, timeout_s: int = 10):
        if b"BUG" in data:
            return 134, _FAKE_ASAN
        return 0, ""

    monkeypatch.setattr(tri, "_run_input", fake_run)

    # NB: real AFL names contain ':' but that is invalid on Windows (dev box);
    # the minimizer is name-agnostic so use a portable name in tests.
    crash = tri.crashes_dir / "id_000000_sig06"
    crash.write_bytes(b"xxxxxxxxBUGyyyyyyyy")

    report = CrashReport(
        input_file=str(crash),
        crash_location="parse at foo.c:42",
        cwe=CWE.HEAP_OVERFLOW,
        severity=Severity.HIGH,
    )
    out = tri.minimize_crash(crash, report)

    assert out is not None and out.exists()
    assert out.read_bytes() == b"BUG"
    assert report.minimized_input == str(out)
    assert out.parent.name == "minimized"


def test_minimize_crash_skips_when_disabled(tmp_path, monkeypatch):
    tri = _make_triager(tmp_path)
    tri.config.target.minimize_crashes = False
    monkeypatch.setattr(tri, "_run_input", lambda d, timeout_s=10: (134, _FAKE_ASAN))

    crash = tri.crashes_dir / "id_1"
    crash.write_bytes(b"BUG")
    report = CrashReport(input_file=str(crash), crash_location="x", cwe=CWE.HEAP_OVERFLOW, severity=Severity.HIGH)
    assert tri.minimize_crash(crash, report) is None
    assert report.minimized_input is None


def test_minimize_crash_skips_oversized_input(tmp_path, monkeypatch):
    tri = _make_triager(tmp_path)
    tri.config.target.minimize_max_bytes = 8
    monkeypatch.setattr(tri, "_run_input", lambda d, timeout_s=10: (134, _FAKE_ASAN))

    crash = tri.crashes_dir / "id_2"
    crash.write_bytes(b"BUG" + b"Z" * 100)
    report = CrashReport(input_file=str(crash), crash_location="x", cwe=CWE.HEAP_OVERFLOW, severity=Severity.HIGH)
    assert tri.minimize_crash(crash, report) is None
    assert report.minimized_input is None


def test_minimize_crash_noop_when_not_reproducible(tmp_path, monkeypatch):
    tri = _make_triager(tmp_path)
    # Binary never crashes → nothing to anchor on.
    monkeypatch.setattr(tri, "_run_input", lambda d, timeout_s=10: (0, ""))

    crash = tri.crashes_dir / "id_3"
    crash.write_bytes(b"BUGpadding")
    report = CrashReport(input_file=str(crash), crash_location="x", cwe=CWE.HEAP_OVERFLOW, severity=Severity.HIGH)
    assert tri.minimize_crash(crash, report) is None
    assert report.minimized_input is None
