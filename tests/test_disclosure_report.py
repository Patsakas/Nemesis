"""Tests for the coordinated-disclosure package generator (reporter.py)."""

from nemesis.reporter import (
    _hexdump,
    generate_disclosure_report,
    load_reproducer,
    save_disclosure_package,
    save_disclosure_report,
)


def _finding(**over):
    base = {
        "id": "NEMESIS-TEST-001",
        "library": "libexample",
        "function": "example_load_from_memory",
        "cwe": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
        "severity": "medium",
        "crash_location": "example_chunk_read at example.c:100",
        "root_cause": "chunk_size is attacker-controlled and advances buffer_ptr with no bounds check.",
        "asan_error": "global-buffer-overflow READ of size 4 at example.c:100:12",
        "call_chain": ["example_chunk_read at example.c:100:12", "main at fuzz.c:33"],
        "upstream_status": "up_to_date",
        "upstream_detail": "HEAD abc1234 == origin/master",
    }
    base.update(over)
    return base


# ── _hexdump ─────────────────────────────────────────────────────────────────


def test_hexdump_basic():
    dump = _hexdump(b"ABC\x00\xff")
    assert "00000000" in dump
    assert "41 42 43 00 ff" in dump
    assert "ABC.." in dump  # non-printables become dots


def test_hexdump_truncates():
    dump = _hexdump(b"A" * 600, max_bytes=512)
    assert "88 more bytes truncated" in dump


# ── load_reproducer ──────────────────────────────────────────────────────────


def test_load_reproducer_prefers_minimized(tmp_path):
    mn = tmp_path / "m.min"
    mn.write_bytes(b"MINI")
    cf = tmp_path / "raw"
    cf.write_bytes(b"RAWCRASH")
    data = load_reproducer(_finding(minimized_input=str(mn), crash_files=[str(cf)]))
    assert data == b"MINI"


def test_load_reproducer_falls_back_to_crash_file(tmp_path):
    cf = tmp_path / "raw"
    cf.write_bytes(b"RAWCRASH")
    data = load_reproducer(_finding(minimized_input="/nonexistent/x.min", crash_files=[str(cf)]))
    assert data == b"RAWCRASH"


def test_load_reproducer_none_when_missing():
    assert load_reproducer(_finding(crash_files=["/nope"])) is None


# ── generate_disclosure_report ───────────────────────────────────────────────


def test_disclosure_report_full_with_patch():
    patch = "--- a/example.c\n+++ b/example.c\n@@\n-old\n+if (ptr < end) new"
    md = generate_disclosure_report(_finding(), patch_diff=patch, reproducer=b"\x89PNG\x00")
    assert "# libexample: Out-of-bounds Read in `example_load_from_memory()`" in md
    assert "## Root Cause" in md
    assert "attacker-controlled" in md
    assert "## Minimized Reproducer" in md
    assert "5 bytes" in md
    assert "89 50 4e 47 00" in md            # hexdump of the reproducer
    assert "```diff" in md and "if (ptr < end) new" in md
    assert "latest upstream" in md            # up_to_date banner
    assert "coordinated disclosure" in md.lower()


def test_disclosure_report_without_patch_falls_back():
    md = generate_disclosure_report(_finding(), reproducer=b"AB")
    assert "```diff" not in md
    assert "No auto-generated patch attached" in md
    # root cause still surfaced in the fix section
    assert md.count("attacker-controlled") >= 1


def test_disclosure_report_behind_upstream_warns():
    md = generate_disclosure_report(
        _finding(upstream_status="behind",
                 upstream_detail="32 commits behind origin/master"),
        reproducer=b"AB",
    )
    assert "behind upstream" in md
    assert "32 commits behind" in md
    assert "verify" in md.lower()


def test_disclosure_report_handles_missing_reproducer():
    md = generate_disclosure_report(_finding(), reproducer=None)
    assert "Reproducer file not available" in md


def test_disclosure_report_autoloads_reproducer(tmp_path):
    mn = tmp_path / "r.min"
    mn.write_bytes(b"ZZZ")
    md = generate_disclosure_report(_finding(minimized_input=str(mn)))
    assert "3 bytes" in md
    assert "5a 5a 5a" in md  # 'ZZZ'


# ── save_disclosure_report ───────────────────────────────────────────────────


def test_save_disclosure_report_writes_file(tmp_path):
    md = generate_disclosure_report(_finding(), reproducer=b"AB")
    out = save_disclosure_report(md, "NEMESIS-TEST-001", reports_dir=tmp_path / "disc")
    assert out.exists()
    assert out.name == "NEMESIS-TEST-001.md"
    assert out.read_text(encoding="utf-8").startswith("# libexample:")


# ── save_disclosure_package ──────────────────────────────────────────────────


def test_package_writes_report_and_raw_poc(tmp_path):
    """The hexdump in the report is for reading; the maintainer reproduces
    from the raw bytes, so both must land on disk."""
    poc_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\xff\xff"
    src = tmp_path / "min.bin"
    src.write_bytes(poc_bytes)
    report, poc = save_disclosure_package(
        _finding(minimized_input=str(src)), reports_dir=tmp_path / "out",
    )
    assert report.name == "NEMESIS-TEST-001.md"
    assert poc is not None and poc.name == "NEMESIS-TEST-001.poc.bin"
    # Byte-for-byte — a re-encoded or truncated PoC doesn't reproduce.
    assert poc.read_bytes() == poc_bytes


def test_package_poc_is_not_truncated_by_hexdump_cap(tmp_path):
    """_hexdump caps at 512 bytes for readability. That cap must NOT reach the
    written PoC file, or a >512-byte reproducer silently stops reproducing."""
    poc_bytes = bytes(range(256)) * 4  # 1024 bytes
    src = tmp_path / "big.bin"
    src.write_bytes(poc_bytes)
    _, poc = save_disclosure_package(
        _finding(minimized_input=str(src)), reports_dir=tmp_path / "out",
    )
    assert poc is not None
    assert poc.read_bytes() == poc_bytes
    assert len(poc.read_bytes()) == 1024


def test_package_without_reproducer_still_writes_report(tmp_path):
    """Crash files often live on the machine that ran the fuzzer. The report
    still stands on the ASAN evidence — but there is no PoC to attach."""
    report, poc = save_disclosure_package(
        _finding(minimized_input=""), reports_dir=tmp_path / "out",
    )
    assert report.exists()
    assert poc is None
    assert "Reproducer file not available" in report.read_text(encoding="utf-8")


def test_package_prefers_minimized_over_raw_crash_file(tmp_path):
    """load_reproducer prefers the minimized input; the package must inherit
    that preference rather than shipping the un-minimized original."""
    minimized = tmp_path / "small.bin"
    minimized.write_bytes(b"SMALL")
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"A" * 5000)
    _, poc = save_disclosure_package(
        _finding(minimized_input=str(minimized), crash_files=[str(raw)]),
        reports_dir=tmp_path / "out",
    )
    assert poc is not None and poc.read_bytes() == b"SMALL"


def test_package_falls_back_to_crash_file(tmp_path):
    """No minimized input (minimizer failed/skipped) → ship the raw crash file
    rather than no PoC at all."""
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"RAWCRASH")
    _, poc = save_disclosure_package(
        _finding(minimized_input="", crash_files=[str(raw)]),
        reports_dir=tmp_path / "out",
    )
    assert poc is not None and poc.read_bytes() == b"RAWCRASH"


def test_package_passes_project_url_through(tmp_path):
    report, _ = save_disclosure_package(
        _finding(), project_url="https://github.com/example/libexample",
        reports_dir=tmp_path / "out",
    )
    assert "https://github.com/example/libexample" in report.read_text(encoding="utf-8")


def test_package_handles_finding_without_id(tmp_path):
    """A hand-written findings.yaml entry may lack an id — write something
    rather than crashing on a None filename."""
    f = _finding()
    del f["id"]
    report, _ = save_disclosure_package(f, reports_dir=tmp_path / "out")
    assert report.name == "UNKNOWN.md"
