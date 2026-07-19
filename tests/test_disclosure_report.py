"""Tests for the coordinated-disclosure package generator (reporter.py)."""

from nemesis.reporter import (
    _hexdump,
    generate_disclosure_report,
    load_reproducer,
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
