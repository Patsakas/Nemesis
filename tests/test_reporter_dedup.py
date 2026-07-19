"""Tests for reporter crash dedup + library derivation (audit Batch 1).

Regression guard: merge_crash_reports previously deduped by function name
ALONE, collapsing distinct bugs in the same function into a single finding.
It now keys on (function, crash_location).
"""
from nemesis.models import CWE, CrashReport, Severity
from nemesis.reporter import (
    _crash_dedup_key,
    _derive_library,
    _finding_dedup_key,
    merge_crash_reports,
)


def _crash(loc, cwe=CWE.HEAP_OVERFLOW, sev=Severity.HIGH, **kw):
    return CrashReport(input_file="in.bin", crash_location=loc, cwe=cwe,
                       severity=sev, **kw)


def test_distinct_locations_same_function_are_separate_findings():
    # Two genuinely different bugs in the same function (different crash sites).
    crashes = [
        _crash("cJSON.c:120", cwe=CWE.HEAP_OVERFLOW),
        _crash("cJSON.c:355", cwe=CWE.USE_AFTER_FREE),
    ]
    out = merge_crash_reports([], crashes, "run1", "cJSON_Parse", "cJSON.c")
    assert len(out) == 2, "distinct crash sites must yield distinct findings"
    cwes = {f["cwe"] for f in out}
    assert cwes == {"CWE-122", "CWE-416"}


def test_same_location_dedups_to_one():
    crashes = [_crash("cJSON.c:120"), _crash("cJSON.c:120")]
    out = merge_crash_reports([], crashes, "run1", "cJSON_Parse", "cJSON.c")
    assert len(out) == 1


def test_locationless_distinct_cwe_stays_separate():
    # No parsed location → fall back to (function, cwe) so bug classes don't merge.
    crashes = [
        _crash("", cwe=CWE.HEAP_OVERFLOW),
        _crash("", cwe=CWE.OUT_OF_BOUNDS_READ),
    ]
    out = merge_crash_reports([], crashes, "run1", "f", "lib/f.c")
    assert len(out) == 2


def test_cwe_upgrade_same_location_preserved():
    # Existing finding with unknown CWE at a location; a known-CWE crash at the
    # SAME location should upgrade (not duplicate).
    existing = merge_crash_reports([], [_crash("png.c:88", cwe=CWE.UNKNOWN)],
                                   "run1", "png_read", "libpng/png.c")
    assert existing[0]["cwe"] == "CWE-unknown"
    after = merge_crash_reports(existing, [_crash("png.c:88", cwe=CWE.HEAP_OVERFLOW)],
                               "run2", "png_read", "libpng/png.c")
    assert len(after) == 1, "same location must upgrade, not duplicate"
    assert after[0]["cwe"] == "CWE-122"


def test_dedup_keys_match_between_crash_and_finding():
    c = _crash("a.c:10")
    out = merge_crash_reports([], [c], "r", "fn", "lib/a.c")
    assert _crash_dedup_key("fn", c) == _finding_dedup_key(out[0])


def test_derive_library():
    assert _derive_library("libarchive/archive_read.c", None) == "libarchive"
    # Bare filename → stem (never "unknown" when a real token exists).
    assert _derive_library("cJSON.c", None) == "cjson"
    # Absolute path: the library dir sits next to the file, leading segments
    # (home/<user>) are filesystem noise and must be skipped.
    assert _derive_library("/home/u/libpng/png.c", None) == "libpng"
    # Generic "src" dir skipped → filename stem.
    assert _derive_library("C:\\src\\png.c", None) == "png"
    # A generic token passed as the explicit library is rejected, not trusted.
    assert _derive_library("lib/xmlparse.c", "lib") == "xmlparse"
    assert _derive_library("anything.c", "cjson") == "cjson"      # explicit wins
