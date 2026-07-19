"""Dropping UBSan `alignment` unmasks the real OOB read so the triager records
CWE-125 instead of generic CWE-758 (an alignment-UB mis-classification)."""
from types import SimpleNamespace

from nemesis.config import load_config
from nemesis.models import CWE
from nemesis.symbolic import _resolve_sanitizer_flags
from nemesis.fuzzing import CrashTriager


def _cfg(profile="asan_ubsan"):
    return SimpleNamespace(target=SimpleNamespace(
        sanitizer_profile=profile, msan_supported=True, tsan_supported=True))


def test_asan_ubsan_drops_alignment():
    flags = _resolve_sanitizer_flags(_cfg("asan_ubsan"))
    assert "-fno-sanitize=alignment" in flags
    assert "-fsanitize=address,undefined" in flags


def test_asan_ubsan_strict_drops_alignment():
    flags = _resolve_sanitizer_flags(_cfg("asan_ubsan_strict"))
    assert "-fno-sanitize=alignment" in flags


def test_msan_tsan_do_not_add_alignment():
    # alignment-off is UBSan-specific; don't bolt it onto msan/tsan builds.
    assert "alignment" not in _resolve_sanitizer_flags(_cfg("msan"))
    assert "alignment" not in _resolve_sanitizer_flags(_cfg("tsan"))


# Real ASAN report once `alignment` is off:
UNMASKED_OOB = """\
==26532==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50b0000004d4
READ of size 4 at 0x50b0000004d4 thread T0
    #0 0x... in example_chunk_read /src/example.c:100:12
SUMMARY: AddressSanitizer: heap-buffer-overflow example.c:100:12 in example_chunk_read
"""

# What it looked like BEFORE the fix — UBSan masks it as a misaligned load:
MASKED_ALIGNMENT = """\
/src/example.c:120:9: runtime error: load of misaligned address \
0x... for type 'unsigned int', which requires 4 byte alignment
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior example.c:120:9
"""


def test_unmasked_oob_read_classifies_as_cwe125():
    tri = CrashTriager(load_config())
    assert tri._classify_cwe(UNMASKED_OOB) == CWE.OUT_OF_BOUNDS_READ


def test_masked_alignment_would_have_been_generic_ub():
    # documents the OLD behavior the build fix avoids (alignment UB → not OOB)
    tri = CrashTriager(load_config())
    assert tri._classify_cwe(MASKED_ALIGNMENT) != CWE.OUT_OF_BOUNDS_READ
