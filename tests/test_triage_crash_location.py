"""Triager must record the REAL fault site, not the abort/sanitizer machinery
frame — where crash_location would otherwise be '__pthread_kill' instead of the
actual heap-overflow line."""
from nemesis.config import load_config
from nemesis.fuzzing import CrashTriager


def _triager():
    return CrashTriager(load_config())

# Representative ASAN report for an OOB-read reproduction.
ASAN = """\
=================================================================
==26387==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50b0000004d4 at pc 0x561c8c192f64 bp 0x7ffe8c583540 sp 0x7ffe8c583538
READ of size 4 at 0x50b0000004d4 thread T0
    #0 0x561c8c192f63 in example_chunk_read /src/example.c:100:12
    #1 0x561c8c19017c in example_load_from_memory /src/example.c:80:34
    #2 0x561c8c19ce50 in main /tmp/x/repro.c:11:17
    #3 0x7f4d4f6411c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

0x50b0000004d4 is located 1071 bytes after 101-byte region [0x50b000000040,0x50b0000000a5)
allocated by thread T0 here:
    #0 0x561c8c1511d3 in malloc (/tmp/x/repro+0xc71d3)
    #1 0x561c8c19cdf7 in main /tmp/x/repro.c:8:17
"""

# GDB backtrace as the triager produced it — tops out at the abort machinery.
GDB_BT = """\
#0  0x00007f00 in __pthread_kill_implementation () at ./nptl/pthread_kill.c:44
#1  0x00007f01 in __pthread_kill_internal () at ./nptl/pthread_kill.c:78
#2  0x00007f02 in __GI___pthread_kill () at ./nptl/pthread_kill.c:89
#3  0x00007f03 in __GI_raise () at ../sysdeps/posix/raise.c:26
#4  0x00007f04 in __GI_abort () at ./stdlib/abort.c:79
#5  0x00005561 in example_chunk_read () at /src/example.c:120
#6  0x00005562 in example_load_from_memory () at /src/example.c:75
"""


def test_parse_asan_stack_gets_fault_frames_only():
    frames = CrashTriager._parse_asan_stack(ASAN)
    # first frame is the real fault site; allocation stack (malloc) excluded
    assert frames[0] == "example_chunk_read at /src/example.c:100:12"
    assert any("example_load_from_memory" in f for f in frames)
    assert not any("malloc" in f for f in frames)


def test_first_app_frame_skips_abort_machinery():
    gdb_frames = _triager()._parse_backtrace(GDB_BT)
    loc = CrashTriager._first_app_frame(gdb_frames)
    assert "pthread_kill" not in loc
    assert "abort" not in loc
    assert "example_chunk_read" in loc


def test_asan_stack_preferred_over_gdb_abort_frame():
    # The ASAN stack should win → exact fault line, not the GDB abort frame.
    asan_frames = CrashTriager._parse_asan_stack(ASAN)
    loc = CrashTriager._first_app_frame(asan_frames)
    assert loc.startswith("example_chunk_read at")
    assert "100" in loc


def test_first_app_frame_fallback_when_all_machinery():
    only_machinery = ["__pthread_kill at pthread_kill.c:44", "__GI_abort at abort.c:79"]
    # no app frame → fall back to top (don't crash / return 'unknown' spuriously)
    assert CrashTriager._first_app_frame(only_machinery) == only_machinery[0]
