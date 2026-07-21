#!/usr/bin/env bash
# Verify this host can report crashes reliably, before trusting any crash count.
#
# Run this before any experiment whose result depends on crashes. Coverage
# benchmarks are unaffected; anything measuring time-to-crash, crash counts or
# CVE rediscovery is worthless without it.
#
# The failure it catches is silent. When /proc/sys/kernel/core_pattern pipes to
# a handler — the default on WSL and most desktop Linux — afl-fuzz refuses to
# start, so runners set AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 to get going.
# AFL then cannot distinguish a crash from a timeout and files timeouts under
# crashes/. A libtiff campaign here produced 16 "crashes" across three arms,
# baseline included, and not one of them reproduced.
#
# Usage:
#   scripts/check_crash_reporting.sh [debug-binary] [crashing-input]
#
# With no arguments it checks the environment only. Give it a debug build and
# an input known to crash it, and it verifies the whole path end to end.
set -uo pipefail

fail=0
say() { printf '%s\n' "$*"; }

say "=== core_pattern ==="
pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "<unreadable>")
say "  $pattern"
if [[ "$pattern" == \|* ]]; then
  say "  FAIL: pipes to a handler, so AFL cannot tell crashes from timeouts."
  say "        Crash counts from this host are not trustworthy."
  say "        Fix:  echo core | sudo tee /proc/sys/kernel/core_pattern"
  fail=1
else
  say "  ok: crashes are delivered normally"
fi

say
say "=== AFL crash-reporting override ==="
if [[ "${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-0}" == "1" ]]; then
  say "  WARNING: AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES is set in this shell."
  say "           It lets afl-fuzz start on a host with a piped core_pattern,"
  say "           at the cost of misfiling timeouts as crashes."
  [[ $fail -eq 0 ]] && say "           core_pattern is fine, so this is only a leftover — unset it."
else
  say "  ok: not set"
fi

BINARY="${1:-}"
INPUT="${2:-}"
if [[ -z "$BINARY" ]]; then
  say
  say "No binary given — environment checked only. To verify the full path, pass"
  say "a debug build and an input known to crash it."
  exit $fail
fi

say
say "=== does the debug build actually report a crash? ==="
if [[ ! -x "$BINARY" ]]; then
  say "  FAIL: not executable: $BINARY"
  exit 1
fi
if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
  say "  skipped: no crashing input given"
  exit $fail
fi

out=$(ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1" \
      timeout 15 "$BINARY" < "$INPUT" 2>&1)
rc=$?
sig=$(echo "$out" | grep -E "ERROR:|SUMMARY:" | head -1)

say "  exit code: $rc"
if [[ -n "$sig" ]]; then
  say "  sanitizer: ${sig:0:100}"
  say "  ok: the crash reproduces and is identifiable"
elif [[ $rc -eq 0 ]]; then
  say "  FAIL: exits cleanly — this input does not crash the debug build."
  say "        If it came from AFL's crashes/ directory, it is an artefact."
  fail=1
else
  say "  WARNING: non-zero exit ($rc) but no sanitizer output. Could be a"
  say "           timeout (124) or an uninstrumented abort."
  fail=1
fi

exit $fail
