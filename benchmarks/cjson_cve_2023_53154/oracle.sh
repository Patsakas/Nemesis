#!/usr/bin/env bash
# CVE oracle: does this input trigger CVE-2023-53154 in cJSON?
#
# Prints CVE-HIT / exit 0 when the input reproduces the bug; CVE-MISS / exit 1
# otherwise. Needs a NON-AFL ASan build (see build_asan.sh).
#
# Matches on the sanitizer's SYMBOL-FREE fingerprint — a heap-buffer-overflow
# that is a READ of size 1 — deliberately, not on the parse_string:786 frame.
# On WSL, ASan's llvm-symbolizer hangs whenever stdout is not a terminal, which
# includes every `$(...)` capture and every pipe an automated oracle uses, so
# the frames come back unnamed and any function-name match silently fails. The
# fingerprint that survives is the overflow class and access size.
#
# That fingerprint alone is not unique to this CVE. What pins it to
# CVE-2023-53154 is the DIFFERENTIAL: the same input crashes a pre-1.7.18 build
# and runs clean on 1.7.18+, where commit 3ef4e4e (the only memory-safety fix
# between the two) resolves it. reproduce.sh performs that differential; this
# oracle is the per-input half of it and assumes it is pointed at the
# vulnerable build.
#
# Usage: oracle.sh <asan-repro-binary> <input-file>
set -uo pipefail

BINARY="${1:?ASan reproducer binary (see build_asan.sh)}"
INPUT="${2:?input file to test}"

# The reproducer alarm()s itself, so no external `timeout` is needed — and must
# not be used, since it too breaks symbolization and, more to the point here,
# there is nothing to symbolize we depend on. Runtime is capped inside the
# binary. abort_on_error=0 so the full report is emitted rather than SIGABRT.
out=$(ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:symbolize=0" \
      "$BINARY" "$INPUT" </dev/null 2>&1)

if echo "$out" | grep -q "heap-buffer-overflow" \
   && echo "$out" | grep -q "READ of size 1"; then
  echo "CVE-HIT"
  exit 0
fi

if echo "$out" | grep -qE "ERROR: .*Sanitizer|runtime error:"; then
  echo "CVE-MISS (other sanitizer finding — not this CVE)"
  exit 1
fi

echo "CVE-MISS (clean)"
exit 1
