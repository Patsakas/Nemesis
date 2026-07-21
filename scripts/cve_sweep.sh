#!/usr/bin/env bash
# Post-hoc CVE rediscovery check over an AFL output directory.
#
# Scans every input AFL kept — both queue/ and crashes/ — and runs the CVE
# oracle on each. A run rediscovered the CVE if any input is a CVE-HIT.
#
# Why scan the queue and not just crashes/: on a host whose core_pattern pipes
# to a handler, AFL cannot tell a crash from a timeout and misfiles both, so
# crashes/ is unreliable in both directions (see check_crash_reporting.sh). The
# queue, by contrast, holds every input that produced new coverage regardless
# of crash detection, and the oracle is a real standalone ASan reproduction —
# ground truth independent of what AFL thought happened. This sidesteps the
# core_pattern blocker entirely.
#
# Time-to-first-hit comes from AFL's own filename encoding (time:NNNN, ms since
# start), so it needs no extra instrumentation.
#
# Usage: cve_sweep.sh <oracle.sh> <repro-binary> <afl-output-dir>
# Prints one line: HIT <ms> <file>  or  MISS
set -uo pipefail

ORACLE="${1:?path to oracle.sh}"
BINARY="${2:?ASan reproducer binary}"
OUT="${3:?AFL output directory}"

earliest_ms=-1
earliest_file=""

# queue first, then crashes — union of everything AFL retained.
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  if bash "$ORACLE" "$BINARY" "$f" >/dev/null 2>&1; then
    # AFL encodes discovery time as time:NNNN (ms since campaign start) in the
    # filename. Missing (e.g. an imported seed) counts as t=0.
    ms=$(basename "$f" | grep -oE 'time:[0-9]+' | head -1 | cut -d: -f2)
    ms=${ms:-0}
    if [[ $earliest_ms -lt 0 || $ms -lt $earliest_ms ]]; then
      earliest_ms=$ms
      earliest_file="$f"
    fi
  fi
done < <(find "$OUT" -type f \( -path '*/queue/*' -o -path '*/crashes/*' \) 2>/dev/null)

if [[ $earliest_ms -ge 0 ]]; then
  echo "HIT $earliest_ms $earliest_file"
  exit 0
fi
echo "MISS"
exit 1
