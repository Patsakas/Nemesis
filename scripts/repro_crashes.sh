#!/usr/bin/env bash
# Replay a directory of AFL crash inputs and group them by sanitizer signature.
#
# AFL saves one file per crashing input, but distinct files routinely share a
# root cause — the same overflow reached by inputs that differ only in padding.
# Counting files therefore overstates how many bugs were found. This replays
# each input, extracts the top sanitizer line, normalises the addresses out of
# it, and reports the distinct signatures with their counts.
#
# Use the DEBUG build, not the fuzzing one: the fuzzing harness is AFL++
# persistent mode with shared-memory test cases and receives no input outside
# afl-fuzz, so every replay would look identical (and clean).
#
# Usage:
#   scripts/repro_crashes.sh <debug-binary> <crashes-dir> [timeout-secs]
#
# Example:
#   scripts/repro_crashes.sh ~/libtiff_clean/build_debug/fuzz_nemesis_debug \
#       ~/nemesis_workspace/fuzzing/findings/<run>/<func>/main/crashes
set -uo pipefail

BINARY="${1:?debug binary (build_debug/fuzz_nemesis_debug, NOT the AFL one)}"
CRASH_DIR="${2:?directory of AFL crash inputs}"
TIMEOUT="${3:-6}"

[[ -x "$BINARY" ]]    || { echo "not executable: $BINARY" >&2; exit 1; }
[[ -d "$CRASH_DIR" ]] || { echo "no such directory: $CRASH_DIR" >&2; exit 1; }

export ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1"

echo "binary:  $BINARY ($(stat -c %s "$BINARY" 2>/dev/null) bytes)"
echo "crashes: $CRASH_DIR"
echo

declare -A SIG_COUNT=()
declare -A SIG_EXAMPLE=()
total=0
clean=0

# Process substitution rather than a pipe: a `... | while read` loop runs in a
# subshell, so the counts would be discarded at the end of it. That is a real
# bug this script inherited from the ad-hoc version it replaces.
while IFS= read -r f; do
  total=$((total + 1))
  out=$(timeout "$TIMEOUT" "$BINARY" < "$f" 2>&1)
  rc=$?

  sig=$(echo "$out" \
        | grep -E "ERROR:|runtime error:|SUMMARY:" \
        | head -1 \
        | sed -E 's/.*ERROR: //; s/.*SUMMARY: //; s/0x[0-9a-fA-F]+/0x../g; s/[0-9]+ bytes/N bytes/g' \
        | head -c 160)

  if [[ -z "$sig" ]]; then
    # No sanitizer output. Exit 124 is the timeout(1) convention for a hang,
    # which is a different finding from "did not reproduce".
    if [[ $rc -eq 124 ]]; then
      sig="(hang, no sanitizer output)"
    else
      sig="(did not reproduce, rc=$rc)"
      clean=$((clean + 1))
    fi
  fi

  SIG_COUNT["$sig"]=$(( ${SIG_COUNT["$sig"]:-0} + 1 ))
  [[ -z "${SIG_EXAMPLE["$sig"]:-}" ]] && SIG_EXAMPLE["$sig"]="$(basename "$f")"
done < <(find "$CRASH_DIR" -name 'id:*' -type f | sort)

if [[ $total -eq 0 ]]; then
  echo "no crash files (looked for 'id:*' in $CRASH_DIR)"
  exit 0
fi

echo "distinct signatures:"
echo
for sig in "${!SIG_COUNT[@]}"; do
  printf "  %4d x  %s\n" "${SIG_COUNT[$sig]}" "$sig"
  printf "          e.g. %s\n" "${SIG_EXAMPLE[$sig]}"
done | sort -rn

echo
echo "$total input(s), ${#SIG_COUNT[@]} distinct signature(s), $clean did not reproduce."
if [[ $clean -gt 0 ]]; then
  echo "Inputs that do not reproduce against the debug build are usually AFL"
  echo "persistent-mode artifacts rather than real findings."
fi
