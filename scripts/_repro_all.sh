#!/usr/bin/env bash
# Triage all 18 AFL crashes with the single-shot debug binary (ASAN+UBSan).
set -u
DBG="$HOME/libtiff_clean/build_debug/fuzz_nemesis_debug"
CDIR="$HOME/nemesis_workspace/fuzzing/findings/65aeb0146cd1/TIFFReadCustomDirectory/main/crashes"
TMP=/tmp/nemesis_triage
mkdir -p "$TMP"

echo "binary: $DBG ($(stat -c %s "$DBG" 2>/dev/null) bytes)"
echo

declare -A SUMMARY=()

i=0
find "$CDIR" -name 'id:*' | while read f; do
  i=$((i+1))
  safe="$TMP/c_$i.bin"
  cp "$f" "$safe"
  out=$(ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0" \
        UBSAN_OPTIONS="print_stacktrace=1" \
        timeout 6 "$DBG" < "$safe" 2>&1)
  rc=$?
  # Capture top sanitizer signature
  sig=$(echo "$out" | grep -E "ERROR:|runtime error:|SUMMARY:" | head -1 | sed 's/.*ERROR: //; s/.*SUMMARY: //; s/0x[0-9a-fA-F]*/0x..../g' | head -c 160)
  if [ -z "$sig" ]; then
    sig="(no sanitizer output, rc=$rc)"
  fi
  printf "%-50s -> %s\n" "$(basename "$f")" "$sig"
done
