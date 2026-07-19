#!/usr/bin/env bash
set -u
DBG="$HOME/cjson_clean/build_debug/fuzz_nemesis_debug"
SNAPSHOT="$HOME/nemesis_workspace/fuzzing/findings/109062ee0363/cJSON_ParseWithLength/binary_debug_snapshot"
BINARY_AFL="$HOME/nemesis_workspace/fuzzing/findings/109062ee0363/cJSON_ParseWithLength/binary_snapshot"
CDIR="$HOME/nemesis_workspace/fuzzing/findings/109062ee0363/cJSON_ParseWithLength/main/crashes"
TMP=/tmp/cj_repro
mkdir -p "$TMP"

echo "=== which binaries are available? ==="
ls -la "$DBG" "$SNAPSHOT" "$BINARY_AFL" 2>&1 | head -10
echo ""
echo "=== crash count ==="
n=$(ls "$CDIR" 2>/dev/null | grep -c "^id:")
echo "$n crashes in $CDIR"
echo ""
echo "=== first 3 crashes — hex dump ==="
for f in $(ls "$CDIR"/id:* 2>/dev/null | head -3); do
  safe="$TMP/c_$(basename "$f" | tr ':,' '__').bin"
  cp "$f" "$safe"
  echo "--- $(basename "$f") (size=$(stat -c %s "$safe") bytes) ---"
  xxd "$safe" | head -2
done

echo ""
echo "=== reproduce first crash with debug binary (single-shot) ==="
first_safe=$(ls "$TMP"/c_*.bin 2>/dev/null | head -1)
if [ -n "$first_safe" ] && [ -x "$DBG" ]; then
  ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0" \
    timeout 5 "$DBG" < "$first_safe" 2>&1 | head -30
fi

echo ""
echo "=== reproduce with debug SNAPSHOT (more reliable) ==="
if [ -n "$first_safe" ] && [ -x "$SNAPSHOT" ]; then
  ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0" \
    timeout 5 "$SNAPSHOT" < "$first_safe" 2>&1 | head -30
fi
