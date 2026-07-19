#!/usr/bin/env bash
# Reproduce all AFL crashes for TIFFReadCustomDirectory and dump ASAN top-frames.
CRASHES_DIR="$HOME/nemesis_workspace/fuzzing/findings/65aeb0146cd1/TIFFReadCustomDirectory/main/crashes"
BINARY="$HOME/libtiff_work/build_fuzz/fuzz_nemesis"

if [ ! -x "$BINARY" ]; then
  echo "BINARY missing: $BINARY"; exit 1
fi
if [ ! -d "$CRASHES_DIR" ]; then
  echo "CRASHES_DIR missing: $CRASHES_DIR"; exit 1
fi

echo "=== full ASAN output for first crash ==="
first=$(ls -1 "$CRASHES_DIR"/id:* 2>/dev/null | head -1)
if [ -n "$first" ]; then
  echo "FILE: $(basename "$first")"
  ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1" \
    "$BINARY" < "$first" 2>&1 | head -60
fi

echo ""
echo "=== stack-frame summary across all 18 ==="
for f in "$CRASHES_DIR"/id:*; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  result=$(ASAN_OPTIONS="symbolize=1:abort_on_error=0" \
    "$BINARY" < "$f" 2>&1 | grep -E "ERROR: AddressSanitizer|#0 |runtime error" | head -2 | tr '\n' '|')
  echo "$name -> $result"
done
