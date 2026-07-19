#!/usr/bin/env bash
set -u
BINARY="$HOME/libtiff_work/build_fuzz/fuzz_nemesis"
CDIR="$HOME/nemesis_workspace/fuzzing/findings/65aeb0146cd1/TIFFReadCustomDirectory/main/crashes"

# Copy first crash to a safe path (no colons)
SAFE=/tmp/crash_repro_001
first=$(find "$CDIR" -name 'id:000000*' -print -quit)
if [ -z "$first" ]; then
  echo "no first crash"; exit 1
fi
cp "$first" "$SAFE"
echo "size: $(stat -c %s "$SAFE")"
echo "first 64 bytes:"
xxd "$SAFE" | head -4

echo ""
echo "=== ASAN repro of $first ==="
ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0" \
  timeout 5 "$BINARY" < "$SAFE" 2>&1 | head -60
echo "exit_code=$?"
