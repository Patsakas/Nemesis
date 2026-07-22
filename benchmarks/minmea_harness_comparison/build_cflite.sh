#!/usr/bin/env bash
# Build minmea's own ClusterFuzzLite harness for AFL++, unmodified.
#
# The harness source is NOT edited. `.clusterfuzzlite/fuzzer.c` defines
# LLVMFuzzerTestOneInput and nothing else; AFL++'s libAFLDriver.a supplies the
# main() and persistent-mode loop, which is the standard way to run a libFuzzer
# harness under AFL++. Editing the harness to add AFL macros would make the
# comparison a comparison of my edits.
#
# Compiler and sanitizer flags are copied from the generated
# config/targets/minmea.yaml so both sides of the comparison are built
# identically. Only the harness differs.
#
# Usage: build_cflite.sh <minmea-checkout> <out-dir> [coverage]
set -euo pipefail
SRC="${1:?path to a minmea checkout}"
OUT="${2:?output directory}"
MODE="${3:-fuzz}"

DRIVER="${AFL_DRIVER:-$HOME/AFLplusplus/utils/aflpp_driver/libAFLDriver.a}"
WARN="-Wno-error -Wno-unused-variable -Wno-unused-parameter -Wno-uninitialized -Wno-deprecated-declarations"

mkdir -p "$OUT"

if [ "$MODE" = "coverage" ]; then
    # Matches coverage_configure in config/targets/minmea.yaml. No sanitizers:
    # they are incompatible with -fprofile-instr-generate.
    CC=clang
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping $WARN"
    # libAFLDriver expects AFL runtime symbols. For offline coverage we want a
    # plain stdin driver instead, so the harness is measured the same way the
    # NEMESIS coverage binary is.
    cat > "$OUT/stdin_driver.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(void) {
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
EOF
    $CC $CFLAGS -I"$SRC" -I"$SRC/compat" \
        "$SRC/.clusterfuzzlite/fuzzer.c" "$SRC/minmea.c" "$OUT/stdin_driver.c" \
        -lm -o "$OUT/cflite_coverage"
    echo "built $OUT/cflite_coverage"
else
    [ -f "$DRIVER" ] || { echo "libAFLDriver.a not found at $DRIVER" >&2; exit 1; }
    CC=afl-clang-fast
    CFLAGS="-g -fsanitize=address $WARN"
    $CC $CFLAGS -I"$SRC" -I"$SRC/compat" \
        "$SRC/.clusterfuzzlite/fuzzer.c" "$SRC/minmea.c" "$DRIVER" \
        -lm -o "$OUT/cflite_fuzz"
    # CMPLOG build, matching what NEMESIS launches for its own harness.
    AFL_LLVM_CMPLOG=1 $CC $CFLAGS -I"$SRC" -I"$SRC/compat" \
        "$SRC/.clusterfuzzlite/fuzzer.c" "$SRC/minmea.c" "$DRIVER" \
        -lm -o "$OUT/cflite_fuzz_cmplog"
    echo "built $OUT/cflite_fuzz and $OUT/cflite_fuzz_cmplog"
fi
