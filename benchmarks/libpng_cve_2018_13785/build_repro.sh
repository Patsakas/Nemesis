#!/usr/bin/env bash
# Build a standalone repro for CVE-2018-13785 from a libpng source checkout.
#
# The bug is an integer divide-by-zero (SIGFPE), not a memory error, so this
# needs no sanitizer — just a clean libpng linked into a stdin-reading harness.
# The AFL fuzzing binary and the ASan/AFL-instrumented libpng.a cannot be used:
# the fuzzing binary takes no input outside afl-fuzz, and the instrumented
# archive pulls in __afl_area_ptr / __asan_* symbols that will not link here.
#
# Compiles the libpng core .c files directly (like the cJSON entry compiles
# cJSON.c) so it works from any checkout without its build system.
#
# Usage: build_repro.sh <libpng-source-checkout> [output-binary]
#   Checkout must carry a generated pnglibconf.h (a normal built tree has one).
set -euo pipefail

SRC="${1:?path to a libpng source checkout}"
OUT="${2:-/tmp/libpng_cve_repro}"
[[ -f "$SRC/png.c" ]] || { echo "no png.c in $SRC" >&2; exit 1; }

# pnglibconf.h is generated at configure time. Reuse one if the checkout lacks it.
if [[ ! -f "$SRC/pnglibconf.h" ]]; then
  for c in "$SRC"/build*/pnglibconf.h "$HOME"/libpng_work/build_fuzz/pnglibconf.h; do
    [[ -f "$c" ]] && cp "$c" "$SRC/" && break
  done
fi
[[ -f "$SRC/pnglibconf.h" ]] || { echo "no pnglibconf.h and none to borrow" >&2; exit 1; }

# The harness is committed alongside (harness.c), not inlined, because it must
# match what NEMESIS fuzzes with — specifically the png_set_user_limits() call
# that raises the width cap enough to reach the bug. A stock decode harness
# rejects the 0x55555555 width first and never triggers it.
HERE="$(cd "$(dirname "$0")" && pwd)"

SRCS="png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c \
      pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c \
      pngwtran.c pngwutil.c"
( cd "$SRC" && clang -g -O0 -I. -o "$OUT" "$HERE/harness.c" $SRCS -lz -lm )
echo "built: $OUT"
