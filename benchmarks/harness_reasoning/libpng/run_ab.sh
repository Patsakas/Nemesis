#!/usr/bin/env bash
# Harness-reachability A/B for CVE-2018-13785 (SIGFPE divide-by-zero).
#
# Builds two harnesses from the SAME libpng checkout with the SAME compiler and
# feeds them the SAME trigger input. The only difference is one line:
#   Arm A (naive)   : default limits              -> width rejected, exit 0
#   Arm B (NEMESIS) : png_set_user_limits(0x7FFF..)-> reaches divide, SIGFPE (137/136)
#
# Usage: run_ab.sh <libpng-source-checkout>
#   Checkout must carry a generated pnglibconf.h (a normal built tree has one).
set -uo pipefail
SRC="${1:?path to a libpng source checkout (must contain png.c + pnglibconf.h)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$SRC/png.c" ]] || { echo "no png.c in $SRC" >&2; exit 2; }
[[ -f "$SRC/pnglibconf.h" ]] || { echo "no pnglibconf.h in $SRC (build tree needed)" >&2; exit 2; }

SRCS="png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c \
      pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c \
      pngwtran.c pngwutil.c"

build() { ( cd "$SRC" && clang -g -O0 -I. -o "$2" "$HERE/$1" $SRCS -lz -lm ); }
echo "building arm A (naive)…";   build arm_a_naive.c   /tmp/harness_a || exit 3
echo "building arm B (NEMESIS)…"; build arm_b_nemesis.c /tmp/harness_b || exit 3

run() {   # $1 binary  $2 label
  "$1" "$HERE/trigger.png"; local rc=$?
  local sig=$((rc>128 ? rc-128 : 0))
  printf "%-18s exit=%-3d %s\n" "$2" "$rc" \
    "$([[ $sig -eq 8 ]] && echo 'SIGFPE  -> TRIGGERED (reached the divide)' \
       || echo 'no signal -> NOT triggered (rejected before divide)')"
}
echo; echo "=== same trigger.png, same libpng, one-line harness difference ==="
run /tmp/harness_a "arm A naive"
run /tmp/harness_b "arm B NEMESIS"
echo
echo "Expected: A not triggered (exit 0), B TRIGGERED (SIGFPE). If both agree with"
echo "that, the harness reasoning — not the input, library, or fuzzer — is what"
echo "unlocks reachability."
