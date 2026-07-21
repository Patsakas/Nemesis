#!/usr/bin/env bash
# Validate the entry by differential: the crash input triggers the SIGFPE on a
# pre-fix libpng and runs clean on 1.6.35, and a well-formed PNG is clean on
# both. All four passing pins the input to CVE-2018-13785 — commit 8a05766cb
# (the row_factor (size_t) cast, released in 1.6.35) is the only relevant change.
#
# Usage: reproduce.sh <libpng-git-checkout>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:?path to a libpng git checkout}"
FIXED_TAG="${FIXED_TAG:-v1.6.35}"
CRASH="$HERE/crash_input.png"

# Well-formed 4x4 RGB PNG, negative control.
python3 - "$HERE/ok.png" <<'PY'
import sys, struct, zlib
def c(t,d):
    x=t+d; return struct.pack(">I",len(d))+x+struct.pack(">I",zlib.crc32(x)&0xffffffff)
png=bytes([137,80,78,71,13,10,26,10])+c(b"IHDR",struct.pack(">II",4,4)+bytes([8,2,0,0,0]))\
    +c(b"IDAT",zlib.compress(b"\x00"*64))+c(b"IEND",b"")
open(sys.argv[1],"wb").write(png)
PY
OK="$HERE/ok.png"

echo "=== vulnerable build ($(git -C "$SRC" describe --tags 2>/dev/null || echo '?')) ==="
bash "$HERE/build_repro.sh" "$SRC" /tmp/libpng_vuln

echo "=== fixed build ($FIXED_TAG, via git worktree) ==="
wt=$(mktemp -d)
git -C "$SRC" worktree add -f "$wt" "$FIXED_TAG" >/dev/null 2>&1
trap 'git -C "$SRC" worktree remove --force "$wt" >/dev/null 2>&1 || true' EXIT
bash "$HERE/build_repro.sh" "$wt" /tmp/libpng_fixed

pass=1
check() { local d="$1" bin="$2" in="$3" want="$4" got
  if bash "$HERE/oracle.sh" "$bin" "$in" >/dev/null 2>&1; then got=HIT; else got=MISS; fi
  if [[ "$got" == "$want" ]]; then echo "  OK   $d -> $got"; else echo "  FAIL $d -> $got (want $want)"; pass=0; fi
}

echo
echo "=== differential ==="
check "crash input on vulnerable" /tmp/libpng_vuln  "$CRASH" HIT
check "crash input on fixed     " /tmp/libpng_fixed "$CRASH" MISS
check "valid PNG on vulnerable  " /tmp/libpng_vuln  "$OK"    MISS
check "valid PNG on fixed       " /tmp/libpng_fixed "$OK"    MISS

echo
if [[ $pass -eq 1 ]]; then
  echo "benchmark entry validated: the crash input is specific to CVE-2018-13785."
else
  echo "VALIDATION FAILED — do not use this entry until the differential holds."
  exit 1
fi
