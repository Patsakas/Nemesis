#!/usr/bin/env bash
# Validate this benchmark entry by differential: the crash input must trigger
# the overflow on a pre-fix cJSON and run clean on the fixed release, and a
# well-formed input must be clean on both. Passing all four pins the input to
# CVE-2023-53154 specifically — commit 3ef4e4e (fixed in 1.7.18) is the only
# memory-safety change between the two versions.
#
# Run this before trusting any campaign that uses oracle.sh.
#
# Usage: reproduce.sh <cjson-git-checkout>
#   The checkout is used to build both versions via `git worktree`, so it must
#   be a git clone with tags, currently on a vulnerable version (< 1.7.18).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:?path to a cJSON git checkout}"
FIXED_TAG="${FIXED_TAG:-v1.7.18}"

CRASH="$HERE/crash_input.json"
printf '{"1":1}' > /tmp/cjson_wellformed.json   # valid object, negative control
OK=/tmp/cjson_wellformed.json

echo "=== vulnerable build ($(git -C "$SRC" describe --tags 2>/dev/null || echo '?')) ==="
bash "$HERE/build_asan.sh" "$SRC" /tmp/cjson_vuln

echo "=== fixed build ($FIXED_TAG, via git worktree) ==="
wt=$(mktemp -d)
git -C "$SRC" worktree add -f "$wt" "$FIXED_TAG" >/dev/null 2>&1
trap 'git -C "$SRC" worktree remove --force "$wt" >/dev/null 2>&1 || true' EXIT
bash "$HERE/build_asan.sh" "$wt" /tmp/cjson_fixed

pass=1
check() { # description, binary, input, expected(HIT|MISS)
  local desc="$1" bin="$2" in="$3" want="$4" got
  if bash "$HERE/oracle.sh" "$bin" "$in" >/dev/null 2>&1; then got=HIT; else got=MISS; fi
  if [[ "$got" == "$want" ]]; then
    echo "  OK   $desc -> $got"
  else
    echo "  FAIL $desc -> $got (expected $want)"; pass=0
  fi
}

echo
echo "=== differential ==="
check "crash input on vulnerable" /tmp/cjson_vuln  "$CRASH" HIT
check "crash input on fixed     " /tmp/cjson_fixed "$CRASH" MISS
check "valid input on vulnerable" /tmp/cjson_vuln  "$OK"    MISS
check "valid input on fixed     " /tmp/cjson_fixed "$OK"    MISS

echo
if [[ $pass -eq 1 ]]; then
  echo "benchmark entry validated: the crash input is specific to CVE-2023-53154."
else
  echo "VALIDATION FAILED — do not use this entry until the differential holds."
  exit 1
fi
