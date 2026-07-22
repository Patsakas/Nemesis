#!/usr/bin/env bash
# Re-run the libnmea end-to-end harness-construction benchmark and check the
# result against thresholds.json.
#
# This validates METHODOLOGY, not exact numbers. The harness is LLM-generated
# and AFL++ throughput is machine-dependent, so nothing here asserts equality
# with the reference run — the bounds sit well below it. What is asserted:
#
#   1. recon selects nmea_parse with no pinning        (deterministic)
#   2. the harness compiles and consumes fuzz input    (distinct probe maps)
#   3. the run reaches the coverage/exec floors        (generous bounds)
#   4. zero crashes                                    (a crash = investigate)
#
# Check 2 is the one that matters: it is what the pre-fix pipeline passed
# vacuously. See harnesses/nmea_load_parsers.BROKEN.c.
#
# Usage: reproduce.sh [minutes]     (default 15, matching the reference run)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
MINUTES="${1:-15}"
SRC="${LIBNMEA_SRC:-$HOME/libnmea_clean}"
PY="${NEMESIS_PYTHON:-$REPO/nemesis-env/bin/python}"

fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1 || fail "missing tool: $1"; }

have git; have clang; have afl-fuzz; have llvm-profdata; have llvm-cov
[ -x "$PY" ] || fail "python not found at $PY (set NEMESIS_PYTHON)"

# AFL refuses to start when core_pattern pipes to a handler. WSL resets this
# on every boot, so check rather than assume.
if [ -r /proc/sys/kernel/core_pattern ] && grep -q '^|' /proc/sys/kernel/core_pattern; then
    fail "core_pattern pipes to a handler; run: echo core | sudo tee /proc/sys/kernel/core_pattern"
fi

echo "=== [1/5] source ==="
[ -d "$SRC" ] || git clone https://github.com/jacketizer/libnmea "$SRC"
echo "libnmea at $SRC ($(git -C "$SRC" rev-parse --short HEAD))"

echo "=== [2/5] target selection (no pinning) ==="
# Asserted before spending 15 minutes on fuzzing: if recon picks the wrong
# function, everything downstream is measuring the wrong thing.
SELECTED=$(cd "$REPO" && PYTHONPATH="$REPO" "$PY" - "$SRC" <<'EOF'
import sys
from nemesis.config import NemesisConfig
from nemesis.recon import IntrospectorParser
cfg = NemesisConfig(); cfg.target.source_root = sys.argv[1]
t = sorted(IntrospectorParser(cfg)._scan_local_source(),
           key=lambda x: x.priority_score, reverse=True)
print(t[0].func_name if t else "NONE")
EOF
)
WANT=$("$PY" -c "import json;print(json.load(open('$HERE/thresholds.json'))['selected_target'])")
echo "selected: $SELECTED (want $WANT)"
[ "$SELECTED" = "$WANT" ] || fail "recon selected '$SELECTED', expected '$WANT'"

echo "=== [3/5] onboard + run (${MINUTES} min) ==="
cd "$REPO"
if [ ! -f config/targets/libnmea.yaml ]; then
    cp "$HERE/libnmea.yaml" config/targets/libnmea.yaml
fi
HOURS=$("$PY" -c "print($MINUTES/60)")
"$PY" -m nemesis.cli run --target libnmea --strategy harness \
      --timeout-hours "$HOURS" 2>&1 | tail -40

echo "=== [4/5] collect ==="
OUT="${BENCH_OUT:-/tmp/libnmea_repro}"
rm -rf "$OUT"; mkdir -p "$OUT"
QUEUE_ROOT=$(find "$HOME/nemesis_workspace/fuzzing/findings" -type d -name "$WANT" | head -1)
[ -n "$QUEUE_ROOT" ] || fail "no findings directory for $WANT"
PYTHONPATH="$REPO" "$PY" "$HERE/collect.py" \
    config/targets/libnmea.yaml "$QUEUE_ROOT" "$OUT"

echo "=== [5/5] check against thresholds ==="
PYTHONPATH="$REPO" "$PY" "$HERE/check_thresholds.py" \
    "$HERE/thresholds.json" "$OUT" && echo "PASS"
