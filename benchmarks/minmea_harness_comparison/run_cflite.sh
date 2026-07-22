#!/usr/bin/env bash
# Fuzz minmea's ClusterFuzzLite harness under AFL++ with the same budget,
# instance count and seed as the NEMESIS harness run.
#
# Fairness notes, because they decide what the comparison means:
#
#  * Same fuzzer (AFL++), same sanitizer (ASan), same instrumentation, same
#    library sources. Only the harness differs.
#  * Same wall-clock budget and instance count.
#  * BOTH sides start from the same single minimal seed. NEMESIS generates its
#    own corpus, and using it here would fold seed generation into what is
#    meant to be a harness comparison; upstream ships no corpus at all, so
#    giving CFLite nothing would be the opposite distortion. One neutral seed
#    isolates the harness.
#
# Usage: run_cflite.sh <cflite-build-dir> <out-dir> [seconds] [instances]
set -euo pipefail
BUILD="${1:?cflite build dir}"
OUT="${2:?output dir}"
SECS="${3:-900}"
N="${4:-4}"

if grep -q '^|' /proc/sys/kernel/core_pattern 2>/dev/null; then
    echo "core_pattern pipes to a handler; run: echo core | sudo tee /proc/sys/kernel/core_pattern" >&2
    exit 1
fi

SEEDS="$OUT/seeds"
rm -rf "$OUT"; mkdir -p "$SEEDS" "$OUT/findings"
# A single well-formed RMC sentence — valid for the one parser this harness
# calls, and a plausible starting point for any NMEA harness.
printf '$GPRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130998,011.3,E*62\r\n' \
    > "$SEEDS/rmc.txt"

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1
CMPLOG=""
[ -f "$BUILD/cflite_fuzz_cmplog" ] && CMPLOG="-c $BUILD/cflite_fuzz_cmplog"

echo "launching $N instances for ${SECS}s"
timeout "$SECS" afl-fuzz -i "$SEEDS" -o "$OUT/findings" -M main $CMPLOG \
    -- "$BUILD/cflite_fuzz" > "$OUT/main.log" 2>&1 &
for i in $(seq 1 $((N - 1))); do
    timeout "$SECS" afl-fuzz -i "$SEEDS" -o "$OUT/findings" -S "slave_$i" $CMPLOG \
        -- "$BUILD/cflite_fuzz" > "$OUT/slave_$i.log" 2>&1 &
done
wait

echo "=== results ==="
for s in "$OUT"/findings/*/fuzzer_stats; do
    echo "--- $(basename "$(dirname "$s")") ---"
    grep -E '^(run_time|execs_done|execs_per_sec|corpus_count|bitmap_cvg|saved_crashes|saved_hangs)' "$s"
done
