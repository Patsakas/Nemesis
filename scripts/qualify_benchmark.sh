#!/usr/bin/env bash
# Benchmark qualification: is this CVE/target discriminating enough to be worth
# a full A/B campaign, BEFORE spending hours on one?
#
# A few short baseline pilot runs, then a verdict:
#   - never found            -> TOO HARD    (both arms would score 0; no signal)
#   - always found very fast -> TOO EASY    (both arms saturate; ceiling effect)
#   - found sometimes, or with wide time spread -> DISCRIMINATING (run the A/B)
#
# This is the same reasoning that ruled out libpng for placement (91% of bytes
# influential -> no headroom) and cJSON for rediscovery (found in <1s -> no
# headroom). A benchmark's fitness is a precondition of the experiment, not a
# conclusion drawn after it.
#
# Uses the oracle + queue sweep as ground truth, so it is independent of AFL's
# crash reporting (see cve_sweep.sh).
#
# Usage:
#   qualify_benchmark.sh <fuzz-binary> <baseline-corpus> <oracle.sh> \
#       <repro-binary> [pilot-runs] [seconds-per-run]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

FUZZ="${1:?AFL fuzzing binary}"
CORPUS="${2:?baseline seed corpus}"
ORACLE="${3:?oracle.sh}"
REPRO="${4:?ASan reproducer for the oracle}"
RUNS="${5:-5}"
SECS="${6:-60}"

export AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1"

# Thresholds for the verdict. TOO_EASY_MS: found this fast in every run means
# no room to improve on. Chosen at 5s per the fuzzing-eval rule of thumb that a
# sub-second-to-few-second bug cannot separate two techniques.
TOO_EASY_MS=5000

echo "qualifying: $RUNS baseline pilot runs, ${SECS}s each"
echo

hits=0
times=()
for rep in $(seq 1 "$RUNS"); do
  o=$(mktemp -d)
  timeout $((SECS + 10)) afl-fuzz -i "$CORPUS" -o "$o" -V "$SECS" -m none \
      -- "$FUZZ" >/dev/null 2>&1 || true
  r=$(bash "$HERE/cve_sweep.sh" "$ORACLE" "$REPRO" "$o")
  if [[ "$r" == HIT* ]]; then
    ms=$(echo "$r" | cut -d' ' -f2)
    hits=$((hits + 1)); times+=("$ms")
    echo "  run $rep: HIT at ${ms}ms"
  else
    echo "  run $rep: MISS (not found in ${SECS}s)"
  fi
  rm -rf "$o"
done

echo
echo "baseline found the CVE in $hits/$RUNS runs"

if [[ $hits -eq 0 ]]; then
  echo "verdict: TOO HARD — baseline never finds it in ${SECS}s. Both arms would"
  echo "         likely score 0; no signal. Raise the budget or pick another CVE."
  exit 2
fi

# Sort the hit times to report the spread.
IFS=$'\n' sorted=($(sort -n <<<"${times[*]}")); unset IFS
lo=${sorted[0]}; hi=${sorted[-1]}; mid=${sorted[$((${#sorted[@]} / 2))]}
echo "hit times: min=${lo}ms median=${mid}ms max=${hi}ms"

if [[ $hits -eq $RUNS && $hi -lt $TOO_EASY_MS ]]; then
  echo "verdict: TOO EASY — found every run in under ${TOO_EASY_MS}ms. The baseline"
  echo "         already saturates, so no seed strategy can show an advantage."
  echo "         This is a ceiling effect; the CVE is not a discriminating benchmark."
  exit 3
fi

echo "verdict: DISCRIMINATING — mixed outcomes or wide time spread. Worth a full"
echo "         A/B campaign; there is room for a strategy to move the numbers."
exit 0
