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

# The verdict is an interpretation of the raw numbers, which are emitted first
# and separately (as JSON if --json-out is given). Keep the data; the
# classification can change. TOO_EASY_MS is deliberately a knob, not a constant
# of nature — the same lesson as the Jaccard threshold and SATURATION_GAP,
# where a value chosen from one dataset needed its own sensitivity check. If
# the qualification ever becomes a headline, sweep this the way those were.
TOO_EASY_MS="${TOO_EASY_MS:-5000}"
JSON_OUT=""
if [[ "${1:-}" == "--json-out" ]]; then JSON_OUT="$2"; shift 2; fi

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

# ── Raw data first — the verdict is just an interpretation of it ──
rate=$(( hits * 100 / RUNS ))
lo="" mid="" hi=""
if [[ $hits -gt 0 ]]; then
  IFS=$'\n' sorted=($(sort -n <<<"${times[*]}")); unset IFS
  lo=${sorted[0]}; hi=${sorted[-1]}; mid=${sorted[$((${#sorted[@]} / 2))]}
fi

# Classify from the stored numbers.
if [[ $hits -eq 0 ]]; then
  verdict=TOO_HARD; code=2
elif [[ $hits -eq $RUNS && ${hi:-0} -lt $TOO_EASY_MS ]]; then
  verdict=TOO_EASY; code=3
else
  verdict=DISCRIMINATING; code=0
fi

echo
echo "qualification:"
echo "  runs:             $RUNS x ${SECS}s"
echo "  rediscovery_rate: ${rate}% ($hits/$RUNS)"
echo "  ttfc_ms:          ${mid:-N/A} median   [${lo:-N/A} .. ${hi:-N/A}]"
echo "  too_easy_ms:      $TOO_EASY_MS"
echo "  verdict:          $verdict"
case $verdict in
  TOO_HARD)       echo "  -> both arms would likely score 0; raise budget or pick another CVE." ;;
  TOO_EASY)       echo "  -> baseline saturates; no seed strategy can show an advantage (ceiling)." ;;
  DISCRIMINATING) echo "  -> room for a strategy to move the numbers; worth a full A/B campaign." ;;
esac

if [[ -n "$JSON_OUT" ]]; then
  printf '{"runs":%d,"secs_per_run":%d,"hits":%d,"rediscovery_rate_pct":%d,"ttfc_ms":[%s],"too_easy_ms":%d,"verdict":"%s"}\n' \
    "$RUNS" "$SECS" "$hits" "$rate" "$(IFS=,; echo "${times[*]:-}")" "$TOO_EASY_MS" "$verdict" > "$JSON_OUT"
  echo "  (raw data written to $JSON_OUT)"
fi
exit $code
