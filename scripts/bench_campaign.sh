#!/usr/bin/env bash
# Fuzzing A/B campaign: does a corpus enriched with measured seeds find more
# than the real corpus alone?
#
# This is the experiment the seed-quality benchmark cannot answer. Seed coverage
# is a leading indicator; time-to-coverage and crash counts are the result.
#
# The comparison is deliberately NOT "real seeds vs generated seeds". Generated
# seeds are exploration inputs and measurably reach less than the genuine files
# they were derived from (see docs/benchmarks/fieldspec_seed_quality.md). The
# question is whether adding them helps:
#
#   arm A  real corpus
#   arm B  real corpus + seeds from the measured fieldspec
#   arm C  real corpus + the same number of random seeds   [control]
#
# Arm C matters. Without it, any gain in B could just be "more seeds" rather
# than "better seeds", and that objection sinks the result.
#
# Everything else is held equal: same AFL binary, same budget, same core count,
# same starting corpus. Repeats exist because a single AFL run is noisy — one
# run of each arm proves nothing at all.
#
# Usage:
#   scripts/bench_campaign.sh <fuzz-binary> <real-corpus> <out-dir> [minutes] [repeats]
#
# Example:
#   scripts/bench_campaign.sh ~/libpng_work/build_fuzz/fuzz_nemesis \
#       seeds/oss_fuzz_corpus_libpng /tmp/campaign 30 5
set -euo pipefail

FUZZ_BIN="${1:?fuzz binary (the AFL one, not the probe)}"
REAL_CORPUS="${2:?directory of real seeds}"
OUT_DIR="${3:?output directory}"
MINUTES="${4:-30}"
REPEATS="${5:-5}"

GENERATED="${GENERATED_SEEDS:-}"   # dir of measured seeds; see bench_fieldspec.py
RANDOM_SEEDS="${RANDOM_SEEDS:-}"   # dir of random seeds of matching count

if [[ ! -x "$FUZZ_BIN" ]]; then echo "not executable: $FUZZ_BIN" >&2; exit 1; fi
if [[ ! -d "$REAL_CORPUS" ]]; then echo "no corpus: $REAL_CORPUS" >&2; exit 1; fi

mkdir -p "$OUT_DIR"
SECS=$((MINUTES * 60))

# AFL needs these or it refuses to start on most systems; setting them here
# rather than expecting the operator to have done it keeps the runs comparable.
export AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1
export AFL_BENCH_UNTIL_CRASH=0
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1"

run_arm() {
  local arm="$1" corpus="$2" rep="$3"
  local in_dir="$OUT_DIR/in_${arm}"
  local sync_dir="$OUT_DIR/${arm}_rep${rep}"
  rm -rf "$sync_dir"; mkdir -p "$sync_dir"

  echo "[$(date +%H:%M:%S)] arm=$arm rep=$rep  ${MINUTES}m  corpus=$(ls "$corpus" | wc -l) files"
  timeout $((SECS + 60)) afl-fuzz -i "$in_dir" -o "$sync_dir" -V "$SECS" \
      -m none -- "$FUZZ_BIN" >"$sync_dir/afl.log" 2>&1 || true

  local stats="$sync_dir/default/fuzzer_stats"
  if [[ -f "$stats" ]]; then
    local edges execs crashes paths
    edges=$(grep -oP 'bitmap_cvg *: *\K[\d.]+' "$stats" || echo 0)
    execs=$(grep -oP 'execs_done *: *\K\d+' "$stats" || echo 0)
    crashes=$(grep -oP 'saved_crashes *: *\K\d+' "$stats" || echo 0)
    paths=$(grep -oP 'corpus_count *: *\K\d+' "$stats" || echo 0)
    echo "$arm,$rep,$edges,$execs,$crashes,$paths" >> "$OUT_DIR/results.csv"
    echo "    bitmap=${edges}%  execs=${execs}  crashes=${crashes}  corpus=${paths}"
  else
    echo "    NO STATS — check $sync_dir/afl.log" >&2
    echo "$arm,$rep,ERROR,,," >> "$OUT_DIR/results.csv"
  fi
}

# Build the three input corpora once, so every repeat starts identically.
rm -rf "$OUT_DIR"/in_*
mkdir -p "$OUT_DIR/in_A"
cp "$REAL_CORPUS"/* "$OUT_DIR/in_A/" 2>/dev/null || true

if [[ -n "$GENERATED" && -d "$GENERATED" ]]; then
  cp -r "$OUT_DIR/in_A" "$OUT_DIR/in_B"
  cp "$GENERATED"/* "$OUT_DIR/in_B/" 2>/dev/null || true
fi
if [[ -n "$RANDOM_SEEDS" && -d "$RANDOM_SEEDS" ]]; then
  cp -r "$OUT_DIR/in_A" "$OUT_DIR/in_C"
  cp "$RANDOM_SEEDS"/* "$OUT_DIR/in_C/" 2>/dev/null || true
fi

echo "arm,repeat,bitmap_cvg_pct,execs,crashes,corpus_count" > "$OUT_DIR/results.csv"
for rep in $(seq 1 "$REPEATS"); do
  run_arm A "$OUT_DIR/in_A" "$rep"
  [[ -d "$OUT_DIR/in_B" ]] && run_arm B "$OUT_DIR/in_B" "$rep"
  [[ -d "$OUT_DIR/in_C" ]] && run_arm C "$OUT_DIR/in_C" "$rep"
done

echo
echo "results: $OUT_DIR/results.csv"
echo "Report the MEDIAN across repeats, not the best run — AFL variance between"
echo "identical runs is routinely larger than the effect being measured."
