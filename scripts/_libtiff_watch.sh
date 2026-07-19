#!/usr/bin/env bash
# Watch libtiff CVE backtest run for milestones. Single-shot per milestone, exits on crash or timeout.
LOG="$HOME/Nemesis/libtiff_run.log"
START=$(date +%s)
MAX=2700
NOTIFIED_BUILD=0
NOTIFIED_PROFILE=0
NOTIFIED_FUZZ=0
while true; do
  if ! pgrep -f "nemesis (setup|run) -t libtiff" > /dev/null 2>&1; then
    echo "PROCESS_EXITED $(date +%H:%M:%S)"
    grep -E "(pipeline.complete|finished:|Traceback|^Error|error)" "$LOG" | tail -10
    break
  fi
  if [ "$NOTIFIED_BUILD" = "0" ] && grep -qE "(harness\.compile\.success|build\.success|stage4\.start|harness\.compiled)" "$LOG" 2>/dev/null; then
    NOTIFIED_BUILD=1
    echo "FIRST_BUILD_OK $(date +%H:%M:%S)"
    grep -E "(harness\.compile\.success|build\.success|stage4\.start|harness\.compiled)" "$LOG" | head -3
  fi
  if [ "$NOTIFIED_PROFILE" = "0" ] && grep -qE "(afl_profile|profile\.start|stage\.start.*name=fuzzing|stage\.start name=fuzzing)" "$LOG" 2>/dev/null; then
    NOTIFIED_PROFILE=1
    echo "FUZZING_STARTED $(date +%H:%M:%S)"
    grep -E "(afl_profile|profile\.start|name=fuzzing)" "$LOG" | tail -3
  fi
  if [ "$NOTIFIED_FUZZ" = "0" ] && grep -qE "(crash\.found|fuzzing\.crash|ASAN:|CWE-|heap-buffer-overflow|global-buffer-overflow|stack-buffer-overflow|setByteArray|_TIFFmemcpy)" "$LOG" 2>/dev/null; then
    NOTIFIED_FUZZ=1
    echo "CRASH_DETECTED $(date +%H:%M:%S)"
    grep -E "(crash\.found|fuzzing\.crash|ASAN:|CWE-|buffer-overflow|setByteArray|_TIFFmemcpy)" "$LOG" | head -10
    break
  fi
  NOW=$(date +%s)
  if [ $((NOW - START)) -gt $MAX ]; then
    echo "WATCHER_TIMEOUT_45min $(date +%H:%M:%S)"
    echo "n_targets_started=$(grep -c target.start "$LOG" 2>/dev/null)"
    echo "n_variants_ok=$(grep -c harness_variant.generated "$LOG" 2>/dev/null)"
    echo "n_compile_success=$(grep -c harness.compile.success "$LOG" 2>/dev/null)"
    echo "n_build_failed=$(grep -c build.failed "$LOG" 2>/dev/null)"
    tail -15 "$LOG"
    break
  fi
  sleep 30
done
