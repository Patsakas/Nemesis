#!/usr/bin/env bash
LOG="$HOME/Nemesis/libpng_run.log"
START=$(date +%s)
MAX=2700
N_BUILD=0
N_FUZZ=0
N_CRASH=0
while true; do
  if ! pgrep -f "nemesis (setup|run) -t libpng" > /dev/null 2>&1; then
    echo "PROCESS_EXITED $(date +%H:%M:%S)"
    grep -E "(pipeline.complete|finished:|cmin\.complete|unique_crashes|fuzz_a\.crashes_found|crash_kept)" "$LOG" | tail -10
    break
  fi
  if [ "$N_BUILD" = "0" ] && grep -q "harness.compile.success" "$LOG" 2>/dev/null; then
    N_BUILD=1
    echo "FIRST_BUILD_OK $(date +%H:%M:%S)"
  fi
  if [ "$N_FUZZ" = "0" ] && grep -q "afl.launch" "$LOG" 2>/dev/null; then
    N_FUZZ=1
    echo "AFL_STARTED $(date +%H:%M:%S)"
  fi
  if [ "$N_CRASH" = "0" ] && grep -qE "(afl\.crash_found|fuzz_a\.crashes_found.*count=[1-9])" "$LOG" 2>/dev/null; then
    N_CRASH=1
    echo "CRASH_DETECTED $(date +%H:%M:%S)"
    grep -E "(afl\.crash_found|fuzz_a\.crashes_found|cmin\.complete|CWE-)" "$LOG" | tail -10
    break
  fi
  NOW=$(date +%s)
  if [ $((NOW - START)) -gt $MAX ]; then
    echo "WATCHER_TIMEOUT_45min $(date +%H:%M:%S)"
    tail -10 "$LOG"
    break
  fi
  sleep 20
done
