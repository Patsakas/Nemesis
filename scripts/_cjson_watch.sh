#!/usr/bin/env bash
LOG="$HOME/Nemesis/cjson_run.log"
START=$(date +%s)
MAX=2700
N_BUILD=0
N_FUZZ=0
N_CRASH=0
while true; do
  if ! pgrep -f "nemesis (setup|run) -t cjson" > /dev/null 2>&1; then
    echo "PROCESS_EXITED $(date +%H:%M:%S)"
    grep -E "(pipeline.complete|finished:|Traceback|^Error|cmin\.complete|unique_crashes)" "$LOG" | tail -10
    break
  fi
  if [ "$N_BUILD" = "0" ] && grep -q "harness.compile.success" "$LOG" 2>/dev/null; then
    N_BUILD=1
    echo "FIRST_BUILD_OK $(date +%H:%M:%S)"
    grep "harness.compile.success" "$LOG" | head -2
  fi
  if [ "$N_FUZZ" = "0" ] && grep -q "afl.launch" "$LOG" 2>/dev/null; then
    N_FUZZ=1
    echo "AFL_STARTED $(date +%H:%M:%S)"
    grep "afl.launch" "$LOG" | head -1
  fi
  if [ "$N_CRASH" = "0" ] && grep -qE "(crash_found|unique_crashes=[1-9]|cmin.complete after=[1-9]|crash\.found|CWE-)" "$LOG" 2>/dev/null; then
    N_CRASH=1
    echo "CRASH_DETECTED $(date +%H:%M:%S)"
    grep -E "(crash_found|unique_crashes|cmin.complete|crash\.found|CWE-|ASAN|setByteArray|ParseWithLength)" "$LOG" | tail -10
  fi
  NOW=$(date +%s)
  if [ $((NOW - START)) -gt $MAX ]; then
    echo "WATCHER_TIMEOUT_45min $(date +%H:%M:%S)"
    tail -15 "$LOG"
    break
  fi
  sleep 20
done
