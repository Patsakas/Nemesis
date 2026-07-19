#!/usr/bin/env bash
# cJSON CVE-2023-53154 backtest. No `set -e` so non-fatal noise won't bail.
set -uo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate

LOG="$HOME/Nemesis/cjson_run.log"
echo "=== nemesis setup -t cjson ===" > "$LOG"
echo "started: $(date)" >> "$LOG"
nemesis setup -t cjson >> "$LOG" 2>&1
echo "" >> "$LOG"
echo "=== nemesis run -t cjson --scan --max-targets 5 --strategy harness ===" >> "$LOG"
nemesis run -t cjson --scan --max-targets 5 --strategy harness >> "$LOG" 2>&1
echo "finished: $(date)" >> "$LOG"
