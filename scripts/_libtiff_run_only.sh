#!/usr/bin/env bash
# Run-only (skip setup since build already completed). No `set -e` so non-fatal noise won't bail.
set -uo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate

LOG="$HOME/Nemesis/libtiff_run.log"
echo "=== nemesis run -t libtiff --scan --max-targets 7 --strategy harness ===" > "$LOG"
echo "started: $(date)" >> "$LOG"
echo "" >> "$LOG"

nemesis run -t libtiff --scan --max-targets 7 --strategy harness >> "$LOG" 2>&1

echo "" >> "$LOG"
echo "finished: $(date)" >> "$LOG"
