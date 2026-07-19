#!/usr/bin/env bash
# Setup + scan-mode run for libtiff @ CVE-2022-22844 commit. Logs to ~/Nemesis/libtiff_run.log.
set -euo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate

LOG="$HOME/Nemesis/libtiff_run.log"
echo "=== nemesis setup -t libtiff ===" > "$LOG"
echo "started: $(date)" >> "$LOG"
echo "" >> "$LOG"

nemesis setup -t libtiff >> "$LOG" 2>&1
echo "" >> "$LOG"
echo "=== nemesis run -t libtiff --scan --max-targets 7 ===" >> "$LOG"
echo "" >> "$LOG"

nemesis run -t libtiff --scan --max-targets 7 --strategy harness >> "$LOG" 2>&1

echo "" >> "$LOG"
echo "finished: $(date)" >> "$LOG"
