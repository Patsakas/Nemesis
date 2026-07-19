#!/usr/bin/env bash
# CVE-2022-22844 backtest — full scan run.
# Logs to ~/Nemesis/cve2022_run.log. Should take ~2h with --max-targets 7.
set -euo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate

LOG="$HOME/Nemesis/cve2022_run.log"
echo "=== nemesis run -t libtiff_cve2022 --scan --max-targets 7 ===" > "$LOG"
echo "started: $(date)" >> "$LOG"
echo "" >> "$LOG"

nemesis run -t libtiff_cve2022 --scan --max-targets 7 >> "$LOG" 2>&1

echo "" >> "$LOG"
echo "finished: $(date)" >> "$LOG"
