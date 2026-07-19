#!/usr/bin/env bash
# libpng CVE-2018-13785 backtest — full pipeline.
set -uo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate

LOG="$HOME/Nemesis/libpng_run.log"

case "${1:-onboard}" in
  onboard)
    rm -f config/targets/libpng.yaml
    nemesis onboard \
      --source-root "$HOME/libpng_clean" \
      --project-name libpng
    ;;
  setup)
    nemesis setup -t libpng
    ;;
  run)
    echo "=== nemesis run -t libpng --scan --max-targets 5 --strategy harness ===" > "$LOG"
    echo "started: $(date)" >> "$LOG"
    nemesis run -t libpng --scan --max-targets 2 --strategy harness >> "$LOG" 2>&1
    echo "finished: $(date)" >> "$LOG"
    ;;
  all)
    nemesis setup -t libpng > "$LOG" 2>&1
    echo "" >> "$LOG"
    echo "=== nemesis run -t libpng --scan --max-targets 2 --strategy harness ===" >> "$LOG"
    nemesis run -t libpng --scan --max-targets 2 --strategy harness >> "$LOG" 2>&1
    echo "finished: $(date)" >> "$LOG"
    ;;
esac
