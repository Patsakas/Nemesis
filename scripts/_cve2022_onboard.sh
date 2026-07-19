#!/usr/bin/env bash
# Throwaway driver for CVE-2022-22844 backtest. Loads API keys from .bashrc
# (bypasses non-interactive early return) and runs `nemesis onboard`.
set -euo pipefail

set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a

cd "$HOME/Nemesis"
source nemesis-env/bin/activate

echo "--- env keys present ---"
for k in GROQ_API_KEY NVIDIA_API_KEY CEREBRAS_API_KEY GOOGLE_AI_KEY; do
  if [ -n "${!k:-}" ]; then echo "$k=<set>"; else echo "$k=<MISSING>"; fi
done

echo "--- running nemesis onboard ---"
nemesis onboard \
  --source-root "$HOME/libtiff_cve2022_clean" \
  --project-name libtiff_cve2022
