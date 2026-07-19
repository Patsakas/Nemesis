#!/usr/bin/env bash
set -euo pipefail
set -a
eval "$(grep -E '^export (GROQ_API_KEY|NVIDIA_API_KEY|CEREBRAS_API_KEY|GOOGLE_AI_KEY|AFL_)' "$HOME/.bashrc")"
set +a
cd "$HOME/Nemesis"
source nemesis-env/bin/activate
nemesis setup -t libtiff_cve2022
