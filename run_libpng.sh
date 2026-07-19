#!/usr/bin/env bash
# Wrapper for nemesis libpng run — loads API keys from .bashrc
# (bypassing the non-interactive guard) and uses the venv python.

# Load API keys (.bashrc skips non-interactive shells, so source the export
# lines directly via grep+eval).
set -a
eval "$(grep -E '^export (GROQ|NVIDIA|CEREBRAS|GOOGLE_AI|MISTRAL|ANTHROPIC|OPENAI)' $HOME/.bashrc)"
set +a

cd /mnt/c/Users/giorg/OneDrive/Desktop/Nemesis/Nemesis
exec $HOME/Nemesis/nemesis-env/bin/python -m nemesis.cli run \
    -t libpng --scan --max-targets 2 --strategy harness
