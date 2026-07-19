#!/usr/bin/env bash
# Probe NVIDIA NIM for available top-tier models. Throwaway diagnostic.
set -u
set -a
eval "$(grep -E '^export NVIDIA_API_KEY' "$HOME/.bashrc")"
set +a

URL="https://integrate.api.nvidia.com/v1/chat/completions"

# Candidates to probe
CANDIDATES=(
  "mistralai/mistral-medium-3.5-128b-instruct"
  "mistralai/mistral-medium-3.5-128b"
  "mistralai/mistral-medium-3.5"
  "mistralai/mistral-medium-3-5-128b"
  "mistralai/mistral-medium-3-5-128b-instruct"
  "mistralai/mistral-medium-3-5"
  "mistralai/mistral-medium-128b-instruct-2506"
  "mistralai/mistral-medium-128b-instruct-2509"
  "mistralai/mistral-large-2-instruct"
  "mistralai/mistral-small-4-119b-2603"
  "deepseek-ai/deepseek-v3.2"
  "deepseek-ai/deepseek-v3-2"
  "deepseek-ai/deepseek-v3"
  "deepseek-ai/deepseek-r1"
  "qwen/qwen3-coder-480b-a35b"
  "qwen/qwen3-coder-30b-a3b-instruct"
  "qwen/qwen3-235b-a22b"
  "qwen/qwen3.5-122b-a10b"
  "nvidia/llama-3.3-nemotron-super-49b-v1"
  "nvidia/nemotron-4-340b-instruct"
  "minimaxai/minimax-m2.5"
)

for m in "${CANDIDATES[@]}"; do
  body=$(printf '{"model":"%s","messages":[{"role":"user","content":"reply OK"}],"max_tokens":3}' "$m")
  code=$(curl -sS -o /tmp/nim_r.json -w '%{http_code}' \
    -X POST "$URL" \
    -H "Authorization: Bearer $NVIDIA_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$body")
  if [ "$code" = "200" ]; then
    echo "OK   $m"
  else
    snippet=$(head -c 120 /tmp/nim_r.json | tr -d '\n')
    echo "FAIL $code  $m  -- $snippet"
  fi
done
