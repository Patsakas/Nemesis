#!/usr/bin/env bash
# CVE oracle: does this input trigger CVE-2018-13785 in libpng?
#
# Prints CVE-HIT / exit 0 when the input reproduces the bug; CVE-MISS / exit 1
# otherwise. Needs a repro built from a vulnerable checkout (see build_repro.sh).
#
# The bug is an integer divide-by-zero: width*channels*factor overflows 32-bit,
# row_factor wraps to 0, and `height > PNG_UINT_32_MAX / row_factor` divides by
# zero, raising SIGFPE. So the fingerprint is simply death by signal 8 (exit
# 136), which needs no sanitizer and no symbolizer — none of the cJSON entry's
# symbolizer-hang problem applies here.
#
# SIGFPE alone is not unique to this CVE in principle; the differential in
# reproduce.sh (crashes on <1.6.35, clean on 1.6.35) is what pins it, since the
# row_factor cast is the only relevant change between the two.
#
# Usage: oracle.sh <repro-binary> <input-file>
set -uo pipefail

BINARY="${1:?repro binary (see build_repro.sh)}"
INPUT="${2:?input file to test}"

# Self-timeout would need an alarm() in the harness; the read path here is
# bounded and never hangs on the trigger, but guard other inputs with a plain
# timeout — it does not interfere with exit-code detection the way it broke
# ASan symbolization in the cJSON entry.
timeout 10 "$BINARY" "$INPUT" >/dev/null 2>&1
code=$?

# 136 = 128 + 8 (SIGFPE). Some shells report the raw signal; accept both.
if [[ $code -eq 136 || $code -eq 8 ]]; then
  echo "CVE-HIT"
  exit 0
fi
if [[ $code -ge 128 ]]; then
  echo "CVE-MISS (crashed on signal $((code - 128)) — not the divide-by-zero)"
  exit 1
fi
echo "CVE-MISS (clean, exit $code)"
exit 1
