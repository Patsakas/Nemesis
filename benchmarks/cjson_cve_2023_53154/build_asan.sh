#!/usr/bin/env bash
# Build a standalone ASan reproducer for CVE-2023-53154.
#
# Not the AFL fuzzing binary and not the debug harness. Both mask this bug:
# the fuzzing binary receives no input outside afl-fuzz, and the debug harness
# parses out of a 1 MB static buffer, so a one-byte over-read at the end of the
# input lands in valid zeroed memory and ASan reports nothing (see Fix 139).
#
# This reproducer heap-copies the input to a malloc of exactly its length, so
# the ASan redzone sits at buf[len] and the over-read is caught.
#
# Usage: build_asan.sh <path-to-cjson-source-checkout> [output-binary]
#   The checkout must be at a version BEFORE the fix (< 1.7.18). Verify with
#   reproduce.sh afterwards.
set -euo pipefail

SRC="${1:?path to a cJSON source checkout (< 1.7.18)}"
OUT="${2:-/tmp/cjson_cve_repro}"

[[ -f "$SRC/cJSON.c" ]] || { echo "no cJSON.c in $SRC" >&2; exit 1; }

work=$(mktemp -d)
cat > "$work/repro.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "cJSON.h"
int main(int argc, char **argv) {
    /* Self-imposed timeout via alarm(), NOT an external `timeout` wrapper.
       On WSL, running this binary under `timeout` (or as a backgrounded job)
       stops ASan's fork-based symbolizer from working — the stack comes back
       unsymbolized and the oracle's parse_string:786 match silently fails.
       alarm() keeps the process in the foreground with a controlling
       terminal, so symbolization works, while still capping runtime. */
    alarm(10);
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    /* Tight allocation: the redzone lands at buf[n], so parse_string reading
       one byte past the declared length is caught rather than absorbed. */
    char *buf = malloc(n > 0 ? n : 1);
    if (n > 0 && fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return 2; }
    fclose(f);
    cJSON *j = cJSON_ParseWithLength(buf, (size_t)n);
    if (j) cJSON_Delete(j);
    free(buf);
    return 0;
}
EOF

# -O0, not -O1: at -O1 clang inlines parse_string into parse_object, so the
# ASan stack top becomes parse_object and the oracle's signature match (which
# names parse_string:786) silently fails. -O0 keeps the frames the oracle
# expects. -fno-omit-frame-pointer for good measure.
clang -g -O0 -fno-omit-frame-pointer -fsanitize=address \
      -I"$SRC" -o "$OUT" "$work/repro.c" "$SRC/cJSON.c" -lm
rm -rf "$work"
echo "built: $OUT"
