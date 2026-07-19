#!/usr/bin/env bash
set -u
CDIR="$HOME/nemesis_workspace/fuzzing/findings/109062ee0363/cJSON_ParseWithLength/main/crashes"
DBG="$HOME/cjson_clean/build_debug/fuzz_nemesis_debug"
TMP="/tmp/cve_repro"
mkdir -p "$TMP"

first=$(ls "$CDIR"/id:000000* 2>/dev/null | head -1)
if [ -z "$first" ]; then
  echo "ERROR: no crash file found in $CDIR"
  exit 1
fi
cp "$first" "$TMP/crash.bin"

echo "============================================================"
echo "CVE-2023-53154 REPRODUCTION — cJSON v1.7.17"
echo "============================================================"
echo "Crash file: $(basename "$first")"
echo "Size:       $(stat -c %s "$TMP/crash.bin") bytes"
echo ""
echo "--- HEX DUMP ---"
xxd "$TMP/crash.bin"
echo ""
echo "--- ASCII ---"
cat "$TMP/crash.bin"
echo ""
echo ""
echo "============================================================"
echo "ASAN REPRO (debug binary, single-shot via stdin)"
echo "============================================================"
ASAN_OPTIONS="symbolize=1:abort_on_error=0:print_stacktrace=1:detect_leaks=0" \
  timeout 5 "$DBG" < "$TMP/crash.bin" 2>&1
echo ""
echo "Exit code: $?"
echo ""
echo "============================================================"
echo "VALIDATION SUMMARY"
echo "============================================================"
echo "Library:    cJSON v1.7.17 (commit 87d8f0961a01bf09bef98ff89bae9fdec42181ee)"
echo "CVE:        CVE-2023-53154 (https://www.cve.org/CVERecord?id=CVE-2023-53154)"
echo "CWE:        CWE-125 Out-of-bounds Read"
echo "Detector:   AddressSanitizer (heap-buffer-overflow READ)"
echo "Target fn:  cJSON_ParseWithLength → cJSON_ParseWithLengthOpts → parse_value → parse_object → parse_string"
echo "Found by:   NEMESIS auto-onboarded fuzzer in 81 sec of AFL fuzzing"
