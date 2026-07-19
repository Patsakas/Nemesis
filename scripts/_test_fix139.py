"""Quick test for Fix 139 heap-copy injection on a sample harness."""
import re

HARNESS = """\
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <cJSON.h>
#include <stdlib.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        cJSON *json = cJSON_ParseWithLength(
            (const char *)__AFL_FUZZ_TESTCASE_BUF,
            (size_t)__AFL_FUZZ_TESTCASE_LEN
        );
        if (json) {
            cJSON_Delete(json);
        }
    }
    return 0;
}
"""

stmt_pattern = re.compile(
    r'((?:[A-Za-z_][A-Za-z0-9_ \t\*]*\s*=\s*)?'
    r'[A-Za-z_][A-Za-z0-9_]*\s*\(\s*'
    r'(?:\([^)]*\)\s*)?'
    r'__AFL_FUZZ_TESTCASE_BUF\s*,'
    r'[^;]*?'
    r'(?:\([^)]*\)\s*)?'
    r'__AFL_FUZZ_TESTCASE_LEN'
    r'[^;]*?'
    r'\)\s*;)',
    re.DOTALL,
)


def wrap(m):
    stmt = m.group(1)
    replaced = stmt.replace("__AFL_FUZZ_TESTCASE_BUF", "_nfx_buf")
    replaced = replaced.replace("__AFL_FUZZ_TESTCASE_LEN", "_nfx_len")
    return (
        "{\n"
        "        size_t _nfx_len = (size_t)__AFL_FUZZ_TESTCASE_LEN;\n"
        "        uint8_t *_nfx_buf = (uint8_t *)malloc(_nfx_len ? _nfx_len : 1);\n"
        "        if (_nfx_buf) {\n"
        "            if (_nfx_len) memcpy(_nfx_buf, __AFL_FUZZ_TESTCASE_BUF, _nfx_len);\n"
        "            " + replaced + "\n"
        "            free(_nfx_buf);\n"
        "        }\n"
        "        }"
    )


m = stmt_pattern.search(HARNESS)
print("Match found:", bool(m))
if m:
    print("--- matched statement ---")
    print(m.group(1))
    print("--- transformed harness ---")
    print(stmt_pattern.sub(wrap, HARNESS))
