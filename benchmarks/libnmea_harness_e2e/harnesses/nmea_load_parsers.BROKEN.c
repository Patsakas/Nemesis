#include <stddef.h>
#include "nmea.h"
#include "parser.h"

/* AFL++ persistent mode initialization – must be at file scope */
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        /* We don't actually feed file contents; instead we set NMEA_PARSER_PATH
           to a directory path controlled by the fuzzer. The harness simply calls
           nmea_load_parsers() which reads the directory itself via getenv(). */
        (void)buf; (void)len; /* suppress unused warnings */

        /* Call the target function */
        int rv = nmea_load_parsers();
        (void)rv; /* suppress unused warning */
    }
    return 0;
}