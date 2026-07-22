#include <stddef.h>
#include "nmea.h"

/* AFL++ persistent mode initialization – must be at file scope */
__AFL_FUZZ_INIT();

int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        /* Enforce maximum NMEA sentence length to avoid out‑of‑bounds reads */
        if (len > NMEA_MAX_LENGTH) continue;

        /* Ensure we have room for the mandatory \r\n terminators */
        if (len < 2) continue;
        if (buf[len-2] != (uint8_t)NMEA_END_CHAR_1 || buf[len-1] != (uint8_t)NMEA_END_CHAR_2) continue;

        /* The API expects a mutable C string, so copy into a temporary buffer and NUL‑terminate */
        char tmp[NMEA_MAX_LENGTH + 1];
        memcpy(tmp, buf, len);
        tmp[len] = '\0';

        /* 1. Identify sentence type */
        nmea_t type = nmea_get_type(tmp);
        (void)type; /* suppress unused warning */

        /* 2. Compute checksum (optional, just for coverage) */
        uint8_t cs = nmea_get_checksum(tmp);
        (void)cs;

        /* 3. Validate the sentence */
        int valid = nmea_validate(tmp, len, 1);
        (void)valid;

        /* 4. Parse the sentence into a struct */
        nmea_s *parsed = nmea_parse(tmp, len, 1);
        if (parsed) {
            /* Use a few fields to increase coverage */
            int err = parsed->errors;
            nmea_t ptype = parsed->type;
            (void)err; (void)ptype;
            nmea_free(parsed);
        }
    }
    return 0;
}