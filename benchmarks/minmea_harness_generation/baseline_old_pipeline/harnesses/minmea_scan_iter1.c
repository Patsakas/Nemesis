#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "minmea.h"
#include <string.h>
#include <stdlib.h>
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        /* Input is null-terminated by AFL++ */
        const char *sentence = (const char *)__AFL_FUZZ_TESTCASE_BUF;
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        /* Ensure null-termination (AFL++ does this, but be explicit) */
        char *buf = (char *)malloc(len + 1);
        if (!buf) return 1;
        memcpy(buf, sentence, len);
        buf[len] = '\0';

        /* Fuzz minmea_scan with various format strings */
        struct minmea_float f;
        struct minmea_time t;
        struct minmea_date d;
        union minmea_type type;
        char c;
        int i;
        char s[MINMEA_MAX_SENTENCE_LENGTH];

        /* Test various format specifiers */
        if (minmea_scan(buf, "t", &type)) {
            volatile int dummy = type.sentence_id[0];
        }
        if (minmea_scan(buf, "T", &t)) {
            volatile int dummy = t.hours;
        }
        if (minmea_scan(buf, "D", &d)) {
            volatile int dummy = d.day;
        }
        if (minmea_scan(buf, "f", &f)) {
            volatile int dummy = f.value;
        }
        if (minmea_scan(buf, "i", &i)) {
            volatile int dummy = i;
        }
        if (minmea_scan(buf, "c", &c)) {
            volatile char dummy = c;
        }
        if (minmea_scan(buf, "s", s)) {
            volatile char dummy = s[0];
        }

        /* Test optional fields */
        if (minmea_scan(buf, ";f", &f)) {
            volatile int dummy = f.scale;
        }

        /* Test combined formats */
        if (minmea_scan(buf, "tTf", &type, &t, &f)) {
            volatile int dummy = type.talker_id[0];
        }

        free(buf);
    }
    return 0;
}