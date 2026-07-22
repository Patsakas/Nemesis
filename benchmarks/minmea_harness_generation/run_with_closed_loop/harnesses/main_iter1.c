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

        /* Parse as RMC sentence to extract date/time components */
        struct minmea_sentence_rmc frame;
        if (minmea_parse_rmc(&frame, buf)) {
            /* Valid parse - extract date/time */
            struct minmea_date d = frame.date;
            struct minmea_time t = frame.time;

            /* Call minmea_getdatetime and minmea_gettime */
            struct tm tm;
            struct timespec ts;
            if (minmea_getdatetime(&tm, &d, &t) == 0 &&
                minmea_gettime(&ts, &d, &t) == 0) {
                /* Prevent dead-store elimination */
                volatile int dummy_year = tm.tm_year;
                volatile time_t dummy_sec = ts.tv_sec;
            }
        }

        /* Alternative: Parse as ZDA sentence for date/time */
        struct minmea_sentence_zda zda_frame;
        if (minmea_parse_zda(&zda_frame, buf)) {
            struct minmea_date d = zda_frame.date;
            struct minmea_time t = zda_frame.time;
            struct tm tm;
            struct timespec ts;
            if (minmea_getdatetime(&tm, &d, &t) == 0 &&
                minmea_gettime(&ts, &d, &t) == 0) {
                volatile int dummy_year = tm.tm_year;
                volatile time_t dummy_sec = ts.tv_sec;
            }
        }

        /* Alternative: Use minmea_scan to extract date/time */
        struct minmea_date d_scan;
        struct minmea_time t_scan;
        if (minmea_scan(buf, "_D_T", &d_scan, &t_scan)) {
            struct tm tm;
            struct timespec ts;
            if (minmea_getdatetime(&tm, &d_scan, &t_scan) == 0 &&
                minmea_gettime(&ts, &d_scan, &t_scan) == 0) {
                volatile int dummy_year = tm.tm_year;
                volatile time_t dummy_sec = ts.tv_sec;
            }
        }

        /* Alternative: Use minmea_float utilities */
        struct minmea_float f;
        if (minmea_scan(buf, "f", &f)) {
            volatile float dummy_float = minmea_tofloat(&f);
        }

        free(buf);
    }
    return 0;
}