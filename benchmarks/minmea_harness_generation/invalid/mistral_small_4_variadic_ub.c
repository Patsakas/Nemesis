#include "minmea.h"
#include <string.h>
#include <stdlib.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    __AFL_LOOP(10000) {
        /* Input is null-terminated by AFL++ */
        const char *sentence = (const char *)__AFL_FUZZ_TESTCASE_BUF;
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        /* Ensure null-termination (AFL++ does this, but be explicit) */
        char *buf = (char *)malloc(len + 1);
        if (!buf) return 1;
        memcpy(buf, sentence, len);
        buf[len] = '\0';

        /* Test minmea_scan with various format strings */
        /* Format strings that cover different parsing paths */
        const char *formats[] = {
            "t",           /* Talker ID */
            "tT",          /* Talker + Time */
            "tTf",         /* Talker + Time + Float */
            "tTf;f",       /* Talker + Time + Float + optional Float */
            "tcfdfd",      /* Talker + Char + Float + Dir + Float + Dir */
            "t;fcfcfcfcc", /* Talker + optional Float + Char + Float + Char + Float + Char + Float + Char + Char */
            "tciiiiiiiiiiiiifff", /* Talker + Char + 12 ints + 3 floats (GSA) */
            "tiii;iiifiiifiiifiiif", /* Talker + 3 ints + optional + 4*4 fields (GSV) */
            "tfdfdTc;c",    /* Talker + Float + Dir + Float + Dir + Time + Char + Char (GLL) */
            "tTfffifff",    /* Talker + Time + 4 floats + int + 3 floats (GBS) */
            "tTfdfdiiffcfcf_", /* Talker + Time + Float + Dir + Float + Dir + int + float + float + char + float + char + float + char + ignore (GGA) */
            "tTiiiii",      /* Talker + Time + 5 ints (ZDA) */
            "tTfffffff",     /* Talker + Time + 7 floats (GST) */
            "t;fcfcfcfcc"   /* Talker + optional Float + Char + Float + Char + Float + Char + Float + Char + Char (VTG) */
        };

        /* Try parsing with each format */
        for (size_t i = 0; i < sizeof(formats)/sizeof(formats[0]); i++) {
            /* Use a union to capture different output types */
            union {
                union minmea_type type;
                struct minmea_time time;
                struct minmea_float fval;
                char cval;
                int ival;
                struct minmea_date dval;
            } output;

            /* Call minmea_scan */
            bool parsed = minmea_scan(buf, formats[i],
                &output.type,
                &output.time,
                &output.fval,
                &output.cval,
                &output.ival,
                &output.dval
            );

            /* Prevent dead-store elimination */
            if (parsed) {
                volatile int dummy = 0;
                (void)dummy;
            }
        }

        free(buf);
    }
    return 0;
}