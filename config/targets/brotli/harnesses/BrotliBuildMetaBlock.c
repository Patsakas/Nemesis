#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/encode.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        /* Skip empty or too-large inputs */
        if (len < 1 || len > 16 * 1024 * 1024) continue;

        /* Create encoder instance */
        BrotliEncoderState *state = BrotliEncoderCreateInstance(NULL, NULL, NULL);
        if (!state) continue;

        /* Set encoder parameters - these affect metablock construction */
        BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, 11);
        BrotliEncoderSetParameter(state, BROTLI_PARAM_LGWIN, 24);
        BrotliEncoderSetParameter(state, BROTLI_PARAM_MODE, BROTLI_MODE_GENERIC);

        /* Allocate output buffer - worst case: slightly larger than input */
        size_t encoded_size = len + 4096;
        unsigned char *encoded = (unsigned char *)malloc(encoded_size);
        if (!encoded) {
            BrotliEncoderDestroyInstance(state);
            continue;
        }

        /* Compress the fuzz input - this triggers WriteMetaBlockInternal
         * which calls BrotliBuildMetaBlock internally */
        /* BrotliEncoderCompress signature:
         * BrotliEncoderCompress(int quality, BrotliEncoderMode mode, int lgwin,
         *                        size_t input_size, const uint8_t* input_buffer,
         *                        size_t* encoded_size, uint8_t* encoded_buffer)
         */
        BROTLI_BOOL result = BrotliEncoderCompress(
            11,                           /* quality */
            BROTLI_DEFAULT_MODE,          /* mode */
            24,                           /* lgwin */
            (size_t)len,                  /* input_size */
            (const uint8_t *)buf,         /* input_buffer */
            &encoded_size,                /* encoded_size */
            encoded                       /* encoded_buffer */
        );

        /* Cleanup */
        free(encoded);
        BrotliEncoderDestroyInstance(state);
    }

    return 0;
}
