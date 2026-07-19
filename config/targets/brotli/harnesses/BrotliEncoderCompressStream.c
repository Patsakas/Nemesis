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
        if (len < 1 || len > 65535) continue;

        /* Use BrotliEncoderCompress (public API) which internally calls
         * BrotliEncoderCompressStream multiple times during compression.
         * This follows the caller escalation pattern - we call the caller,
         * which in turn invokes the deep target internally. */

        /* Vary quality to exercise different code paths in BrotliEncoderCompressStream:
         * - quality 0-4: slow path (uses main compression loop with EncodeData)
         * - quality 5-9: default path
         * - quality 10-11: fast path (uses BrotliEncoderCompressStreamFast) */
        int quality = (buf[0] % 12);

        /* Vary window size to exercise different lgwin paths */
        int lgwin = 16 + (buf[1] % 8);  /* 16-23 */

        /* Vary mode to exercise different encoding modes */
        BrotliEncoderMode mode = (buf[2] % 2) ? BROTLI_MODE_GENERIC : BROTLI_MODE_TEXT;

        /* Calculate max possible output size */
        size_t max_encoded_size = BrotliEncoderMaxCompressedSize(len);
        if (max_encoded_size == 0 || max_encoded_size > 16 << 20) {
            max_encoded_size = 16 << 20;  /* Cap at 16MB */
        }

        uint8_t *encoded = (uint8_t *)malloc(max_encoded_size);
        if (!encoded) continue;

        size_t encoded_size = max_encoded_size;

        /* Call BrotliEncoderCompress - this is the CALLER that internally
         * invokes BrotliEncoderCompressStream. This is the intended path
         * to reach the deep target function indirectly. */
        BROTLI_BOOL result = BrotliEncoderCompress(
            quality,
            lgwin,
            mode,
            (size_t)len,
            buf,
            &encoded_size,
            encoded
        );

        /* If compression succeeded, we exercised BrotliEncoderCompressStream
         * internally. The result is in 'encoded' buffer of size 'encoded_size'. */
        if (result) {
            /* Successfully compressed - BrotliEncoderCompressStream was called
             * internally with BROTLI_OPERATION_PROCESS and BROTLI_OPERATION_FINISH */
        }

        free(encoded);
    }

    return 0;
}
