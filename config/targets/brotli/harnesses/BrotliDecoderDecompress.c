#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/decode.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 1 || len > 512 * 1024) continue;

        /* Allocate output buffer (16MB cap as per hint) */
        const size_t kOutLimit = 1 << 24;  /* 16MB */
        uint8_t *out_buf = (uint8_t *)malloc(kOutLimit);
        if (!out_buf) continue;

        size_t decoded_size = 0;
        
        /* Call the one-shot decompress function */
        BrotliDecoderResult result = BrotliDecoderDecompress(
            (size_t)len, buf, &decoded_size, out_buf);
        
        /* Result check for completeness (unused in fuzzing) */
        (void)result;
        
        free(out_buf);
    }
    return 0;
}