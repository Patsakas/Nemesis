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
    if (len < 3 || len > 131072) continue; /* 128KB cap */

    /* Derive quality and lgwin from fuzz input */
    int quality = buf[0] % 12;           /* 0-11 */
    int lgwin = 10 + (buf[1] % 15);       /* 10-24 */
    if (lgwin > BROTLI_MAX_WINDOW_BITS) lgwin = BROTLI_MAX_WINDOW_BITS;

    const uint8_t *input = buf + 2;
    size_t input_size = (size_t)(len - 2);

    /* Allocate output buffer using public API */
    size_t max_out_size = BrotliEncoderMaxCompressedSize(input_size);
    if (max_out_size == 0) continue; /* overflow */
    uint8_t *encoded = (uint8_t *)malloc(max_out_size);
    if (!encoded) continue;

    size_t encoded_size = max_out_size;
    int mode = BROTLI_MODE_GENERIC;

    /* Call the one-shot compression API */
    int ok = BrotliEncoderCompress(
        quality,
        lgwin,
        mode,
        input_size,
        input,
        &encoded_size,
        encoded
    );

    /* Output invariants */
    if (!(encoded_size <= max_out_size)) abort();
    if (!(encoded_size <= 16 * 1024 * 1024)) abort();

    /* Cleanup */
    free(encoded);
  }
  return 0;
}