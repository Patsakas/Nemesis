#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/decode.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 1 || len > 512 * 1024) continue;

    /* Step 1: Create decoder state */
    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state) continue;

    /* Step 2: Set up input buffer */
    const uint8_t *next_in = buf;
    size_t available_in = (size_t)len;

    /* Step 3: Set up output buffer (needs to be 16MB cap) */
    uint8_t out_buf[4096];
    size_t available_out = sizeof(out_buf);
    uint8_t *next_out = out_buf;
    size_t total_out = 0;

    /* Step 4: Decompress stream — populates internal state */
    BrotliDecoderResult st = BrotliDecoderDecompressStream(
        state,
        &available_in,
        &next_in,
        &available_out,
        &next_out,
        &total_out
    );

    /* Step 5: Call BrotliDecoderTakeOutput after decompression */
    size_t output_size = 0;
    const uint8_t *output_data = BrotliDecoderTakeOutput(state, &output_size);

    /* NOP output_data to prevent dead-code removal */
    if (output_data) {
      (void)output_data[0];
    }

    /* Step 6: Cleanup */
    BrotliDecoderDestroyInstance(state);
  }
  return 0;
}
