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
    if (len < 0 || len > 65536) continue;

    /* Create decoder instance */
    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state) continue;

    /* Set metadata callbacks — target function */
    BrotliDecoderSetMetadataCallbacks(
        state,
        (brotli_decoder_metadata_start_func)((uintptr_t)buf),
        (brotli_decoder_metadata_chunk_func)((uintptr_t)buf + 1),
        (void*)((uintptr_t)buf + 2)
    );

    /* Cleanup */
    BrotliDecoderDestroyInstance(state);
  }
  return 0;
}