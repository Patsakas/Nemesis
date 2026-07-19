#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 4 || len > 128 * 1024) continue;

    /* Split: first 2 bytes = dict_size (LE uint16), then dict, then data */
    uint16_t dict_size = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    if (dict_size > 32768) dict_size = 32768;
    if ((int)dict_size + 2 >= len) continue;

    const uint8_t *dict_data = buf + 2;
    const uint8_t *input = buf + 2 + dict_size;
    size_t input_size = (size_t)(len - 2 - dict_size);
    if (input_size < 1) continue;

    /* Create prepared dictionary from fuzz-controlled data */
    BrotliEncoderPreparedDictionary *pd = BrotliEncoderPrepareDictionary(
        BROTLI_SHARED_DICTIONARY_RAW, dict_size, dict_data, BROTLI_MAX_QUALITY, NULL, NULL, NULL);
    if (!pd) continue;

    /* Compress with compound dictionary at quality 10-11 (Zopfli path) */
    BrotliEncoderState *state = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (!state) {
      BrotliEncoderDestroyPreparedDictionary(pd);
      continue;
    }

    BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, 10 + (buf[2] % 2));
    BrotliEncoderSetParameter(state, BROTLI_PARAM_LGWIN, 16);
    BrotliEncoderAttachPreparedDictionary(state, pd);

    const uint8_t *next_in = input;
    size_t avail_in = input_size;
    uint8_t out_buf[4096];
    size_t avail_out = sizeof(out_buf);
    uint8_t *next_out = out_buf;
    size_t total_out = 0;

    /* Compress with FINISH to exercise full encoder pipeline */
    BrotliEncoderCompressStream(state, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, &total_out);

    /* Drain any remaining output */
    while (BrotliEncoderHasMoreOutput(state)) {
      avail_out = sizeof(out_buf);
      next_out = out_buf;
      BrotliEncoderCompressStream(state, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, &total_out);
    }

    BrotliEncoderDestroyInstance(state);
    BrotliEncoderDestroyPreparedDictionary(pd);
  }
  return 0;
}