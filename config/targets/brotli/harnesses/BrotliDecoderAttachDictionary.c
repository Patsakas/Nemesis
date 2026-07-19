#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/decode.h>
#include <brotli/shared_dictionary.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 2) continue;

    uint16_t dict_size = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    if (dict_size > 32768) dict_size = 32768;
    if ((int)dict_size + 2 > len) continue;

    const uint8_t *dict_data = buf + 2;
    const uint8_t *stream_data = buf + 2 + dict_size;
    size_t stream_size = (size_t)(len - 2 - dict_size);
    if (stream_size == 0) continue;

    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state) continue;

    if (!BrotliDecoderAttachDictionary(state, BROTLI_SHARED_DICTIONARY_RAW, dict_size, dict_data)) {
      BrotliDecoderDestroyInstance(state);
      continue;
    }

    size_t available_in = stream_size;
    const uint8_t *next_in = stream_data;
    size_t available_out = 0;
    uint8_t *next_out = NULL;
    size_t total_out = 0;

    BrotliDecoderResult res = BrotliDecoderDecompressStream(
        state, &available_in, &next_in, &available_out, &next_out, &total_out);

    if (total_out > (1 << 24)) {
      BrotliDecoderDestroyInstance(state);
      continue;
    }

    BrotliDecoderDestroyInstance(state);
  }
  return 0;
}