#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lz4.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  __AFL_INIT();
  __AFL_LOOP(10000) {
    /* Read fuzz input */
    const uint8_t *input = (const uint8_t *)__AFL_FUZZ_TESTCASE_BUF;
    size_t input_len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
    if (input_len == 0) continue;

    /* Clamp input size to LZ4_MAX_INPUT_SIZE for decompression */
    size_t compressedSize = input_len > LZ4_MAX_INPUT_SIZE ? LZ4_MAX_INPUT_SIZE : input_len;

    /* Allocate output buffer using safe upper bound */
    size_t maxDecompressedSize = input_len * 2 + 1024; /* Conservative upper bound */
    if (maxDecompressedSize > LZ4_MAX_INPUT_SIZE) {
      maxDecompressedSize = LZ4_MAX_INPUT_SIZE;
    }
    char *decompressed = (char *)malloc(maxDecompressedSize);
    if (!decompressed) continue;

    /* Call LZ4_decompress_safe to exercise LZ4_decompress_generic */
    int decompressedSize = LZ4_decompress_safe(
        (const char *)input,
        decompressed,
        (int)compressedSize,
        (int)maxDecompressedSize
    );

    /* Validate decompression result */
    if (decompressedSize >= 0) {
      /* Optional: Add validation logic here if needed */
    }

    /* Clean up */
    free(decompressed);
  }
  return 0;
}
