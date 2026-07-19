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

        /* Clamp input size to LZ4_MAX_INPUT_SIZE for compressedSize parameter */
        size_t compressedSize = input_len > LZ4_MAX_INPUT_SIZE ? LZ4_MAX_INPUT_SIZE : input_len;

        /* Allocate output buffer with max possible decompressed size */
        size_t maxDecompressedSize = input_len > LZ4_MAX_INPUT_SIZE ? LZ4_MAX_INPUT_SIZE : input_len;
        char *decompressed = (char *)malloc(maxDecompressedSize);
        if (!decompressed) continue;

        /* Call target function: LZ4_decompress_safe */
        int result = LZ4_decompress_safe(
            (const char *)input,
            decompressed,
            (int)compressedSize,
            (int)maxDecompressedSize
        );

        /* Validate result (negative indicates error) */
        if (result < 0) {
            /* Error: free and continue */
        }

        /* Cleanup */
        free(decompressed);
    }
    return 0;
}
