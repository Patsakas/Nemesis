#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "../common/constants.h"
#include "../common/platform.h"
#include "entropy_encode.h"
#include "compress_fragment_two_pass.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 10) continue;  /* Need enough for all parameters */

        /* We'll use the first few bytes to set up parameters */
        size_t input_size = len - 10;  /* Reserve 10 bytes for parameters */
        if (input_size > 1 << 20)  /* Cap input size at 1MB to prevent OOM */
            input_size = 1 << 20;
        const uint8_t *input = buf + 10;

        /* Extract parameters from the first 10 bytes */
        BROTLI_BOOL is_last = buf[0] & 1;
        size_t table_size = (buf[1] << 8) | buf[2];
        if (table_size > 1 << 20)  /* Cap table size */
            table_size = 1 << 20;
        size_t storage_ix_val = (buf[3] << 24) | (buf[4] << 16) | (buf[5] << 8) | buf[6];
        /* We'll use a storage buffer and update storage_ix via pointer */

        /* Allocate necessary buffers */
        BrotliTwoPassArena *arena = (BrotliTwoPassArena *)calloc(1, sizeof(BrotliTwoPassArena));
        if (!arena) continue;

        /* Fix 129: command_buf/literal_buf must be kCompressFragmentTwoPassBlockSize
         * (1<<17 = 131072) — this is what the library allocates internally. */
        size_t buf_size = 1 << 17;  /* kCompressFragmentTwoPassBlockSize */
        uint32_t *command_buf = (uint32_t *)malloc(buf_size * sizeof(uint32_t));
        if (!command_buf) {
            free(arena);
            continue;
        }
        uint8_t *literal_buf = (uint8_t *)malloc(buf_size);
        if (!literal_buf) {
            free(command_buf);
            free(arena);
            continue;
        }
        int *table = (int *)calloc(table_size, sizeof(int));
        if (!table) {
            free(literal_buf);
            free(command_buf);
            free(arena);
            continue;
        }
        /* Fix 129: Storage buffer must be 2 * input_size + 503 (see encode.c:1033).
         * The library uses GetBrotliStorage(s, 2 * bytes + 503).
         * storage_ix starts from last_bytes_bits_ (max ~16 bits). */
        size_t storage_size = 2 * input_size + 503;
        uint8_t *storage = (uint8_t *)malloc(storage_size);
        if (!storage) {
            free(table);
            free(literal_buf);
            free(command_buf);
            free(arena);
            continue;
        }
        memset(storage, 0, storage_size);
        size_t storage_ix = storage_ix_val % 16;  /* Mimics last_bytes_bits_ (0-15) */

        /* Call the target function */
        BrotliCompressFragmentTwoPass(arena, input, input_size, is_last,
                                      command_buf, literal_buf, table, table_size,
                                      &storage_ix, storage);

        /* Clean up */
        free(storage);
        free(table);
        free(literal_buf);
        free(command_buf);
        free(arena);
    }
    return 0;
}