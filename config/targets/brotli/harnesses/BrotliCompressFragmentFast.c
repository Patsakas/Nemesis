#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "compress_fragment.h"
#include "../common/constants.h"
#include "../common/platform.h"
#include "entropy_encode.h"

/* Fuzzed data provider implementation */
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} fuzzed_data_provider_t;

static fuzzed_data_provider_t* fuzzed_data_provider_create(const uint8_t *buf, size_t len) {
    fuzzed_data_provider_t *dp = malloc(sizeof(fuzzed_data_provider_t));
    if (!dp) return NULL;
    dp->data = buf;
    dp->size = len;
    dp->offset = 0;
    return dp;
}

static void fuzzed_data_provider_destroy(fuzzed_data_provider_t *dp) {
    free(dp);
}

static uint32_t fuzzed_data_provider_consume_uint32(fuzzed_data_provider_t *dp) {
    if (dp->offset + 4 > dp->size) return 0;
    uint32_t val = ((uint32_t)dp->data[dp->offset]) |
                   ((uint32_t)dp->data[dp->offset + 1] << 8) |
                   ((uint32_t)dp->data[dp->offset + 2] << 16) |
                   ((uint32_t)dp->data[dp->offset + 3] << 24);
    dp->offset += 4;
    return val;
}

static int32_t fuzzed_data_provider_consume_int32(fuzzed_data_provider_t *dp) {
    if (dp->offset + 4 > dp->size) return 0;
    int32_t val = ((int32_t)dp->data[dp->offset]) |
                  ((int32_t)dp->data[dp->offset + 1] << 8) |
                  ((int32_t)dp->data[dp->offset + 2] << 16) |
                  ((int32_t)dp->data[dp->offset + 3] << 24);
    dp->offset += 4;
    return val;
}

static uint8_t fuzzed_data_provider_consume_uint8(fuzzed_data_provider_t *dp) {
    if (dp->offset + 1 > dp->size) return 0;
    uint8_t val = dp->data[dp->offset];
    dp->offset += 1;
    return val;
}

static size_t fuzzed_data_provider_remaining_bytes(fuzzed_data_provider_t *dp) {
    return dp->size > dp->offset ? dp->size - dp->offset : 0;
}

static const uint8_t* fuzzed_data_provider_consume_buffer(fuzzed_data_provider_t *dp, size_t len) {
    if (dp->offset + len > dp->size) {
        len = dp->size > dp->offset ? dp->size - dp->offset : 0;
    }
    const uint8_t *result = dp->data + dp->offset;
    dp->offset += len;
    return result;
}

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        if (len < 9) continue;  /* Need at least: 4 (table_size) + 4 (first table element) + 1 (is_last) */
        
        fuzzed_data_provider_t *dp = fuzzed_data_provider_create(buf, len);
        if (!dp) {
            continue;
        }
        
        /* Consume table size (4 bytes) and cap it to avoid excessive allocation */
        uint32_t table_size_val = fuzzed_data_provider_consume_uint32(dp);
        if (table_size_val > (1<<20)) {  /* Cap at 1M entries (4MB for int array) */
            table_size_val = 1<<20;
        }
        if (table_size_val == 0) {
            table_size_val = 1;  /* Avoid zero */
        }
        
        /* Allocate table */
        int *table = malloc(table_size_val * sizeof(int));
        if (!table) {
            fuzzed_data_provider_destroy(dp);
            continue;
        }
        
        /* Fill table with fuzz data */
        for (size_t i = 0; i < table_size_val; i++) {
            table[i] = fuzzed_data_provider_consume_int32(dp);
        }
        
        /* Consume is_last flag (1 byte) */
        uint8_t is_last = fuzzed_data_provider_consume_uint8(dp);
        
        /* Consume input data to compress, cap at 1MB */
        size_t input_size = fuzzed_data_provider_remaining_bytes(dp);
        if (input_size > (1<<20)) {  /* Cap input at 1MB */
            input_size = (1<<20);
        }
        
        const uint8_t *input_data = fuzzed_data_provider_consume_buffer(dp, input_size);
        
        fuzzed_data_provider_destroy(dp);
        
        /* Allocate output buffer (capped at 16MB) */
        size_t storage_cap = 1<<24;  /* 16MB */
        uint8_t *storage = malloc(storage_cap);
        if (!storage) {
            free(table);
            continue;
        }
        
        /* Allocate and zero the BrotliOnePassArena */
        BrotliOnePassArena *arena = malloc(sizeof(BrotliOnePassArena));
        if (!arena) {
            free(table);
            free(storage);
            continue;
        }
        memset(arena, 0, sizeof(BrotliOnePassArena));
        
        size_t storage_ix = 0;
        
        /* Call the target function */
        BrotliCompressFragmentFast(arena, input_data, input_size, is_last ? BROTLI_TRUE : BROTLI_FALSE, table, table_size_val, &storage_ix, storage);
        
        /* Clean up */
        free(arena);
        free(table);
        free(storage);
    }
    
    return 0;
}