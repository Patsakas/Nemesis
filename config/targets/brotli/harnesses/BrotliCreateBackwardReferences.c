/*
 * Hand-crafted harness for BrotliCreateBackwardReferences (Fix 129)
 *
 * This function requires complex initialization that LLMs consistently fail:
 *   - MemoryManager for hasher allocation
 *   - BrotliEncoderParams with dictionary + distance params
 *   - Hasher via HasherInit() + HasherSetup() (allocates internal state)
 *   - ContextLut via BROTLI_CONTEXT_LUT() macro
 *
 * Quality range 2-9 routes through this function (0-1 → CompressFragment,
 * 10-11 → Zopfli path).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* Internal brotli headers — linkable from static .a archive */
#include "backward_references.h"    /* BrotliCreateBackwardReferences */
#include "command.h"                /* Command struct */
#include "hash.h"                   /* Hasher, HasherInit, HasherSetup, DestroyHasher */
#include "memory.h"                 /* MemoryManager, BrotliInitMemoryManager */
#include "params.h"                 /* BrotliEncoderParams */
#include "quality.h"                /* SanitizeParams, ComputeLgBlock, ChooseHasher */
#include "encoder_dict.h"           /* BrotliInitSharedEncoderDictionary */
#include "metablock.h"              /* BrotliInitDistanceParams */
#include "../common/context.h"      /* BROTLI_CONTEXT_LUT, ContextType */
#include "../common/constants.h"    /* BROTLI_MAX_DISTANCE_BITS etc. */

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

        /* Need at least 3 bytes: quality(1) + lgwin(1) + data(1+) */
        if (len < 3) continue;

        /* Cap input to prevent excessive allocation in HasherSetup */
        if (len > 65536) len = 65536;

        /* ---- Extract fuzz-derived parameters from first 2 bytes ---- */
        int quality = 2 + (buf[0] % 8);    /* Range 2-9 (CreateBackwardReferences path) */
        int lgwin = 10 + (buf[1] % 15);    /* Range 10-24 */
        if (lgwin > BROTLI_MAX_WINDOW_BITS)
            lgwin = BROTLI_MAX_WINDOW_BITS;

        const uint8_t *data = buf + 2;
        size_t data_len = (size_t)(len - 2);

        /* ---- 1. Initialize MemoryManager (uses default malloc/free) ---- */
        MemoryManager m;
        BrotliInitMemoryManager(&m, NULL, NULL, NULL);

        /* ---- 2. Initialize BrotliEncoderParams (mirroring BrotliEncoderInitParams) ---- */
        BrotliEncoderParams params;
        memset(&params, 0, sizeof(params));
        params.mode = BROTLI_MODE_GENERIC;
        params.large_window = BROTLI_FALSE;
        params.quality = quality;
        params.lgwin = lgwin;
        params.lgblock = 0;
        params.stream_offset = 0;
        params.size_hint = data_len;
        params.disable_literal_context_modeling = BROTLI_FALSE;

        /* Initialize dictionary (required — contains static dict pointers) */
        BrotliInitSharedEncoderDictionary(&params.dictionary);

        /* Initialize distance params (mirroring ChooseDistanceParams with npostfix=0, ndirect=0) */
        BrotliInitDistanceParams(&params.dist, 0, 0, BROTLI_FALSE);

        /* Sanitize and compute derived params (these are static inline from quality.h) */
        SanitizeParams(&params);
        params.lgblock = ComputeLgBlock(&params);

        /* Choose hasher type based on quality/lgwin (static inline from quality.h) */
        ChooseHasher(&params, &params.hasher);

        /* ---- 3. Initialize Hasher via proper library functions ---- */
        Hasher hasher;
        HasherInit(&hasher);  /* Sets is_setup_ = FALSE, clears extra[] */

        /* HasherSetup allocates internal state via MemoryManager.
         * is_last=TRUE since we process the whole input as one block. */
        HasherSetup(&m, &hasher, &params, data, 0, data_len, BROTLI_TRUE);

        if (BROTLI_IS_OOM(&m)) {
            DestroyHasher(&m, &hasher);
            BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
            BrotliWipeOutMemoryManager(&m);
            continue;
        }

        /* ---- 4. ContextLut from library macro ---- */
        ContextLut literal_context_lut = BROTLI_CONTEXT_LUT(CONTEXT_UTF8);

        /* ---- 5. Prepare output buffers ---- */
        /* Commands: worst case is one command per byte */
        size_t max_commands = data_len + 1;
        if (max_commands > 65536) max_commands = 65536;
        Command *commands = (Command *)calloc(max_commands, sizeof(Command));
        if (!commands) {
            DestroyHasher(&m, &hasher);
            BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
            BrotliWipeOutMemoryManager(&m);
            continue;
        }

        /* dist_cache needs BROTLI_NUM_DISTANCE_SHORT_CODES (16) entries;
         * PrepareDistanceCache() writes up to index 15.
         * Initial values: first 4 from encoder defaults, rest zeroed. */
        int dist_cache[BROTLI_NUM_DISTANCE_SHORT_CODES] = {4, 11, 15, 16};
        size_t last_insert_len = 0;
        size_t num_commands = 0;
        size_t num_literals = 0;
        size_t position = 0;
        size_t ringbuffer_mask = data_len - 1;

        /* ---- 6. Call the target function ---- */
        BrotliCreateBackwardReferences(
            data_len,               /* num_bytes */
            position,               /* position */
            data,                   /* ringbuffer */
            ringbuffer_mask,        /* ringbuffer_mask */
            literal_context_lut,    /* literal_context_lut */
            &params,                /* params */
            &hasher,                /* hasher (properly initialized!) */
            dist_cache,             /* dist_cache */
            &last_insert_len,       /* last_insert_len */
            commands,               /* commands output */
            &num_commands,          /* num_commands output */
            &num_literals);         /* num_literals output */

        /* ---- 7. Cleanup ---- */
        free(commands);
        DestroyHasher(&m, &hasher);
        BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
        BrotliWipeOutMemoryManager(&m);
    }

    return 0;
}
