/**
 * AFL++ custom mutator for brotli encoder fuzzing.
 *
 * Understands the harness input format: buf[0]=quality, buf[1]=lgwin, buf[2:]=data.
 * Applies structure-aware mutations that preserve meaningful parameter values
 * while creating inputs that stress specific encoder code paths.
 *
 * Compile: afl-clang-fast -shared -fPIC -O2 -o brotli_mutator.so this_file.c
 * Use:     AFL_CUSTOM_MUTATOR_LIBRARY=./brotli_mutator.so AFL_CUSTOM_MUTATOR_ONLY=0 afl-fuzz ...
 *
 * AFL_CUSTOM_MUTATOR_ONLY=0 means this mutator runs alongside AFL's default
 * havoc/splice mutations, not replacing them.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* AFL++ custom mutator API */

typedef struct {
    uint8_t *buf;
    size_t buf_size;
    unsigned int seed;
} mutator_state_t;

/* Simple fast PRNG (xorshift32) */
static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

void *afl_custom_init(/* afl_state_t */ void *afl, unsigned int seed) {
    mutator_state_t *state = (mutator_state_t *)calloc(1, sizeof(mutator_state_t));
    if (!state) return NULL;
    state->seed = seed ? seed : 0xDEADBEEF;
    state->buf_size = 256 * 1024;
    state->buf = (uint8_t *)malloc(state->buf_size);
    if (!state->buf) { free(state); return NULL; }
    return state;
}

void afl_custom_deinit(void *data) {
    mutator_state_t *state = (mutator_state_t *)data;
    if (state) {
        free(state->buf);
        free(state);
    }
}

/**
 * Main mutation function.
 *
 * Strategy distribution (each has ~20% chance):
 *   1. Quality byte mutation — change only buf[0] (compression quality 0-11)
 *   2. Block duplication — duplicate a random block to create repetition
 *   3. Power-of-2 resize — resize input to boundary size ± 1
 *   4. Repetition injection — insert long repeated sequence (hash chain stress)
 *   5. Passthrough — return 0 to let AFL use its default mutations
 */
size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf, size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size,
    size_t max_size
) {
    mutator_state_t *state = (mutator_state_t *)data;
    uint32_t rng = state->seed;

    /* Ensure output buffer is large enough */
    if (max_size > state->buf_size) {
        uint8_t *new_buf = (uint8_t *)realloc(state->buf, max_size);
        if (!new_buf) {
            *out_buf = buf;
            return buf_size;
        }
        state->buf = new_buf;
        state->buf_size = max_size;
    }

    uint32_t strategy = xorshift32(&rng) % 5;
    state->seed = rng;

    /* Need at least 3 bytes for our format: quality + lgwin + data */
    if (buf_size < 3) {
        *out_buf = buf;
        return buf_size;
    }

    size_t out_size;

    switch (strategy) {
    case 0: {
        /* Strategy 1: Mutate only quality byte (buf[0]).
         * Keeps the rest of the input intact — explores different
         * encoder quality paths with the same data. */
        memcpy(state->buf, buf, buf_size);
        /* Pick a specific quality value that exercises interesting paths */
        uint8_t qualities[] = {0, 1, 2, 5, 9, 10, 11};
        state->buf[0] = qualities[xorshift32(&rng) % 7];
        out_size = buf_size;
        break;
    }

    case 1: {
        /* Strategy 2: Duplicate a random block within the data portion.
         * Creates repetition patterns that exercise backward reference
         * matching and hash table collision paths. */
        size_t data_len = buf_size - 2;
        if (data_len < 16) {
            *out_buf = buf;
            return buf_size;
        }
        /* Copy header (quality + lgwin) */
        memcpy(state->buf, buf, 2);

        /* Pick a block to duplicate (16-1024 bytes) */
        size_t block_size = 16 + (xorshift32(&rng) % 1008);
        if (block_size > data_len / 2) block_size = data_len / 2;
        size_t src_offset = 2 + (xorshift32(&rng) % (data_len - block_size));
        size_t insert_pos = 2 + (xorshift32(&rng) % data_len);

        /* Copy data before insert point */
        size_t pre_len = insert_pos - 2;
        if (pre_len > 0 && pre_len <= data_len)
            memcpy(state->buf + 2, buf + 2, pre_len);

        /* Insert duplicated block */
        size_t remaining = buf_size - insert_pos;
        out_size = insert_pos + block_size + remaining;
        if (out_size > max_size) out_size = max_size;

        size_t copy_block = block_size;
        if (insert_pos + copy_block > max_size) copy_block = max_size - insert_pos;
        memcpy(state->buf + insert_pos, buf + src_offset, copy_block);

        /* Copy data after insert point */
        size_t tail = out_size - insert_pos - copy_block;
        if (tail > 0 && insert_pos + copy_block + tail <= max_size && insert_pos < buf_size)
            memcpy(state->buf + insert_pos + copy_block, buf + insert_pos,
                   tail < (buf_size - insert_pos) ? tail : (buf_size - insert_pos));

        break;
    }

    case 2: {
        /* Strategy 3: Resize to power-of-2 boundary ± 1.
         * Tests window size boundaries and block splitting triggers.
         * Sizes: 16K, 32K, 64K, 128K, 256K (± 1) */
        size_t boundaries[] = {
            16383, 16384, 16385,
            32767, 32768, 32769,
            65535, 65536, 65537,
            131071, 131072, 131073,
        };
        size_t target_size = boundaries[xorshift32(&rng) % 12] + 2; /* +2 for header */
        if (target_size > max_size) target_size = max_size;

        /* Copy header */
        memcpy(state->buf, buf, 2);

        /* Fill data: copy existing then pad/truncate */
        if (target_size <= buf_size) {
            memcpy(state->buf + 2, buf + 2, target_size - 2);
        } else {
            /* Copy existing data */
            memcpy(state->buf + 2, buf + 2, buf_size - 2);
            /* Pad with repeated pattern from existing data */
            for (size_t i = buf_size; i < target_size; i++) {
                state->buf[i] = buf[2 + ((i - 2) % (buf_size - 2))];
            }
        }
        out_size = target_size;
        break;
    }

    case 3: {
        /* Strategy 4: Inject long repeated sequence.
         * Stresses hash chain building, long match finding, and
         * entropy coding for low-entropy regions. */
        memcpy(state->buf, buf, 2);

        /* Pick a byte to repeat and injection length */
        uint8_t repeat_byte = (uint8_t)(xorshift32(&rng) & 0xFF);
        size_t inject_len = 1024 + (xorshift32(&rng) % 8192);
        size_t inject_pos = 2 + (xorshift32(&rng) % (buf_size > 4 ? buf_size - 4 : 1));

        /* Copy data before injection */
        size_t pre = inject_pos - 2;
        if (pre > 0) memcpy(state->buf + 2, buf + 2, pre);

        /* Inject repeated bytes */
        out_size = inject_pos + inject_len + (buf_size - inject_pos);
        if (out_size > max_size) {
            out_size = max_size;
            inject_len = max_size - inject_pos - (buf_size - inject_pos);
            if (inject_len > max_size) inject_len = 0;
        }
        memset(state->buf + inject_pos, repeat_byte, inject_len);

        /* Copy remaining data */
        size_t tail = out_size - inject_pos - inject_len;
        if (tail > 0 && inject_pos < buf_size)
            memcpy(state->buf + inject_pos + inject_len, buf + inject_pos,
                   tail < (buf_size - inject_pos) ? tail : (buf_size - inject_pos));

        break;
    }

    default:
        /* Strategy 5: Passthrough — let AFL use default mutations */
        *out_buf = buf;
        return 0;  /* returning 0 signals AFL to use its own mutations */
    }

    *out_buf = state->buf;
    return out_size;
}
