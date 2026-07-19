#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "fuzz_data_provider.h"
#include "../c/enc/backward_references_hq.h"
#include "../c/enc/command.h"
#include "../c/enc/hash.h"
#include "../c/enc/memory.h"
#include "../c/enc/params.h"
#include "../c/common/context.h"
#include "../c/common/platform.h"

__AFL_FUZZ_INIT();

/* Default distance cache values from encoder */
static const int kDefaultDistCache[BROTLI_NUM_DISTANCE_SHORT_CODES] = {4, 11, 15, 16, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1};

/* Initialize BrotliEncoderParams with safe defaults */
static void InitBrotliEncoderParams(BrotliEncoderParams* params, int quality, int lgwin) {
  memset(params, 0, sizeof(*params));
  params->mode = BROTLI_MODE_GENERIC;
  params->quality = quality;
  params->lgwin = lgwin;
  params->lgblock = 0;
  params->stream_offset = 0;
  params->size_hint = 0;
  params->disable_literal_context_modeling = BROTLI_FALSE;
  params->large_window = BROTLI_FALSE;
  /* Initialize distance params */
  params->dist.distance_postfix_bits = 0;
  params->dist.num_direct_distance_codes = 0;
  params->dist.alphabet_size_max = 544;
  params->dist.alphabet_size_limit = 544;
  params->dist.max_distance = ((size_t)1 << lgwin) - 16;
  /* Initialize hasher params */
  params->hasher.type = 10; /* H10 hasher */
  params->hasher.bucket_bits = 16;
  params->hasher.block_bits = 4;
  params->hasher.num_last_distances_to_check = 4;
  /* Initialize dictionary */
  BrotliInitSharedEncoderDictionary(&params->dictionary);
}

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
    int quality = 2 + (buf[0] % 8); /* Range 2-9 */
    int lgwin = 10 + (buf[1] % 15); /* Range 10-24 */

    if (lgwin > BROTLI_MAX_WINDOW_BITS) lgwin = BROTLI_MAX_WINDOW_BITS;

    const uint8_t *data = buf + 2;
    size_t data_len = (size_t)(len - 2);

    /* Initialize MemoryManager */
    MemoryManager m;
    BrotliInitMemoryManager(&m, NULL, NULL, NULL);

    if (BROTLI_IS_OOM(&m)) {
      BrotliWipeOutMemoryManager(&m);
      continue;
    }

    /* Initialize BrotliEncoderParams */
    BrotliEncoderParams params;
    InitBrotliEncoderParams(&params, quality, lgwin);

    /* Initialize Hasher */
    Hasher hasher;
    HasherInit(&hasher);

    /* HasherSetup allocates internal state via MemoryManager */
    HasherSetup(&m, &hasher, &params, data, 0, data_len, BROTLI_TRUE);

    if (BROTLI_IS_OOM(&m)) {
      DestroyHasher(&m, &hasher);
      BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
      BrotliWipeOutMemoryManager(&m);
      continue;
    }

    /* ContextLut from library macro */
    ContextLut literal_context_lut = BROTLI_CONTEXT_LUT(CONTEXT_UTF8);

    /* Prepare output buffers */
    size_t max_commands = data_len + 1;
    if (max_commands > 65536) max_commands = 65536;

    Command *commands = (Command *)BrotliAllocate(&m, max_commands * sizeof(Command));

    if (BROTLI_IS_NULL(commands) || BROTLI_IS_OOM(&m)) {
      DestroyHasher(&m, &hasher);
      BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
      BrotliWipeOutMemoryManager(&m);
      continue;
    }

    int dist_cache[BROTLI_NUM_DISTANCE_SHORT_CODES];
    memcpy(dist_cache, kDefaultDistCache, sizeof(dist_cache));

    size_t last_insert_len = 0;
    size_t num_commands = 0;
    size_t num_literals = 0;
    size_t position = 0;
    size_t ringbuffer_mask = data_len - 1;

    /* Allocate ZopfliNode array */
    ZopfliNode *nodes = (ZopfliNode *)BrotliAllocate(&m, (data_len + 1) * sizeof(ZopfliNode));

    if (BROTLI_IS_NULL(nodes) || BROTLI_IS_OOM(&m)) {
      BrotliFree(&m, commands);
      DestroyHasher(&m, &hasher);
      BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
      BrotliWipeOutMemoryManager(&m);
      continue;
    }

    /* Initialize ZopfliNodes */
    BrotliInitZopfliNodes(nodes, data_len + 1);

    /* Call the target function directly */
    size_t result = BrotliZopfliComputeShortestPath(
      &m,
      data_len,
      position,
      data,
      ringbuffer_mask,
      literal_context_lut,
      &params,
      dist_cache,
      &hasher,
      nodes
    );

    /* Cleanup */
    BrotliFree(&m, nodes);
    BrotliFree(&m, commands);
    DestroyHasher(&m, &hasher);
    BrotliCleanupSharedEncoderDictionary(&m, &params.dictionary);
    BrotliWipeOutMemoryManager(&m);
  }

  return 0;
}
