#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <brotli/shared_dictionary.h>

/* Internal declarations for direct fuzzing */
#include "../common/platform.h"
#include "../enc/memory.h"
#include "../enc/compound_dictionary.h"

#ifndef kPreparedDictionaryMagic
#define kPreparedDictionaryMagic 0xCE28F992u
#endif

#ifndef kLeanPreparedDictionaryMagic
#define kLeanPreparedDictionaryMagic 0x6E8CE7B7u
#endif

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 4 || len > (1 << 18)) continue; /* 0B-256KB cap */

    /* Initialize MemoryManager */
    MemoryManager mgr;
    BrotliInitMemoryManager(&mgr, NULL, NULL, NULL);

    /* Call target directly with fuzz input */
    PreparedDictionary* dict = CreatePreparedDictionary(&mgr, buf, (size_t)len);

    /* Cleanup */
    if (dict) {
      DestroyPreparedDictionary(&mgr, dict);
    }
    BrotliWipeOutMemoryManager(&mgr);
  }
  return 0;
}