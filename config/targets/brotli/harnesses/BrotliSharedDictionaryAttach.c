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
        if (len < 1 || len > 128 * 1024) continue;

        /* Create decoder state - must be uninitialized for AttachDictionary to work */
        BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
        if (!state) continue;

        /* The decoder must be in UNINITED state for AttachDictionary to succeed */
        /* This is the default state after creation, so we just call AttachDictionary */

        /* Try attaching as RAW dictionary - exercises BrotliSharedDictionaryAttach */
        /* with BROTLI_SHARED_DICTIONARY_RAW type */
        BROTLI_BOOL raw_result = BrotliDecoderAttachDictionary(
            state,
            BROTLI_SHARED_DICTIONARY_RAW,
            (size_t)len,
            buf
        );

        /* Also try SERIALIZED type - exercises BrotliSharedDictionaryAttach */
        /* with BROTLI_SHARED_DICTIONARY_SERIALIZED type (if experimental enabled) */
        BROTLI_BOOL serialized_result = BrotliDecoderAttachDictionary(
            state,
            BROTLI_SHARED_DICTIONARY_SERIALIZED,
            (size_t)len,
            buf
        );

        /* Clean up */
        BrotliDecoderDestroyInstance(state);
    }

    return 0;
}
