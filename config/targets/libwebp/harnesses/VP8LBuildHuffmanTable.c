#include <webp/decode.h>
#include <stdlib.h>
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  __AFL_INIT();
  __AFL_LOOP(10000) {
    int width = 0, height = 0;
    uint8_t* rgba = NULL;

    // Validate header first (VP8L signature expected)
    if (WebPGetInfo(__AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN, &width, &height)) {
      // Decode to RGBA (allocates buffer internally)
      // This will internally call VP8LDecoder constructor, which eventually calls
      // ReadHuffmanCodeLengths() -> VP8LBuildHuffmanTable()
      rgba = WebPDecodeRGBA(__AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN, &width, &height);
    }

    // Cleanup
    WebPFree(rgba);
  }
  return 0;
}