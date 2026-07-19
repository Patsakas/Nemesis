#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <png.h>

__AFL_FUZZ_INIT();

typedef struct {
  const uint8_t *data;
  size_t size;
  size_t offset;
} mem_buf_t;

static void mem_read_fn(png_structp png_ptr, png_bytep out, png_size_t len) {
  mem_buf_t *buf = (mem_buf_t *)png_get_io_ptr(png_ptr);
  if (buf->offset + len > buf->size)
    png_error(png_ptr, "EOF");
  memcpy(out, buf->data + buf->offset, len);
  buf->offset += len;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  __AFL_INIT();
  while (__AFL_LOOP(10000)) {
    mem_buf_t input = { __AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN, 0 };
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) continue;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
      png_destroy_read_struct(&png_ptr, NULL, NULL);
      continue;
    }
    if (setjmp(png_jmpbuf(png_ptr))) {
      png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
      continue;
    }
    png_set_user_limits(png_ptr, 0x7FFFFFFF, 0x7FFFFFFF);
    png_set_chunk_cache_max(png_ptr, 0x7FFFFFFF);
    png_set_chunk_malloc_max(png_ptr, 0);
    png_set_read_fn(png_ptr, (png_voidp)&input, mem_read_fn);
    png_read_info(png_ptr, info_ptr);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  }
  return 0;
}
