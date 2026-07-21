/* Standalone repro harness for CVE-2018-13785, reading one input from a file.
 *
 * This mirrors the harness NEMESIS generated and fuzzes with, and the mirroring
 * matters: the CVE is only reachable because of png_set_user_limits() below.
 * libpng's default width/height cap is 1,000,000, which rejects the 0x55555555
 * width the overflow needs long before the row_factor divide. NEMESIS
 * discovered it had to raise that limit to reach the bug; a stock decode
 * harness never triggers it. That injected call is part of what "reached the
 * vulnerability" means here.
 *
 * The bug is a SIGFPE (integer divide-by-zero), so no sanitizer is needed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <png.h>

typedef struct { const uint8_t *data; size_t size, offset; } mem_buf_t;

static void mem_read_fn(png_structp png_ptr, png_bytep out, png_size_t len) {
  mem_buf_t *buf = (mem_buf_t *)png_get_io_ptr(png_ptr);
  if (buf->offset + len > buf->size) png_error(png_ptr, "EOF");
  memcpy(out, buf->data + buf->offset, len);
  buf->offset += len;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 2;
  static uint8_t data[1 << 20];
  size_t n = fread(data, 1, sizeof data, f);
  fclose(f);

  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) return 2;
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_read_struct(&png_ptr, NULL, NULL); return 2; }
  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;                       /* png_error longjmp: rejected input, clean */
  }
  png_set_user_limits(png_ptr, 0x7FFFFFFF, 0x7FFFFFFF);   /* the key: raise the cap */
  png_set_chunk_cache_max(png_ptr, 0x7FFFFFFF);
  png_set_chunk_malloc_max(png_ptr, 0);
  mem_buf_t input = { data, n, 0 };
  png_set_read_fn(png_ptr, (png_voidp)&input, mem_read_fn);
  png_read_info(png_ptr, info_ptr); /* reaches png_check_chunk_length -> divide */
  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  return 0;
}
