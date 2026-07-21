/* Arm A — NAIVE harness for the libpng harness-reachability A/B.
 *
 * This is the harness a generic "fuzz the PNG read path" request produces: the
 * standard create -> read_info -> read_image sequence, libpng's DEFAULT limits
 * (user_width_max = 1,000,000). It is deliberately identical to Arm B except it
 * does NOT raise the width cap.
 *
 * On the exact CVE-2018-13785 trigger input (trigger.png, width 0x55555555),
 * png_check_IHDR rejects the width ("exceeds user limit") and png_error longjmps
 * out cleanly BEFORE the row_factor divide is reached. Result: exit 0, no crash.
 *
 * The ONLY difference from arm_b_nemesis.c is the missing png_set_user_limits().
 * Same library, same compiler, same input. That one line is the variable.
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
  /* NO png_set_user_limits() — default cap of 1,000,000 stays in effect. */
  mem_buf_t input = { data, n, 0 };
  png_set_read_fn(png_ptr, (png_voidp)&input, mem_read_fn);
  png_read_info(png_ptr, info_ptr); /* rejects width at png_check_IHDR, never divides */
  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  return 0;
}
