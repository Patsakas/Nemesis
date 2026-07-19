#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static const uint8_t BROTLI_STREAM_MAGIC[4] = {0xCE, 0xB2, 0xCF, 0x81};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
  return size >= 4 && memcmp(buf, BROTLI_STREAM_MAGIC, 4) == 0;
}

#define NM_MAX_META 64
#define NM_MAX_WINDOW_BITS 30
#define NM_MAX_NPOSTFIX 2

/* nm_chunk_t is provided by mutator_scaffold.h (identical fields). Redefining
 * it here is a hard compile error ("typedef redefinition"), which disabled this
 * adapter and forced AFL back to vanilla havoc on the brotli campaign. */

static uint32_t brotli_kind_for_meta(const uint8_t *t) {
  if (memcmp(t, "meta", 4) == 0) return 1;
  if (memcmp(t, "data", 4) == 0) return 2;
  return 0;
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
  if (size < 4) return 0;
  int n = 0;
  size_t off = 4;
  while (n < NM_MAX_CHUNKS && off + 8 <= size) {
    uint32_t len = nm_read_le32(buf + off);
    uint32_t kind = brotli_kind_for_meta(buf + off + 4);
    if (len > 16u * 1024u * 1024u) break;
    if (off + 8 + (size_t)len > size) break;
    out[n].header_off = off;
    out[n].data_off = off + 8;
    out[n].data_len = len;
    out[n].integrity_off = 0;
    out[n].integrity_len = 0;
    out[n].kind = kind;
    out[n].flags = 0;
    n++;
    off += 8 + (size_t)len;
  }
  return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
  (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
  if (n <= 0 || chunks[0].kind != 1 || chunks[0].data_len < 1) return 0;
  size_t d = chunks[0].data_off;
  nm_bitstream_t bs;
  nm_bs_init(&bs, buf, buf_size);
  nm_bs_seek_bytes(&bs, d);

  uint32_t op = nm_xorshift32(rng) % 6;
  switch (op) {
    case 0: {
      uint32_t v = nm_xorshift32(rng) % (NM_MAX_WINDOW_BITS + 1);
      nm_bs_write_bits(&bs, 5, v);
      break;
    }
    case 1: {
      uint32_t v = nm_xorshift32(rng) % 3;
      nm_bs_write_bits(&bs, 2, v);
      break;
    }
    case 2: {
      uint32_t v = nm_xorshift32(rng) % 2;
      nm_bs_write_bits(&bs, 1, v);
      break;
    }
    case 3: {
      uint32_t v = nm_xorshift32(rng) % 4;
      nm_bs_write_bits(&bs, 2, v);
      break;
    }
    case 4: {
      uint32_t v = nm_xorshift32(rng) % 256;
      nm_bs_write_bits(&bs, 8, v);
      break;
    }
    default: {
      uint32_t v = nm_xorshift32(rng) % 2;
      nm_bs_write_bits(&bs, 1, v);
      break;
    }
  }
  return 1;
}