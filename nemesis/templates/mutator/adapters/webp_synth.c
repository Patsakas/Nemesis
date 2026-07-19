#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    return size >= 12 && memcmp(buf, "RIFF", 4) == 0 && memcmp(buf + 8, "WEBP", 4) == 0;
}

enum {
    WEBP_KIND_VP8  = 1,
    WEBP_KIND_VP8L = 2,
    WEBP_KIND_VP8X = 3,
    WEBP_KIND_OTHER= 4,
};

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    if (size < 12 || memcmp(buf, "RIFF", 4) != 0 || memcmp(buf + 8, "WEBP", 4) != 0)
        return 0;
    size_t riff_size = nm_read_le32(buf + 4);
    if (riff_size > 0x0FFFFFFF || riff_size + 8 > size) return 0;

    size_t off = 12;
    while (n < NM_MAX_CHUNKS && off + 8 <= size) {
        if (off + 8 > size) break;
        uint32_t chunk_len = nm_read_le32(buf + off + 4);
        if (chunk_len > 16u * 1024u * 1024u) break;
        if (off + 8 + (size_t)chunk_len > size) break;

        out[n].header_off = off;
        out[n].data_off = off + 8;
        out[n].data_len = chunk_len;
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;

        const uint8_t *id = buf + off;
        if (memcmp(id, "VP8 ", 4) == 0) {
            out[n].kind = WEBP_KIND_VP8;
        } else if (memcmp(id, "VP8L", 4) == 0) {
            out[n].kind = WEBP_KIND_VP8L;
            out[n].integrity_off = off + 8;
            out[n].integrity_len = 12;
        } else if (memcmp(id, "VP8X", 4) == 0) {
            out[n].kind = WEBP_KIND_VP8X;
        } else {
            out[n].kind = WEBP_KIND_OTHER;
        }
        n++;
        off += 8 + (size_t)chunk_len;
        if (off & 1) off++;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    (void)buf_size;
    if (n <= 0) return 0;

    int vp8l_idx = -1;
    for (int i = 0; i < n; i++) {
        if (chunks[i].kind == WEBP_KIND_VP8L) {
            vp8l_idx = i;
            break;
        }
    }
    if (vp8l_idx == -1) return 0;

    nm_chunk_t *c = &chunks[vp8l_idx];
    if (c->data_len < 12) return 0;

    uint8_t *vp8l_data = buf + c->data_off;
    nm_bitstream_t bs;
    nm_bs_init(&bs, vp8l_data, c->data_len);

    uint32_t width  = nm_bs_read_bits(&bs, 14) + 1;
    uint32_t height = nm_bs_read_bits(&bs, 14) + 1;
    (void)nm_bs_read_bits(&bs, 1); /* alpha */
    uint32_t version = nm_bs_read_bits(&bs, 3);

    size_t code_len_start = nm_bs_tell_bits(&bs);
    size_t code_len_bits = (size_t)width * (size_t)height * 8;
    if (code_len_bits > 1000000) code_len_bits = 1000000;
    size_t code_len_bytes = (code_len_bits + 7) / 8;
    if (code_len_start / 8 + code_len_bytes > c->data_len) return 0;

    uint32_t op = nm_xorshift32(rng) % 5;
    switch (op) {
        case 0: {
            uint32_t w = (nm_xorshift32(rng) % 2) ? 0 : (nm_xorshift32(rng) % 0x10000);
            nm_bs_seek_bits(&bs, 0);
            nm_bs_write_bits(&bs, 14, w - 1);
            break;
        }
        case 1: {
            uint32_t h = (nm_xorshift32(rng) % 2) ? 0 : (nm_xorshift32(rng) % 0x10000);
            nm_bs_seek_bits(&bs, 14);
            nm_bs_write_bits(&bs, 14, h - 1);
            break;
        }
        case 2: {
            uint32_t w = (nm_xorshift32(rng) % 2) ? 0 : (nm_xorshift32(rng) % 0x10000);
            uint32_t h = (nm_xorshift32(rng) % 2) ? 0 : (nm_xorshift32(rng) % 0x10000);
            nm_bs_seek_bits(&bs, 0);
            nm_bs_write_bits(&bs, 14, w - 1);
            nm_bs_write_bits(&bs, 14, h - 1);
            break;
        }
        case 3: {
            nm_bs_seek_bits(&bs, 29);
            uint32_t flags = nm_bs_read_bits(&bs, 3);
            flags ^= (1u << (nm_xorshift32(rng) % 3));
            nm_bs_seek_bits(&bs, 29);
            nm_bs_write_bits(&bs, 3, flags);
            break;
        }
        default: {
            size_t bit_off = code_len_start + (size_t)(nm_xorshift32(rng) % (code_len_bits / 8));
            nm_bs_flip_bit_at(vp8l_data, c->data_len, bit_off);
            break;
        }
    }
    return 1;
}