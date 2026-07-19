#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static const uint8_t PNG_SIG[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    return size >= 8 && memcmp(buf, PNG_SIG, 8) == 0;
}

enum {
    PNG_KIND_UNKNOWN = 0,
    PNG_KIND_IHDR,
    PNG_KIND_PLTE,
    PNG_KIND_IDAT,
    PNG_KIND_IEND,
    PNG_KIND_tRNS,
    PNG_KIND_tEXt,
    PNG_KIND_gAMA,
    PNG_KIND_cHRM,
    PNG_KIND_sRGB,
    PNG_KIND_pHYs,
    PNG_KIND_tIME,
};

static uint32_t png_kind_for_type(const uint8_t *t) {
    if (memcmp(t, "IHDR", 4) == 0) return PNG_KIND_IHDR;
    if (memcmp(t, "PLTE", 4) == 0) return PNG_KIND_PLTE;
    if (memcmp(t, "IDAT", 4) == 0) return PNG_KIND_IDAT;
    if (memcmp(t, "IEND", 4) == 0) return PNG_KIND_IEND;
    if (memcmp(t, "tRNS", 4) == 0) return PNG_KIND_tRNS;
    if (memcmp(t, "tEXt", 4) == 0) return PNG_KIND_tEXt;
    if (memcmp(t, "gAMA", 4) == 0) return PNG_KIND_gAMA;
    if (memcmp(t, "cHRM", 4) == 0) return PNG_KIND_cHRM;
    if (memcmp(t, "sRGB", 4) == 0) return PNG_KIND_sRGB;
    if (memcmp(t, "pHYs", 4) == 0) return PNG_KIND_pHYs;
    if (memcmp(t, "tIME", 4) == 0) return PNG_KIND_tIME;
    return PNG_KIND_UNKNOWN;
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 8;
    while (n < NM_MAX_CHUNKS && off + 12 <= size) {
        uint32_t len = nm_read_be32(buf + off);
        if (len > 16u * 1024u * 1024u) break;
        if (off + 12u + (size_t)len > size) break;
        out[n].header_off = off;
        out[n].data_off = off + 8;
        out[n].data_len = len;
        out[n].integrity_off = off + 8 + len;
        out[n].integrity_len = 4;
        out[n].kind = png_kind_for_type(buf + off + 4);
        out[n].flags = 0;
        n++;
        off += 12u + (size_t)len;
        if (out[n-1].kind == PNG_KIND_IEND) break;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    if (!chunk->integrity_len) return;
    size_t type_off = chunk->data_off - 4;
    uint32_t table[256];
    nm_crc32_init(table);
    uint32_t crc = nm_crc32(table, buf + type_off, 4 + chunk->data_len);
    nm_write_be32(buf + chunk->integrity_off, crc);
}

static const uint32_t PNG_INTERESTING_DIM[] = {
    0u, 1u, 2u, 7u, 8u, 16u, 256u, 1024u, 0x7FFFu, 0xFFFEu, 0xFFFFu,
    0x10000u, 0x10001u, 0x1FFFFFFFu, 0x20000000u,
    0x2AAAAAAAu, 0x2AAAAAABu, 0x3FFFFFFFu, 0x40000000u,
    0x55555555u, 0x55555556u, 0x7FFFFFFFu, 0x80000000u,
    0xFFFFFFFEu, 0xFFFFFFFFu,
};
#define PNG_DIM_N (sizeof(PNG_INTERESTING_DIM)/sizeof(PNG_INTERESTING_DIM[0]))

static const uint8_t PNG_INTERESTING_BIT_DEPTH[] = {1, 2, 4, 8, 16, 0, 24, 32};
static const uint8_t PNG_INTERESTING_COLOR_TYPE[] = {0, 2, 3, 4, 6, 1, 5, 7};
static const uint8_t PNG_INTERESTING_INTERLACE[] = {0, 1, 2, 3, 255};

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    (void)buf_size;
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 10;
    switch (op) {
        case 0: case 1: case 2: case 3: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_IHDR && chunks[i].data_len >= 13) {
                    size_t d = chunks[i].data_off;
                    uint32_t w = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
                    uint32_t h = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
                    nm_write_be32(buf + d, w);
                    nm_write_be32(buf + d + 4, h);
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
        case 4: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_IHDR && chunks[i].data_len >= 13) {
                    size_t d = chunks[i].data_off;
                    buf[d + 8]  = PNG_INTERESTING_BIT_DEPTH[nm_xorshift32(rng) % sizeof(PNG_INTERESTING_BIT_DEPTH)];
                    buf[d + 9]  = PNG_INTERESTING_COLOR_TYPE[nm_xorshift32(rng) % sizeof(PNG_INTERESTING_COLOR_TYPE)];
                    buf[d + 10] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                    buf[d + 11] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                    buf[d + 12] = PNG_INTERESTING_INTERLACE[nm_xorshift32(rng) % sizeof(PNG_INTERESTING_INTERLACE)];
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
        case 5: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_PLTE && chunks[i].data_len >= 4) {
                    size_t d = chunks[i].data_off;
                    uint32_t color_count = 1 + (nm_xorshift32(rng) % 256);
                    if (color_count * 3 > chunks[i].data_len) color_count = chunks[i].data_len / 3;
                    if (color_count == 0) color_count = 1;
                    nm_write_be32(buf + d - 4, color_count * 3);
                    for (uint32_t j = 0; j < color_count * 3; j += 3) {
                        buf[d + j + 0] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                        buf[d + j + 1] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                        buf[d + j + 2] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                    }
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
        case 6: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_tRNS && chunks[i].data_len > 0) {
                    size_t d = chunks[i].data_off;
                    uint32_t len = (uint32_t)chunks[i].data_len;
                    for (uint32_t j = 0; j < len && j < 32; j++) {
                        buf[d + j] = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                    }
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
        case 7: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_IDAT && chunks[i].data_len > 0) {
                    size_t d = chunks[i].data_off;
                    uint32_t flips = 1 + (nm_xorshift32(rng) % 16);
                    for (uint32_t j = 0; j < flips; j++) {
                        size_t pos = d + (nm_xorshift32(rng) % chunks[i].data_len);
                        if (pos < buf_size) buf[pos] ^= (uint8_t)(nm_xorshift32(rng) & 0xFFu);
                    }
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
        case 8: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_IHDR && chunks[i].data_len >= 13) {
                    size_t d = chunks[i].data_off;
                    uint8_t depth = buf[d + 8];
                    uint8_t type = buf[d + 9];
                    if ((type == 3 && depth == 8) || (type == 0 && depth == 8) || (type == 2 && depth == 8) || (type == 4 && depth == 8) || (type == 6 && depth == 8)) {
                        uint8_t new_depth = (depth == 8) ? 16 : 8;
                        buf[d + 8] = new_depth;
                        nm_adapter_fix_integrity(buf, &chunks[i]);
                        return 1;
                    }
                }
            }
            break;
        }
        case 9: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == PNG_KIND_IHDR && chunks[i].data_len >= 13) {
                    size_t d = chunks[i].data_off;
                    buf[d + 12] ^= 0xFFu;
                    nm_adapter_fix_integrity(buf, &chunks[i]);
                    return 1;
                }
            }
            break;
        }
    }
    return 0;
}