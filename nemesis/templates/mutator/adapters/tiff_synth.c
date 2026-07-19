#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 8) return 0;
    return (buf[0] == 'I' && buf[1] == 'I' && buf[2] == 0x2A && buf[3] == 0x00) ||
           (buf[0] == 'I' && buf[1] == 'I' && buf[2] == 0x2B && buf[3] == 0x00) ||
           (buf[0] == 'M' && buf[1] == 'M' && buf[2] == 0x00 && buf[3] == 0x2A) ||
           (buf[0] == 'M' && buf[1] == 'M' && buf[2] == 0x00 && buf[3] == 0x2B);
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size < 16) return 0;
    int n = 0;
    uint32_t bo = (buf[0] == 'I' && buf[1] == 'I') ? 0 : 1;
    uint32_t is_bigtiff = (buf[2] == 0x2B) ? 1 : 0;
    size_t hdr_size = 8;
    size_t off = is_bigtiff ? 8 : nm_read_be32(buf + 4);
    if (off >= size) return 0;
    uint32_t entry_size = is_bigtiff ? 20 : 12;
    uint32_t count_size = is_bigtiff ? 8 : 2;
    uint32_t offset_size = is_bigtiff ? 8 : 4;
    while (n < NM_MAX_CHUNKS && off + count_size <= size) {
        uint32_t count = is_bigtiff ? nm_read_be32(buf + off) : nm_read_be16(buf + off);
        if (count > 1024 || off + count_size + count * entry_size > size) break;
        for (uint32_t i = 0; i < count; ++i) {
            size_t entry_off = off + count_size + i * entry_size;
            if (entry_off + entry_size > size) break;
            out[n].header_off = entry_off;
            out[n].data_off = entry_off + 2;
            out[n].data_len = 4;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = nm_read_be16(buf + entry_off);
            out[n].flags = 0;
            n++;
        }
        uint32_t next_off = is_bigtiff ? nm_read_be64(buf + off + count_size + count * entry_size) :
                                        nm_read_be32(buf + off + count_size + count * entry_size);
        if (next_off == 0 || next_off >= size) break;
        off = next_off;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    (void)buf_size;
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 4;
    switch (op) {
        case 0: {
            for (int i = 0; i < n && i < 4; ++i) {
                if (chunks[i].data_len == 4) {
                    uint32_t v = nm_xorshift32(rng);
                    nm_write_be32(buf + chunks[i].data_off, v);
                }
            }
            break;
        }
        case 1: {
            for (int i = 0; i < n && i < 4; ++i) {
                if (chunks[i].data_len == 2) {
                    uint16_t v = (uint16_t)(nm_xorshift32(rng) & 0xFFFFu);
                    buf[chunks[i].data_off] = (uint8_t)(v >> 8);
                    buf[chunks[i].data_off + 1] = (uint8_t)v;
                }
            }
            break;
        }
        case 2: {
            static const uint16_t target_tags[] = {256, 257, 322, 323};
            uint16_t tag = target_tags[nm_xorshift32(rng) % (sizeof(target_tags)/sizeof(target_tags[0]))];
            for (int i = 0; i < n; ++i) {
                if (chunks[i].kind == tag && chunks[i].data_len == 4) {
                    uint32_t v = nm_xorshift32(rng);
                    nm_write_be32(buf + chunks[i].data_off, v);
                }
            }
            break;
        }
        case 3: {
            static const uint16_t type_overrides[] = {0x0100, 0x0200, 0xFFFF, 0x0000, 0x0001};
            for (int i = 0; i < n && i < 8; ++i) {
                if (chunks[i].data_len >= 2) {
                    uint16_t type = nm_read_be16(buf + chunks[i].data_off - 2);
                    type = type_overrides[nm_xorshift32(rng) % (sizeof(type_overrides)/sizeof(type_overrides[0]))];
                    nm_write_be16(buf + chunks[i].data_off - 2, type);
                }
            }
            break;
        }
    }
    return 1;
}