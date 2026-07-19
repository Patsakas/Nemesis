#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 4) return 0;
    return (buf[0] == 0x04 && buf[1] == 0x22 && buf[2] == 0x18 && buf[3] == 0x04) ||
           (buf[0] == 0x18 && buf[1] == 0x04 && buf[2] == 0x22 && buf[3] == 0x18);
}

#define NM_MAX_SEQUENCES 64
#define NM_MAX_EXTENSION_BYTES 16

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off + 1 <= size) {
        uint8_t token = buf[off];
        uint8_t lit_raw = (token >> 4) & 0x0F;
        uint8_t match_raw = token & 0x0F;

        size_t lit_len = lit_raw;
        size_t match_len = match_raw + 4u;

        size_t pos = off + 1;
        if (pos >= size) break;

        if (lit_raw == 15) {
            size_t ext_bytes = 0;
            while (pos + ext_bytes < size && buf[pos + ext_bytes] == 0xFF && ext_bytes < NM_MAX_EXTENSION_BYTES) ext_bytes++;
            if (pos + ext_bytes >= size) break;
            lit_len += 15 * ext_bytes + buf[pos + ext_bytes];
            pos += ext_bytes + 1;
        }

        if (pos + 2 > size) break;
        uint16_t offset = nm_read_le32(buf + pos) & 0xFFFF;
        pos += 2;

        if (match_raw == 15) {
            size_t ext_bytes = 0;
            while (pos + ext_bytes < size && buf[pos + ext_bytes] == 0xFF && ext_bytes < NM_MAX_EXTENSION_BYTES) ext_bytes++;
            if (pos + ext_bytes >= size) break;
            match_len += 15 * ext_bytes + buf[pos + ext_bytes];
            pos += ext_bytes + 1;
        }

        if (pos > size) break;

        out[n].header_off = off;
        out[n].data_off = off + 1;
        out[n].data_len = lit_len;
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind = 1;
        out[n].flags = 0;
        n++;
        off = pos;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 3;
    switch (op) {
        case 0: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            if (chunks[idx].data_len == 0) return 0;
            size_t pos = chunks[idx].data_off + (nm_xorshift32(rng) % chunks[idx].data_len);
            if (pos >= buf_size) return 0;
            buf[pos] ^= 0xFF;
            return 1;
        }
        case 1: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            if (chunks[idx].data_len == 0) return 0;
            size_t pos = chunks[idx].data_off + (nm_xorshift32(rng) % chunks[idx].data_len);
            if (pos + 1 >= buf_size) return 0;
            buf[pos] = 0xFF;
            buf[pos + 1] = 0xFF;
            return 1;
        }
        case 2: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            uint8_t token = buf[chunks[idx].header_off];
            uint8_t lit_raw = (token >> 4) & 0x0F;
            uint8_t match_raw = token & 0x0F;
            uint8_t new_token = 0;
            if ((nm_xorshift32(rng) & 1)) {
                new_token = (lit_raw == 15) ? 0xFF : ((lit_raw == 0) ? 15 : 0);
            } else {
                new_token = (match_raw == 15) ? 0xFF : ((match_raw == 0) ? 15 : 0);
            }
            buf[chunks[idx].header_off] = new_token;
            return 1;
        }
    }
    return 0;
}