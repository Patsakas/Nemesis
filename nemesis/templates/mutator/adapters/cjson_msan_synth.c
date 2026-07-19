#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 1) return 0;
    switch (buf[0]) {
        case '{': case '[': case '"': case 't': case 'f': case 'n': return 1;
        default: return 0;
    }
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size == 0) return 0;
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off < size) {
        if (buf[off] == '{' || buf[off] == '[') {
            out[n].header_off = off;
            out[n].data_off = off;
            out[n].data_len = size - off;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = (buf[off] == '{') ? 1 : 2;
            out[n].flags = 0;
            n++;
            break;
        }
        off++;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0 || chunks[0].data_len < 1) return 0;
    uint32_t op = nm_xorshift32(rng) % 6;
    size_t d = chunks[0].data_off;
    switch (op) {
        case 0: {
            uint32_t v = nm_xorshift32(rng);
            if ((v & 1) == 0) buf[d] = 't';
            else buf[d] = 'f';
            break;
        }
        case 1: {
            uint32_t v = nm_xorshift32(rng);
            if ((v & 1) == 0) {
                if (d + 3 < buf_size) memcpy(buf + d, "true", 4);
            } else {
                if (d + 4 < buf_size) memcpy(buf + d, "false", 5);
            }
            break;
        }
        case 2: {
            uint32_t v = nm_xorshift32(rng);
            if (d + 3 < buf_size) {
                if ((v & 1) == 0) memcpy(buf + d, "null", 4);
                else memcpy(buf + d, "nul", 3);
            }
            break;
        }
        case 3: {
            uint32_t v = nm_xorshift32(rng);
            if (d + 1 < buf_size) buf[d] = (uint8_t)(32 + (v % 95));
            break;
        }
        case 4: {
            uint32_t v = nm_xorshift32(rng);
            if (d + 4 < buf_size) {
                uint32_t w = (v % 10) + 1;
                for (uint32_t i = 0; i < w && d + i < buf_size; i++) buf[d + i] = (uint8_t)('a' + (i % 26));
            }
            break;
        }
        default: {
            uint32_t v = nm_xorshift32(rng);
            if (d + 4 < buf_size) {
                uint32_t w = (v % 8) + 1;
                for (uint32_t i = 0; i < w && d + i < buf_size; i++) buf[d + i] ^= 0xFF;
            }
            break;
        }
    }
    return 1;
}