#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 1) return 0;
    switch (buf[0]) {
        case '{': case '[': case '"': case 't': case 'f': case 'n': return 1;
        default: return 0;
    }
}

#define NM_MAX_TOKENS 64
#define NM_MAX_DEPTH  16

typedef struct {
    size_t off;
    size_t len;
    uint8_t kind;
} nm_token_t;

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size < 2) return 0;
    nm_token_t stack[NM_MAX_DEPTH];
    int sp = -1;
    int n = 0;
    size_t i = 0;
    while (i < size && n < NM_MAX_CHUNKS) {
        if (buf[i] == '"') {
            size_t start = i;
            i++;
            while (i < size && buf[i] != '"') {
                if (buf[i] == '\\') i += 2;
                else i++;
            }
            if (i < size && buf[i] == '"') {
                i++;
                if (sp >= 0 && stack[sp].kind == 'k') {
                    out[n].header_off = start;
                    out[n].data_off = start + 1;
                    out[n].data_len = (i - 1) - (start + 1);
                    out[n].integrity_off = 0;
                    out[n].integrity_len = 0;
                    out[n].kind = 's';
                    out[n].flags = 0;
                    n++;
                    stack[sp].kind = 0;
                }
            } else break;
        } else if (buf[i] == '{' || buf[i] == '[') {
            if (sp + 1 >= NM_MAX_DEPTH) break;
            stack[++sp].off = i;
            stack[sp].kind = buf[i];
            i++;
        } else if (buf[i] == '}' || buf[i] == ']') {
            if (sp < 0) break;
            size_t start = stack[sp].off;
            size_t end = i + 1;
            if (n < NM_MAX_CHUNKS) {
                out[n].header_off = start;
                out[n].data_off = start;
                out[n].data_len = end - start;
                out[n].integrity_off = 0;
                out[n].integrity_len = 0;
                out[n].kind = (buf[i] == '}') ? 'o' : 'a';
                out[n].flags = 0;
                n++;
            }
            sp--;
            i = end;
        } else if (buf[i] == ':') {
            if (sp >= 0 && stack[sp].kind == '{') {
                stack[sp].kind = 'k';
            }
            i++;
        } else {
            i++;
        }
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 8;
    switch (op) {
        case 0: case 1: case 2: case 3: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            nm_chunk_t *c = &chunks[idx];
            if (c->data_len < 4) return 0;
            size_t d = c->data_off;
            if (d + 4 > buf_size) return 0;
            uint32_t v = nm_xorshift32(rng);
            nm_write_le32(buf + d, v);
            nm_adapter_fix_integrity(buf, c);
            return 1;
        }
        case 4: case 5: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            nm_chunk_t *c = &chunks[idx];
            if (c->data_len < 1) return 0;
            size_t d = c->data_off;
            if (d >= buf_size) return 0;
            uint8_t bits[32];
            size_t nb = (c->data_len < 32) ? c->data_len : 32;
            memcpy(bits, buf + d, nb);
            for (size_t k = 0; k < nb; k++) bits[k] ^= (uint8_t)(nm_xorshift32(rng) & 0xFFu);
            size_t w = (nb < 32) ? nb : 32;
            if (d + w > buf_size) w = buf_size - d;
            memcpy(buf + d, bits, w);
            nm_adapter_fix_integrity(buf, c);
            return 1;
        }
        case 6: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            nm_chunk_t *c = &chunks[idx];
            if (c->data_len < 1) return 0;
            size_t d = c->data_off;
            if (d >= buf_size) return 0;
            uint8_t v = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
            buf[d] = v;
            nm_adapter_fix_integrity(buf, c);
            return 1;
        }
        case 7: {
            int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
            nm_chunk_t *c = &chunks[idx];
            if (c->data_len < 2) return 0;
            size_t d = c->data_off;
            if (d + 2 > buf_size) return 0;
            uint16_t v = (uint16_t)(nm_xorshift32(rng) & 0xFFFFu);
            nm_write_le16(buf + d, v);
            nm_adapter_fix_integrity(buf, c);
            return 1;
        }
    }
    return 0;
}