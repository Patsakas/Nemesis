#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

enum {
    JSON_KIND_ROOT = 1,
    JSON_KIND_OBJECT,
    JSON_KIND_ARRAY,
    JSON_KIND_STRING,
    JSON_KIND_NUMBER,
    JSON_KIND_KEY,
    JSON_KIND_TRUE,
    JSON_KIND_FALSE,
    JSON_KIND_NULL,
};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size == 0) return 0;
    switch (buf[0]) {
        case '{':
        case '[':
        case '"':
            return 1;
        case 't': return size >= 4 && memcmp(buf, "true", 4) == 0;
        case 'f': return size >= 5 && memcmp(buf, "false", 5) == 0;
        case 'n': return size >= 4 && memcmp(buf, "null", 4) == 0;
        default: return 0;
    }
}

#define NM_MAX_DEPTH 16
#define NM_MAX_TOKENS 256

typedef struct {
    size_t off;
    size_t len;
    uint32_t kind;
    uint32_t flags;
} json_token_t;

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size == 0 || !nm_adapter_has_signature(buf, size)) return 0;
    json_token_t stack[NM_MAX_DEPTH];
    nm_chunk_t chunks[NM_MAX_CHUNKS];
    int sp = 0;
    int n = 0;
    size_t i = 0;
    uint32_t kind_stack[NM_MAX_DEPTH];
    int tlen = 0;

    while (i < size && n < NM_MAX_CHUNKS) {
        while (i < size && isspace(buf[i])) i++;
        if (i >= size) break;

        size_t start = i;
        uint32_t kind = JSON_KIND_ROOT;
        uint32_t flags = 0;

        switch (buf[i]) {
            case '{':
                kind = JSON_KIND_OBJECT;
                i++;
                break;
            case '[':
                kind = JSON_KIND_ARRAY;
                i++;
                break;
            case '"': {
                kind = JSON_KIND_STRING;
                i++;
                size_t s = i;
                while (s < size && buf[s] != '"') {
                    if (buf[s] == '\\') s++;
                    s++;
                }
                if (s >= size) break;
                i = s + 1;
                break;
            }
            case 't': case 'f': case 'n': {
                const char *lit = (buf[i] == 't') ? "true" :
                                 (buf[i] == 'f') ? "false" : "null";
                size_t l = strlen(lit);
                if (i + l > size) break;
                if (memcmp(buf + i, lit, l) == 0) {
                    kind = (buf[i] == 't') ? JSON_KIND_TRUE :
                           (buf[i] == 'f') ? JSON_KIND_FALSE : JSON_KIND_NULL;
                    i += l;
                } else {
                    i++;
                }
                break;
            }
            default: {
                if (isdigit(buf[i]) || buf[i] == '-' || buf[i] == '+') {
                    kind = JSON_KIND_NUMBER;
                    while (i < size && (isdigit(buf[i]) || buf[i] == '.' || buf[i] == 'e' || buf[i] == 'E' || buf[i] == '+' || buf[i] == '-')) i++;
                } else {
                    i++;
                }
                break;
            }
        }

        if (i == start) break;

        if (kind == JSON_KIND_OBJECT || kind == JSON_KIND_ARRAY) {
            if (sp < NM_MAX_DEPTH) {
                stack[sp].off = start;
                stack[sp].len = i - start;
                stack[sp].kind = kind;
                sp++;
            }
        }

        if (n < NM_MAX_CHUNKS) {
            chunks[n].header_off = start;
            chunks[n].data_off = start;
            chunks[n].data_len = i - start;
            chunks[n].integrity_off = 0;
            chunks[n].integrity_len = 0;
            chunks[n].kind = kind;
            chunks[n].flags = flags;
            n++;
        }
    }

    if (n == 0) return 0;

    for (int k = 0; k < n; k++) {
        out[k] = chunks[k];
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;

    uint32_t op = nm_xorshift32(rng) % 8;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];

    if (c->kind == JSON_KIND_STRING && c->data_len >= 2) {
        size_t s = c->data_off;
        if (buf[s] == '"' && buf[s + c->data_len - 1] == '"') {
            switch (op) {
                case 0: {
                    uint8_t tmp[32];
                    size_t len = (c->data_len - 2) > 31 ? 31 : (c->data_len - 2);
                    memcpy(tmp, buf + s + 1, len);
                    tmp[len] = 0;
                    size_t tlen = strlen((char*)tmp);
                    if (tlen > 0) {
                        size_t flip = nm_xorshift32(rng) % tlen;
                        buf[s + 1 + flip] ^= 0xFF;
                    }
                    return 1;
                }
                case 1: {
                    size_t pos = s + 1 + (nm_xorshift32(rng) % (c->data_len - 2));
                    if (pos < buf_size) buf[pos] = (uint8_t)(nm_xorshift32(rng) & 0x7F);
                    return 1;
                }
                case 2: {
                    size_t pos = s + 1 + (nm_xorshift32(rng) % (c->data_len - 2));
                    if (pos + 1 < buf_size) {
                        uint16_t v = (uint16_t)(nm_xorshift32(rng) & 0xFFFF);
                        buf[pos] = (uint8_t)(v >> 8);
                        buf[pos + 1] = (uint8_t)v;
                    }
                    return 1;
                }
                case 3: {
                    size_t pos = s + 1 + (nm_xorshift32(rng) % (c->data_len - 2));
                    if (pos < buf_size) buf[pos] = (buf[pos] == '\\') ? '/' : '\\';
                    return 1;
                }
                default: break;
            }
        }
    }

    if (c->kind == JSON_KIND_NUMBER && c->data_len > 0) {
        size_t s = c->data_off;
        size_t e = s + c->data_len;
        if (e > buf_size) e = buf_size;
        if (e > s) {
            switch (op) {
                case 0: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    buf[pos] ^= 0xFF;
                    return 1;
                }
                case 1: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos + 3 < e) {
                        uint32_t v = nm_xorshift32(rng);
                        buf[pos] = (uint8_t)(v >> 24);
                        buf[pos + 1] = (uint8_t)(v >> 16);
                        buf[pos + 2] = (uint8_t)(v >> 8);
                        buf[pos + 3] = (uint8_t)v;
                    }
                    return 1;
                }
                case 2: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == '-') ? '+' : '-';
                    return 1;
                }
                case 3: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == '.') ? ',' : '.';
                    return 1;
                }
                default: break;
            }
        }
    }

    if (c->kind == JSON_KIND_OBJECT || c->kind == JSON_KIND_ARRAY) {
        size_t s = c->data_off;
        size_t e = s + c->data_len;
        if (e > buf_size) e = buf_size;
        if (e > s) {
            switch (op) {
                case 0: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == '{') ? '[' : '{';
                    return 1;
                }
                case 1: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == '[') ? '{' : '[';
                    return 1;
                }
                case 2: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == ',') ? ';' : ',';
                    return 1;
                }
                case 3: {
                    size_t pos = s + (nm_xorshift32(rng) % (e - s));
                    if (pos < e) buf[pos] = (buf[pos] == ':') ? '=' : ':';
                    return 1;
                }
                default: break;
            }
        }
    }

    if (c->kind == JSON_KIND_TRUE || c->kind == JSON_KIND_FALSE || c->kind == JSON_KIND_NULL) {
        size_t s = c->data_off;
        size_t e = s + c->data_len;
        if (e > buf_size) e = buf_size;
        if (e > s) {
            size_t pos = s + (nm_xorshift32(rng) % (e - s));
            if (pos < e) buf[pos] ^= 0xFF;
            return 1;
        }
    }

    return 0;
}