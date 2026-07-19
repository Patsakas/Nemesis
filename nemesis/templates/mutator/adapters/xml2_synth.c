#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 5) return 0;
    if (memcmp(buf, "<?xml", 5) == 0) return 1;
    if (size >= 9 && memcmp(buf, "<!DOCTYPE", 9) == 0) return 1;
    if (size >= 4 && memcmp(buf, "<!--", 4) == 0) return 1;
    if (size >= 6 && memcmp(buf, "<root>", 6) == 0) return 1;
    if (size >= 19 && memcmp(buf, "<?xml-stylesheet", 17) == 0) return 1;
    return 0;
}

#define NM_MAX_CHUNKS 64
#define NM_MAX_DEPTH 16
#define NM_MAX_ATTRS 32
#define NM_MAX_ENTITIES 16

typedef struct {
    size_t start;
    size_t end;
    uint32_t kind;
} nm_xml_chunk_t;

static int parse_tag(const uint8_t *buf, size_t size, size_t *pos, size_t *tag_start, size_t *tag_end) {
    size_t p = *pos;
    if (p >= size) return 0;
    if (buf[p] != '<') return 0;
    size_t s = p;
    p++;
    if (p < size && buf[p] == '?') {
        while (p < size && buf[p] != '>') p++;
        if (p < size && buf[p] == '>') { *tag_start = s; *tag_end = p + 1; *pos = p + 1; return 2; }
        return 0;
    }
    if (p < size && buf[p] == '!') {
        if (p + 2 < size && buf[p+1] == '-' && buf[p+2] == '-') {
            p += 3;
            while (p + 2 < size && !(buf[p]=='-' && buf[p+1]=='-' && buf[p+2]=='>')) p++;
            if (p + 2 < size) { *tag_start = s; *tag_end = p + 3; *pos = p + 3; return 3; }
            return 0;
        }
        if (p + 7 < size && memcmp(buf+p+1, "[CDATA[", 7) == 0) {
            p += 8;
            while (p + 3 < size && !(buf[p]==']' && buf[p+1]==']' && buf[p+2]=='>')) p++;
            if (p + 3 < size) { *tag_start = s; *tag_end = p + 3; *pos = p + 3; return 4; }
            return 0;
        }
        while (p < size && buf[p] != '>') p++;
        if (p < size && buf[p] == '>') { *tag_start = s; *tag_end = p + 1; *pos = p + 1; return 5; }
        return 0;
    }
    while (p < size && buf[p] != '>' && !isspace(buf[p])) p++;
    if (p < size && buf[p] == '>') { *tag_start = s; *tag_end = p + 1; *pos = p + 1; return 1; }
    while (p < size && buf[p] != '>') p++;
    if (p < size && buf[p] == '>') { *tag_start = s; *tag_end = p + 1; *pos = p + 1; return 1; }
    return 0;
}

static int parse_attr(const uint8_t *buf, size_t size, size_t *pos, size_t *name_start, size_t *name_end, size_t *val_start, size_t *val_end) {
    size_t p = *pos;
    while (p < size && isspace(buf[p])) p++;
    if (p >= size) return 0;
    size_t ns = p;
    while (p < size && (isalnum(buf[p]) || buf[p]=='-' || buf[p]=='_' || buf[p]=='.')) p++;
    if (p == ns) return 0;
    size_t ne = p;
    while (p < size && isspace(buf[p])) p++;
    if (p >= size || buf[p] != '=') return 0;
    p++;
    while (p < size && isspace(buf[p])) p++;
    if (p >= size) return 0;
    uint8_t quote = buf[p];
    if (quote != '"' && quote != '\'') return 0;
    p++;
    size_t vs = p;
    while (p < size && buf[p] != quote) p++;
    if (p >= size) return 0;
    *name_start = ns; *name_end = ne; *val_start = vs; *val_end = p; *pos = p + 1;
    return 1;
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (!nm_adapter_has_signature(buf, size)) return 0;
    nm_xml_chunk_t chunks[NM_MAX_CHUNKS];
    int n = 0;
    size_t pos = 0;
    int depth = 0;
    while (n < NM_MAX_CHUNKS && pos < size) {
        size_t tag_start, tag_end;
        int kind = parse_tag(buf, size, &pos, &tag_start, &tag_end);
        if (!kind) break;
        if (kind == 1 || kind == 2 || kind == 5) {
            if (buf[tag_start+1] == '/') {
                if (depth > 0) depth--;
            } else {
                depth++;
            }
        }
        chunks[n].start = tag_start;
        chunks[n].end = tag_end;
        chunks[n].kind = (kind == 1) ? 1 : (kind == 2 ? 2 : (kind == 3 ? 3 : (kind == 4 ? 4 : 5)));
        n++;
        if (depth == 0 && n > 1) break;
    }
    if (n == 0) return 0;
    int out_idx = 0;
    for (int i = 0; i < n && out_idx < NM_MAX_CHUNKS; i++) {
        out[out_idx].header_off = chunks[i].start;
        out[out_idx].data_off = chunks[i].start;
        out[out_idx].data_len = chunks[i].end - chunks[i].start;
        out[out_idx].integrity_off = 0;
        out[out_idx].integrity_len = 0;
        out[out_idx].kind = chunks[i].kind;
        out[out_idx].flags = 0;
        out_idx++;
    }
    return out_idx;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static void flip_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] ^= 0xFFu;
}

static void corrupt_utf8(uint8_t *p, size_t n) {
    if (n == 0) return;
    size_t flip_at = nm_xorshift32(&nm_xorshift32) % n;
    if (flip_at + 1 < n) {
        p[flip_at] ^= 0x80u;
        p[flip_at+1] ^= 0x80u;
    } else {
        p[flip_at] ^= 0xC0u;
    }
}

static void corrupt_entity(uint8_t *p, size_t n) {
    if (n < 3) return;
    size_t pos = nm_xorshift32(&nm_xorshift32) % (n - 2);
    if (memcmp(p+pos, "&", 1) == 0 || memcmp(p+pos, "#", 1) == 0) {
        size_t end = pos + 1;
        while (end < n && p[end] != ';') end++;
        if (end < n) {
            if (nm_xorshift32(&nm_xorshift32) & 1) {
                p[pos] = 'x';
            } else {
                p[end] = 'x';
            }
        }
    }
}

static void flip_quote(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '"') p[i] = '\'';
        else if (p[i] == '\'') p[i] = '"';
    }
}

static void mutate_decl_version(uint8_t *p, size_t n) {
    if (n < 10) return;
    size_t eq = 0;
    while (eq < n && p[eq] != '=') eq++;
    if (eq + 2 >= n) return;
    size_t q = eq + 2;
    if (p[eq+1] != '"' && p[eq+1] != '\'') return;
    while (q < n && p[q] != p[eq+1]) q++;
    if (q >= n) return;
    size_t len = q - (eq + 2);
    if (len == 0) {
        const char *v = "999.999";
        size_t vl = strlen(v);
        if (eq + 2 + vl <= n) memcpy(p + eq + 2, v, vl);
    } else {
        if (nm_xorshift32(&nm_xorshift32) & 1) {
            p[eq+2] = '9';
            if (len > 1) memset(p + eq + 3, '9', len - 1);
        } else {
            memset(p + eq + 2, '0', len);
        }
    }
}

static void mutate_tag_name(uint8_t *p, size_t n) {
    if (n < 3) return;
    size_t start = 0;
    while (start < n && p[start] != '<') start++;
    if (start >= n) return;
    size_t end = start + 1;
    while (end < n && p[end] != '>' && !isspace(p[end])) end++;
    if (end >= n) return;
    size_t len = end - (start + 1);
    if (len == 0) return;
    if (nm_xorshift32(&nm_xorshift32) & 1) {
        p[start+1] = 'x';
        if (len > 1) p[start+2] = 'x';
    } else {
        for (size_t i = 0; i < len && i < 4; i++) p[start+1+i] ^= 0xFFu;
    }
}

static void mutate_attr_value(uint8_t *p, size_t n) {
    size_t eq = 0;
    while (eq < n && p[eq] != '=') eq++;
    if (eq >= n) return;
    uint8_t quote = p[eq+1];
    if (quote != '"' && quote != '\'') return;
    size_t start = eq + 2;
    size_t end = start;
    while (end < n && p[end] != quote) end++;
    if (end >= n) return;
    size_t len = end - start;
    if (len == 0) return;
    uint32_t op = nm_xorshift32(&nm_xorshift32) % 4;
    switch (op) {
        case 0: flip_quote(p + start - 1, 1); break;
        case 1: corrupt_utf8(p + start, len); break;
        case 2: if (len < 8) memset(p + start, 'x', len); else { size_t z = nm_xorshift32(&nm_xorshift32) % 8; memset(p + start, 'x', z); } break;
        case 3: corrupt_entity(p + start, len); break;
    }
}

static void mutate_text_content(uint8_t *p, size_t n) {
    if (n == 0) return;
    uint32_t op = nm_xorshift32(&nm_xorshift32) % 3;
    switch (op) {
        case 0: flip_bytes(p, n); break;
        case 1: corrupt_utf8(p, n); break;
        case 2: for (size_t i = 0; i < n && i < 8; i++) if (nm_xorshift32(&nm_xorshift32) & 1) p[i] = '<'; break;
    }
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 10;
    size_t idx = nm_xorshift32(rng) % (size_t)n;
    nm_chunk_t *c = &chunks[idx];
    if (c->data_len == 0) return 0;
    size_t rel_start = c->data_off - c->header_off;
    size_t rel_end = rel_start + c->data_len;
    if (rel_end > buf_size) return 0;
    uint8_t *p = buf + c->data_off;
    size_t len = c->data_len;
    switch (op) {
        case 0: mutate_decl_version(p, len); break;
        case 1: mutate_tag_name(p, len); break;
        case 2: mutate_attr_value(p, len); break;
        case 3: mutate_text_content(p, len); break;
        case 4: flip_bytes(p, len > 32 ? 32 : len); break;
        case 5: corrupt_utf8(p, len > 32 ? 32 : len); break;
        case 6: corrupt_entity(p, len > 32 ? 32 : len); break;
        case 7: flip_quote(p, len > 32 ? 32 : len); break;
        case 8: {
            size_t pos = nm_xorshift32(rng) % len;
            if (pos + 1 < len) { p[pos] = '<'; p[pos+1] = '/'; }
            else p[pos] = '>';
            break;
        }
        case 9: {
            size_t pos = nm_xorshift32(rng) % len;
            if (pos < len) p[pos] = '&';
            break;
        }
    }
    nm_adapter_fix_integrity(buf, c);
    return 1;
}