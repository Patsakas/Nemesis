#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 5) return 0;
    if (memcmp(buf, "<?xml", 5) == 0) return 1;
    if (size >= 2 && buf[0] == 0xEF && buf[1] == 0xBB) return 1;
    if (size >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) return 1;
    if (size >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) return 1;
    if (size >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) return 1;
    if (size >= 9 && memcmp(buf, "<!DOCTYPE", 9) == 0) return 1;
    if (size >= 4 && memcmp(buf, "<!--", 4) == 0) return 1;
    if (size >= 6 && memcmp(buf, "<root>", 6) == 0) return 1;
    if (size >= 8 && memcmp(buf, "<!ENTITY", 8) == 0) return 1;
    return 0;
}

#define NM_MAX_DEPTH 64
#define NM_MAX_TAGS  32
#define NM_MAX_ATTRS 16
#define NM_MAX_CHUNKS 64

typedef struct {
    size_t off;
    size_t len;
} nm_slice_t;

static int parse_xml_decl(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 5 >= size) return 0;
    if (buf[*pos] != '<' || buf[*pos+1] != '?') return 0;
    size_t start = *pos;
    *pos += 2;
    while (*pos < size && !(buf[*pos] == '?' && buf[*pos+1] == '>')) (*pos)++;
    if (*pos + 2 > size) return 0;
    *pos += 2;
    return (int)(*pos - start);
}

static int parse_doctype(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 9 >= size) return 0;
    if (memcmp(buf + *pos, "<!DOCTYPE", 9) != 0) return 0;
    size_t start = *pos;
    *pos += 9;
    while (*pos < size && buf[*pos] != '>') (*pos)++;
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int parse_tag(const uint8_t *buf, size_t size, size_t *pos, int closing) {
    if (*pos >= size) return 0;
    if (buf[*pos] != '<') return 0;
    size_t start = *pos;
    (*pos)++;
    if (closing && buf[*pos] == '/') (*pos)++;
    while (*pos < size && buf[*pos] != '>' && buf[*pos] != ' ' && buf[*pos] != '\t' && buf[*pos] != '\n' && buf[*pos] != '\r') (*pos)++;
    if (*pos >= size) return 0;
    while (*pos < size && buf[*pos] != '>') (*pos)++;
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int parse_comment(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 4 >= size) return 0;
    if (memcmp(buf + *pos, "<!--", 4) != 0) return 0;
    size_t start = *pos;
    *pos += 4;
    while (*pos + 3 <= size && !(buf[*pos] == '-' && buf[*pos+1] == '-' && buf[*pos+2] == '>')) (*pos)++;
    if (*pos + 3 > size) return 0;
    *pos += 3;
    return (int)(*pos - start);
}

static int parse_cdata(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 9 >= size) return 0;
    if (memcmp(buf + *pos, "<![CDATA[", 9) != 0) return 0;
    size_t start = *pos;
    *pos += 9;
    while (*pos + 3 <= size && !(buf[*pos] == ']' && buf[*pos+1] == ']' && buf[*pos+2] == '>')) (*pos)++;
    if (*pos + 3 > size) return 0;
    *pos += 3;
    return (int)(*pos - start);
}

static int parse_pi(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 2 >= size) return 0;
    if (buf[*pos] != '<' || buf[*pos+1] != '?') return 0;
    size_t start = *pos;
    *pos += 2;
    while (*pos < size && !(buf[*pos] == '?' && buf[*pos+1] == '>')) (*pos)++;
    if (*pos + 2 > size) return 0;
    *pos += 2;
    return (int)(*pos - start);
}

static int parse_content_model_parens(const uint8_t *buf, size_t size, size_t *pos, int depth) {
    if (depth > NM_MAX_DEPTH) return 0;
    if (*pos >= size || buf[*pos] != '(') return 0;
    size_t start = *pos;
    (*pos)++;
    while (*pos < size && buf[*pos] != ')') {
        if (buf[*pos] == '(') {
            if (!parse_content_model_parens(buf, size, pos, depth + 1)) return 0;
        } else {
            (*pos)++;
        }
    }
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int parse_element_decl(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 10 >= size) return 0;
    if (memcmp(buf + *pos, "<!ELEMENT", 9) != 0) return 0;
    size_t start = *pos;
    *pos += 9;
    while (*pos < size && buf[*pos] != '>') (*pos)++;
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int parse_entity_decl(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 8 >= size) return 0;
    if (memcmp(buf + *pos, "<!ENTITY", 8) != 0) return 0;
    size_t start = *pos;
    *pos += 8;
    while (*pos < size && buf[*pos] != '>') (*pos)++;
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int parse_attlist_decl(const uint8_t *buf, size_t size, size_t *pos) {
    if (*pos + 9 >= size) return 0;
    if (memcmp(buf + *pos, "<!ATTLIST", 9) != 0) return 0;
    size_t start = *pos;
    *pos += 9;
    while (*pos < size && buf[*pos] != '>') (*pos)++;
    if (*pos >= size) return 0;
    (*pos)++;
    return (int)(*pos - start);
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off < size) {
        if (off + 5 <= size && memcmp(buf + off, "<?xml", 5) == 0) {
            int len = parse_xml_decl(buf, size, &off);
            if (len <= 0) break;
            out[n].header_off = off - (size_t)len;
            out[n].data_off = off - (size_t)len;
            out[n].data_len = (size_t)len;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = 1;
            out[n].flags = 0;
            n++;
            continue;
        }
        if (off + 9 <= size && memcmp(buf + off, "<!DOCTYPE", 9) == 0) {
            int len = parse_doctype(buf, size, &off);
            if (len <= 0) break;
            out[n].header_off = off - (size_t)len;
            out[n].data_off = off - (size_t)len;
            out[n].data_len = (size_t)len;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = 2;
            out[n].flags = 0;
            n++;
            continue;
        }
        if (off + 4 <= size && memcmp(buf + off, "<!--", 4) == 0) {
            int len = parse_comment(buf, size, &off);
            if (len <= 0) break;
            out[n].header_off = off - (size_t)len;
            out[n].data_off = off - (size_t)len;
            out[n].data_len = (size_t)len;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = 3;
            out[n].flags = 0;
            n++;
            continue;
        }
        if (off + 6 <= size && memcmp(buf + off, "<root>", 6) == 0) {
            int len = parse_tag(buf, size, &off, 0);
            if (len <= 0) break;
            out[n].header_off = off - (size_t)len;
            out[n].data_off = off - (size_t)len;
            out[n].data_len = (size_t)len;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = 4;
            out[n].flags = 0;
            n++;
            continue;
        }
        if (off < size && buf[off] == '<') {
            if (off + 1 < size && buf[off+1] == '!') {
                if (off + 9 <= size && memcmp(buf + off, "<![CDATA[", 9) == 0) {
                    int len = parse_cdata(buf, size, &off);
                    if (len <= 0) break;
                    out[n].header_off = off - (size_t)len;
                    out[n].data_off = off - (size_t)len;
                    out[n].data_len = (size_t)len;
                    out[n].integrity_off = 0;
                    out[n].integrity_len = 0;
                    out[n].kind = 5;
                    out[n].flags = 0;
                    n++;
                    continue;
                }
                if (off + 8 <= size && memcmp(buf + off, "<!ENTITY", 8) == 0) {
                    int len = parse_entity_decl(buf, size, &off);
                    if (len <= 0) break;
                    out[n].header_off = off - (size_t)len;
                    out[n].data_off = off - (size_t)len;
                    out[n].data_len = (size_t)len;
                    out[n].integrity_off = 0;
                    out[n].integrity_len = 0;
                    out[n].kind = 6;
                    out[n].flags = 0;
                    n++;
                    continue;
                }
                if (off + 9 <= size && memcmp(buf + off, "<!ATTLIST", 9) == 0) {
                    int len = parse_attlist_decl(buf, size, &off);
                    if (len <= 0) break;
                    out[n].header_off = off - (size_t)len;
                    out[n].data_off = off - (size_t)len;
                    out[n].data_len = (size_t)len;
                    out[n].integrity_off = 0;
                    out[n].integrity_len = 0;
                    out[n].kind = 7;
                    out[n].flags = 0;
                    n++;
                    continue;
                }
                if (off + 9 <= size && memcmp(buf + off, "<!ELEMENT", 9) == 0) {
                    int len = parse_element_decl(buf, size, &off);
                    if (len <= 0) break;
                    out[n].header_off = off - (size_t)len;
                    out[n].data_off = off - (size_t)len;
                    out[n].data_len = (size_t)len;
                    out[n].integrity_off = 0;
                    out[n].integrity_len = 0;
                    out[n].kind = 8;
                    out[n].flags = 0;
                    n++;
                    continue;
                }
            }
            if (off + 2 <= size && buf[off+1] == '?') {
                int len = parse_pi(buf, size, &off);
                if (len <= 0) break;
                out[n].header_off = off - (size_t)len;
                out[n].data_off = off - (size_t)len;
                out[n].data_len = (size_t)len;
                out[n].integrity_off = 0;
                out[n].integrity_len = 0;
                out[n].kind = 9;
                out[n].flags = 0;
                n++;
                continue;
            }
            int is_closing = (off + 2 <= size && buf[off+1] == '/');
            int len = parse_tag(buf, size, &off, is_closing);
            if (len <= 0) break;
            out[n].header_off = off - (size_t)len;
            out[n].data_off = off - (size_t)len;
            out[n].data_len = (size_t)len;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = is_closing ? 11 : 10;
            out[n].flags = 0;
            n++;
            continue;
        }
        off++;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 10;
    size_t pos = 0;
    size_t len = 0;
    switch (op) {
        case 0: case 1: case 2: case 3: case 4: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 1) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t ver_off = 0;
            while (ver_off < len - 8 && !(buf[pos + ver_off] == 'v' && buf[pos + ver_off + 1] == 'e' && buf[pos + ver_off + 2] == 'r' && buf[pos + ver_off + 3] == 's' && buf[pos + ver_off + 4] == 'i' && buf[pos + ver_off + 5] == 'o' && buf[pos + ver_off + 6] == 'n')) ver_off++;
            if (ver_off + 8 >= len) return 0;
            size_t q1 = ver_off + 7;
            while (q1 < len && buf[pos + q1] != '"' && buf[pos + q1] != '\'') q1++;
            if (q1 >= len) return 0;
            size_t q2 = q1 + 1;
            while (q2 < len && buf[pos + q2] != '"' && buf[pos + q2] != '\'') q2++;
            if (q2 >= len) return 0;
            uint32_t pick = nm_xorshift32(rng) % 8;
            const char *vers[] = {"1.0", "1.1", "2.0", "0.0", "99.0", "1.9", "0.9", "0.1"};
            size_t vlen = strlen(vers[pick]);
            if (vlen > q2 - q1 - 1) vlen = q2 - q1 - 1;
            if (vlen > 0) {
                memcpy(buf + pos + q1 + 1, vers[pick], vlen);
                memset(buf + pos + q1 + 1 + vlen, ' ', (q2 - q1 - 1) - vlen);
            }
            break;
        }
        case 5: case 6: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 1) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t enc_off = 0;
            while (enc_off < len - 8 && !(buf[pos + enc_off] == 'e' && buf[pos + enc_off + 1] == 'n' && buf[pos + enc_off + 2] == 'c' && buf[pos + enc_off + 3] == 'o' && buf[pos + enc_off + 4] == 'd' && buf[pos + enc_off + 5] == 'i' && buf[pos + enc_off + 6] == 'n' && buf[pos + enc_off + 7] == 'g')) enc_off++;
            if (enc_off + 8 >= len) return 0;
            size_t q1 = enc_off + 8;
            while (q1 < len && buf[pos + q1] != '"' && buf[pos + q1] != '\'') q1++;
            if (q1 >= len) return 0;
            size_t q2 = q1 + 1;
            while (q2 < len && buf[pos + q2] != '"' && buf[pos + q2] != '\'') q2++;
            if (q2 >= len) return 0;
            uint32_t pick = nm_xorshift32(rng) % 6;
            const char *encs[] = {"UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "ASCII", "ISO-8859-1"};
            size_t elen = strlen(encs[pick]);
            if (elen > q2 - q1 - 1) elen = q2 - q1 - 1;
            if (elen > 0) {
                memcpy(buf + pos + q1 + 1, encs[pick], elen);
                memset(buf + pos + q1 + 1 + elen, ' ', (q2 - q1 - 1) - elen);
            }
            break;
        }
        case 7: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 8) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t paren_start = 0;
            while (paren_start < len && buf[pos + paren_start] != '(') paren_start++;
            if (paren_start >= len) return 0;
            size_t depth = 0;
            size_t cur = paren_start;
            while (cur < len && depth < NM_MAX_DEPTH) {
                if (buf[pos + cur] == '(') depth++;
                else if (buf[pos + cur] == ')') depth--;
                cur++;
            }
            if (depth >= NM_MAX_DEPTH) return 0;
            size_t insert_pos = paren_start + 1 + (nm_xorshift32(rng) % (cur - paren_start - 1));
            if (insert_pos >= len) insert_pos = paren_start + 1;
            if (buf_size < pos + len + 2) return 0;
            memmove(buf + pos + insert_pos + 2, buf + pos + insert_pos, len - insert_pos);
            buf[pos + insert_pos] = '(';
            buf[pos + insert_pos + 1] = ')';
            for (int i = 0; i < n; i++) {
                if (chunks[i].data_off >= pos + insert_pos) chunks[i].data_len += 2;
                if (chunks[i].header_off >= pos + insert_pos) chunks[i].header_off += 2;
            }
            break;
        }
        case 8: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 8) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t paren_start = 0;
            while (paren_start < len && buf[pos + paren_start] != '(') paren_start++;
            if (paren_start >= len) return 0;
            size_t insert_pos = paren_start + 1 + (nm_xorshift32(rng) % (len - paren_start - 1));
            if (insert_pos >= len) insert_pos = paren_start + 1;
            if (buf_size < pos + len + 2) return 0;
            memmove(buf + pos + insert_pos + 2, buf + pos + insert_pos, len - insert_pos);
            buf[pos + insert_pos] = '(';
            buf[pos + insert_pos + 1] = ')';
            for (int i = 0; i < n; i++) {
                if (chunks[i].data_off >= pos + insert_pos) chunks[i].data_len += 2;
                if (chunks[i].header_off >= pos + insert_pos) chunks[i].header_off += 2;
            }
            break;
        }
        case 9: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 10) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t tag_start = 1;
            while (tag_start < len && buf[pos + tag_start] != '>' && buf[pos + tag_start] != ' ' && buf[pos + tag_start] != '\t') tag_start++;
            if (tag_start >= len) return 0;
            size_t name_end = tag_start;
            while (name_end < len && buf[pos + name_end] != '>' && buf[pos + name_end] != ' ' && buf[pos + name_end] != '\t' && buf[pos + name_end] != '/' && buf[pos + name_end] != '>') name_end++;
            if (name_end >= len) return 0;
            uint32_t pick = nm_xorshift32(rng) % 4;
            const char *names[] = {"x", "a", "root", "1a"};
            size_t nlen = strlen(names[pick]);
            size_t max_len = name_end - tag_start;
            if (nlen > max_len) nlen = max_len;
            memcpy(buf + pos + tag_start, names[pick], nlen);
            if (nlen < max_len) memset(buf + pos + tag_start + nlen, ' ', max_len - nlen);
            break;
        }
        default: {
            for (int i = 0; i < n; i++) {
                if (chunks[i].kind == 1) { pos = chunks[i].data_off; len = chunks[i].data_len; break; }
            }
            if (len == 0) return 0;
            size_t standalone_off = 0;
            while (standalone_off < len - 9 && !(buf[pos + standalone_off] == 's' && buf[pos + standalone_off + 1] == 't' && buf[pos + standalone_off + 2] == 'a' && buf[pos + standalone_off + 3] == 'n' && buf[pos + standalone_off + 4] == 'd' && buf[pos + standalone_off + 5] == 'a' && buf[pos + standalone_off + 6] == 'l' && buf[pos + standalone_off + 7] == 'o' && buf[pos + standalone_off + 8] == 'n') ) standalone_off++;
            if (standalone_off + 9 >= len) return 0;
            size_t q1 = standalone_off + 9;
            while (q1 < len && buf[pos + q1] != '"' && buf[pos + q1] != '\'') q1++;
            if (q1 >= len) return 0;
            size_t q2 = q1 + 1;
            while (q2 < len && buf[pos + q2] != '"' && buf[pos + q2] != '\'') q2++;
            if (q2 >= len) return 0;
            uint32_t pick = nm_xorshift32(rng) % 4;
            const char *vals[] = {"yes", "no", "", "maybe"};
            size_t vlen = strlen(vals[pick]);
            if (vlen > q2 - q1 - 1) vlen = q2 - q1 - 1;
            if (vlen > 0) {
                memcpy(buf + pos + q1 + 1, vals[pick], vlen);
                memset(buf + pos + q1 + 1 + vlen, ' ', (q2 - q1 - 1) - vlen);
            } else {
                memmove(buf + pos + q1, buf + q2, len - q2);
                len -= (q2 - q1);
                for (int i = 0; i < n; i++) {
                    if (chunks[i].data_off >= pos + q2) chunks[i].data_len -= (q2 - q1);
                    if (chunks[i].header_off >= pos + q2) chunks[i].header_off -= (q2 - q1);
                }
            }
            break;
        }
    }
    return 1;
}