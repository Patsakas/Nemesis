#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 6) return 0;
    if (memcmp(buf, "FILE \"", 6) == 0) return 1;
    if (size >= 9 && memcmp(buf, "CATALOG ", 9) == 0) return 1;
    if (size >= 12 && memcmp(buf, "CDTEXTFILE ", 12) == 0) return 1;
    if (size >= 6 && memcmp(buf, "TRACK ", 6) == 0) return 1;
    if (size >= 6 && memcmp(buf, "INDEX ", 6) == 0) return 1;
    if (size >= 4 && memcmp(buf, "REM ", 4) == 0) return 1;
    if (size >= 6 && memcmp(buf, "FLAGS ", 6) == 0) return 1;
    return 0;
}

enum { CUE_KIND_GLOBAL_REM, CUE_KIND_CATALOG, CUE_KIND_CDTEXTFILE, CUE_KIND_TRACK, CUE_KIND_INDEX };

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off < size) {
        size_t nl = 0;
        while (off + nl < size && buf[off + nl] != '\n' && buf[off + nl] != '\r') nl++;
        if (nl == 0) break;
        if (off + nl > size) break;

        if (memcmp(buf + off, "REM ", 4) == 0) {
            out[n].header_off = off;
            out[n].data_off = off + 4;
            out[n].data_len = nl - 4;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = CUE_KIND_GLOBAL_REM;
            n++;
        } else if (memcmp(buf + off, "CATALOG ", 9) == 0) {
            out[n].header_off = off;
            out[n].data_off = off + 9;
            out[n].data_len = nl - 9;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = CUE_KIND_CATALOG;
            n++;
        } else if (memcmp(buf + off, "CDTEXTFILE ", 12) == 0) {
            out[n].header_off = off;
            out[n].data_off = off + 12;
            out[n].data_len = nl - 12;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = CUE_KIND_CDTEXTFILE;
            n++;
        } else if (memcmp(buf + off, "TRACK ", 6) == 0) {
            out[n].header_off = off;
            out[n].data_off = off + 6;
            out[n].data_len = nl - 6;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = CUE_KIND_TRACK;
            n++;
        } else if (memcmp(buf + off, "INDEX ", 6) == 0) {
            out[n].header_off = off;
            out[n].data_off = off + 6;
            out[n].data_len = nl - 6;
            out[n].integrity_off = 0;
            out[n].integrity_len = 0;
            out[n].kind = CUE_KIND_INDEX;
            n++;
        }
        off += nl;
        if (buf[off] == '\r') off++;
        if (off >= size) break;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 10;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    if (c->data_len == 0) return 0;

    size_t line_start = c->header_off;
    size_t line_end = line_start;
    while (line_end < buf_size && buf[line_end] != '\n' && buf[line_end] != '\r') line_end++;
    if (line_end >= buf_size) return 0;
    size_t line_len = line_end - line_start;
    if (line_len > 128) line_len = 128;

    switch (op) {
        case 0: {
            if (c->kind == CUE_KIND_TRACK) {
                size_t num_start = c->data_off;
                size_t num_end = num_start;
                while (num_end < line_end && buf[num_end] != ' ') num_end++;
                if (num_end - num_start > 0 && num_end <= line_end) {
                    uint32_t v = 1 + (nm_xorshift32(rng) % 99u);
                    for (size_t i = num_start; i < num_end; i++) buf[i] = ' ';
                    char tmp[4];
                    int l = snprintf(tmp, sizeof(tmp), "%u", v);
                    if (l > 0 && (size_t)l <= num_end - num_start) {
                        memcpy(buf + num_start, tmp, (size_t)l);
                    }
                }
            }
            break;
        }
        case 1: {
            if (c->kind == CUE_KIND_INDEX) {
                size_t num_start = c->data_off;
                size_t num_end = num_start;
                while (num_end < line_end && buf[num_end] != ' ') num_end++;
                if (num_end - num_start == 2) {
                    uint32_t v = nm_xorshift32(rng) % 100u;
                    char tmp[3];
                    int l = snprintf(tmp, sizeof(tmp), "%02u", v);
                    if (l == 2) memcpy(buf + num_start, tmp, 2);
                }
            }
            break;
        }
        case 2: {
            if (c->kind == CUE_KIND_INDEX) {
                size_t pos_start = c->data_off;
                while (pos_start < line_end && buf[pos_start] != ' ') pos_start++;
                if (pos_start < line_end) {
                    size_t mm = 1 + (nm_xorshift32(rng) % 100u);
                    size_t ss = nm_xorshift32(rng) % 60u;
                    size_t ff = nm_xorshift32(rng) % 75u;
                    char tmp[16];
                    int l = snprintf(tmp, sizeof(tmp), "%02zu:%02zu:%02zu", mm, ss, ff);
                    size_t write_len = (size_t)l;
                    if (write_len > line_end - pos_start) write_len = line_end - pos_start;
                    if (write_len > 0) memcpy(buf + pos_start, tmp, write_len);
                }
            }
            break;
        }
        case 3: {
            if (c->kind == CUE_KIND_TRACK) {
                size_t mode_start = c->data_off;
                while (mode_start < line_end && buf[mode_start] != ' ') mode_start++;
                if (mode_start < line_end) {
                    const char *modes[] = {"AUDIO","MODE1","MODE1/2352","MODE1/RAW","MODE2","MODE2/FORM1","MODE2/FORM2","MODE2/FORM_MIX","MODE2/RAW","MODE3","AUDIO_RAW"};
                    const char *m = modes[nm_xorshift32(rng) % (sizeof(modes)/sizeof(modes[0]))];
                    size_t mlen = strlen(m);
                    size_t space = line_end - mode_start;
                    if (mlen > space) mlen = space;
                    memcpy(buf + mode_start, m, mlen);
                }
            }
            break;
        }
        case 4: {
            if (c->kind == CUE_KIND_GLOBAL_REM) {
                size_t type_start = c->data_off;
                size_t type_end = type_start;
                while (type_end < line_end && buf[type_end] != ' ') type_end++;
                if (type_end - type_start > 0) {
                    const char *types[] = {"DATE","REPLAYGAIN_ALBUM_GAIN","REPLAYGAIN_ALBUM_PEAK","REPLAYGAIN_TRACK_GAIN","REPLAYGAIN_TRACK_PEAK","COMMENT","DISCNUMBER","TOTALDISCS","REM_FOO"};
                    const char *t = types[nm_xorshift32(rng) % (sizeof(types)/sizeof(types[0]))];
                    size_t tlen = strlen(t);
                    size_t space = line_end - type_start;
                    if (tlen > space) tlen = space;
                    memcpy(buf + type_start, t, tlen);
                }
            }
            break;
        }
        case 5: {
            if (c->kind == CUE_KIND_TRACK || c->kind == CUE_KIND_INDEX || c->kind == CUE_KIND_GLOBAL_REM) {
                size_t pos = c->header_off + (nm_xorshift32(rng) % line_len);
                if (pos < line_end) buf[pos] ^= 0xFFu;
            }
            break;
        }
        case 6: {
            if (c->kind == CUE_KIND_INDEX) {
                if (line_len < buf_size - 1) {
                    memmove(buf + line_end + 1, buf + line_end, buf_size - line_end);
                    buf[line_end] = '\n';
                    line_end++;
                    if (line_end < buf_size) buf[line_end] = '\n';
                    buf_size++;
                }
            }
            break;
        }
        case 7: {
            if (c->kind == CUE_KIND_INDEX) {
                if (line_len > 0) {
                    size_t del = 1 + (nm_xorshift32(rng) % (line_len / 2 + 1));
                    if (del > line_len) del = line_len;
                    memmove(buf + line_start, buf + line_start + del, line_len - del);
                    line_end -= del;
                }
            }
            break;
        }
        case 8: {
            if (c->kind == CUE_KIND_TRACK) {
                size_t num_start = c->data_off;
                size_t num_end = num_start;
                while (num_end < line_end && buf[num_end] != ' ') num_end++;
                if (num_end - num_start > 0) {
                    uint32_t v = 0;
                    memcpy(&v, buf + num_start, num_end - num_start);
                    v = (v == 0) ? 1 : (v - 1);
                    char tmp[4];
                    int l = snprintf(tmp, sizeof(tmp), "%u", v);
                    if (l > 0) {
                        size_t pad = num_end - num_start - (size_t)l;
                        if (pad > 0) memmove(buf + num_start + pad, buf + num_start, num_end - num_start);
                        memcpy(buf + num_start, tmp, (size_t)l);
                    }
                }
            }
            break;
        }
        case 9: {
            if (c->kind == CUE_KIND_INDEX) {
                size_t pos_start = c->data_off;
                while (pos_start < line_end && buf[pos_start] != ' ') pos_start++;
                if (pos_start < line_end) {
                    size_t mm = 99u;
                    size_t ss = 59u;
                    size_t ff = 74u;
                    char tmp[16];
                    int l = snprintf(tmp, sizeof(tmp), "%02zu:%02zu:%02zu", mm, ss, ff);
                    size_t write_len = (size_t)l;
                    if (write_len > line_end - pos_start) write_len = line_end - pos_start;
                    if (write_len > 0) memcpy(buf + pos_start, tmp, write_len);
                }
            }
            break;
        }
    }
    return 1;
}