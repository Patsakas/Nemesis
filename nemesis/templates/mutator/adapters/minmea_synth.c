#include "../mutator_scaffold.h"

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 6) return 0;
    return (buf[0] == '$' &&
            ((buf[1] == 'G' && (buf[2] == 'P' || buf[2] == 'A' || buf[2] == 'L' || buf[2] == 'N' || buf[2] == 'B' || buf[2] == 'M')) ||
             (buf[1] == 'G' && buf[2] == 'A') ||
             (buf[1] == 'G' && buf[2] == 'L') ||
             (buf[1] == 'G' && buf[2] == 'N') ||
             (buf[1] == 'B' && buf[2] == 'D')));
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size < 6 || buf[0] != '$') return 0;
    size_t off = 0;
    int n = 0;
    while (n < NM_MAX_CHUNKS && off + 6 <= size) {
        if (buf[off] != '$') break;
        size_t start = off;
        off++;
        if (off + 5 > size) break;
        size_t talker_off = off;
        off += 2;
        size_t sentence_off = off;
        off += 3;
        size_t fields_start = off;
        size_t comma_count = 0;
        size_t last_comma = fields_start - 1;
        while (off < size && comma_count < 64) {
            if (buf[off] == ',') {
                comma_count++;
                last_comma = off;
            } else if (buf[off] == '*' && off + 3 <= size && isxdigit(buf[off+1]) && isxdigit(buf[off+2])) {
                size_t data_len = off - fields_start;
                size_t checksum_off = off;
                size_t crlf_off = off + 3;
                if (crlf_off + 2 > size) break;
                if (buf[crlf_off] != '\r' || buf[crlf_off+1] != '\n') break;
                out[n].header_off = start;
                out[n].data_off = fields_start;
                out[n].data_len = data_len;
                out[n].integrity_off = checksum_off;
                out[n].integrity_len = 3;
                out[n].kind = 1;
                out[n].flags = 0;
                n++;
                off = crlf_off + 2;
                break;
            }
            off++;
        }
        if (n >= NM_MAX_CHUNKS) break;
        if (off >= size) break;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    if (!chunk->integrity_len || chunk->integrity_off + chunk->integrity_len + 2 > SIZE_MAX) return;
    size_t start = chunk->header_off;
    size_t end = chunk->integrity_off;
    uint8_t tmp[256];
    size_t len = end - start;
    if (len > sizeof(tmp)) len = sizeof(tmp);
    memcpy(tmp, buf + start, len);
    uint32_t state = 1;
    uint32_t table[256];
    nm_crc32_init(table);
    uint32_t crc = nm_crc32(table, tmp, len);
    buf[chunk->integrity_off] = '*';
    buf[chunk->integrity_off+1] = "0123456789ABCDEF"[(crc >> 4) & 0xF];
    buf[chunk->integrity_off+2] = "0123456789ABCDEF"[crc & 0xF];
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0 || chunks[0].data_len < 6 || buf[0] != '$') return 0;
    size_t data_off = chunks[0].data_off;
    size_t data_len = chunks[0].data_len;
    uint32_t op = nm_xorshift32(rng) % 6;
    switch (op) {
        case 0: {
            if (data_len >= 2) {
                uint8_t t1 = buf[data_off];
                uint8_t t2 = buf[data_off+1];
                const char *talkers[] = {"GP","GA","GL","GN","BD","GA","GB","GC","GD","GE","GF","GG","GH","GI","GJ","GK","GL","GM","GN","GO","GP","GQ","GR","GS","GT","GU","GV","GW","GX","GY","GZ"};
                uint32_t tidx = nm_xorshift32(rng) % (sizeof(talkers)/sizeof(talkers[0]));
                buf[data_off] = talkers[tidx][0];
                if (data_len >= 3) buf[data_off+1] = talkers[tidx][1];
            }
            break;
        }
        case 1: {
            if (data_len >= 5) {
                const char *sentences[] = {"GGA","GLL","GSA","GSV","RMC","VTG","ZDA","GBS","GST","GGA","GLA","GLB","GLC","GSA","GSB","GSC","GSD","GSE","GSV","GVA","GVB","GVC","GVD","VTG","ZDA","RMC","GGA"};
                uint32_t sidx = nm_xorshift32(rng) % (sizeof(sentences)/sizeof(sentences[0]));
                memcpy(buf + data_off + 2, sentences[sidx], 3);
            }
            break;
        }
        case 2: {
            if (data_len >= 2) {
                buf[data_off] = (uint8_t)(nm_xorshift32(rng) & 0x7F);
                if (data_len >= 3) buf[data_off+1] = (uint8_t)(nm_xorshift32(rng) & 0x7F);
            }
            break;
        }
        case 3: {
            size_t pos = data_off + (nm_xorshift32(rng) % (data_len > 0 ? data_len : 1));
            if (pos < buf_size && pos >= data_off) {
                buf[pos] = (uint8_t)(nm_xorshift32(rng) & 0x7F);
            }
            break;
        }
        case 4: {
            size_t pos = data_off + (nm_xorshift32(rng) % (data_len > 0 ? data_len : 1));
            if (pos + 1 < buf_size && pos >= data_off) {
                uint8_t v = buf[pos];
                if (v == ',') buf[pos] = ';';
                else if (v == '*') buf[pos] = '+';
                else if (v == '\r') buf[pos] = '\n';
                else if (v == '\n') buf[pos] = '\r';
            }
            break;
        }
        case 5: {
            size_t pos = data_off + (nm_xorshift32(rng) % (data_len > 0 ? data_len : 1));
            if (pos + 1 < buf_size && pos >= data_off) {
                if (buf[pos] == ',') {
                    size_t shift = (nm_xorshift32(rng) % 16) + 1;
                    if (pos + shift < buf_size) {
                        memmove(buf + pos + shift, buf + pos, buf_size - pos - shift);
                        memset(buf + pos, ',', shift);
                    }
                } else {
                    buf[pos] = ',';
                }
            }
            break;
        }
    }
    nm_adapter_fix_integrity(buf, &chunks[0]);
    return 1;
}