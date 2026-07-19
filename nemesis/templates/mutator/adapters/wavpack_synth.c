#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static const uint8_t WVPK_SIG[4] = {'w','v','p','k'};
static const uint8_t WVC_P_SIG[4] = {'w','v','c','P'};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    if (size < 4) return 0;
    if (memcmp(buf, WVPK_SIG, 4) == 0) return 1;
    if (size >= 8 && memcmp(buf, WVC_P_SIG, 4) == 0) return 1;
    return 0;
}

#define NM_MAX_WVPK_BLOCKS 64
#define NM_MAX_META_CHUNKS 16

typedef struct {
    uint32_t block_index;
    uint32_t total_samples;
    uint32_t block_samples;
    uint32_t flags;
    uint16_t version;
    size_t header_off;
    size_t data_off;
    size_t data_len;
    size_t integrity_off;
    size_t integrity_len;
    uint32_t kind;
} wv_chunk_t;

static uint32_t wv_read_le32(const uint8_t *p) { return nm_read_le32(p); }
static void wv_write_le32(uint8_t *p, uint32_t v) { nm_write_le32(p, v); }
static uint16_t wv_read_le16(const uint8_t *p) { return nm_read_le16(p); }
static void wv_write_le16(uint8_t *p, uint16_t v) { nm_write_le16(p, v); }

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;

    if (size >= 12 && memcmp(buf, "RIFF", 4) == 0) {
        uint32_t riff_size = wv_read_le32(buf + 4);
        if (riff_size > 16u * 1024u * 1024u) return 0;
        if (size < 12 + riff_size) return 0;
        if (memcmp(buf + 8, "WAVE", 4) != 0) return 0;
        off = 12;
    }

    while (n < NM_MAX_CHUNKS && off + 32 <= size && n < NM_MAX_WVPK_BLOCKS) {
        if (memcmp(buf + off, WVPK_SIG, 4) != 0) break;
        uint32_t ckSize = wv_read_le32(buf + off + 4);
        if (ckSize > 16u * 1024u * 1024u) break;
        if (off + 32 + (size_t)ckSize > size) break;

        wv_chunk_t tmp;
        tmp.header_off = off;
        tmp.data_off = off + 32;
        tmp.data_len = (size_t)ckSize;
        tmp.integrity_off = 0;
        tmp.integrity_len = 0;
        tmp.kind = 1;

        out[n].header_off = tmp.header_off;
        out[n].data_off = tmp.data_off;
        out[n].data_len = tmp.data_len;
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind = 1;
        out[n].flags = 0;

        off += 32 + (size_t)ckSize;
        n++;
    }

    if (n == 0 && size >= 8 && memcmp(buf, WVC_P_SIG, 4) == 0) {
        out[n].header_off = 0;
        out[n].data_off = 4;
        out[n].data_len = size - 4;
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind = 2;
        n++;
    }

    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    if (chunk->integrity_len != 4) return;
    uint32_t crc = nm_crc32(((nm_state_t*)NULL)->crc_table, buf + chunk->header_off, 32 + chunk->data_len);
    wv_write_le32(buf + chunk->integrity_off, crc);
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 8;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    if (c->data_len < 32) return 0;

    size_t hdr = c->header_off;
    uint32_t *p_ckSize = (uint32_t*)(buf + hdr + 4);
    uint16_t *p_version = (uint16_t*)(buf + hdr + 8);
    uint8_t *p_block_idx_msb = buf + hdr + 12;
    uint8_t *p_total_smpl_msb = buf + hdr + 13;
    uint32_t *p_total_samples = (uint32_t*)(buf + hdr + 16);
    uint32_t *p_block_index = (uint32_t*)(buf + hdr + 20);
    uint32_t *p_block_samples = (uint32_t*)(buf + hdr + 24);
    uint32_t *p_flags = (uint32_t*)(buf + hdr + 28);

    switch (op) {
        case 0: { *(uint32_t*)p_block_samples = 0u; break; }
        case 1: { *(uint32_t*)p_block_samples = 0xFFFFFFFFu; break; }
        case 2: { *(uint32_t*)p_block_samples = 0x7FFFFFFFu; break; }
        case 3: { *(uint32_t*)p_block_samples = 0x80000000u; break; }
        case 4: { *p_flags ^= 0x4u; break; }
        case 5: { *p_flags ^= 0x80u; break; }
        case 6: { *p_flags ^= 0x100u; break; }
        case 7: {
            uint16_t v = wv_read_le16((uint8_t*)p_version);
            if ((v & 0xFF00u) == 0) v = 0x401u;
            else if ((v & 0xFF00u) == 0x400u) v = 0x411u;
            else v = (uint16_t)(nm_xorshift32(rng) & 0xFFFFu);
            wv_write_le16((uint8_t*)p_version, v);
            break;
        }
    }

    uint32_t new_ckSize = (uint32_t)(c->data_len - 32);
    wv_write_le32((uint8_t*)p_ckSize, new_ckSize);
    nm_adapter_fix_integrity(buf, c);
    return 1;
}