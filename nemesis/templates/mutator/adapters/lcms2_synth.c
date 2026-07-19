#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static const uint8_t ICC_SIG[4] = {'a','c','s','p'};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    return size >= 4 && memcmp(buf, ICC_SIG, 4) == 0;
}

#define ICC_MAX_CHUNKS 64
#define ICC_MAX_TAGS  256

typedef struct {
    uint32_t sig;
    uint32_t off;
    uint32_t len;
} icc_tag_t;

/* nm_chunk_t is provided by mutator_scaffold.h (identical fields). Redefining
 * it here is a hard compile error ("typedef redefinition") that disabled this
 * adapter and forced AFL back to vanilla havoc. */

static uint32_t icc_tag_for_sig(uint32_t sig) {
    switch (sig) {
        case 0x70726632u: return 1; /* 'prf2' profile */
        case 0x63686164u: return 2; /* 'chad' chromatic adaptation */
        case 0x77747074u: return 3; /* 'wtpt' white point */
        case 0x626B7074u: return 4; /* 'bkpt' black point */
        case 0x72545243u: return 5; /* 'rTRC' red TRC */
        case 0x67545243u: return 6; /* 'gTRC' green TRC */
        case 0x62545243u: return 7; /* 'bTRC' blue TRC */
        case 0x7258595Au: return 8; /* 'rXYZ' red colorant */
        case 0x6758595Au: return 9; /* 'gXYZ' green colorant */
        case 0x6258595Au: return 10; /* 'bXYZ' blue colorant */
        case 0x63757276u: return 11; /* 'curv' curve */
        case 0x7461626Cu: return 12; /* 'tabL' table */
        case 0x70617261u: return 13; /* 'para' parametric curve */
        case 0x6D617466u: return 14; /* 'matf' matrix */
        case 0x636C7266u: return 15; /* 'clrf' colorant */
        case 0x64657363u: return 16; /* 'desc' profile description */
        case 0x74657874u: return 17; /* 'text' text */
        case 0x6D656173u: return 18; /* 'meas' measurement */
        case 0x73663332u: return 19; /* 'sf32' signature */
        default: return 0;
    }
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    if (size < 128) return 0;
    uint32_t sz = nm_read_be32(buf + 0);
    if (sz < 128 || sz > 16*1024*1024) return 0;
    if (size < (size_t)sz) return 0;
    uint32_t cmm_type = nm_read_be32(buf + 4);
    uint32_t version = nm_read_be32(buf + 8);
    (void)cmm_type; (void)version;

    size_t off = 128;
    int n = 0;
    icc_tag_t tags[ICC_MAX_TAGS];
    uint32_t tag_count = nm_read_be32(buf + 128 - 12);
    if (tag_count > ICC_MAX_TAGS) tag_count = ICC_MAX_TAGS;
    for (uint32_t i = 0; i < tag_count; ++i) {
        if (off + 12 > size) break;
        tags[i].sig = nm_read_be32(buf + off);
        tags[i].off = nm_read_be32(buf + off + 4);
        tags[i].len  = nm_read_be32(buf + off + 8);
        if (tags[i].off + tags[i].len > size) break;
        off += 12;
    }

    off = 128;
    for (int i = 0; i < (int)tag_count && n < ICC_MAX_CHUNKS; ++i) {
        uint32_t tag_sig = tags[i].sig;
        uint32_t tag_off = tags[i].off;
        uint32_t tag_len = tags[i].len;
        if (tag_off + tag_len > size) continue;
        out[n].header_off = off;
        out[n].data_off = tag_off;
        out[n].data_len = tag_len;
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind = icc_tag_for_sig(tag_sig);
        out[n].flags = 0;
        n++;
        off += 12;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng) {
    if (n <= 0) return 0;
    uint32_t op = nm_xorshift32(rng) % 6;
    switch (op) {
        case 0: {
            if (chunks[0].data_len < 4) return 0;
            uint32_t v = nm_xorshift32(rng);
            nm_write_be32(buf + chunks[0].data_off, v);
            break;
        }
        case 1: {
            if (chunks[0].data_len < 4) return 0;
            uint32_t v = 0u;
            switch (nm_xorshift32(rng) % 5) {
                case 0: v = 0u; break;
                case 1: v = 1u; break;
                case 2: v = 0x7FFFFFFFu; break;
                case 3: v = 0xFFFFFFFFu; break;
                case 4: v = 0x80000000u; break;
            }
            nm_write_be32(buf + chunks[0].data_off, v);
            break;
        }
        case 2: {
            if (n < 2 || chunks[1].data_len < 4) return 0;
            uint32_t v = 0u;
            switch (nm_xorshift32(rng) % 5) {
                case 0: v = 0u; break;
                case 1: v = 1u; break;
                case 2: v = 0x7FFFFFFFu; break;
                case 3: v = 0xFFFFFFFFu; break;
                case 4: v = 0x80000000u; break;
            }
            nm_write_be32(buf + chunks[1].data_off, v);
            break;
        }
        case 3: {
            if (chunks[0].data_len < 1) return 0;
            uint8_t v = (uint8_t)(nm_xorshift32(rng) & 0xFFu);
            buf[chunks[0].data_off] = v;
            break;
        }
        case 4: {
            nm_bitstream_t bs;
            nm_bs_init(&bs, buf, buf_size);
            size_t bit_pos = nm_bs_tell_bits(&bs);
            if (bit_pos + 8 <= (size_t)(buf_size * 8)) {
                nm_bs_write_bits(&bs, 8, 0xFFu);
            }
            break;
        }
        case 5: {
            if (chunks[0].data_len < 32) return 0;
            size_t len = 1u + (nm_xorshift32(rng) % 32u);
            for (size_t i = 0; i < len; ++i) {
                if (chunks[0].data_off + i >= buf_size) break;
                buf[chunks[0].data_off + i] ^= 0xFFu;
            }
            break;
        }
    }
    return 1;
}