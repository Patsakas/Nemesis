/**
 * NEMESIS PNG mutator adapter.
 *
 * Implements the four hooks expected by mutator_scaffold.h for the PNG
 * file format (chunked, CRC32-armored).
 *
 * Targeted mutations focus on the IHDR chunk fields (width, height,
 * bit_depth, color_type, interlace) because the most interesting libpng
 * bugs — including CVE-2018-13785, an integer overflow in row-size
 * computation — are driven by attacker-controlled IHDR values that pass
 * early validation but overflow downstream multiplications.
 *
 * Compile: afl-clang-fast -shared -fPIC -O2 -o libpng_mutator.so png.c
 * (the pipeline does this automatically when custom_mutator_source
 *  in the YAML target points at this file)
 */

#include "../mutator_scaffold.h"

/* PNG chunk-type tag codes for nm_chunk_t.kind */
enum {
    PNG_KIND_UNKNOWN = 0,
    PNG_KIND_IHDR = 1,
    PNG_KIND_IDAT = 2,
    PNG_KIND_PLTE = 3,
    PNG_KIND_IEND = 4,
    PNG_KIND_tRNS = 5,
    PNG_KIND_iCCP = 6,
};

static const uint8_t PNG_SIG[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    return size >= 8 && memcmp(buf, PNG_SIG, 8) == 0;
}

static uint32_t png_kind_for_type(const uint8_t *t) {
    if (memcmp(t, "IHDR", 4) == 0) return PNG_KIND_IHDR;
    if (memcmp(t, "IDAT", 4) == 0) return PNG_KIND_IDAT;
    if (memcmp(t, "PLTE", 4) == 0) return PNG_KIND_PLTE;
    if (memcmp(t, "IEND", 4) == 0) return PNG_KIND_IEND;
    if (memcmp(t, "tRNS", 4) == 0) return PNG_KIND_tRNS;
    if (memcmp(t, "iCCP", 4) == 0) return PNG_KIND_iCCP;
    return PNG_KIND_UNKNOWN;
}

/* Walk PNG chunks: 4B length BE, 4B type, <length>B data, 4B CRC. */
static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 8;
    while (n < NM_MAX_CHUNKS && off + 12 <= size) {
        uint32_t len = nm_read_be32(buf + off);
        if (len > 16u * 1024u * 1024u) break;            /* sanity cap */
        if (off + 12 + (size_t)len > size) break;        /* truncated */

        out[n].header_off    = off;
        out[n].data_off      = off + 8;
        out[n].data_len      = len;
        out[n].integrity_off = off + 8 + len;
        out[n].integrity_len = 4;
        out[n].kind          = png_kind_for_type(buf + off + 4);
        out[n].flags         = 0;
        n++;

        off += 12 + (size_t)len;
        if (out[n - 1].kind == PNG_KIND_IEND) break;
    }
    return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    if (!chunk->integrity_len) return;
    /* CRC is computed over (chunk type + data) — i.e. 4 bytes of type
     * immediately preceding data_off, plus the data field itself. */
    size_t type_off = chunk->data_off - 4;
    uint32_t state_seed = 1;          /* dummy — we just need the table */
    /* Build table on the stack each time. Cheap enough vs. the AFL fork
     * cost; avoids threading a state ptr through the adapter contract. */
    uint32_t table[256];
    nm_crc32_init(table);
    (void)state_seed;
    uint32_t crc = nm_crc32(table, buf + type_off, 4 + chunk->data_len);
    nm_write_be32(buf + chunk->integrity_off, crc);
}

/* "Interesting" 4-byte BE values for width/height — chosen to provoke
 * integer overflow in libpng's row-size computation:
 *   row_factor = width * channels * (bit_depth>8?2:1) + 1 + (interlaced?6:0)
 * which is computed in 32-bit arithmetic. The bug fires when row_factor
 * wraps to 0 (CVE-2018-13785 → divide-by-zero in idat_limit/row_factor).
 * libpng's png_get_uint_31 hard-rejects width > 0x7FFFFFFF, so the
 * useful triggers are widths W such that W*(channels*factor) ≡ 0xFFFFFFFF
 * mod 2^32 with W ≤ 0x7FFFFFFF. The closed-form solutions are 0xFFFFFFFF/N
 * for N ∈ {3,4,6,8} (the only viable channels*factor combinations). */
static const uint32_t PNG_INTERESTING_DIM[] = {
    0u, 1u, 2u, 7u, 8u, 16u, 256u, 1024u,
    0x7FFFu, 0xFFFEu, 0xFFFFu,                          /* 16-bit edges */
    0x10000u, 0x10001u,
    0x1FFFFFFFu, 0x20000000u,                            /* N=8: RGBA 16bit row-factor=0 */
    0x2AAAAAAAu, 0x2AAAAAABu,                            /* N=6: RGB 16bit row-factor≈0 */
    0x3FFFFFFFu, 0x40000000u,                            /* N=4: RGBA 8bit row-factor≈0 */
    0x55555555u, 0x55555556u,                            /* N=3: RGB 8bit row-factor=0 (CVE-2018-13785) */
    0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu, /* 32-bit edges (some hit png_get_uint_31 cap) */
};
#define PNG_DIM_N (sizeof(PNG_INTERESTING_DIM)/sizeof(PNG_INTERESTING_DIM[0]))

/* Bit depths and color types — both valid and slightly invalid. libpng
 * validates these but the CVE math runs before the validation in some
 * code paths. */
static const uint8_t PNG_INTERESTING_BIT_DEPTH[]  = {1, 2, 4, 8, 16, 0, 24, 32};
static const uint8_t PNG_INTERESTING_COLOR_TYPE[] = {0, 2, 3, 4, 6, 1, 5, 7};

/* Returns 1 if a targeted mutation was applied, 0 if the adapter
 * declined (caller should fall back to a generic strategy). */
static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    (void)buf_size;
    if (n <= 0 || chunks[0].kind != PNG_KIND_IHDR || chunks[0].data_len < 13) {
        return 0;
    }
    size_t d = chunks[0].data_off;
    uint32_t op = nm_xorshift32(rng) % 5;

    switch (op) {
    case 0: { /* width */
        uint32_t w = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
        nm_write_be32(buf + d, w);
        break;
    }
    case 1: { /* height */
        uint32_t h = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
        nm_write_be32(buf + d + 4, h);
        break;
    }
    case 2: { /* both width AND height — primary CVE-2018-13785 path */
        uint32_t w = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
        uint32_t h = PNG_INTERESTING_DIM[nm_xorshift32(rng) % PNG_DIM_N];
        nm_write_be32(buf + d,     w);
        nm_write_be32(buf + d + 4, h);
        break;
    }
    case 3: { /* bit_depth + color_type */
        buf[d + 8] = PNG_INTERESTING_BIT_DEPTH[
            nm_xorshift32(rng) % sizeof(PNG_INTERESTING_BIT_DEPTH)];
        buf[d + 9] = PNG_INTERESTING_COLOR_TYPE[
            nm_xorshift32(rng) % sizeof(PNG_INTERESTING_COLOR_TYPE)];
        break;
    }
    default: { /* interlace flip */
        buf[d + 12] = (uint8_t)(nm_xorshift32(rng) & 1u);
        break;
    }
    }
    nm_adapter_fix_integrity(buf, &chunks[0]);
    return 1;
}
