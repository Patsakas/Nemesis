/**
 * NEMESIS custom-mutator scaffold (header-only).
 *
 * Generic mutation orchestration for AFL++ custom mutators that target
 * structured / armored binary formats (chunked, length-prefixed, CRC-protected).
 *
 * Each *adapter* (e.g. adapters/png.c) is a self-contained translation unit
 * that #includes this header and implements four format-specific hooks.
 * The scaffold provides the AFL API entry points, RNG, scratch buffer
 * management, CRC32, and the strategy dispatch — none of which the adapter
 * has to reinvent.
 *
 * Adding a new format: copy adapters/png.c, replace the four hooks, point
 * `target.fuzzing.custom_mutator_source` at the new file in YAML. The
 * pipeline already compiles whatever single .c file you point it at via
 * afl-clang-fast -shared -fPIC.
 */

#ifndef NEMESIS_MUTATOR_SCAFFOLD_H
#define NEMESIS_MUTATOR_SCAFFOLD_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* Fix 149 (2026-05-10): generated adapters often emit ASCII payloads
 * (DTD nesting, JSON arrays, ...) and reach for snprintf/sprintf. Without
 * stdio.h they hit "implicit declaration" → clang errors → custom mutator
 * disabled → AFL falls back to vanilla havoc. Pre-include it here so every
 * adapter inherits it transitively. */
#include <stdio.h>
/* Same rationale as stdio.h above: text-format adapters (xml2, json, cue, ...)
 * reach for isspace/isdigit/isalpha/tolower when scanning ASCII payloads.
 * Without ctype.h those are implicit declarations → clang error → custom
 * mutator disabled. Pre-include so every adapter inherits it transitively. */
#include <ctype.h>

/* ---------- Generic chunk descriptor ----------
 * The adapter populates an array of these for whatever structural unit
 * makes sense in its format (PNG chunks, RIFF chunks, TIFF IFD entries,
 * MP4 boxes, ELF sections, ...). Fields the adapter doesn't use can be
 * left zero. */
typedef struct {
    size_t header_off;     /* where the chunk's framing starts */
    size_t data_off;       /* where the payload starts */
    size_t data_len;       /* payload length in bytes */
    size_t integrity_off;  /* offset of CRC/checksum field, 0 if format has none */
    size_t integrity_len;  /* size of CRC field (4 for PNG, 0 if none) */
    uint32_t kind;         /* adapter-defined type tag, 0 = unknown/generic */
    uint32_t flags;        /* adapter-defined flags */
} nm_chunk_t;

#define NM_MAX_CHUNKS 64

/* ---------- Adapter contract ----------
 * Each adapter MUST define these four static functions before its
 * #include of this header expands the AFL entry points. They are static
 * because each adapter is its own TU; no symbol clashes across .so's. */

static int  nm_adapter_has_signature(const uint8_t *buf, size_t size);
static int  nm_adapter_parse(const uint8_t *buf, size_t size,
                             nm_chunk_t *out_chunks);
static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk);
static int  nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                      nm_chunk_t *chunks, int n,
                                      uint32_t *rng);

/* ---------- Helpers ---------- */

typedef struct {
    uint8_t *buf;
    size_t buf_size;
    unsigned int seed;
    int crc_table_init;
    uint32_t crc_table[256];
} nm_state_t;

static uint32_t nm_xorshift32(uint32_t *state) {
    uint32_t x = *state ? *state : 0xC0FFEEu;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t nm_read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void nm_write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t nm_read_le32(const uint8_t *p) {
    return  (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void nm_write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* 16-bit and 64-bit accessors. LLM-synthesised format adapters routinely call
 * these (wavpack/sndfile field widths are 16-bit; tiff/bigtiff offsets are
 * 16/64-bit), but the scaffold previously shipped only the 32-bit pair — so
 * every adapter touching a 16- or 64-bit field failed to compile with
 * "call to undeclared function 'nm_read_le16'" and silently fell back to no
 * structure-aware mutation. Declared `static inline` so adapters that don't
 * use a given width don't trip -Wunused-function. */
static inline uint16_t nm_read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void nm_write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline uint16_t nm_read_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline void nm_write_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline uint64_t nm_read_be64(const uint8_t *p) {
    return ((uint64_t)nm_read_be32(p) << 32) | (uint64_t)nm_read_be32(p + 4);
}

static inline void nm_write_be64(uint8_t *p, uint64_t v) {
    nm_write_be32(p, (uint32_t)(v >> 32));
    nm_write_be32(p + 4, (uint32_t)v);
}

static inline uint64_t nm_read_le64(const uint8_t *p) {
    return (uint64_t)nm_read_le32(p) | ((uint64_t)nm_read_le32(p + 4) << 32);
}

static inline void nm_write_le64(uint8_t *p, uint64_t v) {
    nm_write_le32(p, (uint32_t)v);
    nm_write_le32(p + 4, (uint32_t)(v >> 32));
}

/* CRC32 (zlib polynomial 0xEDB88320). Table built lazily per state. */
static void nm_crc32_init(uint32_t *table) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : (c >> 1);
        }
        table[i] = c;
    }
}

static uint32_t nm_crc32(const uint32_t *table, const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) c = table[(c ^ buf[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---------- Generic mutation strategies ----------
 * Operate on the scratch buffer using parsed chunk descriptors.
 * Each returns the new size of the data in `out`, or 0 to signal
 * passthrough (let AFL use its own havoc). */

/* Flip 1..8 random bytes inside a random chunk's data field. */
static size_t nm_mut_byte_flip_in_chunk(uint8_t *out, size_t size,
                                        nm_chunk_t *chunks, int n,
                                        uint32_t *rng) {
    if (n <= 0) return 0;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    if (c->data_len == 0) return size;
    uint32_t flips = 1 + (nm_xorshift32(rng) % 8);
    for (uint32_t i = 0; i < flips; i++) {
        size_t pos = c->data_off + (nm_xorshift32(rng) % c->data_len);
        if (pos < size) out[pos] ^= (uint8_t)(nm_xorshift32(rng) & 0xFFu);
    }
    nm_adapter_fix_integrity(out, c);
    return size;
}

/* Duplicate a random chunk inline (header + data + integrity). The
 * duplicate is appended just before the last chunk. Useful for stressing
 * duplicate-chunk handling logic. */
static size_t nm_mut_duplicate_chunk(uint8_t *out, size_t size, size_t cap,
                                     const uint8_t *src, size_t src_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    if (n < 2) return size;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    size_t whole = (c->integrity_off ? c->integrity_off + c->integrity_len
                                     : c->data_off + c->data_len) - c->header_off;
    if (size + whole > cap) return size;

    /* Insert before the last chunk (assumed terminator like IEND). */
    size_t insert_at = chunks[n - 1].header_off;
    if (insert_at > size || insert_at + whole > cap) return size;

    memmove(out + insert_at + whole, out + insert_at, size - insert_at);
    memcpy(out + insert_at, src + c->header_off, whole);
    return size + whole;
}

/* ---------- AFL custom mutator entry points ---------- */

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    nm_state_t *st = (nm_state_t *)calloc(1, sizeof(nm_state_t));
    if (!st) return NULL;
    st->seed = seed ? seed : 0xC0FFEEu;
    st->buf_size = 1u * 1024u * 1024u;
    st->buf = (uint8_t *)malloc(st->buf_size);
    if (!st->buf) { free(st); return NULL; }
    nm_crc32_init(st->crc_table);
    st->crc_table_init = 1;
    return st;
}

void afl_custom_deinit(void *data) {
    nm_state_t *st = (nm_state_t *)data;
    if (st) { free(st->buf); free(st); }
}

size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf, size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size,
    size_t max_size
) {
    (void)add_buf;
    (void)add_buf_size;
    nm_state_t *st = (nm_state_t *)data;
    if (!st || !st->crc_table_init) { *out_buf = buf; return buf_size; }

    if (max_size > st->buf_size) {
        uint8_t *grow = (uint8_t *)realloc(st->buf, max_size);
        if (!grow) { *out_buf = buf; return buf_size; }
        st->buf = grow;
        st->buf_size = max_size;
    }

    /* No signature → can't apply structured mutations. Let AFL handle it. */
    if (!nm_adapter_has_signature(buf, buf_size)) { *out_buf = buf; return 0; }

    nm_chunk_t chunks[NM_MAX_CHUNKS];
    int n = nm_adapter_parse(buf, buf_size, chunks);
    if (n <= 0) { *out_buf = buf; return 0; }

    /* Copy whole input to scratch */
    size_t out_size = buf_size;
    if (out_size > st->buf_size) out_size = st->buf_size;
    memcpy(st->buf, buf, out_size);

    uint32_t rng = st->seed;
    uint32_t strategy = nm_xorshift32(&rng) % 4;

    switch (strategy) {
    case 0: {
        /* Format-specific targeted mutation (the "smart" path — adapter
         * picks high-value edges like IHDR width=0xFFFFFFFF). */
        int touched = nm_adapter_apply_targeted(st->buf, out_size,
                                                chunks, n, &rng);
        if (!touched) {
            /* Adapter declined → fall back to byte flip */
            out_size = nm_mut_byte_flip_in_chunk(st->buf, out_size,
                                                 chunks, n, &rng);
        }
        break;
    }
    case 1:
        out_size = nm_mut_byte_flip_in_chunk(st->buf, out_size,
                                             chunks, n, &rng);
        break;
    case 2:
        out_size = nm_mut_duplicate_chunk(st->buf, out_size, st->buf_size,
                                          buf, buf_size, chunks, n, &rng);
        break;
    default:
        /* Passthrough — let AFL's own havoc do this round. */
        st->seed = rng;
        *out_buf = buf;
        return 0;
    }

    st->seed = rng;
    *out_buf = st->buf;
    return out_size;
}

#endif /* NEMESIS_MUTATOR_SCAFFOLD_H */
