/**
 * NEMESIS protobuf (wire-format) mutator adapter.
 *
 * Implements the four hooks expected by mutator_scaffold.h for the protocol
 * buffers binary wire format — the encoding underneath gRPC payloads, and
 * anything using protobuf-c, upb, or nanopb.
 *
 * Why protobuf is worth a dedicated adapter: the wire format is a flat stream
 * of (varint key, value) pairs where the key packs a field number and a
 * 3-bit wire type. Every structural property is encoded in variable-length
 * integers, so a single flipped bit inside a varint shifts the interpretation
 * of every following byte — random havoc reliably produces "malformed, reject
 * at byte 3" rather than anything that reaches decoding logic. Editing keys
 * and length prefixes as the varints they are keeps the stream parseable
 * right up to the field being attacked.
 *
 * Highest-value edits, in order: a length-delimited field whose length exceeds
 * the remaining buffer (the classic protobuf OOB read), an overlong varint
 * (10 bytes of continuation, which overflows 64-bit accumulators), and an
 * undefined wire type (3 and 4 are the deprecated group markers; 6 and 7 have
 * never been assigned, so they hit the default branch of every decoder).
 *
 * Compile: clang -shared -fPIC -O2 -o protobuf_mutator.so protobuf.c
 * (the pipeline does this automatically when custom_mutator_source
 *  in the YAML target points at this file)
 */

#include "../mutator_scaffold.h"

/* Wire types (the low 3 bits of every field key). */
#define PB_WT_VARINT   0
#define PB_WT_64BIT    1
#define PB_WT_LEN      2   /* length-delimited: strings, bytes, submessages */
#define PB_WT_SGROUP   3   /* deprecated start-group */
#define PB_WT_EGROUP   4   /* deprecated end-group   */
#define PB_WT_32BIT    5
/* 6 and 7 are not assigned — every decoder must reject them. */

/* nm_chunk_t.kind carries the wire type so apply_targeted can pick a field
 * whose shape matches the mutation it wants to make. */

#define PB_MAX_VARINT_BYTES 10   /* ceil(64/7) — the widest legal varint */

/* Decode a varint at `off`. Returns the number of bytes consumed, or 0 if the
 * encoding runs past `size` or exceeds the 10-byte maximum. */
static size_t pb_read_varint(const uint8_t *buf, size_t size, size_t off,
                             uint64_t *out) {
    uint64_t val = 0;
    size_t i = 0;
    while (off + i < size && i < PB_MAX_VARINT_BYTES) {
        uint8_t b = buf[off + i];
        val |= (uint64_t)(b & 0x7Fu) << (7 * i);
        i++;
        if (!(b & 0x80u)) {
            *out = val;
            return i;
        }
    }
    return 0;   /* truncated, or more continuation bytes than can be legal */
}

/* Write `val` as a varint padded to exactly `width` bytes by setting
 * continuation bits on the redundant ones. Overlong-but-decodable encodings
 * are legal on the wire and are their own bug class, so being able to
 * generate them deliberately matters. */
static void pb_write_varint_padded(uint8_t *p, size_t width, uint64_t val) {
    for (size_t i = 0; i < width; i++) {
        uint8_t b = (uint8_t)(val & 0x7Fu);
        val >>= 7;
        p[i] = (i + 1 < width) ? (uint8_t)(b | 0x80u) : b;
    }
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out);

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    /* Protobuf has no magic bytes — self-description is the only signal.
     * Accept a buffer only if it parses cleanly as a field stream covering
     * essentially all of it. Being strict matters: claiming arbitrary binary
     * input would suppress AFL's own havoc on non-protobuf targets. */
    if (size < 2) return 0;
    nm_chunk_t probe[NM_MAX_CHUNKS];
    int n = nm_adapter_parse(buf, size, probe);
    if (n <= 0) return 0;
    size_t end = probe[n - 1].data_off + probe[n - 1].data_len;
    /* Allow a small tail: the parse stops at NM_MAX_CHUNKS on large messages. */
    return n >= NM_MAX_CHUNKS || end + 8 >= size;
}

/* Walk the top-level field stream. Submessages are not descended into: their
 * payload is addressable as a whole, which is what the length-prefix
 * mutations below need, and a submessage's own fields become reachable once
 * an outer mutation makes the decoder treat them as top level. */
static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off < size) {
        uint64_t key;
        size_t key_len = pb_read_varint(buf, size, off, &key);
        if (key_len == 0) return n;

        uint32_t wire_type = (uint32_t)(key & 0x7u);
        uint64_t field_num = key >> 3;
        if (field_num == 0) return n;    /* field 0 is illegal → not protobuf */

        size_t data_off = off + key_len;
        size_t data_len = 0;

        switch (wire_type) {
        case PB_WT_VARINT: {
            uint64_t v;
            size_t vlen = pb_read_varint(buf, size, data_off, &v);
            if (vlen == 0) return n;
            data_len = vlen;
            break;
        }
        case PB_WT_64BIT:
            if (data_off + 8 > size) return n;
            data_len = 8;
            break;
        case PB_WT_32BIT:
            if (data_off + 4 > size) return n;
            data_len = 4;
            break;
        case PB_WT_LEN: {
            uint64_t len;
            size_t llen = pb_read_varint(buf, size, data_off, &len);
            if (llen == 0) return n;
            /* The declared length is exactly what gets mutated, so the walk
             * clamps instead of trusting it. */
            data_off += llen;
            if (len > (uint64_t)(size - data_off)) return n;
            data_len = (size_t)len;
            break;
        }
        case PB_WT_SGROUP:
        case PB_WT_EGROUP:
            data_len = 0;   /* group markers carry no payload of their own */
            break;
        default:
            return n;       /* wire type 6/7 → not a valid stream */
        }

        out[n].header_off    = off;
        out[n].data_off      = data_off;
        out[n].data_len      = data_len;
        out[n].integrity_off = 0;   /* protobuf carries no checksum */
        out[n].integrity_len = 0;
        out[n].kind          = wire_type;
        out[n].flags         = (uint32_t)key_len;   /* varint width of the key */
        n++;

        size_t advance = (data_off - off) + data_len;
        if (advance == 0) return n;   /* group marker with no payload → stop */
        off = off + advance;
    }
    return n;
}

/* No-op: the wire format has no checksum. (gRPC frames one level up do, but
 * that is a different layer and a different adapter.) */
static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf;
    (void)chunk;
}

/* Lengths that decode fine and then break whatever is done with them. */
static const uint64_t PB_INTERESTING_LEN[] = {
    0u, 1u, 0x7Fu, 0x80u,               /* varint width boundaries      */
    0x3FFFu, 0x4000u,
    0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu,
    0xFFFFFFFFFFFFFFFFull,              /* 64-bit all-ones              */
    0x8000000000000000ull,              /* sign bit only                */
};
#define PB_LEN_N (sizeof(PB_INTERESTING_LEN)/sizeof(PB_INTERESTING_LEN[0]))

/* Field numbers at the edges of the reserved and maximum ranges. */
static const uint64_t PB_INTERESTING_FIELD[] = {
    1u, 15u, 16u,                       /* 1-byte vs 2-byte key boundary */
    18999u, 19000u, 19999u, 20000u,     /* reserved range 19000-19999    */
    536870911u,                         /* 2^29-1, the documented maximum */
    536870912u,                         /* one past it                    */
    0xFFFFFFFFull,
};
#define PB_FIELD_N (sizeof(PB_INTERESTING_FIELD)/sizeof(PB_INTERESTING_FIELD[0]))

/* Returns 1 if a targeted mutation was applied, 0 if the adapter declined. */
static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    if (n <= 0) return 0;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    size_t key_width = c->flags ? c->flags : 1;
    if (c->header_off + key_width > buf_size) return 0;

    uint32_t op = nm_xorshift32(rng) % 5;

    switch (op) {
    case 0: { /* Rewrite the length prefix of a length-delimited field to
               * claim far more data than the buffer holds — the canonical
               * protobuf out-of-bounds read. The new length is written into
               * the SAME number of bytes the original occupied, so the rest
               * of the stream stays where the decoder expects it. */
        if (c->kind != PB_WT_LEN) return 0;
        size_t len_off = c->header_off + key_width;
        size_t len_width = c->data_off - len_off;
        if (len_width == 0 || len_off + len_width > buf_size) return 0;
        pb_write_varint_padded(buf + len_off, len_width,
                               PB_INTERESTING_LEN[nm_xorshift32(rng) % PB_LEN_N]);
        break;
    }
    case 1: { /* Change the wire type in place, keeping the field number.
               * The decoder now reads the following bytes as a completely
               * different shape — and 6/7 are undefined, so they exercise
               * the rejection path every decoder is supposed to have. */
        uint64_t key;
        if (pb_read_varint(buf, buf_size, c->header_off, &key) == 0) return 0;
        static const uint8_t wts[] = {0, 1, 2, 3, 4, 5, 6, 7};
        uint64_t new_key = (key & ~(uint64_t)0x7u)
                         | wts[nm_xorshift32(rng) % sizeof(wts)];
        pb_write_varint_padded(buf + c->header_off, key_width, new_key);
        break;
    }
    case 2: { /* Change the field number to a reserved or out-of-range one,
               * written into the original key width so the stream stays
               * aligned. Only widths that can hold the value are used. */
        uint64_t key;
        if (pb_read_varint(buf, buf_size, c->header_off, &key) == 0) return 0;
        uint64_t field = PB_INTERESTING_FIELD[
            nm_xorshift32(rng) % PB_FIELD_N];
        uint64_t new_key = (field << 3) | (key & 0x7u);
        /* A varint of width w holds 7*w bits; skip values that would not fit
         * rather than silently truncating them into a different field. */
        if (key_width < PB_MAX_VARINT_BYTES
            && (new_key >> (7 * key_width)) != 0) {
            return 0;
        }
        pb_write_varint_padded(buf + c->header_off, key_width, new_key);
        break;
    }
    case 3: { /* Overlong varint: pad the key out to the full 10 bytes with
               * continuation bits. The value is unchanged and the encoding is
               * still decodable, but accumulators that shift by 7*i overflow
               * on the 10th byte. Needs room, hence the bounds check. */
        if (c->header_off + PB_MAX_VARINT_BYTES > buf_size) return 0;
        /* Only safe when the padding stays inside this field's own bytes —
         * otherwise it would overwrite the next field's key. */
        size_t avail = (c->data_off + c->data_len) - c->header_off;
        if (avail < PB_MAX_VARINT_BYTES) return 0;
        uint64_t key;
        if (pb_read_varint(buf, buf_size, c->header_off, &key) == 0) return 0;
        pb_write_varint_padded(buf + c->header_off, PB_MAX_VARINT_BYTES, key);
        break;
    }
    default: { /* Fill a length-delimited payload with 0x80 continuation
                * bytes. If the decoder treats it as a submessage, it now
                * contains a varint that never terminates. */
        if (c->kind != PB_WT_LEN || c->data_len == 0) return 0;
        size_t fill = c->data_len < 16 ? c->data_len : 16;
        if (c->data_off + fill > buf_size) return 0;
        memset(buf + c->data_off, 0x80, fill);
        break;
    }
    }
    return 1;
}
