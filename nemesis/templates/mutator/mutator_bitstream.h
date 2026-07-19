/**
 * NEMESIS bit-cursor helper for bit-packed format mutators (Tier 2 #4).
 *
 * Why this exists
 * ---------------
 * Some target formats (libwebp/VP8L Huffman, deflate, JPEG arithmetic
 * coding, FLAC, ...) carry their structurally meaningful decisions in
 * sub-byte fields. A byte-level mutator views the input as
 * `<header><payload bytes>` and flips bytes uniformly — but for these
 * formats the meaningful bits cross byte boundaries, so byte flips
 * either land on padding (no effect) or corrupt the bitstream so the
 * parser bails before the bug.
 *
 * This header gives the adapter a tiny LSB-first bit cursor so it can
 * read / mutate at the right granularity. Big-endian bit packings (e.g.
 * raw deflate's "stored" block headers) need their own cursor — left
 * here as a copy-paste extension when needed.
 *
 * Integration
 * -----------
 * #include this from a mutator adapter alongside `mutator_scaffold.h`.
 * Pass `nm_bs_init(&bs, buf, size)` once, then read or write at byte+bit
 * positions of your choosing. The cursor is byref so adapters can keep
 * positional state across multiple read/write calls.
 *
 * The semantics target the most common bit-packing convention used by
 * lossless image and audio formats:
 *   - bytes are filled LSB first
 *   - within a byte, the lowest-numbered bit is the LEAST significant
 *   - multi-byte values are little-endian-bit-packed
 * Most VP8L / deflate / FLAC bitstreams follow this convention.
 */

#ifndef NEMESIS_MUTATOR_BITSTREAM_H
#define NEMESIS_MUTATOR_BITSTREAM_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf;          /* underlying byte buffer (read or write) */
    size_t   size;          /* buffer length in bytes */
    size_t   bit_pos;       /* current cursor in BITS from buf[0] LSB */
} nm_bitstream_t;

static inline void nm_bs_init(nm_bitstream_t *bs, uint8_t *buf, size_t size) {
    bs->buf = buf;
    bs->size = size;
    bs->bit_pos = 0;
}

static inline void nm_bs_seek_bits(nm_bitstream_t *bs, size_t bit_offset) {
    bs->bit_pos = bit_offset;
}

static inline void nm_bs_seek_bytes(nm_bitstream_t *bs, size_t byte_offset) {
    bs->bit_pos = byte_offset * 8u;
}

static inline size_t nm_bs_tell_bits(const nm_bitstream_t *bs) {
    return bs->bit_pos;
}

static inline int nm_bs_eof(const nm_bitstream_t *bs, unsigned n) {
    return (bs->bit_pos + n) > (bs->size * 8u);
}

/* Peek up to 32 bits LSB-first without advancing the cursor.
 * Returns 0 if the read would run past the end of the buffer. */
static inline uint32_t nm_bs_peek_bits(const nm_bitstream_t *bs, unsigned n) {
    if (n == 0 || n > 32 || nm_bs_eof(bs, n)) return 0;
    uint32_t v = 0;
    size_t bp = bs->bit_pos;
    for (unsigned i = 0; i < n; ++i, ++bp) {
        const uint8_t byte = bs->buf[bp >> 3];
        const unsigned bit = (byte >> (bp & 7u)) & 1u;
        v |= (uint32_t)bit << i;
    }
    return v;
}

static inline uint32_t nm_bs_read_bits(nm_bitstream_t *bs, unsigned n) {
    const uint32_t v = nm_bs_peek_bits(bs, n);
    bs->bit_pos += n;
    return v;
}

/* Write `n` LSB-first bits of `value` at the cursor and advance.
 * Silently truncates if the cursor would run past the buffer. */
static inline void nm_bs_write_bits(nm_bitstream_t *bs, unsigned n, uint32_t value) {
    if (n == 0 || n > 32) return;
    size_t bp = bs->bit_pos;
    for (unsigned i = 0; i < n; ++i, ++bp) {
        if ((bp >> 3) >= bs->size) break;
        const unsigned bit = (value >> i) & 1u;
        const unsigned mask = 1u << (bp & 7u);
        if (bit)
            bs->buf[bp >> 3] |= (uint8_t)mask;
        else
            bs->buf[bp >> 3] &= (uint8_t)~mask;
    }
    bs->bit_pos += n;
}

/* Round the cursor UP to the next byte boundary. */
static inline void nm_bs_align_byte(nm_bitstream_t *bs) {
    if (bs->bit_pos & 7u)
        bs->bit_pos = (bs->bit_pos + 7u) & ~(size_t)7u;
}

/* Convenience: flip a single bit at the absolute bit offset. */
static inline void nm_bs_flip_bit_at(uint8_t *buf, size_t buf_size, size_t bit_off) {
    if ((bit_off >> 3) >= buf_size) return;
    buf[bit_off >> 3] ^= (uint8_t)(1u << (bit_off & 7u));
}

#endif /* NEMESIS_MUTATOR_BITSTREAM_H */
