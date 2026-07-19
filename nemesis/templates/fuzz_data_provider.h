#ifndef FUZZ_DATA_PROVIDER_H
#define FUZZ_DATA_PROVIDER_H

/*
 * FuzzedDataProvider — splits a fuzz buffer into typed slices.
 *
 * Each fdp_consume_* call advances an internal cursor forward.
 * Defensively returns 0/NULL when the buffer is exhausted.
 *
 * WHY: Using typed slices gives AFL++ CMPLOG (RedQueen) independent
 * control over each parameter. Without FDP, the fuzzer must guess
 * the full serialization format; with FDP each byte range maps to
 * exactly one parameter → faster convergence on magic values.
 *
 * USAGE PATTERN:
 *   FuzzDataProvider fdp;
 *   fdp_init(&fdp, buf, (size_t)len);
 *
 *   uint32_t flags   = fdp_consume_u32(&fdp);   // 4 bytes → flags
 *   uint8_t  mode    = fdp_consume_u8(&fdp);    // 1 byte  → mode
 *   size_t   rem     = fdp_remaining(&fdp);     // rest    → format data
 *   const uint8_t *payload = fdp_consume_bytes(&fdp, rem);
 *
 * RULE: Use fdp for TYPED PARAMETERS (flags, sizes, enum values).
 *       Pass the REMAINDER as raw format data to the library parser.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} FuzzDataProvider;

static inline void fdp_init(FuzzDataProvider *fdp,
                             const uint8_t *data, size_t size)
{
    fdp->data = data;
    fdp->size = size;
    fdp->pos  = 0;
}

static inline uint8_t fdp_consume_u8(FuzzDataProvider *fdp)
{
    if (fdp->pos >= fdp->size) return 0;
    return fdp->data[fdp->pos++];
}

static inline uint16_t fdp_consume_u16(FuzzDataProvider *fdp)
{
    uint16_t v = 0;
    if (fdp->pos + 2 <= fdp->size) {
        memcpy(&v, fdp->data + fdp->pos, 2);
        fdp->pos += 2;
    }
    return v;
}

static inline uint32_t fdp_consume_u32(FuzzDataProvider *fdp)
{
    uint32_t v = 0;
    if (fdp->pos + 4 <= fdp->size) {
        memcpy(&v, fdp->data + fdp->pos, 4);
        fdp->pos += 4;
    }
    return v;
}

static inline uint64_t fdp_consume_u64(FuzzDataProvider *fdp)
{
    uint64_t v = 0;
    if (fdp->pos + 8 <= fdp->size) {
        memcpy(&v, fdp->data + fdp->pos, 8);
        fdp->pos += 8;
    }
    return v;
}

/* Returns non-zero (true) or zero (false) from the low bit. */
static inline int fdp_consume_bool(FuzzDataProvider *fdp)
{
    return (int)(fdp_consume_u8(fdp) & 1u);
}

/*
 * Returns a pointer directly into the original fuzz buffer (zero-copy).
 * The pointer is only valid while the original AFL buffer is in scope.
 * Returns NULL when n == 0 or not enough bytes remain.
 */
static inline const uint8_t *fdp_consume_bytes(FuzzDataProvider *fdp, size_t n)
{
    if (n == 0 || fdp->pos + n > fdp->size) return NULL;
    const uint8_t *p = fdp->data + fdp->pos;
    fdp->pos += n;
    return p;
}

/* How many bytes are left in the buffer. */
static inline size_t fdp_remaining(const FuzzDataProvider *fdp)
{
    return (fdp->pos < fdp->size) ? (fdp->size - fdp->pos) : 0u;
}

#endif /* FUZZ_DATA_PROVIDER_H */
