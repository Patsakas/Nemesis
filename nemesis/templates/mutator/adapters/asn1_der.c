/**
 * NEMESIS ASN.1 / BER / DER mutator adapter.
 *
 * Implements the four hooks expected by mutator_scaffold.h for TLV-encoded
 * ASN.1 (X.509 certificates, PKCS structures, SNMP PDUs, LDAP messages,
 * Kerberos tickets — anything a crypto or directory library parses).
 *
 * Why ASN.1 is worth a dedicated adapter: the format is pure nested
 * tag-length-value, and the length field is a variable-width, self-describing
 * integer. That makes it the archetypal "length lies about the data" format —
 * a length longer than the remaining buffer, a long-form length with more
 * size bytes than fit in a size_t, an indefinite length inside DER where it is
 * forbidden. These are one-byte edits that random havoc will almost never
 * make coherently, because a corrupted tag byte usually ends parsing at the
 * outermost element before any of the nested structure is reached.
 *
 * The parse walks INTO constructed elements rather than skipping over them,
 * so deeply nested certificate fields are reachable as mutation targets, not
 * just the outer SEQUENCE.
 *
 * Compile: clang -shared -fPIC -O2 -o asn1_mutator.so asn1_der.c
 * (the pipeline does this automatically when custom_mutator_source
 *  in the YAML target points at this file)
 */

#include "../mutator_scaffold.h"

/* Element classes for nm_chunk_t.kind */
enum {
    ASN1_KIND_PRIMITIVE = 0,
    ASN1_KIND_CONSTRUCTED = 1,  /* has children; bit 0x20 of the tag */
};

/* nm_chunk_t.flags */
#define ASN1_FLAG_LONG_LEN    0x1u  /* length used the long form  */
#define ASN1_FLAG_INDEFINITE  0x2u  /* length was 0x80 (BER only) */

#define ASN1_TAG_CONSTRUCTED  0x20u
#define ASN1_TAG_HIGH_FORM    0x1Fu  /* low 5 bits set → multi-byte tag */

/* Universal tags worth swapping between: each selects a different decoder,
 * and a mismatched type is a classic confusion bug (an INTEGER decoded where
 * an OCTET STRING was expected, a BIT STRING with a bogus unused-bits byte). */
static const uint8_t ASN1_INTERESTING_TAG[] = {
    0x01, /* BOOLEAN      */
    0x02, /* INTEGER      */
    0x03, /* BIT STRING   — leading "unused bits" byte, off-by-one magnet */
    0x04, /* OCTET STRING */
    0x05, /* NULL         — must have length 0; anything else is a bug path */
    0x06, /* OBJECT IDENTIFIER — base-128 subidentifiers, own overflow class */
    0x0C, /* UTF8String   */
    0x13, /* PrintableString */
    0x17, /* UTCTime      */
    0x18, /* GeneralizedTime */
    0x30, /* SEQUENCE (constructed) */
    0x31, /* SET (constructed)      */
    0xA0, /* context-specific [0] constructed — X.509 explicit tagging */
    0x00, /* reserved / end-of-contents */
    0x1F, /* high-tag-number form   */
};
#define ASN1_TAG_N (sizeof(ASN1_INTERESTING_TAG))

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    /* ASN.1 has no magic. The universal marker is that the encoding is a
     * single well-formed TLV covering (essentially) the whole buffer, and in
     * practice the outermost element of every real-world DER structure is a
     * SEQUENCE or SET. Requiring that is a strong enough filter to avoid
     * claiming arbitrary binaries, which would starve AFL's own havoc. */
    if (size < 2) return 0;
    if (buf[0] != 0x30 && buf[0] != 0x31) return 0;

    size_t len_byte = buf[1];
    if (len_byte < 0x80) return len_byte + 2 <= size;
    if (len_byte == 0x80) return 1;              /* indefinite (BER) */
    size_t nbytes = len_byte & 0x7Fu;
    if (nbytes > 4 || 2 + nbytes > size) return 0;
    size_t len = 0;
    for (size_t i = 0; i < nbytes; i++) len = (len << 8) | buf[2 + i];
    return len + 2 + nbytes <= size;
}

/* Decode one TLV header at `off`.
 * Returns 0 on success and fills the out-params; non-zero if the header is
 * malformed or runs past `size`. */
static int asn1_decode_header(const uint8_t *buf, size_t size, size_t off,
                              size_t *data_off, size_t *data_len,
                              uint32_t *flags) {
    if (off + 2 > size) return -1;
    size_t p = off;
    *flags = 0;

    /* Tag: low 5 bits all set selects the multi-byte form, where subsequent
     * bytes carry 7 bits each and the top bit is a continuation flag. */
    uint8_t tag = buf[p++];
    if ((tag & ASN1_TAG_HIGH_FORM) == ASN1_TAG_HIGH_FORM) {
        size_t guard = 0;
        while (p < size && (buf[p] & 0x80u) && guard < 8) { p++; guard++; }
        if (p >= size) return -1;
        p++;   /* final tag byte (top bit clear) */
    }
    if (p >= size) return -1;

    uint8_t l = buf[p++];
    if (l == 0x80u) {
        /* Indefinite length: contents run until an end-of-contents pair.
         * Rather than scanning for it, treat the rest of the buffer as the
         * payload — the walk only needs a bound, and this is the safe one. */
        *flags |= ASN1_FLAG_INDEFINITE;
        *data_off = p;
        *data_len = size - p;
        return 0;
    }
    if (l < 0x80u) {
        *data_off = p;
        *data_len = l;
    } else {
        size_t nbytes = l & 0x7Fu;
        /* >8 length bytes cannot fit a size_t; real parsers differ on whether
         * they reject or silently truncate, which is exactly why we generate
         * such lengths — but the WALK must not trust them. */
        if (nbytes == 0 || nbytes > 8 || p + nbytes > size) return -1;
        *flags |= ASN1_FLAG_LONG_LEN;
        size_t len = 0;
        for (size_t i = 0; i < nbytes; i++) len = (len << 8) | buf[p + i];
        p += nbytes;
        *data_off = p;
        *data_len = len;
    }
    if (*data_off > size) return -1;
    if (*data_off + *data_len > size) *data_len = size - *data_off;
    return 0;
}

/* Depth-first walk that descends into constructed elements, so nested fields
 * (a serial number inside a TBSCertificate inside a Certificate) are
 * individually addressable rather than hidden inside one outer chunk. */
static int asn1_walk(const uint8_t *buf, size_t size, size_t off, size_t end,
                     nm_chunk_t *out, int n, int depth) {
    while (n < NM_MAX_CHUNKS && off + 2 <= end) {
        size_t data_off, data_len;
        uint32_t flags;
        if (asn1_decode_header(buf, size, off, &data_off, &data_len, &flags) != 0) {
            return n;
        }
        uint8_t tag = buf[off];
        int constructed = (tag & ASN1_TAG_CONSTRUCTED) != 0;

        out[n].header_off    = off;
        out[n].data_off      = data_off;
        out[n].data_len      = data_len;
        out[n].integrity_off = 0;   /* ASN.1 carries no checksum */
        out[n].integrity_len = 0;
        out[n].kind          = constructed ? ASN1_KIND_CONSTRUCTED
                                           : ASN1_KIND_PRIMITIVE;
        out[n].flags         = flags;
        n++;

        /* Bound the recursion: a hostile input can nest as deeply as it likes,
         * and this walk runs on every single mutation. */
        if (constructed && depth < 6 && data_len > 0) {
            n = asn1_walk(buf, size, data_off, data_off + data_len,
                          out, n, depth + 1);
        }

        size_t advance = (data_off - off) + data_len;
        if (advance == 0) return n;         /* no progress → stop */
        off += advance;
    }
    return n;
}

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    return asn1_walk(buf, size, 0, size, out, 0, 0);
}

/* No-op: ASN.1 has no checksum anywhere in the encoding. (X.509 signatures
 * are over the DER bytes, but a fuzzer WANTS those broken — signature
 * verification happens after parsing, which is the code under test.) */
static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf;
    (void)chunk;
}

/* Returns 1 if a targeted mutation was applied, 0 if the adapter declined. */
static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    if (n <= 0) return 0;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    if (c->header_off + 2 > buf_size) return 0;

    /* Where the length field starts: right after the tag, accounting for the
     * multi-byte tag form. */
    size_t len_off = c->header_off + 1;
    if ((buf[c->header_off] & ASN1_TAG_HIGH_FORM) == ASN1_TAG_HIGH_FORM) {
        size_t p = len_off, guard = 0;
        while (p < buf_size && (buf[p] & 0x80u) && guard < 8) { p++; guard++; }
        len_off = p + 1;
    }
    if (len_off >= buf_size) return 0;

    uint32_t op = nm_xorshift32(rng) % 6;

    switch (op) {
    case 0: { /* short-form length: claim more content than exists */
        buf[len_off] = (uint8_t)(nm_xorshift32(rng) % 0x80u);
        break;
    }
    case 1: { /* long form declaring a huge 4-byte length. Parsers that add
               * this to an offset before range-checking it wrap here. */
        if (len_off + 5 > buf_size) return 0;
        buf[len_off] = 0x84u;                    /* 4 length bytes follow */
        static const uint32_t big[] = {
            0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFF0u, 0x00000000u,
        };
        nm_write_be32(buf + len_off + 1, big[nm_xorshift32(rng) % 5]);
        break;
    }
    case 2: { /* long form with an absurd byte count — 0x88 means 8 length
               * bytes (a full 64-bit length), 0xFF means 127 of them, which
               * cannot fit any integer type and forces the error path */
        buf[len_off] = (nm_xorshift32(rng) & 1u) ? 0x88u : 0xFFu;
        break;
    }
    case 3: { /* indefinite length — legal in BER, forbidden in DER. Decoders
               * that accept it here often lose track of nesting depth. */
        buf[len_off] = 0x80u;
        break;
    }
    case 4: { /* swap the tag: same bytes, different decoder. A BIT STRING
               * whose first content byte is now an unused-bits count > 7, or
               * a NULL with a non-zero length, are both immediate error
               * paths that plenty of parsers get wrong. */
        buf[c->header_off] = ASN1_INTERESTING_TAG[
            nm_xorshift32(rng) % ASN1_TAG_N];
        break;
    }
    default: { /* flip the constructed bit: a primitive suddenly claims to
                * contain children (so the parser recurses into arbitrary
                * bytes), or a SEQUENCE claims to be a leaf. */
        buf[c->header_off] ^= ASN1_TAG_CONSTRUCTED;
        break;
    }
    }
    return 1;
}
