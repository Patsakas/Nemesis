/**
 * NEMESIS ZIP mutator adapter.
 *
 * Implements the four hooks expected by mutator_scaffold.h for the ZIP
 * container (little-endian records, PK signatures, redundant size/offset
 * bookkeeping in two places).
 *
 * Why ZIP is worth a dedicated adapter: the format stores every file's size
 * and offset TWICE — once in the local header and once in the central
 * directory — and readers disagree about which one wins. Nearly every serious
 * ZIP vulnerability comes from a mismatch between the two, or from a size
 * field that overflows when added to an offset. Random havoc destroys the
 * "PK\x03\x04" signatures long before it can produce an interesting
 * disagreement; this adapter edits the numeric fields while leaving the
 * record framing intact.
 *
 * Note on CRCs: unlike PNG, this adapter deliberately does NOT repair the
 * stored CRC32. It is computed over the *uncompressed* data, so recomputing
 * it would mean running the decompressor — and a wrong CRC is itself a target,
 * since it decides whether a reader takes the error path after having already
 * parsed and acted on the headers.
 *
 * Compile: clang -shared -fPIC -O2 -o zip_mutator.so zip.c
 * (the pipeline does this automatically when custom_mutator_source
 *  in the YAML target points at this file)
 */

#include "../mutator_scaffold.h"

/* ZIP record tags for nm_chunk_t.kind */
enum {
    ZIP_KIND_UNKNOWN = 0,
    ZIP_KIND_LOCAL = 1,    /* PK\3\4 — local file header      */
    ZIP_KIND_CENTRAL = 2,  /* PK\1\2 — central directory entry */
    ZIP_KIND_EOCD = 3,     /* PK\5\6 — end of central directory */
    ZIP_KIND_DESC = 4,     /* PK\7\8 — data descriptor          */
};

/* Local file header layout (offsets from the signature). */
#define ZIP_LOC_FLAGS      6
#define ZIP_LOC_METHOD     8
#define ZIP_LOC_CRC        14
#define ZIP_LOC_COMPSZ     18
#define ZIP_LOC_UNCOMPSZ   22
#define ZIP_LOC_NAMELEN    26
#define ZIP_LOC_EXTRALEN   28
#define ZIP_LOC_HDRLEN     30

/* Central directory entry layout (offsets from the signature). */
#define ZIP_CEN_METHOD     10
#define ZIP_CEN_CRC        16
#define ZIP_CEN_COMPSZ     20
#define ZIP_CEN_UNCOMPSZ   24
#define ZIP_CEN_NAMELEN    28
#define ZIP_CEN_EXTRALEN   30
#define ZIP_CEN_COMMENTLEN 32
#define ZIP_CEN_LOCALOFF   42
#define ZIP_CEN_HDRLEN     46

/* End of central directory layout (offsets from the signature). */
#define ZIP_EOCD_ENTRIES   10
#define ZIP_EOCD_TOTAL     12
#define ZIP_EOCD_CDSIZE    14
#define ZIP_EOCD_CDOFF     16
#define ZIP_EOCD_COMMENTLEN 20
#define ZIP_EOCD_HDRLEN    22

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    /* A normal archive starts with a local header; an empty one is just an
     * EOCD record. Both are worth mutating. */
    if (size < 4) return 0;
    return memcmp(buf, "PK\x03\x04", 4) == 0 || memcmp(buf, "PK\x05\x06", 4) == 0;
}

static uint32_t zip_kind_for_sig(const uint8_t *p) {
    if (memcmp(p, "PK\x03\x04", 4) == 0) return ZIP_KIND_LOCAL;
    if (memcmp(p, "PK\x01\x02", 4) == 0) return ZIP_KIND_CENTRAL;
    if (memcmp(p, "PK\x05\x06", 4) == 0) return ZIP_KIND_EOCD;
    if (memcmp(p, "PK\x07\x08", 4) == 0) return ZIP_KIND_DESC;
    return ZIP_KIND_UNKNOWN;
}

/* Walk PK records. Records are self-describing but their declared sizes are
 * exactly what we mutate, so the walk clamps every advance to the buffer and
 * stops on anything inconsistent rather than trusting the fields. */
static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off + 4 <= size) {
        uint32_t kind = zip_kind_for_sig(buf + off);
        size_t hdr_len, data_len = 0;

        switch (kind) {
        case ZIP_KIND_LOCAL: {
            if (off + ZIP_LOC_HDRLEN > size) return n;
            size_t namelen  = nm_read_le16(buf + off + ZIP_LOC_NAMELEN);
            size_t extralen = nm_read_le16(buf + off + ZIP_LOC_EXTRALEN);
            size_t compsz   = nm_read_le32(buf + off + ZIP_LOC_COMPSZ);
            hdr_len = ZIP_LOC_HDRLEN + namelen + extralen;
            data_len = compsz;
            break;
        }
        case ZIP_KIND_CENTRAL: {
            if (off + ZIP_CEN_HDRLEN > size) return n;
            hdr_len = ZIP_CEN_HDRLEN
                    + nm_read_le16(buf + off + ZIP_CEN_NAMELEN)
                    + nm_read_le16(buf + off + ZIP_CEN_EXTRALEN)
                    + nm_read_le16(buf + off + ZIP_CEN_COMMENTLEN);
            break;
        }
        case ZIP_KIND_EOCD: {
            if (off + ZIP_EOCD_HDRLEN > size) return n;
            hdr_len = ZIP_EOCD_HDRLEN
                    + nm_read_le16(buf + off + ZIP_EOCD_COMMENTLEN);
            break;
        }
        case ZIP_KIND_DESC:
            hdr_len = 16;
            break;
        default:
            /* Unknown signature — the record chain has ended (or the previous
             * record's declared size was a lie). Stop rather than scanning. */
            return n;
        }

        /* Clamp: a mutated length field must not push the walk out of bounds. */
        if (off + hdr_len > size) hdr_len = size - off;
        if (off + hdr_len + data_len > size) data_len = size - off - hdr_len;

        out[n].header_off    = off;
        out[n].data_off      = off + hdr_len;
        out[n].data_len      = data_len;
        /* CRC is over uncompressed data — not recomputable here, see below. */
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind          = kind;
        out[n].flags         = 0;
        n++;

        if (kind == ZIP_KIND_EOCD) break;   /* EOCD is the last record */
        off += hdr_len + data_len;
    }
    return n;
}

/* No-op by design. The stored CRC32 covers the *uncompressed* payload, so
 * repairing it would require running the decompressor — and leaving it wrong
 * is itself a useful state, since it decides whether the reader takes its
 * error path after having already parsed the headers. */
static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    (void)buf;
    (void)chunk;
}

/* 32-bit values that survive being read as a size and then break the
 * arithmetic done on it: wrap points, the ZIP64 sentinel, and neighbours. */
static const uint32_t ZIP_INTERESTING_U32[] = {
    0u, 1u, 0xFFFFu, 0x10000u,
    0x7FFFFFFFu, 0x80000000u, 0x80000001u,
    0xFFFFFFFEu,
    0xFFFFFFFFu,   /* ZIP64 sentinel — "real size is in the extra field" */
};
#define ZIP_U32_N (sizeof(ZIP_INTERESTING_U32)/sizeof(ZIP_INTERESTING_U32[0]))

static const uint16_t ZIP_INTERESTING_U16[] = {
    0u, 1u, 0x7FFFu, 0x8000u, 0xFFFEu, 0xFFFFu,
};
#define ZIP_U16_N (sizeof(ZIP_INTERESTING_U16)/sizeof(ZIP_INTERESTING_U16[0]))

/* Compression methods: the two universally supported ones, the modern
 * optional ones, and values no reader implements (default-branch coverage). */
static const uint16_t ZIP_INTERESTING_METHOD[] = {
    0,      /* stored     */
    8,      /* deflate    */
    9,      /* deflate64  */
    12, 14, /* bzip2, lzma */
    93, 95, 98, /* zstd, xz, ppmd */
    1, 6, 99, 0xFFFF,  /* shrink, implode, "AES", undefined */
};
#define ZIP_METHOD_N (sizeof(ZIP_INTERESTING_METHOD)/sizeof(ZIP_INTERESTING_METHOD[0]))

/* Returns 1 if a targeted mutation was applied, 0 if the adapter declined. */
static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    if (n <= 0) return 0;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    uint8_t *h = buf + c->header_off;
    uint32_t pick = nm_xorshift32(rng);

    switch (c->kind) {
    case ZIP_KIND_LOCAL: {
        if (c->header_off + ZIP_LOC_HDRLEN > buf_size) return 0;
        switch (pick % 5) {
        case 0: /* compressed size — drives how much the reader consumes */
            nm_write_le32(h + ZIP_LOC_COMPSZ,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            break;
        case 1: /* uncompressed size — drives the output allocation */
            nm_write_le32(h + ZIP_LOC_UNCOMPSZ,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            break;
        case 2: /* name/extra lengths — decide where the payload starts, so a
                 * lie here shifts every subsequent record */
            nm_write_le16(h + ZIP_LOC_NAMELEN,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            nm_write_le16(h + ZIP_LOC_EXTRALEN,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            break;
        case 3: /* method — selects an entire decompressor */
            nm_write_le16(h + ZIP_LOC_METHOD,
                          ZIP_INTERESTING_METHOD[nm_xorshift32(rng) % ZIP_METHOD_N]);
            break;
        default: /* flag bit 3 moves the sizes to a trailing data descriptor,
                  * so the header sizes become zero and the reader has to
                  * scan forward — a completely different code path */
            nm_write_le16(h + ZIP_LOC_FLAGS,
                          (uint16_t)(nm_read_le16(h + ZIP_LOC_FLAGS) ^ 0x0008u));
            break;
        }
        break;
    }
    case ZIP_KIND_CENTRAL: {
        if (c->header_off + ZIP_CEN_HDRLEN > buf_size) return 0;
        switch (pick % 4) {
        case 0: /* local-header offset — a pointer the reader follows blindly */
            nm_write_le32(h + ZIP_CEN_LOCALOFF,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            break;
        case 1: /* sizes that now disagree with the local header — the single
                 * richest source of real ZIP vulnerabilities */
            nm_write_le32(h + ZIP_CEN_COMPSZ,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            nm_write_le32(h + ZIP_CEN_UNCOMPSZ,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            break;
        case 2:
            nm_write_le16(h + ZIP_CEN_NAMELEN,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            nm_write_le16(h + ZIP_CEN_EXTRALEN,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            break;
        default:
            nm_write_le16(h + ZIP_CEN_METHOD,
                          ZIP_INTERESTING_METHOD[nm_xorshift32(rng) % ZIP_METHOD_N]);
            break;
        }
        break;
    }
    case ZIP_KIND_EOCD: {
        if (c->header_off + ZIP_EOCD_HDRLEN > buf_size) return 0;
        switch (pick % 3) {
        case 0: /* entry counts — usually used to size an allocation before
                 * the entries themselves are read */
            nm_write_le16(h + ZIP_EOCD_ENTRIES,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            nm_write_le16(h + ZIP_EOCD_TOTAL,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            break;
        case 1: /* central-directory offset + size: where the reader seeks */
            nm_write_le32(h + ZIP_EOCD_CDOFF,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            nm_write_le32(h + ZIP_EOCD_CDSIZE,
                          ZIP_INTERESTING_U32[nm_xorshift32(rng) % ZIP_U32_N]);
            break;
        default: /* comment length beyond the record end */
            nm_write_le16(h + ZIP_EOCD_COMMENTLEN,
                          ZIP_INTERESTING_U16[nm_xorshift32(rng) % ZIP_U16_N]);
            break;
        }
        break;
    }
    default:
        return 0;   /* data descriptor / unknown — nothing worth targeting */
    }
    return 1;
}
