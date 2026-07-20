/**
 * NEMESIS tar/ustar mutator adapter.
 *
 * Implements the four hooks expected by mutator_scaffold.h for POSIX tar
 * (fixed 512-byte headers, octal-ASCII numeric fields, additive checksum).
 *
 * Why tar is worth a dedicated adapter: every numeric field is *ASCII octal*,
 * so AFL's byte-level havoc almost never produces a field that still parses
 * as a number — it just corrupts the header into "not a tar entry" and the
 * parser bails at the first check. The interesting bugs live past that check,
 * in the arithmetic on a field that parsed fine but holds an absurd value
 * (size = 0777777777777, a base-256 length with the high bit set, a pax
 * attribute whose declared length exceeds the record). Mutating those fields
 * *as octal numbers* and repairing the checksum is what gets the fuzzer there.
 *
 * The pax extended-header path (typeflag 'x'/'g') is weighted deliberately:
 * libarchive's pax attribute parsing is where NEMESIS already aims harnesses
 * (config/targets/libarchive/harnesses/pax_attribute*.c).
 *
 * Compile: clang -shared -fPIC -O2 -o tar_mutator.so tar.c
 * (the pipeline does this automatically when custom_mutator_source
 *  in the YAML target points at this file)
 */

#include "../mutator_scaffold.h"

/* tar entry-type tags for nm_chunk_t.kind */
enum {
    TAR_KIND_FILE = 0,      /* regular file / anything unremarkable */
    TAR_KIND_PAX_EXT = 1,   /* 'x' — pax extended header, per-file  */
    TAR_KIND_PAX_GLOBAL = 2,/* 'g' — pax extended header, global    */
    TAR_KIND_GNU_LONG = 3,  /* 'L'/'K' — GNU long name / long link  */
    TAR_KIND_DIR = 4,       /* '5' — directory                      */
};

#define TAR_BLOCK 512

/* Field offsets inside a 512-byte ustar header. */
#define TAR_OFF_NAME      0    /* 100 bytes */
#define TAR_OFF_MODE      100  /*   8 bytes, octal */
#define TAR_OFF_UID       108  /*   8 bytes, octal */
#define TAR_OFF_GID       116  /*   8 bytes, octal */
#define TAR_OFF_SIZE      124  /*  12 bytes, octal (or base-256) */
#define TAR_OFF_MTIME     136  /*  12 bytes, octal */
#define TAR_OFF_CHKSUM    148  /*   8 bytes, octal */
#define TAR_OFF_TYPEFLAG  156  /*   1 byte  */
#define TAR_OFF_LINKNAME  157  /* 100 bytes */
#define TAR_OFF_MAGIC     257  /*   6 bytes, "ustar\0" or "ustar " */
#define TAR_OFF_PREFIX    345  /* 155 bytes */

#define TAR_LEN_SIZE      12
#define TAR_LEN_CHKSUM    8

static int nm_adapter_has_signature(const uint8_t *buf, size_t size) {
    /* "ustar" at 257 covers both POSIX ("ustar\0" + "00") and GNU
     * ("ustar  \0") variants; old V7 tar has no magic at all and is
     * therefore left to AFL's own havoc. */
    return size >= TAR_BLOCK && memcmp(buf + TAR_OFF_MAGIC, "ustar", 5) == 0;
}

/* Read a tar octal field. Fields are space/NUL padded and may be terminated
 * early, so parsing stops at the first non-octal byte rather than assuming a
 * well-formed field — a corrupted header must still yield *some* length so
 * the walk can continue to the next entry. */
static size_t tar_read_octal(const uint8_t *p, size_t len) {
    size_t val = 0;
    size_t i = 0;
    while (i < len && (p[i] == ' ' || p[i] == '0')) {
        if (p[i] == '0') break;   /* leading zeros are significant digits */
        i++;
    }
    for (; i < len; i++) {
        if (p[i] < '0' || p[i] > '7') break;
        val = (val << 3) | (size_t)(p[i] - '0');
        if (val > (size_t)1 << 40) return (size_t)1 << 40;  /* overflow guard */
    }
    return val;
}

/* Write a value as a NUL-terminated octal field, zero-padded, the way tar
 * writers do. Values too large for the field wrap rather than truncating the
 * field width, because a short field is a *structural* corruption the parser
 * rejects early, while a wrapped one still parses and reaches the arithmetic. */
static void tar_write_octal(uint8_t *p, size_t len, size_t val) {
    if (len == 0) return;
    for (size_t i = 0; i + 1 < len; i++) {
        p[len - 2 - i] = (uint8_t)('0' + (val & 7u));
        val >>= 3;
    }
    p[len - 1] = '\0';
}

static uint32_t tar_kind_for_typeflag(uint8_t t) {
    switch (t) {
    case 'x': return TAR_KIND_PAX_EXT;
    case 'g': return TAR_KIND_PAX_GLOBAL;
    case 'L': case 'K': return TAR_KIND_GNU_LONG;
    case '5': return TAR_KIND_DIR;
    default:  return TAR_KIND_FILE;
    }
}

/* Walk tar entries: 512-byte header, then ceil(size/512) data blocks. */
static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out) {
    int n = 0;
    size_t off = 0;
    while (n < NM_MAX_CHUNKS && off + TAR_BLOCK <= size) {
        /* Two consecutive zero blocks terminate the archive; one is enough
         * for us to stop walking. Detect via an all-zero name+magic. */
        if (buf[off] == 0 && memcmp(buf + off + TAR_OFF_MAGIC, "ustar", 5) != 0) {
            break;
        }

        size_t data_len = tar_read_octal(buf + off + TAR_OFF_SIZE, TAR_LEN_SIZE);
        /* A base-256 size (high bit set) is not octal; treat the payload as
         * empty for walking purposes rather than trusting a huge decoded
         * value that would run the walk off the end of the buffer. */
        if (buf[off + TAR_OFF_SIZE] & 0x80u) data_len = 0;
        size_t padded = (data_len + TAR_BLOCK - 1) & ~((size_t)TAR_BLOCK - 1);
        if (off + TAR_BLOCK + padded > size) padded = size - off - TAR_BLOCK;

        out[n].header_off    = off;
        out[n].data_off      = off + TAR_BLOCK;
        out[n].data_len      = padded;
        /* The checksum covers the header, not the payload, so it is not an
         * "integrity field over data_off..data_len" in the scaffold's sense.
         * Left zero; nm_adapter_fix_integrity recomputes from header_off. */
        out[n].integrity_off = 0;
        out[n].integrity_len = 0;
        out[n].kind          = tar_kind_for_typeflag(buf[off + TAR_OFF_TYPEFLAG]);
        out[n].flags         = 0;
        n++;

        off += TAR_BLOCK + padded;
    }
    return n;
}

/* tar checksum: unsigned sum of all 512 header bytes, with the checksum field
 * itself read as 8 spaces. Written as 6 octal digits + NUL + space, which is
 * the historical layout every tar reader accepts. */
static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk) {
    uint8_t *h = buf + chunk->header_off;
    unsigned int sum = 0;
    for (size_t i = 0; i < TAR_BLOCK; i++) {
        if (i >= TAR_OFF_CHKSUM && i < TAR_OFF_CHKSUM + TAR_LEN_CHKSUM) {
            sum += ' ';
        } else {
            sum += h[i];
        }
    }
    tar_write_octal(h + TAR_OFF_CHKSUM, 7, sum & 0777777u);
    h[TAR_OFF_CHKSUM + 6] = '\0';
    h[TAR_OFF_CHKSUM + 7] = ' ';
}

/* Sizes chosen to survive octal parsing and then break the arithmetic that
 * follows it: field-width maxima, 32-bit and 64-bit wrap points, and the
 * off-by-one neighbours of each. */
static const size_t TAR_INTERESTING_SIZE[] = {
    0u, 1u, 511u, 512u, 513u,
    0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu,        /* 32-bit edges */
    077777777777u,                                 /* 11-digit octal max */
    0x7FFFFFFFFFu,
};
#define TAR_SIZE_N (sizeof(TAR_INTERESTING_SIZE)/sizeof(TAR_INTERESTING_SIZE[0]))

/* Type flags: the standard set plus the vendor extensions that select
 * entirely different parsing code paths (pax attributes, GNU long names)
 * and the undefined ones that exercise the default branch. */
static const uint8_t TAR_INTERESTING_TYPEFLAG[] = {
    'x', 'g',                 /* pax extended headers — richest parser  */
    'L', 'K',                 /* GNU long name / long link              */
    '0', '\0', '5', '1', '2', /* file, old-style file, dir, links       */
    'S', 'M', 'V',            /* GNU sparse, multivolume, volume label  */
    '7', 'Z', 0xFF,           /* reserved / undefined                   */
};
#define TAR_TYPEFLAG_N (sizeof(TAR_INTERESTING_TYPEFLAG))

/* pax attribute records are "LEN KEY=VALUE\n" where LEN counts the whole
 * record including its own digits — a self-referential length that parsers
 * get wrong in interesting ways. */
static const char *TAR_PAX_RECORDS[] = {
    "1 =\n",                                  /* length far too small        */
    "99999999 size=1\n",                      /* length far beyond record    */
    "0 size=8589934592\n",                    /* zero length, huge value     */
    "30 path=../../../../etc/passwd\n",       /* traversal via pax path      */
    "18 size=-1\n",                           /* negative size               */
    "25 linkpath=\n",                         /* empty value                 */
    "20 GNU.sparse.size=\n",                  /* sparse map, empty           */
};
#define TAR_PAX_N (sizeof(TAR_PAX_RECORDS)/sizeof(TAR_PAX_RECORDS[0]))

/* Returns 1 if a targeted mutation was applied, 0 if the adapter declined
 * (caller falls back to a generic strategy). */
static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                     nm_chunk_t *chunks, int n,
                                     uint32_t *rng) {
    if (n <= 0) return 0;
    int idx = (int)(nm_xorshift32(rng) % (uint32_t)n);
    nm_chunk_t *c = &chunks[idx];
    if (c->header_off + TAR_BLOCK > buf_size) return 0;
    uint8_t *h = buf + c->header_off;
    uint32_t op = nm_xorshift32(rng) % 7;

    switch (op) {
    case 0: { /* size — the field most arithmetic depends on */
        size_t sz = TAR_INTERESTING_SIZE[nm_xorshift32(rng) % TAR_SIZE_N];
        tar_write_octal(h + TAR_OFF_SIZE, TAR_LEN_SIZE, sz);
        break;
    }
    case 1: { /* base-256 size: high bit set, then a big-endian value. This
               * is a separate decoder in every tar implementation and it is
               * where signedness bugs live. */
        memset(h + TAR_OFF_SIZE, 0, TAR_LEN_SIZE);
        h[TAR_OFF_SIZE] = 0x80u | (uint8_t)(nm_xorshift32(rng) & 0x7Fu);
        nm_write_be64(h + TAR_OFF_SIZE + 4, (uint64_t)nm_xorshift32(rng) << 32
                                            | (uint64_t)nm_xorshift32(rng));
        break;
    }
    case 2: { /* typeflag — switches the parser to a different code path */
        h[TAR_OFF_TYPEFLAG] = TAR_INTERESTING_TYPEFLAG[
            nm_xorshift32(rng) % TAR_TYPEFLAG_N];
        break;
    }
    case 3: { /* turn this entry into a pax header and plant a hostile record
               * in its payload — reaches libarchive's pax attribute parser */
        h[TAR_OFF_TYPEFLAG] = (nm_xorshift32(rng) & 1u) ? 'x' : 'g';
        const char *rec = TAR_PAX_RECORDS[nm_xorshift32(rng) % TAR_PAX_N];
        size_t rec_len = strlen(rec);
        if (c->data_off + rec_len <= buf_size && c->data_len >= rec_len) {
            memcpy(buf + c->data_off, rec, rec_len);
            tar_write_octal(h + TAR_OFF_SIZE, TAR_LEN_SIZE, rec_len);
        }
        break;
    }
    case 4: { /* mode / uid / gid — octal fields feeding permission logic */
        size_t which = nm_xorshift32(rng) % 3;
        size_t off = which == 0 ? TAR_OFF_MODE
                   : which == 1 ? TAR_OFF_UID : TAR_OFF_GID;
        tar_write_octal(h + off, 8,
                        TAR_INTERESTING_SIZE[nm_xorshift32(rng) % TAR_SIZE_N]);
        break;
    }
    case 5: { /* name/prefix: traversal and boundary lengths. ustar rebuilds
               * the path as prefix + "/" + name, so a full 155-byte prefix
               * next to a full 100-byte name is the concatenation edge. */
        if (nm_xorshift32(rng) & 1u) {
            memset(h + TAR_OFF_NAME, 'A', 100);      /* unterminated name */
        } else {
            memcpy(h + TAR_OFF_NAME, "../../../../../../etc/passwd", 28);
            h[TAR_OFF_NAME + 28] = '\0';
        }
        if (nm_xorshift32(rng) & 1u) {
            memset(h + TAR_OFF_PREFIX, 'B', 155);    /* unterminated prefix */
        }
        break;
    }
    default: { /* corrupt the magic itself — selects V7/GNU/ustar dispatch */
        static const char *magics[] = {"ustar", "ustar ", "GNUta", "\0\0\0\0\0", "usta\xff"};
        const char *m = magics[nm_xorshift32(rng) % 5];
        memcpy(h + TAR_OFF_MAGIC, m, 5);
        break;
    }
    }

    /* Always repair the checksum: a header that fails its checksum is
     * rejected before any of the fields above are even looked at, which
     * would waste every one of these mutations. */
    nm_adapter_fix_integrity(buf, c);
    return 1;
}
