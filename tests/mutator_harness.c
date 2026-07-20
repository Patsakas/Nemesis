/**
 * Exercise harness for NEMESIS mutator adapters.
 *
 * Compiled once per adapter (the adapter is #included, since each is a
 * self-contained TU with static hooks), then run for thousands of rounds
 * against a valid seed for its format.
 *
 * What it checks, per round:
 *   - afl_custom_fuzz returns a size within the caller's max_size contract;
 *   - the mutator never reads or writes outside the buffers it was given
 *     (enforced by ASAN when available, and by canary padding regardless);
 *   - the adapter's own parse of its own output does not hang or run away.
 *
 * A mutator that violates any of these takes down afl-fuzz itself rather than
 * finding a bug in the target, which is why these get their own harness
 * instead of being trusted because they compile.
 *
 * Build:  cc -DADAPTER=\"../nemesis/templates/mutator/adapters/tar.c\" \
 *            -o tar_harness mutator_harness.c
 * Usage:  ./tar_harness <rounds>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef ADAPTER
#error "define ADAPTER as the adapter .c path to include"
#endif

#include ADAPTER

/* AFL entry points provided by the scaffold. */
void *afl_custom_init(void *afl, unsigned int seed);
void afl_custom_deinit(void *data);
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size);

#define CANARY 0xA5
#define PAD 64

static int failures = 0;

static void fail(const char *what, size_t round) {
    fprintf(stderr, "FAIL [round %zu]: %s\n", round, what);
    failures++;
}

/* ---------- Seeds ---------- */

static size_t seed_tar(uint8_t *out) {
    memset(out, 0, 1024);
    memcpy(out, "testfile.txt", 12);
    memcpy(out + 100, "0000644", 7);       /* mode  */
    memcpy(out + 108, "0000000", 7);       /* uid   */
    memcpy(out + 116, "0000000", 7);       /* gid   */
    memcpy(out + 124, "00000000010", 11);  /* size = 8 octal */
    memcpy(out + 136, "00000000000", 11);  /* mtime */
    out[156] = '0';                         /* typeflag: regular file */
    memcpy(out + 257, "ustar", 5);
    out[263] = '0'; out[264] = '0';         /* version "00" */
    /* checksum over the header with the field read as spaces */
    memset(out + 148, ' ', 8);
    unsigned int sum = 0;
    for (int i = 0; i < 512; i++) sum += out[i];
    snprintf((char *)out + 148, 8, "%06o", sum & 0777777u);
    out[154] = '\0'; out[155] = ' ';
    memcpy(out + 512, "PAYLOAD!", 8);
    return 1024;
}

static size_t seed_zip(uint8_t *out) {
    size_t n = 0;
    memset(out, 0, 256);
    /* local file header */
    memcpy(out, "PK\x03\x04", 4); n = 4;
    out[n++] = 20; out[n++] = 0;          /* version */
    out[n++] = 0;  out[n++] = 0;          /* flags */
    out[n++] = 0;  out[n++] = 0;          /* method: stored */
    n += 4;                                /* time+date */
    out[14] = 0x11; out[15] = 0x22; out[16] = 0x33; out[17] = 0x44; /* crc */
    out[18] = 4;                           /* comp size = 4 */
    out[22] = 4;                           /* uncomp size = 4 */
    out[26] = 5;                           /* name len */
    out[28] = 0;                           /* extra len */
    memcpy(out + 30, "a.txt", 5);
    memcpy(out + 35, "DATA", 4);
    /* end of central directory */
    memcpy(out + 39, "PK\x05\x06", 4);
    /* counts/offsets left zero; comment length zero */
    return 39 + 22;
}

static size_t seed_asn1(uint8_t *out) {
    /* SEQUENCE { INTEGER 1, OCTET STRING "hi", SEQUENCE { BOOLEAN TRUE } }
     * Contents: 3 (INTEGER) + 4 (OCTET STRING) + 5 (nested SEQUENCE) = 12. */
    size_t n = 0;
    out[n++] = 0x30; out[n++] = 0x0C;     /* SEQUENCE, len 12 */
    out[n++] = 0x02; out[n++] = 0x01; out[n++] = 0x01;          /* INTEGER 1 */
    out[n++] = 0x04; out[n++] = 0x02; out[n++] = 'h'; out[n++] = 'i';
    out[n++] = 0x30; out[n++] = 0x03;     /* nested SEQUENCE, len 3 */
    out[n++] = 0x01; out[n++] = 0x01; out[n++] = 0xFF;          /* BOOLEAN */
    return n;
}

static size_t seed_protobuf(uint8_t *out) {
    size_t n = 0;
    out[n++] = 0x08; out[n++] = 0x96; out[n++] = 0x01;  /* field 1 varint 150 */
    out[n++] = 0x12; out[n++] = 0x05;                    /* field 2 len 5 */
    memcpy(out + n, "hello", 5); n += 5;
    out[n++] = 0x1D;                                     /* field 3, 32-bit */
    out[n++] = 0x01; out[n++] = 0x02; out[n++] = 0x03; out[n++] = 0x04;
    out[n++] = 0x21;                                     /* field 4, 64-bit */
    for (int i = 0; i < 8; i++) out[n++] = (uint8_t)i;
    return n;
}

static size_t make_seed(uint8_t *out) {
#if defined(SEED_TAR)
    return seed_tar(out);
#elif defined(SEED_ZIP)
    return seed_zip(out);
#elif defined(SEED_ASN1)
    return seed_asn1(out);
#elif defined(SEED_PROTOBUF)
    return seed_protobuf(out);
#else
#error "define one of SEED_TAR / SEED_ZIP / SEED_ASN1 / SEED_PROTOBUF"
#endif
}

/* ---------- Main loop ---------- */

int main(int argc, char **argv) {
    size_t rounds = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 20000;

    uint8_t seed_buf[4096];
    size_t seed_size = make_seed(seed_buf);

    if (!nm_adapter_has_signature(seed_buf, seed_size)) {
        fprintf(stderr, "FAIL: adapter does not recognise its own valid seed\n");
        return 1;
    }
    nm_chunk_t probe[NM_MAX_CHUNKS];
    int nprobe = nm_adapter_parse(seed_buf, seed_size, probe);
    if (nprobe <= 0) {
        fprintf(stderr, "FAIL: adapter parsed 0 chunks from its own valid seed\n");
        return 1;
    }
    printf("seed: %zu bytes, %d chunks\n", seed_size, nprobe);

    void *st = afl_custom_init(NULL, 0xC0FFEEu);
    if (!st) { fprintf(stderr, "FAIL: afl_custom_init returned NULL\n"); return 1; }
    srand(12345);   /* fixed: a failing round must be reproducible */

    /* The input buffer is padded with canaries on both sides so an adapter
     * that writes outside the region AFL owns is caught even without ASAN. */
    size_t cap = 8192;
    uint8_t *region = (uint8_t *)malloc(cap + 2 * PAD);
    if (!region) return 1;

    for (size_t r = 0; r < rounds; r++) {
        memset(region, CANARY, cap + 2 * PAD);
        uint8_t *in = region + PAD;

        /* Feed the pristine seed most rounds, and a randomly corrupted copy
         * the rest — the adapter must survive input it did not produce. */
        size_t in_size = seed_size;
        memcpy(in, seed_buf, seed_size);
        if (r % 3 == 0) {
            for (int k = 0; k < 8; k++) {
                in[rand() % (int)seed_size] = (uint8_t)(rand() & 0xFF);
            }
        }
        if (r % 7 == 0 && seed_size > 4) {
            in_size = (size_t)(rand() % (int)seed_size) + 1;  /* truncated */
        }

        uint8_t *out = NULL;
        size_t max_size = 4096;
        size_t got = afl_custom_fuzz(st, in, in_size, &out, NULL, 0, max_size);

        if (got > max_size) { fail("returned size exceeds max_size", r); break; }
        if (got > 0 && out == NULL) { fail("non-zero size with NULL out_buf", r); break; }

        for (size_t i = 0; i < PAD; i++) {
            if (region[i] != CANARY) { fail("underflow: wrote before input buffer", r); break; }
            if (region[PAD + cap + i] != CANARY) { fail("overflow: wrote past input buffer", r); break; }
        }
        if (failures) break;

        /* Re-parsing the mutator's own output must terminate and stay in
         * bounds — this is what catches a length field mutated into a value
         * that makes the walk loop forever. */
        if (got > 0 && out != NULL) {
            nm_chunk_t chunks[NM_MAX_CHUNKS];
            int n = nm_adapter_parse(out, got, chunks);
            if (n < 0 || n > NM_MAX_CHUNKS) { fail("parse returned bogus count", r); break; }
            for (int i = 0; i < n; i++) {
                if (chunks[i].data_off > got) { fail("chunk data_off past end", r); break; }
                if (chunks[i].data_off + chunks[i].data_len > got) {
                    fail("chunk extends past end", r); break;
                }
            }
            if (failures) break;
        }
    }

    free(region);
    afl_custom_deinit(st);
    if (failures) { printf("FAILURES: %d\n", failures); return 1; }
    printf("phase 1 (afl_custom_fuzz contract): %zu rounds clean\n", rounds);

    /* ---- Phase 2: direct hook calls on tightly-sized buffers ----
     *
     * Phase 1 cannot see a semantic overflow. The scaffold hands adapters a
     * 1 MB scratch buffer and tells them the DATA size, so a write at
     * buf[buf_size] lands inside a valid allocation and ASAN stays silent —
     * the same masking that made NEMESIS heap-copy AFL inputs before handing
     * them to a parser (Fix 139). Calling the hooks directly against a buffer
     * malloc'd to exactly the data size removes the padding, so every byte
     * past the end is a real ASAN redzone. */
    for (size_t r = 0; r < rounds; r++) {
        size_t sz = seed_size;
        if (r % 7 == 0 && seed_size > 4) sz = (size_t)(rand() % (int)seed_size) + 1;

        uint8_t *tight = (uint8_t *)malloc(sz);   /* exact size — no slack */
        if (!tight) break;
        memcpy(tight, seed_buf, sz);
        if (r % 3 == 0) {
            for (int k = 0; k < 8; k++) tight[rand() % (int)sz] = (uint8_t)(rand() & 0xFF);
        }

        if (nm_adapter_has_signature(tight, sz)) {
            nm_chunk_t chunks[NM_MAX_CHUNKS];
            int n = nm_adapter_parse(tight, sz, chunks);
            if (n > 0) {
                uint32_t rng = (uint32_t)(r * 2654435761u) | 1u;
                /* Several passes so the adapter's own mutations become the
                 * input to the next parse — the state real fuzzing reaches. */
                for (int pass = 0; pass < 4; pass++) {
                    nm_adapter_apply_targeted(tight, sz, chunks, n, &rng);
                    for (int i = 0; i < n; i++) nm_adapter_fix_integrity(tight, &chunks[i]);
                    n = nm_adapter_parse(tight, sz, chunks);
                    if (n <= 0) break;
                }
            }
        }
        free(tight);
    }

    printf("phase 2 (tight-buffer hooks): %zu rounds clean\n", rounds);
    printf("OK: %zu rounds clean\n", rounds);
    return 0;
}
