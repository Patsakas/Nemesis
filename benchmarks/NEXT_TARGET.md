# Picking the next rediscovery benchmark

The cJSON entry (`cjson_cve_2023_53154/`) validated the framework but qualified
**TOO_EASY** — the baseline finds it in under a second. The next target must be
*discriminating*: reproducible, differential-oracle-able, and one the baseline
neither always nor never finds. This file records the reconnaissance so the next
attempt starts from evidence rather than a guess.

## A target needs, in order of how cheaply it can be checked

1. **Harness reaches the buggy function.** Grep the generated harness. Cheap.
2. **A fix commit in the library** (not a CLI tool) → build vulnerable and fixed
   for a differential oracle. `git log -- <lib file>`. Cheap.
3. **The trigger is reachable with inputs fuzzing can produce.** This is the one
   that decides difficulty, and it is where reconnaissance pays off — reading
   the fix diff shows what the trigger requires *before* building anything.
4. **Standalone ASan reproduction** with a tight buffer (see cJSON build_asan.sh).
5. **Passes `scripts/qualify_benchmark.sh`** — not TOO_EASY, not TOO_HARD.

## libtiff CVE-2022-3970 — reachable, but probably TOO_HARD

- Harness targets `TIFFReadRGBATileExt` ✓ (calls it directly).
- Fix commit `22750089` is in `libtiff/tif_getimage.c` ✓ (library, not a tool).
- **But the trigger is a `tile_xsize * tile_ysize` overflow — tiles > 2 GB.** The
  fix just adds `(size_t)` casts to those multiplications. To reach it, a TIFF
  must declare tile dimensions whose 32-bit product overflows (~536 M pixels),
  and the harness then tries to allocate a multi-gigabyte raster.

  That is an allocation-size overflow, and it is a poor fuzzing target for the
  same reason it is a poor standalone repro: the path needs multi-GB allocations
  that `allocator_may_return_null=1` turns into clean nulls and that a fuzzer
  rarely stumbles into. Expected qualifier verdict: TOO_HARD (or not reproducible
  in a normal budget at all). Not worth building before that is confirmed cheaply.

## What a good next target looks like

The opposite of both failures so far:

- **Not** an allocation-size / >2 GB overflow (TOO_HARD, awkward to reproduce).
- **Not** trivially reachable by truncating a seed (cJSON, TOO_EASY).
- A memory-safety bug (heap OOB read/write, use-after-free) reachable with a
  **small, structured** input where the structure is what gates reachability —
  the regime where the baseline stumbles some of the time and structural
  inference has room to help.

## libpng CVE-2018-13785 — the recommended next target

Reconnaissance done (fix commit `8a05766cb`, `pngrutil.c`). This is the one to
build and qualify next.

- Harness does a full `png_read` ✓. Fix is in the library ✓.
- Root cause: `width * channels * factor` overflows 32-bit, so `row_factor`
  wraps to 0 and the next line, `height > PNG_UINT_32_MAX / row_factor`, is a
  **divide-by-zero**. Not a huge allocation — the overflow makes a value *small*,
  so it does not have libtiff's TOO_HARD problem.
- Trigger: valid PNG signature + an IHDR whose width forces the overflow
  (`0x55555555` for RGB 8-bit) + a **valid IHDR CRC** (libpng checks it by
  default, `png_crc`). That CRC gate is what makes it structure-dependent and
  plausibly mid-difficulty — a random width flip invalidates the CRC and is
  rejected, so the baseline may hit it only sometimes. Exactly the regime the
  qualifier is for.

**Oracle is different from cJSON's:** the crash is a SIGFPE (integer
divide-by-zero), not an ASan report. Detect it by the process dying on signal 8,
and use the same differential (v1.6.34 crashes, v1.6.35 clean). No sanitizer, no
symbolizer-hang problem.

**Confound to control, stated up front:** the hand-written `png.c` mutator adapter
hardcodes the exact trigger value (`0x55555555 /* row-factor=0 */`, with a note
naming this CVE). Any arm that runs NEMESIS's custom mutator is therefore *given*
the answer by a human, not discovering it — the README's 60 s libpng result used
that mutator and should be read that way. A clean A/B here must be **seeds-only**,
with the custom mutator disabled in both arms, or it measures the hardcoded
constant rather than anything learned. The genuinely interesting NEMESIS question
would be a separate, clearly-labelled arm: does the CRC-aware mutator help a
baseline reach a CRC-gated bug — but that is a mutator experiment, not a seed one,
and must not be conflated with the placement/seed work.

lz4 CVE-2021-3520 is a second candidate (harness targets `LZ4_decompress_safe`),
but the README already records it as a miss where the harness reached the function
and byte flips could not synthesise the trigger — likely TOO_HARD. Recon its fix
diff before investing.
