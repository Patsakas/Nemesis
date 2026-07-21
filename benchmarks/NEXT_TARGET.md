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

Candidates worth checking against the five criteria above (both have git tags for
the differential): a **libpng** chunk-parsing CVE, or an **lz4** block-header CVE.
Read the fix diff first (criterion 3) — that is what cracked cJSON and what flagged
libtiff as too hard, each in one step.
