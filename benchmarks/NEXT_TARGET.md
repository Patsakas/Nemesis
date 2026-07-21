# Next session: MAGMA

Start here. The single-CVE recon below (libpng, libtiff) stays as fallback for
non-MAGMA targets, but the primary next step is MAGMA, because it removes the
cost that dominated this work: proving, per target, that the benchmark is valid.

## The claim being tested — narrower than "evaluate NEMESIS on MAGMA"

> Does NEMESIS structural inference + seed generation produce a better starting
> corpus than the baseline, on validated vulnerability targets?

Explicitly **not** in scope, because none of it has been shown to help and mixing
it in would reintroduce "what caused the result?":
mutation placement (refuted), custom-mutator scheduling, harness generation,
symbolic execution. The experiment stays boring on purpose — the isolation of one
variable is the strongest thing NEMESIS has right now.

## Harness decision: use MAGMA's, not NEMESIS's

MAGMA ships its own libFuzzer harnesses plus **canary instrumentation**
(`MAGMA_LOG` per bug, distinguishing *reached* from *triggered*). Use them.

- This reduces "NEMESIS" in the experiment to *its seed generator feeding MAGMA's
  harness* — say it that way, not "NEMESIS evaluated on MAGMA".
- The canary oracle is an upgrade over the differential oracle built this session
  (reached-vs-triggered, single build). The `benchmarks/cjson_cve_2023_53154/`
  differential oracle becomes the fallback for non-MAGMA targets.
- MAGMA harnesses are plain entry points — none of the `continue` predicate gates
  the NEMESIS cJSON harness had (which blocked the minimal `{"1":1,` trigger). One
  less surprise.
- Consistency note: generate the NEMESIS seeds by running the inference against a
  probe binary built from **MAGMA's** harness source, so seeds and campaign
  exercise the same code path.

## Evaluation model

```
A: MAGMA baseline corpus
B: A + NEMESIS-generated seeds   (custom mutator OFF in both — the png.c confound)
```

Primary metric: bug triggered? (canary). Secondary: TTFC distribution
(censored at budget). Tertiary: edge coverage, diagnostic only.
Stats: Fisher exact on trigger rate, exact permutation on TTFC — same as
`scripts/bench_report.py`.

## Qualification gate first — `scripts/qualify_benchmark.sh`

Composes with the canary oracle. Per bug: TOO_EASY (baseline triggers fast every
run) → discard; TOO_HARD (neither arm triggers in budget) → discard; keep only
the mid-difficulty ones. This is the step that makes the whole thing worth
running, and it is why single-CVE hunting was a trap.

## Initial targets — the four MAGMA/NEMESIS overlap

Not five: **lz4 is not in MAGMA**. The overlap with what NEMESIS has onboarded
(config + structural adapter, all confirmed present) is exactly:

| target | adapter | why this order |
|--------|---------|----------------|
| libxml2 | `xml2_synth.c` | untested; parsing-heavy, deep nesting, field relationships — where structure is most likely to matter |
| libsndfile | `sndfile_synth.c` | untested; binary chunks + headers + metadata |
| libpng | `png.c` | the one target where seed generation *did* beat baseline (p=0.008) — confirm it holds on MAGMA's different bugs, mutator off |
| libtiff | `tiff_synth.c` | seed generation did *not* help here (p=0.691) — include for honesty, expect a negative |

## Prediction, recorded before running

Most likely target-dependent, not a universal win — consistent with libpng-yes /
libtiff-no already seen. A result like libxml2 +, libsndfile +, libpng +,
libtiff − would be more informative than a uniform 10/10, and is the honest bet.

---

# Picking the next rediscovery benchmark (single-CVE, non-MAGMA fallback)

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
