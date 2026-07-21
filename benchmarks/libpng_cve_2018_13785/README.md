# CVE-2018-13785 — libpng integer-overflow → divide-by-zero

A validated benchmark target with a crash input, a build recipe, and a
differential oracle. Unlike cJSON (which qualified TOO_EASY), this one is
**hard for a baseline fuzzer** — which makes it interesting, and also exposes a
confound in how NEMESIS "rediscovers" it.

## The bug

In `png_check_chunk_length` (`pngrutil.c`), `row_factor = width * channels *
(bit_depth>8?2:1) + 1 + …` is computed in 32-bit. With RGB 8-bit and
`width = 0x55555555`, `width*3 + 1` overflows to exactly 0, so `row_factor`
becomes 0 and the next line, `height > PNG_UINT_32_MAX / row_factor`, is an
integer divide-by-zero → **SIGFPE**.

- Fixed in **1.6.35**, commit `8a05766cb` (adds `(size_t)` casts).
- Trigger: valid PNG signature + IHDR with `width = 0x55555555` (RGB8) + a
  **correct IHDR CRC**.

## Files & validation

`crash_input.png` (68 bytes), `harness.c`, `build_repro.sh`, `oracle.sh`
(SIGFPE = CVE-HIT), `reproduce.sh` (differential). Validate:

```bash
benchmarks/libpng_cve_2018_13785/reproduce.sh ~/libpng_work
```

All four checks pass: crash input hits v1.6.34, clean on v1.6.35; a well-formed
PNG clean on both.

## Two non-obvious things

**Reachability depends on a harness modification NEMESIS made.** libpng's default
width cap is 1,000,000, which rejects `0x55555555` before the divide. The harness
calls `png_set_user_limits(png_ptr, 0x7FFFFFFF, …)` to raise it — an injection
NEMESIS discovered it needed. Without it the bug is unreachable, so `harness.c` is
committed rather than inlined, to keep that explicit.

**The oracle is a SIGFPE**, not an ASan report, so it needs no sanitizer and none
of the cJSON entry's symbolizer-hang handling.

## Qualification: TOO_HARD for baseline, and the confound

Baseline plain AFL, 3 runs × 120 s, generic PNG seeds: **0/3 — never found.**
The IHDR CRC gate is the barrier: to reach the divide, a mutation must set
`width = 0x55555555` *and* carry a matching CRC, and any havoc flip of the width
invalidates the CRC so libpng rejects the chunk before the arithmetic.

This makes the target genuinely hard — and exposes how NEMESIS's published "60 s
libpng rediscovery" actually worked. It used the chunk-aware PNG mutator
(`nemesis/templates/mutator/adapters/png.c`), which:

1. recomputes the IHDR CRC after mutating (real capability — passes the gate), **and**
2. **hardcodes the exact trigger value** `0x55555555 /* row-factor=0 */`, with a
   comment naming this CVE.

So the baseline cannot reach it, and NEMESIS reaches it partly because a human
put the answer in the mutator. The unconfounded question — *does the CRC-aware
mutator find it with the hardcoded value removed?* — was measured directly by
driving the mutator standalone (15 000 outputs from a valid PNG seed, each
checked by the oracle):

| mutator | produces the CVE trigger? |
|---------|---------------------------|
| as-is (with `0x55555555` hardcoded) | **yes — 64 / 15 000 (0.4 %)** |
| deconfounded (row-factor-zero values removed) | **no — 0 / 15 000** |

**The CRC-awareness is a real capability but not sufficient on its own.** The
mutator recomputes the IHDR CRC so a mutated width survives the gate that stops
plain AFL — that part is genuine. But reaching `row_factor == 0` needs `width`
to be *exactly* `0x55555555` (or the other reverse-engineered per-channel
values), a needle in a 2³² space that generic boundary-value mutation never
hits. Remove the hardcoded constants and the mutator produces the trigger zero
times.

So NEMESIS's published "60 s libpng rediscovery" is, at the mutation level,
**replaying a human-supplied trigger value through a CRC-aware mutator**, not
discovering it. A full-pipeline run would "succeed" for the same reason and
would not change this — the standalone measurement above is the honest one, and
it is independent of the AFL crash-detection problem on this host (a SIGFPE in
persistent mode is not reliably captured when `core_pattern` pipes to a handler;
see `scripts/check_crash_reporting.sh`).
