# Seed-quality benchmark — measured fieldspec vs the alternatives

Reproduce with `scripts/bench_fieldspec.py`. No LLM call, no fuzzing campaign,
fixed RNG — runs in minutes and is deterministic.

## What is measured

Given 40 seeds generated from each source, how much of the target do they reach?
Coverage of the generated corpus is a leading indicator for fuzzing outcome
(Rebert 2014: ~1% more coverage correlates with ~0.92% more bugs found) and is
measurable without a campaign.

Arms:

| arm | what it is |
|---|---|
| `original` | the single real seed the spec was measured from — what we already had |
| `random` | uniform random bytes, same length — the floor |
| `all-at-once` | one spec varying **every** measured field simultaneously |
| `measured` | one spec **per field**, the rest held at observed values |

All arms are run against a *probe binary* (`nemesis/recon/probe_build.py`), never
the AFL fuzzing binary — that one receives no input outside `afl-fuzz` and reports
identical coverage for every seed.

## Results

40 seeds per arm. Probe seed chosen by measured parser depth.

| target | probe seed | influential bytes | | `original` | `random` | `all-at-once` | `measured` |
|---|---|---|---|---|---|---|---|
| **libtiff** | 2504 B | 294/2504 (11.7%) | unique edges | 378 | 3 | 207 | **237** |
| | | | mean/seed | 378.0 | 3.0 | 24.1 | **220.2** |
| | | | distinct sets | 1 | 1 | 7 | 4 |
| **libpng** | 325 B | 296/325 (91.1%) | unique edges | 304 | 91 | 91 | **280** |
| | | | mean/seed | 304.0 | 91.0 | 91.0 | **234.2** |
| | | | distinct sets | 1 | 1 | 1 | 11 |
| **cJSON** | 27 B | 27/27 (100%) | unique edges | 104 | 29 | 43 | **112** |
| | | | mean/seed | 104.0 | 4.6 | 5.7 | **44.6** |
| | | | distinct sets | 1 | 4 | 5 | 4 |

## Reading these

**Varying one field at a time is what makes measured structure usable.** libpng
shows this most starkly: `all-at-once` is *identical* to `random` on every metric.
Rendering boundary values into all ten measured fields destroys the 8-byte PNG
signature, so those seeds are rejected at exactly the point uniform noise is, and
the arm carries no information at all. On libtiff the same mistake still reached
207 edges only because its header survived more often.

**The margin tracks how much of the input is inert.** The influential-byte
fraction spans 11.7% (libtiff, large compressed payload) to 100% (cJSON, a
character-by-character parser). Where most bytes matter, knowing which ones do
buys little — the measured spec earns its cost on binary container formats, and
that is the honest scope of the claim.

**Generated seeds do not replace real ones.** On libtiff and libpng the measured
arm stays below the seed it was derived from (237 vs 378, 280 vs 304); only on
cJSON does it exceed it. These are exploration inputs, and the corpus they belong
in is the union with the real ones, not a substitute for them.

**Distinct edge sets are a weak metric here.** Seeds differing in one field reach
the same deep code and look alike, so the count stays low even when mean coverage
per seed is 9x higher. A corpus of 20 deep seeds beats 100 shallow ones; the
fuzzing A/B should measure paths and crashes, not corpus diversity.

## Not yet measured

Whether any of this translates into finding bugs faster. That needs a fuzzing
campaign — same corpus, same budget, repeated runs — and is the next step.
