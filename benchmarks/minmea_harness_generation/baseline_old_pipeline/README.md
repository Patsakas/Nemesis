# Baseline — minmea under the pre-fix pipeline

Reference run of the pipeline **before** the closed measurement loop and the
reweighted quality score (commits up to `472a8b5`). Kept so later runs can be
compared against something, not because its numbers are good.

**Do not use this to evaluate the current architecture.** It ran with the old
code loaded; the changes in `aaa9d02` are not exercised anywhere in it.

## How it ended

`rc=124` after 5282s — killed by the 90-minute wall-clock limit passed to
`timeout`, not by a crash and not by finishing. It was processing the third
target when it was cut. Two of three targets completed.

The third target was `main` from `tests.c`, which recon had ranked last with a
score of **−4.80**. Ranking worked; there is no acceptance threshold, so a
negatively-scored candidate still consumed a full fuzzing budget. That is a
Layer 1 gap, recorded here and not yet fixed.

## What it recorded

| target | iteration | line coverage | quality score | exit path |
|---|---|---|---|---|
| `minmea_scan` | 0 | 21.35% | 0.8824 | `no_crashes` → refine |
| `minmea_scan` | 1 | **not measured** | not computed | `bitmap_expanded` (Δ 44.26) |
| `minmea_getdatetime` | 0 | **not measured** (`n/a`) | 0.6 | `no_crashes_no_coverage` → refine |
| `minmea_getdatetime` | 1 | **not measured** | not computed | `bitmap_expanded` (Δ 59.34) |

Three of four measurements are missing, and both `bitmap_expanded` exits skipped
coverage entirely — the loop returned on AFL map growth before measuring
anything about the target. This is the defect `aaa9d02` fixes, confirmed on two
independent targets rather than one.

## The numbers that do exist were measured by hand

`minmea_scan` iteration 1 was measured afterwards, outside the pipeline, by
replaying the saved corpus (`corpora/minmea_scan_iter1_corpus.tar.gz`, 38
inputs) through a clean `-fcoverage-mapping` build of the saved harness:

| | iteration 0 | iteration 1 |
|---|---|---|
| harness calls | 1 | 9 |
| line coverage | 41/192 (21.35%) | 147/192 (**76.56%**) |
| region coverage | 20.25% | 76.58% |
| branch coverage | 18.38% | 60.29% |

A 3.6× gain the run never observed. Both harnesses are in `harnesses/`:
`minmea_scan.c` is iteration 0 (one `minmea_scan(buf, "t", type)` call),
`minmea_scan_iter1.c` is iteration 1 (nine calls, including one three-directive
format).

## Caveat on comparing against this

The generator is stochastic and the provider endpoint was unstable throughout
(4 recorded `api.error` timeouts). A later run reaching, say, 60% instead of
76.56% would not show the changes hurt — it would be n=1 against n=1. What the
fixes actually change is better answered by `../generation_benchmark.py` with a
distribution than by a pair of full runs.
