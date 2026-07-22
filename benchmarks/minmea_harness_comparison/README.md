# minmea — generated harness vs the project's own

**Status: scaffolding only. This benchmark has not been run and has no results.**

`build_cflite.sh` works and has been executed; `run_cflite.sh` and `compare.py`
have not. Nothing here should be cited.

## The question

Not "is the AI better than the human". minmea's ClusterFuzzLite harness was
written to guard one parser inside a PR-time budget and does that correctly —
it was never trying to cover the API. The comparable question is:

> how does an automatically generated broad harness compare with a
> deliberately written maintenance harness?

## What is already measured

| | CFLite |
|---|---|
| minmea public API | 17 functions |
| harness LOC | 20 |
| public functions called directly | **1** (`minmea_parse_rmc`, guarded by `size < 7`) |

The NEMESIS side is not filled in: the run that would have produced it was
stopped when its harness was found to contain variadic UB. See
`../minmea_harness_generation/`.

## How fairness is arranged

Three decisions that determine what any eventual result would mean:

- **The CFLite harness is used unmodified.** AFL++'s `libAFLDriver.a` supplies
  `main()` and the persistent loop for a libFuzzer harness. Editing it to add
  AFL macros would make this a comparison of those edits.
- **Identical build flags**, copied from the generated
  `config/targets/minmea.yaml`. Same fuzzer, sanitizer, instrumentation,
  library sources, wall clock and instance count. Only the harness differs.
- **The same single seed for both** — one well-formed `$GPRMC` sentence.
  NEMESIS generates its own corpus, and using it here would fold seed
  generation into what is meant to be a harness comparison; upstream ships no
  corpus at all, so giving CFLite nothing would be the opposite distortion.

## Metrics

`compare.py` reports API surface reach two ways, because they answer different
questions and quoting either alone is misleading:

- `entry_points_called` — functions the harness invokes directly (static)
- `functions_covered` — functions llvm-cov saw execute (dynamic)

The second is always larger, since a parser calls its own helpers. Quoting only
the first understates both harnesses; quoting only the second hides the breadth
difference, which is the point.

Plus line/branch/region coverage, executions, corpus size and crashes.
