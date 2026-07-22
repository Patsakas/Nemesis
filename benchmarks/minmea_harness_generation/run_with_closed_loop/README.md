# minmea run with the closed measurement loop

The run that tested three fixes from `472a8b5` and `aaa9d02`: the variadic
arity gate, the exploration-aware quality score, and the closed measurement
loop. Compare against `../baseline_old_pipeline/`, which is the same target set
under the pre-fix code.

**Executed at `aaa9d02`**, working tree matching that commit for pipeline code.
Runs did not record their own version at the time — that landed in `3b7bca4`
— so this was established afterwards by comparing commit timestamps against the
run start (2026-07-22 20:44:28 UTC). Later runs carry `git_sha` in
`execute.start` and need no such archaeology.

Completed normally after 8176s (136 min), all three targets, `rc=1` because no
target produced a confirmed crash.

## What the fixes did

Two health properties moved from FAIL to PASS:

| property | baseline | this run |
|---|---|---|
| observability | FAIL — 2 of 2 bitmap exits returned without measuring | **PASS** — 3 of 3 carry source coverage |
| consumption | FAIL — 1 of 2 scores computed with `line_cov=n/a` | **PASS** — 6 of 6 had coverage available |

The loop no longer returns on AFL map growth before measuring anything about
the target. That was the point of the change and it holds.

## What it then exposed

`artifacts/health_check.txt`:

```
PASS           3
FAIL           4
NOT_EXERCISED  1

wiring            NOT_EXERCISED
observability     PASS
consumption       PASS
provenance        FAIL
attribution       FAIL
interpretability  FAIL
```

Three of the four failures are checks that did not exist when this run started
— they were written *because* of what this run showed, and then applied back to
its log. See `docs/known_gaps.md` for each with its evidence.

## The clearest single result

Target 3, `main` from `tests.c`, across its two iterations:

```
compiled      0.2500
reachability  0.0000
exploration   0.1118    ← 31.94%, identical in both iterations
efficiency    0.0619 → 0.1500
score         0.4237 → 0.5118
```

The score rose 9 points. Three independent defects are stacked in that number:

1. **The rise is entirely `efficiency`** — AFL paths and map density saturating.
   Activity, not progress, on a target reachability measured at 0%.
2. **`exploration` did not move** because the coverage value is carried over
   from iteration 0. `TargetResult` outlives an iteration, so the guard meant to
   avoid measuring twice stopped the second measurement entirely.
3. **The coverage it reports is not the target's.** `tests.c:main` is ten lines;
   the reported 23/72 is the generated harness's own `main`. llvm-cov resolved
   the symbol name, not the definition site.

A number that looks like improvement, describing the wrong function, from the
wrong iteration, driven by the wrong term.

Also worth noting: given `reason=low_function_coverage`, the refinement produced
a harness calling `minmea_parse_rmc`, `minmea_scan`, `minmea_getdatetime`,
`minmea_gettime`, `minmea_parse_zda` and `minmea_tofloat` — real library entry
points, and not `main` at all (`harnesses/main_iter1.c`). Asked to reach a poor
target, the generator quietly harnessed the library instead. Sensible instinct,
unsanctioned mechanism: the result is still scored and logged as a `main`
harness.

## Reading the failures

`provenance` and `attribution` are not regressions introduced by the fixes under
test. `metric_provenance` was caused by the closed-loop fix and is corrected in
`3b7bca4`; `reachability_confidence` and `coverage_attribution` predate this
work entirely and were simply invisible until something looked. None of them
produced an error, a warning that changed a decision, or a number that looked
wrong.

`interpretability` remains open by choice — see `score_explainability` in
`docs/known_gaps.md`.

## Contents

```
run.log                        full pipeline log, 3 targets x 2 iterations
harnesses/main_iter1.c         the refined harness that abandoned its target
artifacts/health_check.txt     health summary as reported
artifacts/health_check.json    same, machine-readable
```
