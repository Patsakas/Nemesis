# Known gaps

Deliberately open items, with the evidence that identified them. Recorded here
rather than fixed immediately when a fix would add a variable to an experiment
already in flight, or when the gap is itself worth measuring first.

`scripts/pipeline_health_check.py` reports several of these against any run log,
so they stay visible instead of living in a conversation.

---

## score_explainability — quality score cannot be audited from the log

**Status:** known failure. Reported by the `score_explainable` check
(`interpretability`).

**Impact:** observability only. The score is computed correctly and consumed
correctly; it simply cannot be reproduced by a reader.

Does not affect generation, fuzzing, triage, scoring, or any decision.

**Evidence.** `harness.quality_score` emits the value and `line_cov`, but not
the terms that produced it. Explaining why `minmea_scan` iteration 0 scored
0.8824 required recomputing the formula offline from `fuzzer_stats` and the run
log. That reconstruction is what revealed the whole 0.12 rise between iterations
came from AFL map density while line coverage contributed nothing — a finding
that should have been readable directly from the log.

**Intended fix.** Emit the decomposition and the weights:

```
harness.quality_score
  score=0.9180
  compiled=1.0  reachability=1.00  exploration=0.7656
  paths=1.00    density=1.00
  weights=0.25/0.25/0.35/0.15
```

A regression test should assert that the components are present, that the
weighted sum reproduces the logged score, and that the weights are declared —
not that any particular value is correct. The point is auditability, not the
number.

**Deferred until:** the evaluation run started 2026-07-22 20:44 UTC completes.
That run is testing three runtime wiring fixes (variadic gate, exploration-aware
objective, closed measurement loop). Changing the log schema mid-flight would
leave a run executed under one schema and a commit altering it before the run
finished — no harm to the results, but a muddle to explain later.

---

## target_acceptance_threshold — negatively scored candidates still get fuzzed

**Status:** open. Not yet covered by a health check.

**Evidence.** On minmea, recon ranked `main` from `tests.c` last with a score of
**−4.80** — correctly, it is a test-suite entry point. With only three
candidates found, the pipeline processed all three, so a negatively scored
candidate consumed a full 15-minute fuzzing budget.

Ranking works; there is no acceptance threshold. `tests.c` sits at the repo
root rather than under `tests/`, so the directory exclusion added on
2026-07-22 does not catch it either.

**Intended fix.** Discard candidates below a score threshold, and emit
"no suitable fuzz target" when none remain — more honest than fuzzing a
`main()` because budget was available.

**Deferred until:** after the current evaluation run, so that baseline and new
run process the same target set and the only difference between them is the
pipeline changes under test.

---

## function_coverage_pct is misnamed

**Status:** open, cosmetic but load-bearing.

The field holds the gdb measurement of *what fraction of corpus inputs reach
the target* — reachability. The scoring layer read it as source coverage. Two
subsystems held different interpretations of the same field, which is the same
failure class as the two divergent library resolvers fixed in `cbc10b2`.

The scoring bug is fixed; the name is not. Renaming to
`target_reachability_pct` touches several call sites and the API routes, so it
is queued rather than slipped into an unrelated change.
