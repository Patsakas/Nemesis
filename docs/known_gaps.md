# Known gaps

Deliberately open items, with the evidence that identified them. Recorded here
rather than fixed immediately when a fix would add a variable to an experiment
already in flight, or when the gap is itself worth measuring first.

`scripts/pipeline_health_check.py` reports several of these against any run log,
so they stay visible instead of living in a conversation.

---

## crash_triage_soundness — analysis errors become negative findings

**Status:** open. **Affects result reliability, not just observability** — this
is the only gap here that can lose a real finding.

**The invariant being violated:** a failed analysis must never reduce
confidence in a finding. `analysis failure ≠ no vulnerability`.

**Evidence.** minmea run 2026-07-22, iteration 1. AFL found a crash; every
upstream step agreed it was real, and the last one erased it:

```
21:35:37  triage.start           crash_count=1
21:35:38  triage.upstream_check  reproduces on the latest upstream code
21:36:08  analyze.failed         Command '[binary_debug_snapshot]' timed out after 30 seconds
21:36:08  triage.complete        unique_crashes=0
```

The crash did reproduce. Running the same debug snapshot on the same input by
hand shows a clean `AddressSanitizer: stack-buffer-overflow`. The triager never
classified it — it timed out, and a timed-out analysis is silently reported as
zero crashes.

**Immediate cause.** The crash-analysis path builds its environment as

```python
"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1"
```

with no `symbolize=0`. ASAN then spawns llvm-symbolizer, which hangs off-TTY
under WSL. Same binary, same input, one flag apart:

| ASAN_OPTIONS | exit |
|---|---|
| as the triager sets them | **124** — timed out at 30s |
| plus `symbolize=0` | **134** — SIGABRT, crash detected |

The cmin and corpus-minset paths in the same file already set `symbolize=0`;
the crash-analysis path does not.

**Structural cause, and the one that matters.** Triage has only two outcomes in
the code — a crash is counted or it is not — so an error has nowhere to go but
into "not". It needs three:

```
confirmed   reproduced and classified
rejected    tested and shown to be a false positive
unknown     could not be decided — preserved, flagged for review
```

An `unknown` reported as `rejected` is how a real finding disappears leaving
only a warning line behind.

**Why this surfaced.** The crash that exposed it was itself a false positive: a
harness-side stack overflow (`char s[80]` receiving a 95-character field
through minmea's unbounded `s` directive). Dropping it was the right outcome
reached by the wrong mechanism — and the same mechanism would drop a genuine
library crash identically.

**Intended fix.** A shared ASAN environment helper so every path uses the same
options, and an explicit triage result type where a timeout increments an
`unknown` count rather than being absorbed into the crash count.

**Deferred until:** the current evaluation run completes. Both changes touch
the triage path the run is exercising.

---

## metric_provenance — values carried between iterations

**Status:** the immediate bug is fixed; the model behind it is not.

**Evidence.** Introduced while fixing the closed measurement loop, and caught by
`metric_provenance` on the first real run that exercised it:

```
FAIL  metric_provenance  minmea_scan iteration 1 reported 21.35
                         with no measurement for that iteration
```

`TargetResult` is created once per target (`pipeline.py:777`) and the refinement
loop reuses it. A `source_coverage_pct < 0.0` guard meant to avoid measuring
twice therefore stopped firing after iteration 0, and iteration 1 logged
iteration 0's coverage for a harness that was a different program. The quality
score was then computed from it.

This was worse than the bug it replaced. The missing value was visibly missing —
`n/a`. The stale one is present, plausible, and wrong.

Note the separation that made it visible: `score_consumes_coverage` **passed** —
a value did reach the score — while `metric_provenance` failed, because the
value belonged to another iteration. Folding provenance into consumption would
have hidden it behind a green check.

**Fixed:** the bitmap-exit path measures unconditionally. The two measurement
sites cannot both run in one iteration anyway — the branch returns.

### Follow-ups

These are three faces of one problem: metrics and artifacts have no lifecycle
or provenance model. The chain the pipeline needs is

```
metric exists → consumed → measured → belongs to this iteration
              → artifact still available for verification
```

and today it reliably covers only the first two.

**1. Iteration-scoped result state.** `TargetResult` holds target-level and
iteration-level fields in one mutable object. Every iteration-local metric can
inherit a stale value the same way: `quality_score`, `paths`, `density`,
`corpus_size`, `crash_count`. `metric_provenance` detects that; it does not
prevent it. Direction: iteration-scoped result objects rather than mutating
shared target state.

**2. Metric event identity.** Provenance had to be validated by pairing values
with measurement *events*, because a value alone carries no evidence of where it
came from. Every metric event should identify target, iteration, metric name and
measurement source — not just the number. `source_coverage_pct=21.35` is not
checkable; `source_coverage.result target=… iteration=1 line_cov_pct=21.35` is.

**3. Immutable artifact archival.** The iteration-1 harness for run 3 was
overwritten by the next target before it could be measured, so the true value is
unrecoverable — the same class as the binary-snapshot problem, and the second
time in one day. Direction: archive an immutable copy at generation time, before
execution, rather than reconstructing afterwards.

---

## harness_input_length — unvalidated length into unbounded-write APIs

**Status:** open. A third class of harness unsoundness, caught by neither the
variadic arity gate nor anything else.

**Evidence.** The generated minmea harness sizes its string buffer at
`MINMEA_MAX_SENTENCE_LENGTH` (80) and passes AFL input of arbitrary length
straight to `minmea_scan(buf, "s", s)`. minmea's `s` directive copies without a
bound:

```c
case 's': {
    char *buf = va_arg(ap, char *);
    while (minmea_isfield(*field))
        *buf++ = *field++;      /* no size parameter anywhere */
    *buf = '\0';
}
```

A 95-byte input with a 95-character field overflows `s`. Proven by changing
only the harness buffer to 65536 and nothing else: the same input then runs
clean (exit 0 vs. a reproducible ASan stack-buffer-overflow, 3/3).

**Why it is worse than the variadic case.** Those crashes did not reproduce —
0 of 11 under ASan — so a reproduction check filters them. This one reproduces
reliably with a clean ASan report, so it *passes* that check and would be
recorded as a genuine finding. A false positive that survives verification is
worse than one that does not.

**Note on the API.** `minmea_scan` with `"s"` cannot be used safely on
unvalidated input at all — it offers no bound. A correct harness must clamp the
input length before the call, or not use that directive.

**Intended fix.** Extend the preflight gate: when a target writes through a
caller-supplied buffer with no size parameter, the harness must bound the input
before calling it.

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
