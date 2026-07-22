# Known gaps

Deliberately open items, with the evidence that identified them. Recorded here
rather than fixed immediately when a fix would add a variable to an experiment
already in flight, or when the gap is itself worth measuring first.

Everything here has been observed in a run. Hypotheses do not belong on this
list — a reader must be able to treat every entry as a report of something that
happened.

`scripts/pipeline_health_check.py` reports several of these against any run log,
so they stay visible instead of living in a conversation.

## The shape most of these share

Three of the entries below are the same mistake at different layers:

| where | what failed | what was recorded |
|---|---|---|
| triage | crash analysis timed out | `unique_crashes=0` |
| metrics | no measurement for this iteration | the previous iteration's value |
| reachability | GDB breakpoint missed the target | `function_reached=True`, 100% |

In each, **uncertainty was collapsed into a definitive state**. Not one of them
produced an error, a warning that changed a decision, or a number that looked
wrong. A pipeline that says "I could not tell" is far easier to trust than one
that answers confidently when it could not measure.

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

## function_reachability_proxy_overclaims — inferred reach reported as measured

**Status:** open. Affects the correctness of the reachability metric, which
feeds both the quality score and the refinement trigger.

**Evidence.** minmea run 2026-07-22, target `minmea_getdatetime`. Two mechanisms
answered the same question and the indirect one won:

| method | result |
|---|---|
| `post_fuzz_cov` — GDB breakpoint on the target | `hits=0 pct=0.0 samples=10` |
| `variant.profile` — AFL bitmap fallback | `bitmap_pct=63.85` |
| what the pipeline recorded | `function_reached=True`, `coverage_pct=100.0` |

Not zero of ten inputs reached the function, and the pipeline recorded complete
reachability.

**Cause.**

```python
# Fix 116: Bitmap-based reach fallback — if GDB says not reached but
# AFL achieved significant bitmap coverage, the function IS being exercised.
if not function_reached and bitmap_pct > 3.0:
    function_reached = True

coverage_pct = 100.0 if function_reached else 0.0
```

The fallback itself is reasonable: GDB breakpoints do fail on inlined, static
and renamed functions, and without it those targets would read as unreachable.
Two things go wrong around it.

The evidence changes semantic level. `bitmap_cvg` is the AFL edge map for the
**whole binary**, harness included; it says nothing about one function. A 3%
threshold is cleared by any harness that runs at all — this one measured 63.85%
while reaching the target zero times.

And the uncertainty is discarded. `coverage_pct = 100.0 if function_reached`
turns a proxy inference into a stated certainty, with no way downstream to tell
a measured 100% from an inferred one.

**Required direction.** Keep inferred reach separate from measured reach:
`function_reached` set only by function-specific evidence, bitmap activity kept
as its own metric, and a confidence field distinguishing `direct` / `inferred` /
`unknown`. Never convert proxy evidence into a boolean function coverage.

**Consequence for in-flight work.** Any reachability figure from this run is
suspect where GDB missed. That includes target 3 (`main` from `tests.c`): a high
reachability there will not, on its own, distinguish "reached `main`" from
"binary was busy and the fallback fired".

---

## target_relevance — exploration counts the wrong code

**Status:** open. A dimension the score has no term for.

**Evidence.** minmea run 2026-07-22, target 3: `main` from `tests.c`, which
recon had ranked last at **−4.80**.

| | `main` (test runner) | `minmea_getdatetime` (library) |
|---|---|---|
| reachability | 0% (0 of 4 inputs) | 0% (0 of 10) |
| line coverage | **31.94%** (23/72) | 0% |
| quality score | **0.4237** | 0.4000 |

The test-suite entry point scored *higher* than a real library function. It
earned 0.1118 of exploration credit for covering 32% of a test runner — real
executable surface, and none of it the library's attack surface.

`main` is not a mislabelled library function. It is the thing under which the
library's own tests run, so exercising it is close to worthless for finding
bugs in the library, and the score has no way to say so.

**Why this is not the acceptance-threshold gap.** A threshold would have
dropped `main` on its −4.80 recon score. It would not help against a test
driver with rich control flow that scores positively — the score would still
reward exploring it. Ranking and relevance are different questions.

**The 31.94% is not test-suite coverage — it is the harness measuring itself.**
The two measurements looked contradictory (GDB: 0 of 4 inputs reached `main`;
llvm-cov: 31.94% of `main` executed) until the line counts are compared:

| function named `main` | lines |
|---|---|
| `tests.c:1271` — the target | **10** |
| the generated AFL harness | **68** |
| what `source_coverage` reported | **23 / 72** |

72 cannot be a 10-line function. llvm-cov measured the harness's own `main`,
because every AFL harness defines one and the target here is also called `main`.
GDB was right that the target was never reached; llvm-cov was right about a
function called `main`; they were measuring different functions.

So the exploration credit was not for exercising test infrastructure. It was
for executing the harness itself — the score rewarded the harness for existing.
Any target whose name collides with a symbol the harness defines is exposed to
this, and `main` is the obvious case but not necessarily the only one.

**Required direction.** Two separate things.

Coverage must be attributed by definition site, not by symbol name, so a
collision cannot silently redirect the measurement. That is a correctness fix.

And exploration needs scoping to code that belongs to the library's attack
surface rather than whatever the binary executed — a Layer 1 question, resolved
before fuzzing rather than inside the score.

**Related observation.** Given `reason=low_function_coverage` for this target,
the refinement produced a harness calling `minmea_parse_rmc`, `minmea_scan`,
`minmea_getdatetime`, `minmea_gettime`, `minmea_parse_zda` and
`minmea_tofloat` — real library entry points, and not `main` at all. Asked to
reach a bad target, the generator quietly went and harnessed the library
instead. That is the right instinct and the wrong mechanism: nothing in the
pipeline sanctioned changing the target, and the result will still be scored,
logged and attributed as a `main` harness.

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
