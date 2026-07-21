# Harness Autonomy / Provenance Experiment — libpng CVE-2018-13785

## The question this isolates

The libpng harness A/B (`benchmarks/harness_reasoning/`) proved a *harness-effect*
claim:

> A semantically-aware harness (`png_set_user_limits(png_ptr, 0x7FFFFFFF, ...)`)
> reaches CVE-2018-13785; a naive harness with default limits cannot, on the exact
> same trigger input.

That is real and confound-free. It does **not** prove the *autonomy* claim:

> NEMESIS/the LLM **discovers on its own** that `png_set_user_limits` is required.

The `png_set_user_limits` call appears in a saved harness
(`config/targets/libpng/harnesses/png_check_chunk_length.c`) and could be *reused*
rather than *reasoned*. This experiment determines which, under a strict
no-leakage protocol.

## Why it matters (the two claims are different contributions)

- **Engineering claim** (proven by the A/B): NEMESIS constructs semantically-valid
  harnesses that raise reachability. Same problem OSS-Fuzz-Gen targets. Real value.
- **Research claim** (tested here): the semantic requirement is *inferred* from the
  target, i.e. genuinely neuro-symbolic — not a human-provided recipe replayed.

Overclaiming the second when only the first holds is exactly the kind of confound
this project has been retracting. So the word "neuro-symbolic discovery" is banned
from the writeup until L1 below succeeds.

## Leakage control (what the generation environment must NOT see)

`forbidden/` — none of this is provided to any LLM call:
- `config/targets/libpng.yaml` `harness_template` (human-curated libpng expertise)
- `config/targets/libpng/harnesses/*` (the saved harness containing the answer)
- Any string containing `png_set_user_limits`, `user_width_max`, `0x7FFFFFFF`,
  or the CVE id, in the *goal* given to the model.

`input/` — the only things provided, per level:
- `api_subset.txt` — read-path public API from `png.h`, with `png_set_user_limits`
  present among ~20 other functions (so L0 tests *reasoning*, not *recall*: the
  function is available; will the model choose it?).
- `source_snippets.txt` — the guard (`png.c` `png_check_IHDR`) + the overflow
  (`pngrutil.c` row_factor) verbatim. **L1 only.**

## Three levels of assistance

| Level | System prompt | What it is given | Isolates |
|-------|---------------|------------------|----------|
| **L0** LLM-only, neutral | generic `HARNESS_STRATEGY_A_SYSTEM` | API subset + neutral goal "fuzz the PNG read path". No source, no blocker, no CVE. | Pure autonomy (outcome A if it emits the call) |
| **L1** LLM + source | `blocker_analysis.md` then generic | The two source snippets; asked *why the deep path is unreachable and how to bypass* — **without** naming `user_width_max` or the fix. | Neuro-symbolic (outcome C): symbolic layer surfaces the guard, LLM synthesizes the call |
| **L2** LLM + named blocker | generic | Neutral goal + "png_check_IHDR rejects width > user_width_max (default 1e6); raise it to reach large-width paths." Constraint named, **API not named**. | Positive control: can the model *recall* the API once told the constraint? |

Scored per rep: does the generated `c_code` (L0, L1b, L2) or analysis (L1a) contain
`png_set_user_limits`? N reps per level; report a rate, not a single draw.

Model: `mistralai/mistral-small-4-119b-2603` (NEMESIS architect), temp 0.2,
max_tokens 16384 — identical to production.

## Pre-registered predictions (written BEFORE running)

- **L0**: 0–1 / 5. The neutral goal gives no reason to want large-dimension inputs,
  and the generic prompt explicitly says *"produce input that PASSES validation, not
  bypass it."* Expect the standard create→read_info→read_image sequence with no
  limit manipulation.
- **L1a** (analysis names the limit): 3–5 / 5. The guard source literally reads
  `if (width > png_ptr->user_width_max)`; a competent analysis should identify it.
- **L1b** (harness emits the call): 2–5 / 5, conditional on L1a.
- **L2**: 4–5 / 5. Constraint is handed to it; only API recall remains.

**Predicted outcome: C.** L0 low, L1 substantially higher → "neuro-symbolic" is
legitimate but *narrower* than "autonomous vulnerability reasoning": the symbolic/
source layer does the localization, the LLM does the API synthesis. If L0 is already
high → outcome A (stronger, autonomous). If L1 is also low → outcome B (the call was
a human recipe all along; reposition to "executes expert-guided strategies").

Results and the verdict-vs-prediction comparison land in `results/`.

---

## RESULTS (N=5, mistral-small-4-119b, temp 0.2)

### The crude metric was confounded — and a single draw nearly fooled me

The runner's first metric was *"does the string `png_set_user_limits` appear."*
Two things went wrong with it, both instructive:

1. **N=1 smoke test drew L0 = 0/1**, which would have declared "outcome C" on one
   sample. At **N=5, the crude L0 rose to 3/5 (60%)** — the single draw was noise.
   (Report a rate, not a draw.)
2. **The 60% was itself a confound.** Inspecting the actual calls: mistral uses
   `png_set_user_limits` as *generic boilerplate*, and in 2 of the 3 "hits" it set
   the limit **below** the default (`8192`, `16384`) — which blocks the bug
   *harder*, not unlocks it. The crude metric counted those as successes.

What actually gates reachability is the **direction**: does the width argument
exceed the default cap (1,000,000) so width `0x55555555` can pass `png_check_IHDR`?
Re-scored on that honest metric (`results/rescore.py`, reproducible):

| Level | crude (name appears) | **corrected (raises limit > default)** |
|-------|----------------------|-----------------------------------------|
| **L0** neutral, LLM-only | 3/5 | **0/5 (0%)** |
| **L1a** analysis names the blocker | — | **5/5 (100%)** |
| **L1b** harness after analysis | 5/5 | **3/5 (60%)** |
| **L2** named-constraint control | 5/5 | **5/5 (100%)** |

### Verdict: outcome C, confirmed on the corrected metric

- **L0 = 0/5.** From a neutral goal the model *never* raises the limit. It either
  omits the call or uses it as hardening that *lowers* the cap. So there is **no
  autonomous reachability reasoning** — even though libpng is famous and the model
  clearly *knows the function exists* (it reaches for it 60% of the time). It just
  never points it the right way on its own.
- **L1 = 100% blocker-ID, 60% correct synthesis.** Given the guard + overflow
  source (without being told the fix), the analysis identifies `user_width_max` as
  the blocker every time and proposes raising it; the harness step then raises it
  correctly 3/5. (The 2 misses echoed the literal "1,000,000" from the analysis
  instead of exceeding it — synthesis is imperfect even with correct analysis.)
- **L2 = 5/5.** Told the constraint in prose, it recalls the API and raises it every
  time — so the L1 gap is synthesis, not capability.

**The clean reading:** the symbolic/source layer supplies the one thing the neutral
LLM lacks — the *direction* of the fix. Knowing `png_set_user_limits` exists (prior)
is not enough; knowing to *raise* it to reach a large-width overflow requires the
guard to be surfaced. That is exactly what "neuro-symbolic" should mean here, and
it is **narrower than "autonomous vulnerability reasoning."**

### Prediction scorecard (pre-registered above)

- L0 predicted 0–1/5 → **correct on the corrected metric (0/5)**; the crude metric
  (3/5) would have falsely refuted it. The proxy, not the hypothesis, was wrong.
- L1a predicted 3–5/5 → **5/5**. L1b predicted 2–5/5 → **3/5**. L2 predicted 4–5/5
  → **5/5**. Predicted outcome C → **confirmed**.

### Honest limitations

- One target, one model, N=5, temp 0.2. libpng's fame means the *prior* (function
  exists) is strong; the result that survives that is the **direction** gap, which
  priors do not close. A truly memorization-proof test would repeat this on an
  obscure or renamed library — recorded as future work, not claimed here.
- "Symbolic layer" in L1 was the hand-provided guard+overflow snippet standing in
  for NEMESIS's static/coverage analysis. It shows the LLM *can* synthesize the
  bypass from a localized guard; it does not yet show NEMESIS's own analyzer
  localizes that guard unaided. **That link is closed below.**

---

## ANALYZER LOOP — closing it with NEMESIS's own components (no hand-picked snippet)

L1 above stood in for the symbolic layer with a hand-picked source snippet. The
real question a fuzzing reviewer asks: *"where is NEMESIS here — did you just hand
the LLM the blocker?"* This section runs NEMESIS's **shipping** analyzer
(`nemesis/recon/validation_gates.py`, wired into `ContextBuilder` section 0) on
**raw** libpng source and closes the loop end-to-end. Reproduce with
`analyzer_loop.py //wsl.localhost/Ubuntu/home/giorg/libpng_work`.

### (1) Static extraction localizes the setter — unaided

`extract_validation_gates(raw libpng)` scans `.c` definitions for limit-relaxer
name idioms and returns 8 setters. **`png_set_user_limits` (pngset.c) is among
them and flagged injectable** — with no CVE text, no saved harness, no target hint.

### (2) Pure-symbolic injection turns the naive harness into the triggering one — NO LLM

`inject_setter_calls(arm_a_naive.c, gates)` inserts
`png_set_user_limits(png_ptr, 0x7FFFFFFFU, 0x7FFFFFFFU)` (+ chunk caps) right after
the context factory. Built and run against `trigger.png`:

```
arm_a_naive.c            → exit 0    (rejected, not triggered)
arm_a_ANALYZER_injected.c → exit 136 SIGFPE (TRIGGERED)
```

The naive harness becomes reachability-unlocking **with no LLM and no human in the
loop** — the deterministic analyzer alone closes it. (`render_validation_gates_block`
also feeds the identical prototype + a MANDATORY directive into the LLM prompt, so
the neuro path produces the same call; but the symbolic path needs no model at all.)

### The honest mechanism — heuristic, not guard reasoning

This is **more robust than the LLM path to the memorization confound** (the
extractor never "knows" libpng — it greps function-name idioms, library-agnostic),
but it is **cruder than L1 implied**:

- It matches **name idioms** (`_set_user`, `_set_*_max`, …) and injects **every**
  matched setter at max-permissive values — a *"relax all limit-setters"* shotgun.
- It does **not** read the guard `if (width > user_width_max)`, nor connect it to
  the `row_factor` overflow. There is no semantic guard→overflow reasoning here.
- So it works when the library **names** its limit setter idiomatically (libpng
  does). Its own docstring admits the real risk is **false negatives** on
  non-idiomatically-named setters — which it would silently miss.

The targeted, guard-aware reasoning that L1 demonstrated (LLM reads the specific
guard, names `user_width_max`, proposes raising it) is a **more general** capability
than the shipping extractor uses — it could handle non-idiomatic guards — but it is
**not** what the current pipeline relies on for this bug class. Honest split:

| layer | what it does | for this bug |
|-------|--------------|--------------|
| shipping symbolic extractor | name-idiom setter relaxation (deterministic, library-agnostic mechanism, heuristic coverage) | **closes the loop, no LLM** |
| LLM guard reasoning (L1) | reads the specific guard, synthesizes targeted bypass | capable, but not the extractor's mechanism |

### Bug found and fixed while testing

`inject_setter_calls`' idempotency check (`\bsetter_name\s*\(`) matched the setter
name in a **comment**, so a harness that merely *mentioned* `png_set_user_limits`
in a comment silently skipped injecting it (Arm A did exactly this). Fixed by
stripping comments before the presence check (`_strip_comments`). Found only
because this experiment ran the injector on a commented harness.
