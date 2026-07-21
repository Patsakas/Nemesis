# Automatic Harness Construction in NEMESIS: Capabilities and Boundaries

*A synthesis of three linked experiments (2026-07-21). Every number below is
reproducible from the scripts in this directory and `benchmarks/harness_reasoning/`.*

---

## 1. Research question

Fuzzing a library parser needs a *harness* that reaches deep code. Conservative
default limits (e.g. libpng's 1,000,000-pixel width cap) make adversarial inputs
bounce off validators before reaching the code where bugs live. NEMESIS combines a
deterministic static analyzer with an LLM to construct harnesses that relax such
limits. The question these experiments answer is not "does it find bugs" but:

> **What is the actual contribution of the static analysis and of the LLM to
> automatically constructing a harness that increases vulnerability reachability —
> and where does each stop working?**

The goal was a *bounded* answer (when each layer succeeds and fails), not an
impressive aggregate score.

---

## 2. Experimental progression

Each experiment was pre-registered with predictions and matched controls; where a
crude proxy metric turned out to be confounded it was retracted and re-scored (noted
inline). The four steps build on one another.

### 2.1 Harness effect — does a semantic harness change reachability at all?

`benchmarks/harness_reasoning/libpng/` — CVE-2018-13785 (integer divide-by-zero,
SIGFPE). Two harnesses, identical but for one line, same libpng 1.6.34, same clang
`-O0`, same trigger input:

```
arm A (default limits)                 → exit 0    NOT triggered  (width rejected)
arm B (png_set_user_limits 0x7FFFFFFF) → exit 136  SIGFPE         (reaches the divide)
```

The harness — nothing else — decides reachability. **Confound-free.** (This replaces
the earlier "60 s libpng rediscovery", which was confounded by a custom mutator that
*hardcoded* the trigger constant; that claim is retracted.)

### 2.2 Provenance — who produces the limit-relaxing call?

Two independent checks, no-leakage protocol (the libpng `harness_template`, saved
harnesses, and CVE text are withheld).

**(a) LLM autonomy probe** (`libpng/`, N=5, scored on *raising* the limit, not on the
call merely appearing — the crude "name appears" metric counted hardening that
*lowered* the cap and was retracted):

| condition | raises the limit → unlocks bug |
|-----------|-------------------------------|
| neutral goal, LLM only | **0/5** |
| + guard/overflow source surfaced (fix not named) | **3/5** (blocker identified 5/5) |
| + constraint named in prose | **5/5** |

From a neutral goal the model never raises the limit — it knows the API exists
(reaches for it 60 % of the time) but points it the wrong way. The relaxation
appears only once the guard is surfaced.

**(b) Deterministic analyzer loop** (`nemesis/recon/validation_gates.py`, wired into
`ContextBuilder`). Run on *raw* libpng source, no hint: `extract_validation_gates`
finds `png_set_user_limits` unaided, and `inject_setter_calls` rewrites the naive
Arm A into a harness that **triggers the SIGFPE with no LLM and no human** (built and
run: exit 136). A comment-matching bug in the injector's idempotency check was found,
fixed (`_strip_comments`), and covered by regression tests (`tests/test_validation_gates.py`).

### 2.3 Idiom stress — does the deterministic layer generalize beyond libpng?

`idiom_stress/` — `extract_validation_gates` on three freshly cloned libraries:

| library | setters found | key relaxation API found? |
|---------|---------------|---------------------------|
| libpng | 8 (incl. `png_set_user_limits`) | ✓ |
| libtiff | **0** | ✗ |
| libxml2 | **0** | ✗ |
| libsndfile | **0** | ✗ |

**0/3.** Two failure modes: (i) *naming* — libtiff's `TIFFOpenOptionsSetMaxSingleMemAlloc`
has the idiom but camelCase, and anyway has the wrong polarity (it *imposes* a cap,
default unlimited); (ii) *paradigm* — libxml2's lever is a parse flag
(`XML_PARSE_HUGE`) and libsndfile's a command code (`SFC_SET_*`), neither a setter
function that any name-heuristic could match. **The deterministic layer is
paradigm-tuned to libpng's shape** ("restrictive default + snake_case raise-setter"),
not library-agnostic.

For the one valid non-idiomatic case (libxml2, Case C), the LLM was given the
HUGE-gated guard: it named `XML_PARSE_HUGE` and applied it via parse options **5/5**,
with correct reasoning and trigger derivation. So the LLM covers exactly where the
heuristic structurally cannot.

### 2.4 Mechanism-inference ladder — where does the LLM's coverage come from?

`idiom_stress/run_mechanism_inference.py` — same libxml2 guard at three visibility
levels, N=5, scored on the *correct* relaxation (enable HUGE to *raise* the limit):

| level | the guard shows | correct: enable-to-raise |
|-------|-----------------|--------------------------|
| L1 recognition | `options & XML_PARSE_HUGE` verbatim | 5/5 |
| L2 nearby inference | an alias + `#define ALIAS XML_PARSE_HUGE` elsewhere | 5/5 |
| **L3 mechanism inference** | only `maxLength = XML_MAX_NAME_LENGTH` (flag removed) | **0/5** |

**L3 collapses.** With the flag→limit structure hidden, the model never correctly
infers the mechanism. The 2/5 that *recalled* `XML_PARSE_HUGE` (libxml2 is famous)
reasoned it **backwards** — proposing to *disable* it — which would keep the
restrictive limit. Residual recall is thus both unreliable and semantically wrong.

### 2.5 Ground-truth reachability on MAGMA — the harness edge, independently confirmed

`experiments/harness_autonomy/magma_reachability/`. MAGMA forward-ports real bugs
with a canary oracle that separates *reached* from *triggered*. Two results:

**Oracle verified.** A 3-min baseline libpng campaign gave, per bug, distinct
reached/triggered counts (PNG001 reached=42898 / triggered=0; PNG003 triggered=20486
proves the trigger counter fires). So "not triggered" is real, never "no crash =
not reached".

**Harness A/B on PNG001 (CVE-2018-13785), same trigger input, MAGMA's canary
libpng, only variable = `user_width_max`:**

| arm | user_width_max | reached | triggered |
|-----|----------------|---------|-----------|
| default (stock 1,000,000) | 1e6 | **0** | **0** |
| NEMESIS (`png_set_user_limits` 0x7FFFFFFF) | 2^31−1 | **1** | **1** |

The augmentation flips the bug from not-even-reached to reached-and-triggered.

**Critical caveat (found, not assumed):** the first A/B had *both* arms trigger.
Investigating rather than accepting it revealed MAGMA's `pnglibconf.h` sets
`PNG_USER_WIDTH_MAX=0x7FFFFFFF` (stock libpng: 1,000,000) — MAGMA raised the exact
barrier this thesis is about, at the library-config level, to make the bug
benchmarkable. Arm A above restores the stock default so the variable is faithful to
stock libpng. That MAGMA *had to* raise the limit is itself independent corroboration
that the default width limit is the reachability barrier. Three oracles now agree:
stock-libpng SIGFPE (§2.1), MAGMA's config choice, and MAGMA's canary A/B.

---

## 3. Observed capability boundaries

The four steps compose into a decision procedure for "relax a validation limit so a
fuzzer can reach deeper code":

```
                    Need to relax a validation limit
                                  │
                  Is there an explicit setter API
                  (snake_case  *_set_*_max / _set_user)?
                                  │
                 ┌──── yes ───────┴─────── no ────┐
                 ▼                                 ▼
     DETERMINISTIC ANALYSIS               Is the enabling mechanism
     succeeds, no LLM needed              explicit in the guard
     (libpng: png_set_user_limits,        (flag / option / alias)?
      static extract + inject)                        │
                                          ┌── yes ─────┴──── no ──┐
                                          ▼                        ▼
                              LLM RECOGNIZES & APPLIES     HIDDEN MECHANISM
                              it reliably                  NEITHER LAYER SUCCEEDS
                              (libxml2 L1/L2: 5/5)         (libxml2 L3: 0/5 correct)
```

**Proven:**
- A semantic harness change alone can flip reachability (§2.1).
- A deterministic static analyzer localizes and injects the relaxing call for
  libpng-shaped APIs, unaided and without an LLM (§2.2b).
- The LLM reliably recognizes and correctly applies a relaxation mechanism **when it
  is expressed in the code shown to it**, including behind an alias, and covers cases
  the heuristic structurally cannot (flags) (§2.3, §2.4 L1/L2).

**Not proven / refuted:**
- The neutral LLM does **not** autonomously produce the relaxation (§2.2a, 0/5).
- The deterministic layer does **not** generalize past libpng's naming+paradigm
  (§2.3, 0/3).
- The LLM does **not** infer a configuration mechanism that is absent from the code
  shown to it (§2.4 L3, 0/5 correct). "Mechanism inference" is not a NEMESIS capability.

The precise, defensible one-sentence claim:

> NEMESIS automatically constructs limit-relaxing fuzzing harnesses by static
> extraction of idiomatic setter APIs, and by LLM recognition and application of
> relaxation mechanisms that are visible in the target's guard code — but it does not
> infer relaxation mechanisms that the code does not expose.

---

## 4. Implications for NEMESIS

- **When the deterministic layer suffices:** libraries exposing snake_case
  limit-relaxation setters (`*_set_*_max`, `_set_user_*`) over restrictive defaults —
  the libpng family. Here NEMESIS needs no LLM for reachability, which is cheaper and
  fully explainable.
- **When the LLM is needed:** libraries whose relaxation lever is a flag/option/alias
  rather than an idiomatically-named setter (libxml2). The LLM recognizes and applies
  it from the guard — a genuine, complementary contribution over the analyzer.
- **When both fail:** the relaxation mechanism is not expressed in the localized guard
  (or does not exist as a config, only as a source change). Neither layer helps; a
  human, or coverage-guided discovery of the setter elsewhere, is required.

This turns "does NEMESIS work" into a routing decision, and tells us where to invest:
broadening the extractor's idioms (cheap, closes Case B), and — only if a
memorization-controlled study justified it — improving true mechanism inference (the
L3 gap), which today does not work.

---

## 5. Threats to validity

- **Target familiarity.** libpng and libxml2 are heavily represented in LLM training
  data. This most affects §2.4 L3 (a "success" could be recall, not inference) — but
  the finding is a *failure* there, so the prior works *against* it and it survives.
  §2.2b (deterministic) is prior-free by construction. A clean replication would use
  obscure or identifier-renamed libraries.
- **Sample size.** N=5 per condition at temp 0.2. Rates are indicative, not tight
  estimates; the effects reported are large (0/5 vs 5/5 splits), not marginal.
- **Single library family.** All targets are C parser libraries with a
  "restrictive-default limit" shape. The conclusions are scoped to that family; other
  reachability blockers (state machines, checksums, multi-step protocols) are out of
  scope and untested here.
- **One model.** mistral-small-4-119b (the NEMESIS architect). A stronger model might
  move the L3 number; nothing here claims a model-independent bound.
- **Guard localization in §2.4 was hand-provided** (a snippet standing in for the
  analyzer's output). §2.2b shows the shipping analyzer localizes the libpng guard;
  wiring that localization into the libxml2/flag path end-to-end is future work.

**Future work, in priority order:** (1) case-insensitive/camelCase idioms in the
extractor (closes Case B cheaply); (2) memorization-controlled L3 on an obscure
library (settles whether mechanism inference is ever worth pursuing); (3) extend the
harness A/B to more MAGMA targets (libxml2, libsndfile) to test the routing decision
at scale.

---

*Reproduce:* `benchmarks/harness_reasoning/libpng/run_ab.sh`,
`experiments/harness_autonomy/libpng/{run_autonomy.py,analyzer_loop.py,results/rescore.py}`,
`experiments/harness_autonomy/idiom_stress/{run_libxml2_llm.py,run_mechanism_inference.py}`.
