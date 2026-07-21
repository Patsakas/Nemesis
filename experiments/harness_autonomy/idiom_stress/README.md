# Idiom-Stress Experiment — where the deterministic extractor fails, does the LLM recover?

## Purpose

The libpng analyzer loop (`../libpng/`) closed with a **deterministic** extractor
(`nemesis/recon/validation_gates.py`): it found `png_set_user_limits` from raw
source by matching function-name idioms (`_set_user`, `_set_*_max`). This experiment
stresses that heuristic across libraries with **different naming/relaxation
conventions**, to isolate a clean, complementary question:

> When the name-idiom heuristic (Layer 1) misses the relaxation mechanism, does the
> LLM (Layer 2) recover it — a real, measurable LLM contribution *over* the
> deterministic analyzer?

This replaces the vaguer "memorization-proof" idea with a surgical two-layer test.

## Case design (naming/relaxation convention spread)

| Case | Library | Relaxation mechanism | Convention |
|------|---------|----------------------|------------|
| A | libpng | `png_set_user_limits(...)` | snake_case setter, `_set_user` idiom |
| B | libtiff | `TIFFOpenOptionsSetMaxSingleMemAlloc(...)` | camelCase setter, `SetMax` |
| C | libxml2 | `XML_PARSE_HUGE` parse **flag** | option constant, **no setter fn** |
| D | libsndfile | `sf_command(f, SFC_SET_*, ...)` | command-code dispatch |

## Pre-registered predictions (before running)

- **Layer 1 heuristic**: A ✓ (proven in `../libpng/`). B ✗ — the regex requires
  snake_case `_set_`, so camelCase `SetMax` is missed. C ✗ — a flag constant is not
  a function definition; no name-heuristic can ever match it. D ✗ — `sf_command`
  is a generic dispatcher; the relaxation is an enum code, not a named setter.
- **Layer 2 LLM** (Case C, libxml2): should recover `XML_PARSE_HUGE` if given the
  HUGE-gated guard — the flag is the one lever the heuristic can never see.

## RESULTS — Layer 1 (deterministic heuristic sweep)

`extract_validation_gates` on freshly-cloned sources:

| Library | setters found | key relaxation API found? |
|---------|---------------|---------------------------|
| libpng | 8 (incl. `png_set_user_limits`) | **✓** |
| libtiff | **0** | ✗ |
| libxml2 | **0** | ✗ |
| libsndfile | **0** | ✗ |

**0/3 on the non-libpng libraries.** Two failure modes, and one is deeper than
naming:

1. **Naming (Case B).** libtiff *does* expose `TIFFOpenOptionsSetMaxSingleMemAlloc`
   — the idiom ("SetMax") is there, but camelCase, which the snake_case regex
   misses. A heuristic improvement (case-insensitive `set.*(max|limit)`) would
   catch it. **But note the polarity:** libtiff's `SetMax*` *impose* a cap (default
   0 = unlimited); they do **not** relax a restrictive default the way libpng's do.
   So even catching them would not "unlock" reachability — it is not a limit-gate
   in the libpng sense.
2. **Paradigm (Cases C, D).** libxml2's relaxation is a **parse flag**
   (`XML_PARSE_HUGE`, OR-ed into options) and libsndfile's is a **command code**
   (`SFC_SET_*` through `sf_command`). Neither is a setter *function*, so **no
   name-based extractor can ever find them** — and libsndfile's `SFC_SET_*` are
   mostly feature toggles (dither, header padding), not limit relaxation at all.

**Honest consequence:** the deterministic validation-gate mechanism is not merely
name-tuned — it is **paradigm-tuned to libpng's shape** ("restrictive default limit
+ a raise-setter"). That shape is not universal. The earlier "library-agnostic in
mechanism" phrasing was too generous and is corrected here.

## RESULTS — Layer 2 (LLM recovery, Case C = libxml2)

`run_libxml2_llm.py`, N=5, mistral-small, blocker-analysis prompt over the
HUGE-gated name-length guard:

| metric | rate |
|--------|------|
| names `XML_PARSE_HUGE` as the lever | **5/5** |
| names it **and** applies it via parse options | **5/5** |

Reasoning quality (spot-checked, rep 1): correctly explains the guard —
*"maxLength is XML_MAX_TEXT_LENGTH only when XML_PARSE_HUGE is enabled, otherwise
XML_MAX_NAME_LENGTH (default 1000); `len > maxLength` fails for long names"* — and
derives the correct trigger — *"a valid XML name char followed by 1001+ name
chars."* That is genuine understanding, not a pattern-match on the word "HUGE".

**Leakage caveat:** the guard snippet contains `XML_PARSE_HUGE` in its ternary
(that is how libxml2 writes it). So this measures *recognition + application*
(bridge flag → harness options), not *blind discovery* — the same bridge the
libpng L1 tested (struct field visible, setter API not). A blind-discovery test
would hide the flag; recorded as future work.

### The two-layer picture, isolated

| Case | Library | Layer 1 heuristic | Layer 2 LLM |
|------|---------|-------------------|-------------|
| A | libpng | ✓ finds the setter | ✓ (`../libpng/`: raises 3/5, blocker-ID 5/5) |
| B | libtiff | ✗ camelCase — *and* wrong polarity | not a real relax-gate (skipped) |
| C | libxml2 | ✗ structural (flag ≠ function) | **✓ 5/5 names + applies** |
| D | libsndfile | ✗ command-code, feature toggles | not a real relax-gate (skipped) |

**The isolated result:** the deterministic layer is libpng-paradigm-specific (0/3
on other libraries). The LLM recovers the one valid non-idiomatic case (libxml2,
where the lever is a flag no name-heuristic can ever match) 5/5. That is a **clean,
complementary LLM contribution over the deterministic analyzer** — narrow, but
real and measured, exactly where Layer 1 structurally cannot reach.

## RESULTS — where does the LLM's Case-C success come from? (mechanism-inference ladder)

`run_mechanism_inference.py`, N=5 each, same model. Three difficulty levels on the
same libxml2 guard: L1 shows `options & XML_PARSE_HUGE` verbatim; L2 hides it behind
an alias with `#define ALIAS XML_PARSE_HUGE` elsewhere in the snippet; L3 removes the
flag entirely (`maxLength = XML_MAX_NAME_LENGTH`, hardcoded) so the model must
*infer* that a separate configuration mechanism exists.

Scored on the **correct relaxation** (enable HUGE to *raise* the limit), not just
whether the string appears — because the crude metric overstates:

| level | guard shows | names `XML_PARSE_HUGE` | **correct: enable-to-raise** |
|-------|-------------|------------------------|-------------------------------|
| L1 recognition | the flag verbatim | 5/5 | ✓ (spot-checked correct) |
| L2 nearby inference | an alias + its `#define` | 5/5 | 5/5 |
| **L3 mechanism inference** | only the hardcoded limit | 2/5 | **0/5** |

**L3 collapses.** When the flag→limit structure is hidden, the model **never**
correctly infers "enable XML_PARSE_HUGE to raise the cap." The two reps that
*recalled* the name (libxml2 is famous) reasoned it **backwards** — proposing to
*disable* HUGE (`set options to 0`, `add XML_PARSE_NOHUGE`), which keeps the
restrictive limit. The rest proposed irrelevant options (`XML_PARSE_NOERROR`), a
source patch, or a vague buffer-size change. So the residual name-recall is both
unreliable (2/5) and semantically wrong (0/5 correct).

**Interpretation — the LLM's contribution is RECOGNITION + APPLICATION, not
mechanism inference.** Its Case-C win depends on *seeing* the guard structure that
links the flag to the limit (the ternary `(options & HUGE) ? big : small`). Given
that structure — even behind an alias — it reliably names and correctly applies the
lever (L1/L2: 5/5). Remove the structure and it fails (L3: 0/5 correct), its
libxml2 prior notwithstanding. The bounded picture the whole experiment establishes:

| scenario | Layer 1 heuristic | Layer 2 LLM |
|----------|-------------------|-------------|
| explicit setter (libpng) | ✓ | ✓ |
| flag/guard structure visible (libxml2 L1/L2) | ✗ | ✓ (5/5, direction correct) |
| mechanism hidden (libxml2 L3) | ✗ | ✗ (0/5 correct; 2/5 recall the name, backwards) |

Confound noted up front (libxml2 is famous): L3 conflates inference with recall.
But the finding survives it — even *with* the prior available, hidden-mechanism
inference fails. A truly clean L3 on an obscure library would only push the number
further down, not up. **"Mechanism inference" is not a capability NEMESIS can claim.**

## What this establishes

- The **deterministic layer is narrow**: it works on libpng-shaped
  restrictive-default + snake_case-setter libraries and misses everything else
  tested. That is a precise, defensible scope statement — not a general
  "semantic analysis" claim.
- The **LLM's complementary value** is exactly the Case-C/D regime, where the
  relaxation is not a name-matchable setter. The libxml2 run measures whether it
  delivers there.
