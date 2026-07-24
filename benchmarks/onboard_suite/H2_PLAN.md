# H2 — autonomous build convergence: pre-registered plan

Written **before** any H2 implementation, for the reason the baseline metrics and the
H1 protocol were frozen first: an experiment that defines its success criterion after
seeing the result is not an experiment. H1 (see [H1_PROTOCOL.md](H1_PROTOCOL.md) and its
run `baseline_8606b70d_491eaad8`) was a **cartographic** experiment — it did not merely
improve NEMESIS, it revealed the *structure* of the problem. This plan turns that
structure into a set of **independently evaluable repair capabilities**, each with its own
protocol, governed by shared validity invariants.

## What H1 changed

H1 measured that automatic dependency resolution is **necessary but insufficient**:
19/19 installs succeeded, yet `gvm-libs` resolved 8 dependencies and still failed at
configure, and `turbovnc` chained 4 and hit an arbitrary budget. The obstacle is not a
missing package — it is **convergence over a repair graph**. It also exposed a
*false success*: `astera` "reached T2" by building a **bundled GLFW dependency**
(`library_name: dep/glfw/src/libglfw.a`), not its own target.

**Problem reframe (thesis-level).** The core contribution is **autonomous build
acquisition / convergence for arbitrary C/C++ repositories** — turning a repository into a
buildable artifact with no human intervention. Fuzzing is not dropped: it is the
**driving application and the success criterion**. "Buildable *and* has a fuzzable entry
point" (T5), not merely "compiles", is what distinguishes this from generic CI and keeps
the OSS-Fuzz-Gen comparison meaningful.

## Success criteria (declared before implementation)

H1's central lesson is that **"moved further" is not "succeeded"** — a repository that
resolved 8 dependencies and still failed did not succeed. H2 as a whole is declared a
success only if **all** of the following hold. Each is measurable against the frozen suite.

1. **Genuine T2 increases** — measured under the Target-validity invariant, not nominal/raw
   T2. A build that reaches T2 by producing a bundled dependency does not count.
2. **The increase survives the target-validity audit** — including the re-audit of the
   existing baseline (2) and H1 (4) T2 results.
3. **Median repair depth does not increase disproportionately** — a build that needs 15
   repair operators to reach T2 is a warning about the approach, not a win.
4. **False-success rate does not increase** — spurious / wrong-target "T2" builds must not
   grow; ideally they fall (H2a should remove astera's).
5. **Every improvement is attributable to a specific recorded repair operator** — via the
   Repair-independence invariant and the repair trace. An unattributable gain is not a
   result.

A partial outcome (e.g. genuine T2 unchanged, but false-success rate falls and repair
traces become interpretable) is reported honestly as such — not relabelled a success.

## Validity invariants (bind every H2 intervention)

These are **invariants, not caveats**. A run that violates one is invalid, not merely
noisy.

- **Target validity.** A repository is considered to have reached T2 only if the produced
  artifact corresponds to the **intended project target**, not a bundled dependency or
  third-party component. Artifacts built from `dep/`, `deps/`, `third_party/`, `vendor/`,
  `external/`, `contrib/` subtrees do not count. All existing T2 results (baseline's 2 and
  H1's 4) are **re-audited** under this invariant before any H2 number is reported.
- **Progress.** Progress is recorded only when the current failure state differs
  **semantically** from the previous one — compared as a normalised tuple
  `(locality, missing-artifact identity, top error-frame signature)`, **never** by raw log
  substring. This invariant is load-bearing: the convergence loop's termination depends on
  it (see H2b, H2c).
- **Repair independence.** Every repair capability must be **independently disableable and
  independently measurable** (a config flag per operator). This is what makes later
  ablations possible: if H2c fails but H2a succeeds, the results must say so.

## The system is a set of repair operators, not "a smart agent"

The convergence engine does not reason; it applies **measurable repair operators**. Each
operator is a pure function of a classified failure state.

| Repair operator | Input (failure signature) | Success criterion |
|---|---|---|
| Dependency install | missing package (header / pkg-config / library / tool) | failure state changes (semantic) |
| Recursive submodule | missing / empty submodule source | build progresses past that source |
| Generated sources / bootstrap | missing generated file (`revision.h`, `config.h`) or absent `configure` | the file / script now exists |
| Configure flags & paths | configure error, or dependency present but sought elsewhere | configure proceeds past that point |
| Target inference | wrong or absent build target; artifact ≠ intended target | a **genuine** target artifact is built |

## New recorded dimension: repair trace

Tiers (T0–T5) are one axis. H1 revealed a second: **repair depth**. Every repository run
records a **repair trace** — the ordered list of repair operators applied and the failure
state each cleared:

```
configure → dep(libgmime) → dep(libpcap) → codegen(autogen) → target(fix) → compile
```

This is recorded, not scored as a tier. It enables analyses the T-funnel cannot express,
e.g. "repositories needing > 5 repair operators never reached genuine T2" or "70 % of
genuine builds completed with ≤ 2 operators." The trace is the primary artifact of the
convergence study.

## The five interventions (each independently pre-registered)

Splitting H2 into independent interventions is deliberate: a single "H2 = convergence
engine" hypothesis could not tell us *which* repair earned the result.

### H2a — Genuine target inference  *(priority 1; validity-critical)*
- **Motivation.** `astera` produced a *false success* by building bundled GLFW; `gifsicle`,
  `tiny-AES-c`, `gensio` failed because NEMESIS invented a make target (`libX.la` / `X`)
  the project does not define. False successes are worse than failures — they poison the
  metric for every repository.
- **Intervention.** Derive the library/target from the project's own build system, excluding
  vendored subtrees; stop inventing targets.
- **Expected effect.** `gifsicle`, `tiny-AES-c`, `gensio` reach **genuine** T2; `astera`'s
  spurious T2 is **removed** (genuine-T2 may drop before it rises — reported honestly).
- **Primary metric.** genuine-T2 count (Target-validity invariant applied).
- **Secondary.** spurious T2 corrected; target-inference errors detected across all 25.
- **Threats.** "intended target" is itself an inference; it must be defined mechanically
  (the target the project's build files name, minus vendored subtrees) and frozen.

### H2b — Failure-state metric reliability  *(priority 1; prerequisite for H2c)*
- **Motivation.** H1's `cleared` / `false_positive_install` / `made_progress` are
  substring-based and unreliable (turbovnc: cleared=1/fp=3 despite clean chaining; dbmail:
  made_progress=False despite installing gmime and changing failure stage). The fixed-point
  loop cannot terminate correctly on an unreliable progress signal.
- **Intervention.** Replace substring matching with the **semantic failure-state**
  comparison defined in the Progress invariant.
- **Expected effect.** A trustworthy progress/no-progress signal.
- **Primary metric.** agreement with a hand-labelled subset of repair transitions.
- **Secondary.** count of corrected false made_progress / false_positive labels in H1's run.
- **Threats.** the definition of "semantically different failure" is a design choice; it is
  fixed here (different locality, or different missing-artifact identity, or different top
  error frame) and not tuned to outcomes.

### H2c — Fixed-point dependency convergence
- **Motivation.** `max_attempts = 4` has no theoretical basis; `turbovnc` hit it at dep #4,
  `gvm-libs` needed 8.
- **Intervention.** Replace the budget with a fixed-point loop:
  `while progress: classify → repair → retry`, terminating on **success**, **identical
  failure** (no progress, per H2b), or **out-of-scope**. A large, justified hard cap guards
  against pathological oscillation, and the termination reason is always recorded.
- **Expected effect.** deep-chain repos either converge to genuine T2 or terminate with a
  clearly identified **non-dependency** blocker (the residual problem, made explicit).
- **Primary metric.** genuine-T2 among DEP-class repositories.
- **Secondary.** repair-depth distribution; count terminating on a non-dependency blocker.
- **Threats.** correctness depends entirely on H2b; without a reliable progress signal the
  loop is unbounded or premature — hence the ordering.

### H2d — Code generation & acquisition
- **Motivation.** `iris` (uninitialised submodule) and `libdc` (missing generated
  `revision.h`) fail on absent sources, not missing packages.
- **Intervention.** recursive submodule init; run project bootstrap / code-gen
  (`autogen.sh`, `./bootstrap`, generated-header rules) as repair operators.
- **Expected effect.** `iris`, `libdc` reach genuine T2.
- **Primary metric.** genuine-T2 among CODEGEN-class repositories.
- **Secondary.** which acquisition operators fired.
- **Threats.** running a project's own bootstrap script executes untrusted code; restrict to
  a known, named set of scripts and record every invocation.

### H2e — Configure / path repair
- **Motivation.** `turbovnc` had `libturbojpeg0-dev` installed in `/usr/include` but its
  `FindTurboJPEG.cmake` searches a hard-coded `/opt/libjpeg-turbo/include` — installed but
  not found. Plus known `-D<OPT>=ON/OFF` toggles.
- **Intervention.** infer/set configure flags and redirect finders to system paths from a
  **curated** operator set (not open-ended flag search).
- **Expected effect.** installed-but-not-found and known-option failures resolve.
- **Primary metric.** configure failures repaired.
- **Secondary.** flags/paths applied.
- **Threats.** flag inference is open-ended and can mask a real incompatibility; restricted
  to a curated, reviewable set and every change recorded in the repair trace.

## Exit criteria (pre-declared abandonment conditions)

An operator is not "attempted and kept". Each carries a stop condition, fixed now, so a
null or harmful result is a **recorded outcome**, not a silent tweak. Stating when a repair
would be judged a failure — before building it — is what separates a protocol from a
post-hoc justification.

| Intervention | Abandon (declare failed) if |
|---|---|
| **H2a** target inference | it introduces **any** new false success, or yields 0 additional genuine-T2 |
| **H2b** metric reliability | the semantic comparator does not beat substring on the hand-labelled transition set |
| **H2c** fixed-point convergence | median repair depth to genuine-T2 exceeds a pre-set bound **without** raising genuine-T2, or convergence probability plateaus |
| **H2d** codegen & acquisition | < 1 genuine recovery, or a bootstrap/codegen operator causes a regression on a previously-passing repo |
| **H2e** configure/path repair | it breaks a previously-passing configure (regression), or contributes < 1 genuine recovery |

The two global guards over all operators: **false-success rate must not rise**, and every
retained operator must have ≥ 1 attributable genuine recovery (Repair-independence → ablation).

## Ordering and protocol

1. **H2a + H2b first** — H2a restores the validity of the very metric being measured;
   H2b makes the progress signal reliable. Both are prerequisites: measuring H2c on an
   invalid metric or an unreliable progress signal would be meaningless.
2. **H2c → H2d → H2e** — each on its own branch, each independently disableable.
3. **Harness generation (H3 / the old "H2.4")** — only once enough repositories reach
   **genuine** T2 to make harness-quality measurable.

**Evaluation.** Same frozen `repos.yaml`, same instance `491eaad8`. Each intervention is a
controlled change against baseline `b8b7cf70`, run unattended, reported as **genuine-T2**
(Target-validity invariant) plus the repair-trace distribution — never raw T2. Because
every operator is independently disableable, the final ablation attributes the effect to
specific operators rather than to an opaque "engine". No intervention is declared a success
on a metric it did not pre-register here.

*Control: experiment `b8b7cf70` (baseline). H1: experiment `8606b70d`. H2 interventions:
new experiment ids, recorded per run.*
