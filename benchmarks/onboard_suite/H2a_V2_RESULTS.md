# H2a v2 — results (frozen control vs conservative target validation)

Evidence artifact for the H2a v2 experiment, pre-registered in `H2a_V2_DESIGN.md` and run
against a **fresh paired control**. Headline, up front:

> **Every pre-registered requirement was met, and the pre-registered prediction — genuine
> T2 = 7 — was met exactly. Four recoveries, three maintained, zero regressions.**

The result that matters is not the count. v1 showed that more build targets *can* be
corrected; v2 shows that the system can decide **when not to intervene** — and pays nothing
for the knowledge.

## 1. Experiment definition

| | |
|---|---|
| Branch | `treatment/h2a-target-v2` (`688a262`) |
| Control | `run_suite --frozen-configs --run-id h2a_v2_control` — 14:19→14:55, rc 0 |
| Treatment | `run_suite --frozen-configs --target-repair --run-id h2a_v2_treatment` — 14:55→16:05, rc 0 |
| Variable | `--target-repair` — nothing else differs |
| Constraints | frozen configs (no T1 regeneration) · no dependency installation · no system mutation · serial execution · **symmetric pre-arm reset** of every work copy and build directory |
| Experiment id | `d4d2845b` (differs from the locked baseline id, as expected for changed code; recorded in the results) |

A fresh control was run rather than reusing the v1 control: v2 is a different intervention
(new predicate, new decision procedure), and a control is only cheap if it is
*unquestionably* the right control for the treatment it is paired with.

## 2. Two kinds of number in this document

The symmetric pre-arm reset removed the control's build directories before the treatment
started, and the control — having no oracle — never recorded artifact identity. So:

- **Primary measurements** (tiers, failure classes, timings) are what each arm recorded
  during its run. They are not revised here.
- **Artifact identity for the control** comes from a separate, later stage:
  **post-run artifact re-derivation** — the four repos that reached raw T2 in the control
  were rebuilt with the *identical* control command (`nemesis setup -t X`, no flags, frozen
  config, arm starting condition reproduced), and the shipped oracle was applied by code.
  This produces **oracle classification only**. The output file declares its own status in a
  `_provenance` block so it cannot later be read as arm data.

This is a reconstruction of a measurement that was never stored — not a re-run of the arm.
It is also why §8 makes the artifact inventory a framework invariant.

## 3. Attribution (genuine T2)

Control **raw T2 = 4**, **genuine T2 = 3** (astera's raw T2 is rejected by the oracle:
`only_vendored_artifact`). v2 **genuine T2 = 7**.

| Repo | Control | v2 | Phase 0 verdict | Outcome |
|---|:---:|:---:|---|---|
| gensio | fail | **genuine** | replace — `subdir_invocation_bypasses_root_build_graph` | **recovery** |
| tiny-AES-c | fail | **genuine** | replace — `undeclared_target` | **recovery** |
| libdc | fail | **genuine** | replace — `subdir_invocation_bypasses_root_build_graph` | **recovery** |
| astera | fail *(vendored-only)* | **genuine** | replace — `declared_in_vendored_subtree` | **recovery** |
| bcg729 | genuine | genuine | keep — `declared_project_target` | maintained |
| onomondo-uicc | genuine | genuine | keep — `declared_project_target` | maintained |
| pg_ivm | genuine | genuine | keep — `command_falls_back_to_default_build` | maintained |
| gifsicle | fail | fail | replace — `undeclared_target` | **censored** (§5) |
| + 17 repos | fail | fail | — | unresolved |

**Zero regressions.** The three targets the control built genuinely were all kept intact —
and two of them (`onomondo-uicc`, `pg_ivm`) are precisely the repos v1 regressed. Both were
preserved with `target_repaired=False`: the operator's contribution there was to *do
nothing*, deliberately and for a recorded reason.

Each recovery fired through a different rule, and each rule was forced by different
evidence:

```
gensio      declared, but -C glib bypasses its parent lib/   -> reachability rule
tiny-AES-c  configured tiny_AES_c, declared tiny-AES-c       -> identity rule (no normalisation)
libdc       declared, but -C src bypasses the build graph    -> reachability rule
astera      glfw declared — inside dep/glfw (vendored)       -> ownership rule
```

The astera case is the one the supplementary audit (`H2a_astera_audit.md`) predicted: a
*declared, valid* CMake target belonging to a bundled dependency. It is the only repo in the
suite whose verdict came from the ownership rule, and it converted a vendored-only false
success into a genuine `libastera.a`.

## 4. Exit criteria (pre-registered in `H2a_V2_DESIGN.md` §6)

| # | Condition for rejecting v2 | Observed | |
|---|---|---|:---:|
| 1 | any v1 recovery lost | none — all four recovered | ✅ |
| 2 | any new regression on a control-genuine target | none | ✅ |
| 3 | genuine T2 not exceeding v1's 5 | 7 | ✅ |
| 4 | a KEEP that preserved a false success | **none** — no repo was both `validate_keep_target` and `oracle=reject` | ✅ |

Criterion 4 is the one that would indict the validity predicate itself rather than its
implementation. It is reported separately for that reason, and it is clean.

The static pre-flight predicted the executed verdicts **exactly** — same distribution
(9 `declared_project_target`, 9 `undeclared_target`, 4 subdir, 2 fallback, 1 vendored), same
repos. The validator is deterministic in practice, not only by construction.

## 5. gifsicle — a censored observation, not a result

Pre-registered expectation: replace → build succeeds → **oracle rejects** (gifsicle is an
application; it declares no library). Observed: the target was replaced as predicted, and
then `configure` failed:

```
configure: error: newly created file is older than distributed files!  Check your system clock
```

An autotools timestamp check. The measurement point was never reached, so this is a
**censored observation** — neither a confirmation of the oracle nor a failure of the
operator, and it is not filed as either. The oracle-only correction cell is **not
reproduced** in this experiment.

It is not attributable to the intervention: the operator modifies only the `make` command,
and the failure occurred in `configure`, which is byte-identical in both arms. It appeared in
one repo, in one arm, in no other run.

**But the control produced something better than the expected reject.** In the control the
target was left as configured, and `make` answered directly:

```
make: *** No rule to make target 'libgifsicle.la'.  Stop.
```

which is an independent confirmation, by the build system itself, of what the static
validator had already concluded — `undeclared_target`:

```
static validator: undeclared_target
        ↓
control build attempt (target unmodified)
        ↓
build system: "No rule to make target"
```

A confirmed true positive for the validator, obtained without the validator being involved.
This is a stronger form of evidence than the reject it replaced, and it was not designed for.

## 6. Cost: the operator is not what makes the treatment slower

The treatment took ~70 minutes against the control's ~36. None of that difference is the
operator.

**Operator execution cost** — Phase 0, measured from the arms' own log timestamps across all
25 repos: **min 8 ms, median 13 ms, max 42 ms.** Four orders of magnitude below the tier
timeouts; it cannot account for any wall-clock difference.

**Pipeline continuation cost** — the treatment brought seven repos to genuine T2 instead of
three, and every genuine T2 goes on to attempt T3 harness generation, which is LLM-bound and
budgeted at 1800 s. The treatment is slower **because it succeeded more often**.

Reporting a single wall-clock delta would invert the meaning of the result. The two costs are
therefore reported separately and never summed.

## 7. Independent result: control-path stability

The fresh control reached raw T2 on exactly the same four repos as the v1 frozen control
(bcg729, onomondo-uicc, pg_ivm, astera) — three days later, from a different commit, with the
whole validator added to the codebase. Post-run re-derivation also reproduced v1's oracle
verdicts, including astera's `only_vendored_artifact` rejection.

Scope, stated precisely: this shows the **control path is stable under identical
conditions**. It is not a claim of full reproducibility of the benchmark.

## 8. What this experiment does not show

- **Nothing reaches T3.** All seven genuine-T2 repos then fail at harness generation
  (COMPILE_FAILURE ×5, HARNESS_VALIDATION_FAILURE, LINK_FAILURE). The wall has **moved**
  from T2 to T3; it has not fallen. H2a delivers genuine build targets, not fuzzable
  harnesses.
- **Target correction is not artifact-identity correction.** astera reaches genuine T2 with
  `libastera.a` and then fails T3 with LINK_FAILURE, because the frozen config's
  `library_name` still points at `dep/glfw/src/libglfw.a` — the vendored artifact of the
  target that was just corrected. Both arms log `library_not_found`. These are two different
  operators, and the second does not exist.
- **No v1 comparison is made here.** v1 and v2 are different interventions measured against
  different controls; a v1↔v2 analysis is separate work and is deliberately not folded into
  this pair.
- **17 repos remain unresolved** for reasons outside H2a (dependencies, toolchains,
  out-of-scope build systems).

## 9. Framework invariant discovered by this run

> **Every completed arm MUST persist an artifact inventory before workspace cleanup.**

The symmetric pre-arm reset — correct for arm symmetry — destroyed the control's build
directories, and the control has no oracle, so its genuine-T2 could not be read off the
finished run. The recovery (§2) worked, but provenance should not depend on a reconstruction
being possible. Order: `arm completes → snapshot artifact inventory → cleanup workspace`.

This is the same pattern as the config-freezing invariant: the protocol discovered a
requirement *because a run tried to violate it*. It is implemented separately from this
experiment, never mixed into it.

## 10. Refined statement of R3

`H2a_V2_DESIGN.md` states R3 as "build-system awareness". The pg_ivm evidence supports a
stronger and more useful formulation:

> The unit the operator must protect is not the target but the pair
> **(build system, build command)**.

v1 did not merely replace a target name in pg_ivm — it discarded the build system *and* the
command's own `|| ninja` fallback. Under this reading R1 (conservative replacement) is a
special case: do not throw away valid information already present in the configured command.
Recorded here rather than in the design document, which stays as pre-registered.

---

*H2a v2 is complete. The conservative, ownership-aware predicate satisfies every requirement
that v1's falsification produced, at a measured cost of ~13 ms per repository.*
