# H2a — results (frozen control vs target-repair treatment)

Evidence artifact for the first H2a experiment. Written to **freeze the interpretation
before the next iteration**. It records what was tested, against which control, which
recoveries occurred, which regressions appeared, and what change the data forces on the
operator. Headline framing, up front:

> **H2a validated the target-correction hypothesis but falsified the naive replacement
> policy.**

## 1. Experiment definition

| | |
|---|---|
| Branch | `treatment/h2a-target` (0e52b05) |
| Intervention | `nemesis setup --target-repair` (Phase 1 target correction + Phase 2 genuine-target oracle) |
| Treatment run | `run_suite --target-repair --frozen-configs`, experiment `4d1e4d6e` |
| Control run | `run_suite --frozen-configs` (no repair), same experiment id, `_T211234Z` |
| Constraints | no auto-deps · no config regeneration (Config-freezing invariant) · same frozen configs · **oracle applied to BOTH** arms (post-hoc on the control's build dirs, since the control has no oracle) |

The two runs differ in exactly one variable: `--target-repair`. They ran serially (the
benchmark workspace is not concurrency-isolated; the treatment's transient artifacts were
cleaned before the control to prevent cross-run build contamination).

**Limitation (documented, not blocking).** The system carried ~150 packages installed by
the earlier H1 run. Both arms share this identical state, so the treatment−control
comparison still isolates `--target-repair`; only the *absolute* reachability of some repos
(e.g. astera builds because OpenAL is present) is conditional on that state.

## 2. Executive findings

> H2a demonstrates that build-acquisition failures contain **multiple distinct failure
> classes**. A deterministic target-repair operator recovered **four genuine targets** and
> exposed **one measurement failure mode**, but the initial **unconditional** replacement
> strategy caused **two regressions** on previously valid targets.

Genuine-T2 (oracle-validated): control **3** → treatment **5**. The raw +2 hides four
recoveries and two regressions.

## 3. Attribution table (genuine-T2)

| Repo | Frozen control | H2a | Result |
|---|:---:|:---:|---|
| gensio | fail | pass | **recovery** — broken build ordering |
| tiny-AES-c | fail | pass | **recovery** — wrong target name |
| libdc | fail | pass | **recovery** — target/codegen via default build |
| astera | fail *(false: only glfw)* | pass | **recovery** — target-identity conversion |
| bcg729 | pass | pass | maintained *(operator-safety evidence)* |
| onomondo-uicc | pass | fail | **regression** |
| pg_ivm | pass | fail | **regression** |
| gifsicle | fail | fail | **oracle-only correction** *(see §4 — not a recovery/regression)* |
| + 17 repos | fail | fail | unresolved (dependencies / out-of-scope) |

`gifsicle` is deliberately **not** filed under "unresolved". Its result is not "did not
build" — it is **build completion ≠ genuine target availability**, a distinct property.

## 4. Oracle findings

The oracle is not only a filter; **astera shows it can reveal that an intervention changed
the identity of the target**.

```
astera — control (no repair)        astera — H2a (target repair)
  build success                       default build
        ↓                                   ↓
  only vendored artifact (glfw)       project artifact exists (libastera.a)
        ↓                                   ↓
  oracle REJECT                       oracle ACCEPT
```

So the control's astera "T2" was a **false success** (the benchmark's original T2 classifier
would have counted it — the same defect H1 hit). Under the oracle it is rejected; under H2a
it becomes a *genuine* build of the project's own library.

The oracle changed the T2 verdict in **two** places: `gifsicle` (treatment build-success →
rejected) and `astera` (control build-success → exposed as vendored-only). This is an
**independent** contribution from target repair.

## 5. Regression analysis

Not a footnote — the most important limitation the run produced.

### onomondo-uicc
- Control: **genuine T2** (`libuicc.a`)
- H2a: **LINK_FAILURE** (T1)
- Cause: unconditional target replacement — the declared specific target was valid; the
  default build links artifacts that fail.

### pg_ivm
- Control: **genuine T2** (`pg_ivm.so`)
- H2a: **LINK_FAILURE** (T1)
- Cause: unconditional default-build preference over a valid declared target.

**Conclusion.**

> The Phase 1 policy "replace the target with the default build" is **invalid when an
> existing target declaration is already valid**. onomondo was not a config artifact; it is
> a real regression, confirmed against a frozen-config control.

## 6. Operator refinement (mandated by the data)

v1 is **rejected**:

```
if a specific target is selected:
    replace it with the default build      # too aggressive — regressed onomondo, pg_ivm
```

v2 (next iteration):

```
if the selected target is invalid / undeclared:
    replace it (default build, or a discovered valid target)
else:
    preserve the declared valid target
```

Validation signals for "is the target valid?":
- CMake declared target (`add_library` / `add_executable` names)
- Autotools library declarations (`lib_LTLIBRARIES`, `bin_PROGRAMS`)
- Make target existence (a rule exists for it)
- artifact-ownership oracle (Phase 2, unchanged)

This is no longer a hypothesis — it is a **requirement derived from observed regressions**.

## 7. Final classification

Mutually-exclusive outcomes (sum to 25):

| Outcome | Count |
|---|---:|
| Genuine recoveries | 4 |
| Maintained targets | 1 |
| Regressions | 2 |
| Oracle-only correction (false success caught) | 1 |
| Unresolved | 17 |

Cross-cutting (overlaps the above): **oracle verdict corrections = 2** (gifsicle treatment,
astera control).

> Counts are **not** collapsed into a single score: recovery, safety (no regression on a
> valid target), and measurement correction are different properties and must be reported
> as such.

---

*This document freezes H2a v1. The historical record — hypothesis → intervention → evidence
→ falsification → refinement — is kept intact; v2 (conservative target validation) is a
separate future intervention, not an edit to this result.*
