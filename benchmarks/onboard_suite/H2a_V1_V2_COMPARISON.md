# H2a v1 → v2 — comparative analysis

Written after both experiments closed, deliberately **not** folded into either results
document. v1 and v2 are separate experiments, each measured against its own control; this
compares two experiments, it is not a third one.

> **The entire v1 → v2 gain is regression elimination. v2 introduced no new recovery
> capability — and that is what a conservative refinement is supposed to look like.**

## 1. Why the comparison is admissible

The two treatments ran days apart, on different code, in different sessions. What makes them
comparable is not that assumption but a checkable fact:

> Both arms' controls produced the **same genuine-T2 set** — `bcg729`, `onomondo-uicc`,
> `pg_ivm` (3 repos).

v1's control was classified by applying the oracle post-hoc to its build directories; v2's by
post-run artifact re-derivation. They agree repo for repo, including astera's rejection as
`only_vendored_artifact`. The two treatments therefore sit on a common baseline, and a
difference between them is a difference between the operators.

Where this stops: it does not license claims about anything the controls did not fix in
common, and it is not a head-to-head run of the two operators in one session.

## 2. Outcome deltas

| | v1 | v2 |
|---|:---:|:---:|
| Genuine T2 | 5 | **7** |
| Recoveries | 4 | 4 |
| Recoveries lost | — | **0** |
| New recoveries | — | **0** |
| Regressions | **2** | **0** |
| Oracle-only correction | 1 (gifsicle) | censored (§5) |

Recoveries, repo for repo: `gensio`, `tiny-AES-c`, `libdc`, `astera` — **identical sets**.

The two repos v2 gained are exactly the two v1 broke:

```
v2 genuine T2  =  v1 genuine T2  +  { onomondo-uicc, pg_ivm }
                                     └── v1's two regressions
```

So the honest reading of "5 → 7" is not that v2 fixes more projects. It is that v2 stops
breaking two projects that were **already working before either operator ran**.

## 3. Intervention precision

This is the dimension where the operators differ most, and it is not visible in the T2 count.

| | v1 | v2 |
|---|:---:|:---:|
| Repositories | 25 | 25 |
| Builds modified | **25 (100 %)** | **14 (56 %)** |
| Builds left untouched | 0 | 11 |
| Harmful modifications | 2 | 0 |

v1 modified **every build in the suite** — a direct consequence of its rule ("replace any
specific target"), combined with the fact that the onboarder never emits a default build.
v2 modified 14 and reached a strictly better outcome.

Of the 11 interventions v2 judged unnecessary, **three were on repositories the control had
already built genuinely**: `bcg729`, `onomondo-uicc`, `pg_ivm`. One was harmless; two
destroyed a working build. That is the precise cost of unconditional intervention, and it is
measurable rather than rhetorical:

```
v1: 25 interventions, 11 unnecessary, 2 harmful   -> 5 genuine T2
v2: 14 interventions,  0 unnecessary by this test -> 7 genuine T2
```

"Unnecessary by this test" is load-bearing, and the claim should be stated at exactly its
scope:

> On these frozen configurations, the eleven non-intervention decisions lost no genuine T2
> and avoided both known harmful interventions.

What must **not** be claimed is that KEEP is always safe. The evidence bounds the decision on
this suite, under these configs; it does not establish a general property of withholding
repair.

## 4. Where the improvement actually came from

Each v2 keep-decision traces to a rule, and each rule to the evidence that forced it:

| Repo | v1 | v2 | Rule | Requirement |
|---|---|---|---|---|
| onomondo-uicc | replace → LINK_FAILURE | keep → `libuicc.a` | `declared_project_target` | R1 conservative replacement |
| pg_ivm | replace → COMPILE_FAILURE | keep → `pg_ivm.so` | `command_falls_back_to_default_build` | R3 build-system awareness |

pg_ivm is the more interesting of the two. Its config is `ninja libpg_ivm.a || ninja` — a
meson project whose build command already carries its own fallback. v1 replaced the whole
command with `make -j$(nproc)`, discarding the build system *and* the recovery the command
already contained. The unit that had to be protected was never the target name; it was the
pair **(build system, build command)**, of which R1 is a special case.

## 5. What v1 has that v2 does not

v2 does not supersede v1's evidence. Two things live only in v1:

- **The falsification itself.** v1 is the experiment that showed unconditional replacement is
  unsafe. v2's design is downstream of that result and cannot substitute for it.
- **The oracle-only correction.** In v1, gifsicle built successfully and the oracle rejected
  it (`no_project_library_artifact`) — a false success caught at the measurement layer. In
  v2 the same repo's `configure` failed on an autotools timestamp check, so the oracle was
  never reached: a **censored observation**, not a reproduction. v2 did, however, produce an
  independent confirmation of the underlying diagnosis from its control arm, where the
  unmodified target made `make` answer `No rule to make target 'libgifsicle.la'` — matching
  the static validator's `undeclared_target`.

## 6. What neither version changes

Both operators stop at the same wall. In v1 and in v2, **every** genuine-T2 repository then
fails at T3 harness generation. Raising genuine T2 from 3 to 7 moved the failure, it did not
remove it — and astera shows why the next question is a different one: it now builds
`libastera.a` and fails T3 with LINK_FAILURE because the frozen config's `library_name` still
names the vendored `dep/glfw/src/libglfw.a`. Target correction and artifact-identity
correction are different operators, and only the first exists.

---

*Summary: v1 established that target correction can recover build targets. v2 establishes
that it must be selective — and pays 13 ms per repository to know when intervening is more
dangerous than the failure it would fix.*
