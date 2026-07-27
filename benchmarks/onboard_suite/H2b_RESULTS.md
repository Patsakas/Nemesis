# H2b — results (identity-aware resolution, paired on a shared build)

Evidence artifact for the first H2b evaluation, pre-registered in `H2b_PLAN.md`.
Headline, up front, because the pre-registered rule decides it and not the numbers:

> **The mechanism works exactly as designed on its witness, the regression guard holds —
> and the pre-registered single-witness exit criterion is TRIGGERED. H2b is refined, not
> reported.**

## 1. Design

Each repository was built **once**, with the H2a v2 command (`nemesis setup -t X
--target-repair`), and then resolved **twice** — identity off, identity on — against that
same tree. The build is shared by construction, so the resolution criterion is the only
thing that can differ between the arms. This is a stronger pairing than two suite runs, and
it needs no LLM, which is what `H2b_PLAN.md` §5 required given the provider outage.

All seven repositories rebuilt to `genuine_t2=True`, reproducing the H2a v2 treatment for a
third time.

## 2. Primary metric — symbol containment (n = 2, as declared)

| Repo | Arm | Selected | Class |
|---|---|---|---|
| **astera** | control | `dep/glfw/src/libglfw3.a` | **unsatisfied** |
| **astera** | H2b | `libastera.a` | **satisfied** |
| onomondo-uicc | control | `src/softsim/uicc/libuicc.a` | satisfied |
| onomondo-uicc | H2b | *unchanged* | satisfied |

**False artifact acceptances: 1 → 0. None introduced. No previously correct resolution
changed.** The one changed resolution is attributable to a recorded identity decision
(`strategy=identity_ownership`), and the interface contract was not violated: the operator
consulted ownership only, the evaluator symbols only.

The other five repositories are `undetermined` — their frozen configs carry the placeholder
`function_name` rather than a real symbol. That is the declared coverage limit, and it is not
scored in either direction.

## 3. The exit criterion that fires

`H2b_PLAN.md` §6 pre-registered:

> H2b is rejected or refined if … the only demonstrable effect is on astera. One witness is a
> motivating case, not a result.

Across all seven repositories, exactly **one** resolution changed: astera. So the criterion
applies as written. The measurement is real and the operator is sound, but a single witness
does not establish the hypothesis, and this document does not claim it does.

## 4. Why only one — the population decomposes

`library_name` is wrong in four of the seven repositories. The evaluation shows those four
fail through **four different mechanisms**, and H2b's ownership rule addresses exactly one:

| Repo | Configured | Produced | Mechanism | H2b |
|---|---|---|---|---|
| astera | `dep/glfw/src/libglfw.a` | `libastera.a` | names a **vendored dependency** | **corrected** |
| tiny-AES-c | `libtiny_aes_c.a` | `libtiny-aes.a` | name spelling | already handled by `fuzzy_glob` |
| pg_ivm | `libpg_ivm.a` | `pg_ivm.so` | **artifact kind** (`.a` vs `.so`) | not addressed — `not_found` in both arms |
| gensio | `glib/.libs/libgensioglib.a` (230 KB) | `lib/.libs/libgensio.a` (8.1 MB) | **wrong project-owned artifact** | **invisible to the rule** |

### 4.1 gensio is the important one

Its configured library exists, so resolution succeeds by `exact_path`. Both the selected
`libgensioglib.a` and the main `libgensio.a` are project-owned, so the ownership predicate
does not fire — and the symbol metric cannot see the case either, because gensio's config has
no pinned function. It is plausibly a false acceptance that **neither the operator nor the
evaluator can currently detect**.

> Ownership separates *project* from *vendored*. It does not decide *which* project artifact.

The size gap (230 KB against 8.1 MB) is recorded as an observation and **not** as a rule.
"Larger is the right one" is not established by a single case, and adopting it because it
happens to hold for gensio would be exactly the kind of unvalidated heuristic this operator
was written to avoid.

### 4.2 pg_ivm shows a third class

The config names `libpg_ivm.a`; the build produces `pg_ivm.so`. Every resolver glob is
`lib*.a`, so nothing is found in either arm. H2b correctly does not rescue it — the operator
re-decides a selection and does not invent one — but the gap is real and belongs to a
different operator.

## 5. Refinement mandate

Derived from the data, not from preference:

1. **Artifact kind belongs in resolution** — it rests on an objective mismatch rather than a
   heuristic: the config requests an archive, the build produced a shared library, and
   nothing has to be inferred to see it. **But its population is 1.** Measured across the
   seven repositories that have artifacts at all: kind mismatch occurs in `pg_ivm` alone,
   exactly as vendored-name occurs in `astera` alone. Promoting it to "the next operator"
   would recreate the single-witness situation this document was written to refuse — before
   the operator was even written. It is recorded as a known defect, not scheduled as the next
   hypothesis.
2. **Ownership is necessary but not sufficient.** Some second criterion is needed to choose
   among project-owned candidates, but the evidence does not yet name it. Build-graph
   position and symbol breadth are *possible discriminators to investigate*, not the next
   discriminator: one case cannot establish either, and symbol breadth would additionally
   collide with the information-leakage invariant unless the evaluator changes with it.
   Choosing a discriminator on this evidence would repeat v1's mistake of generalising from
   the case in front of us.
3. **The evaluator's coverage is a binding constraint, not the operator's.** Five of seven
   configs cannot be judged at all. Route 2 (header-derived symbol sets) has to be built and
   validated before any wider claim is possible — including the claim that H2b *failed* to
   help elsewhere.

### 5.1 The structural finding: artifact-level work is population-bound

An artifact-level operator can only be evaluated where artifacts exist, so its population is
**the genuine-T2 set — seven repositories** — and within that, each distinct mechanism has one
or two witnesses. Measured:

| Mechanism | Witnesses |
|---|---:|
| vendored name | 1 (astera) |
| artifact kind | 1 (pg_ivm) |
| wrong project-owned artifact | 1 (gensio, and unmeasurable today) |
| name spelling | 1 (tiny-AES-c, already handled) |

No refinement of artifact resolution can escape n≈1 at present. That is not a property of any
particular operator; it is a property of the sample. So the honest next step is **not another
artifact-level operator**. It is to enlarge the genuine-T2 population — the 17 unresolved
repositories, where `H2_PLAN.md`'s remaining interventions (H2c dependency convergence, H2d
codegen and submodule acquisition, H2e configure and path repair) operate on a population an
order of magnitude larger.

Sequencing artifact work before population work would produce a chain of special-case rules,
each defensible on its single witness and none of them a general principle.

## 6. What is established

- The identity mechanism works, and its effect is attributable and reversible.
- The regression guard holds: no correct resolution was disturbed.
- The failure population is **four mechanisms, not one**, which is new information and the
  reason the next iteration has a defined target.

What is **not** established: that identity-aware resolution improves artifact selection in
general. That needed more than one witness, and the pre-registration said so in advance.

Stated as a reviewer would want it:

> The proposed identity criterion resolves the motivating vendored-artifact failure without
> introducing regressions, but the pre-registered benchmark shows that this failure mode is
> only one of several artifact-resolution mechanisms. The hypothesis is refined rather than
> confirmed.

The useful result is the bound, not the fix: **the ownership criterion is necessary but not
sufficient.** That constrains the problem space correctly and gives the next iteration a
defined target instead of a direction.

---

*H2b v1 is frozen as evidence. The next iteration is a separate intervention, on its own
branch, and must widen evaluator coverage before it can widen any claim.*
