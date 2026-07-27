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

### 4.2 pg_ivm shows a third class

The config names `libpg_ivm.a`; the build produces `pg_ivm.so`. Every resolver glob is
`lib*.a`, so nothing is found in either arm. H2b correctly does not rescue it — the operator
re-decides a selection and does not invent one — but the gap is real and belongs to a
different operator.

## 5. Refinement mandate

Derived from the data, not from preference:

1. **Ownership is necessary but not sufficient.** A second criterion is needed to choose
   among project-owned candidates. gensio suggests build-graph position or symbol breadth;
   both must be pre-registered before use, and symbol breadth would collide with the
   information-leakage invariant unless the evaluator changes with it.
2. **Artifact kind must be part of resolution.** A configured `.a` should not prevent finding
   the `.so` the build produced.
3. **The evaluator's coverage is the binding constraint, not the operator's.** Five of seven
   configs cannot be judged at all. Route 2 (header-derived symbol sets) has to be built and
   validated before any wider claim is possible — including the claim that H2b *failed* to
   help elsewhere.

## 6. What is established

- The identity mechanism works, and its effect is attributable and reversible.
- The regression guard holds: no correct resolution was disturbed.
- The failure population is **four mechanisms, not one**, which is new information and the
  reason the next iteration has a defined target.

What is **not** established: that identity-aware resolution improves artifact selection in
general. That needed more than one witness, and the pre-registration said so in advance.

---

*H2b v1 is frozen as evidence. The next iteration is a separate intervention, on its own
branch, and must widen evaluator coverage before it can widen any claim.*
