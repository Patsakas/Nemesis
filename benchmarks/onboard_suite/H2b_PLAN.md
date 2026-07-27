# H2b — artifact identity-aware library resolution (pre-registered)

Written before any H2b code, as with `H2_PLAN.md` and `H2a_V2_DESIGN.md`.

> **The capability is not missing. The decision criterion is misaligned.**

## 1. What the evidence actually shows

The initial framing — "we need artifact identity repair" — was the wrong abstraction. The
system already has build-artifact discovery, a shared `LibraryResolver` with three ordered
strategies and recorded provenance, and an oracle that can say which artifact is a genuine
project output. astera fails anyway, and the chain (from v1's uncontaminated log, see
`H2a_V2_RESULTS.md` §8) is:

```
config library_name = dep/glfw/src/libglfw.a      names the VENDORED dependency
      ↓  no such file — the real vendored artifact is libglfw3.a
LibraryResolver strategy 3 (renamed_output): libglfw.a -> libglfw3.a
      ↓  resolution SUCCEEDS
the harness links libglfw3.a; libastera.a is never considered
      ↓
undefined reference to pak_open_mem, pak_count, pak_extract_noalloc, pak_close
```

Those are astera's *own* API symbols. Measured directly on the two archives H2a produces:

| archive | `pak_open_mem` | `pak_count` | `pak_extract_noalloc` | `pak_close` |
|---|:---:|:---:|:---:|:---:|
| `libastera.a` | 1 | 1 | 1 | 1 |
| `dep/glfw/src/libglfw3.a` | 0 | 0 | 0 | 0 |

So the failure is not *"no library found"*. It is:

> **A library was found, and nothing could judge whether it was the right one.**

The distinction the experiment must respect:

```
resolver correctness :  "I found a file matching the requested name"
artifact correctness :  "I found the file corresponding to the intended target"
```

These are not equivalent. H2b addresses the second.

## 2. Hypothesis

> When several candidate artifacts satisfy a configured library expectation, selection based
> only on filename and path heuristics can select an incorrect artifact. Incorporating
> artifact ownership identity — which the genuine-target oracle already determines —
> prevents false library matches.

astera is the **motivating witness, not the hypothesis.** "H2b fixes astera" is explicitly
*not* a success criterion.

Population: `library_name` is wrong in **4 of the 7 repositories that reach genuine T2** —
astera (names a vendored dependency), tiny-AES-c (`libtiny_aes_c.a` vs `libtiny-aes.a`),
pg_ivm (`libpg_ivm.a` vs `pg_ivm.so`), gensio (names the `glib` leaf, not `lib/libgensio.a`).
The remaining three (bcg729, onomondo-uicc, libdc) are correct and form the regression guard.

## 3. Intervention

Not a new resolver. Not a build repair. Not a rename, copy or symlink. An **identity
predicate added to the ranking of an existing resolver**:

```
candidate artifacts
        |
        v
existing resolver strategies (unchanged, still recorded)
        |
        +---- artifact identity predicate
                 |
                 +-- project-owned artifact preferred
                 +-- vendored-only artifact rejected when a project-owned one exists
```

### Invariants

1. **The build command is not modified.** H2b is not target repair; H2a owns that.
2. **No artifact is created, renamed or copied.** Making the expected name exist would hide
   the mismatch rather than resolve it.
3. **Only identity resolution changes** — which existing artifact is selected, nothing else.
4. **The oracle verdict is recorded before and after**, so any change in outcome is traceable
   to the selection and not to a build difference.

## 4. Frozen oracle interface contract

The oracle's output is an **input** to resolution. It therefore cannot also serve as the
measure of whether resolution was correct — that would be circular. The boundary is frozen
here, before any H2b code:

**The oracle MAY pass:**

| Field | Meaning |
|---|---|
| `artifact` | path of the accepted project-owned artifact (empty if none) |
| `oracle` | `accept` \| `reject` \| `n/a` |
| `reason` | `project_library_present` \| `only_vendored_artifact` \| `no_project_library_artifact` \| `build_failed` |

**The oracle MUST NOT pass** — and the resolver must not consult — anything derived from the
evaluation criterion: symbol tables, harness contents, the set of functions a consumer needs,
or link results. The oracle decides ownership from *path and size*. The evaluator decides
correctness from *symbol containment*. Two independent signals, and neither may borrow from
the other.

Violating this contract invalidates an H2b run regardless of its numbers.

## 5. Evaluation — deliberately not the oracle

**Inadmissible as a primary metric:** `selected artifact == oracle's artifact`. That measures
whether the intervention did what it was told, not whether the result is correct.

**Primary metric — symbol containment.** Independent of both oracle and resolver, computed
with `nm` over the archives:

> A resolution is a **false artifact acceptance** if it returns an archive that defines none
> of the symbols the consumer requires, while another archive in the same build tree defines
> them.

Ground truth for "what the consumer requires", in priority order, all **frozen inputs**
predating every experiment in this series:

1. the concretely pinned `target_func` in the frozen config — available for astera
   (`pak_open_mem`) and onomondo-uicc (`ss_access_check_command`);
2. failing that, function declarations parsed from the headers named in the config's
   `harness_includes`.

**Honest limitation, declared now:** five of the seven configs carry the template placeholder
`function_name` rather than a real symbol, so route 1 covers **2 of 7**. Route 2 must be
built and validated *before* the run, and if it cannot be made reliable the primary metric is
reported at n=2 rather than quietly widened.

**Secondary metric:** harness link success at T3. **Currently blocked** — two LLM providers
reached end-of-life on 2026-07-27 and every T3 attempt in the H2a v2 pair failed against
them. The primary metric is deliberately LLM-independent so H2b can run and be evaluated
while the provider chain is broken; the secondary is deferred, not silently dropped.

**Regression guard:** the three repositories whose `library_name` is already correct
(bcg729, onomondo-uicc, libdc) must resolve to the same archive as before.

## 6. Success and exit criteria

H2b succeeds only if **all** hold:

1. false artifact acceptances decrease, and none are introduced;
2. no previously correct resolution changes;
3. every changed resolution is attributable to a recorded identity decision;
4. the frozen interface contract (§4) is not violated.

H2b is rejected or refined if any of:

- a resolution changes on a repository whose configured name was already correct;
- the intervention improves the secondary metric while the primary is unchanged — that would
  indicate the effect came from somewhere other than identity selection;
- the only demonstrable effect is on astera. One witness is a motivating case, not a result.

---

*H1 acquires dependencies · H2a acquires the correct build target · H2b selects the correct
artifact among those built · H3 remains harness generation.*
