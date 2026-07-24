# H2a — build-target repair: operator and validation evidence

Implements the H2a intervention of [H2_PLAN.md](H2_PLAN.md). This document records
the mechanism hypothesis, the operator, and its validation on the frozen configs of
the three probe repositories — **before** the full-25 experiment, so the operator's
definition cannot be adjusted to fit the outcome.

## Mechanism hypothesis (probe-confirmed)

> The T2 failures of `tiny-AES-c`, `gifsicle`, `gensio` are **not** dependency
> failures. They are **target-selection** failures caused by guessed build targets.

The onboarder guessed a specific build target that was either wrong, order-violating,
or non-existent:

| Repo | Guessed target | What was wrong |
|---|---|---|
| tiny-AES-c | `make tiny_AES_c` | used the NEMESIS-normalised name; real CMake target is `add_library(${PROJECT_NAME})` = `tiny-AES-c` |
| gensio | `make -C glib libgensioglib.la` | built a **leaf** whose parent `lib/libgensio.la` was unbuilt — invalid build graph |
| gifsicle | `make -C src libgifsicle.la` | the project produces **no** library — it is an application |

The validation probe (target correction only, **no dependency installs**) confirmed
this: correcting the target moved all three past the `make` failure with zero installs.

## The operator (`nemesis/repair.py`)

Two deterministic phases — few rules, a recorded trace, an explicit rejection reason.

- **Phase 1 — target correction.** A specific or `-C subdir` target bypasses the
  build graph; replace it with the build-system default (`make -j$(nproc)`), which
  respects dependency ordering. In-memory only — the frozen config is never rewritten
  (Config-freezing invariant).
- **Phase 2 — genuine-target oracle.** Build success is necessary but insufficient.
  Accept T2 only if a non-vendored project library artifact was produced; otherwise
  reject with a reason (`no_project_library_artifact`, `only_vendored_artifact`).

Enabled by `nemesis setup --target-repair` (off by default). Emits
`setup.target_repair`, `setup.target_oracle`, `setup.h2a_summary`.

## Validation on frozen configs

`nemesis setup -t <repo> --target-repair`, no auto-deps, committed configs untouched.

| Repo | baseline T2 | H2a genuine T2 | operator action | oracle verdict |
|---|:---:|:---:|---|---|
| tiny-AES-c | ✗ | **✓** | target-name correction | accept — `libtiny-aes.a` |
| gensio | ✗ | **✓** | build-graph correction | accept — `lib/.libs/libgensio.a` (main lib) |
| gifsicle | ✗ | **✗ (rejected)** | target correction | **reject — `no_project_library_artifact`** |

### H2a impact is two metrics, not a pass-rate

The strength of this result is the **combination**, not a T2 count:

- **Recovery metric** — real failures turned into genuine T2: **tiny-AES-c, gensio (2)**.
- **Validity metric** — false successes eliminated: **gifsicle (1)**; `astera` is the
  next expected candidate (H1 built its bundled GLFW).

```
H2a impact = + genuine recoveries  (tiny-AES-c, gensio)
             + invalid-success elimination  (gifsicle; astera expected)
```

Most benchmark operators report only the first line. This one has **rejection
capability** — `gifsicle` is kept as a **negative control**, not discarded.

### Repair trace (attribution)

```
gensio
  target_repair  { action: replace_invalid_target,
                   before: "make -j$(nproc) -C glib libgensioglib.la",
                   after:  "make -j$(nproc)",
                   reason: specific_or_subdir_target_bypasses_build_graph }
  target_oracle  { action: genuine_target_oracle, build_exit: 0, oracle: accept,
                   artifact: lib/.libs/libgensio.a, reason: project_library_present }

gifsicle
  target_repair  { action: replace_invalid_target, after: "make -j$(nproc)" }
  target_oracle  { build_exit: 0, oracle: reject, reason: no_project_library_artifact }
```

### Self-enforcement property

`genuine_t2 = False` lands in `nemesis setup`'s failure set → `setup` exits non-zero.
So under `--target-repair` the benchmark's rc-based T2 tier **automatically reflects
genuine T2** — the target-validity invariant is enforced at the tier without changing
the T2 definition in `run_suite.py`.

## Pending (full-25 experiment)

1. Run all 25 frozen configs with `--target-repair` (no auto-deps), record the
   recovery and validity metrics across the suite.
2. **Audit the existing baseline (2) and H1 (4) T2 results under the oracle.** `astera`
   is expected to reject `only_vendored_artifact`, which would revise H1's genuine T2
   from 4 to 3. This does not diminish H1: it is protocol evolution —

   > H1 measured dependency recovery under the original T2 classifier. H2 introduced
   > target-validity enforcement and revealed that some prior T2 transitions were
   > artifact-validity false positives.

   — improved benchmark accuracy, not a corrected result.
3. `gifsicle` likely reclassifies toward *not-a-library / needs a different harness
   strategy*, rather than a build failure to be repaired.
