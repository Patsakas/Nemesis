# H2a — supplementary audit: astera (H1 ⊥ H2a)

Single-repo paired audit, run **outside** the H2a v1 experiment and reported separately from
it. It answers one attribution question left open by `H2a_RESULTS.md` §4, and it does not
change any number in that document.

> **Dependency availability is necessary but not sufficient for a genuine build target.**
> With every dependency present, the build still succeeds while producing nothing that
> belongs to the project.

## 1. The question

In the frozen-config experiment, `astera` was recorded as a **genuine recovery**: the control
built only a vendored artifact (oracle reject), the treatment built `libastera.a` (oracle
accept). But astera is also the repo whose build consumes the external stack H1 installs
(OpenAL, X11, Wayland, XKBCommon…), and that run inherited ~150 packages from the earlier H1
run. So:

> Was astera's recovery a **target** effect, or a **dependency** effect measured in a system
> that H1 had already prepared?

The audit removes the ambiguity by holding dependencies constant **at maximum availability**
in both arms and varying only `--target-repair`.

## 2. Design

| | Arm A — H1 alone | Arm B — H1 + H2a |
|---|---|---|
| Command | `nemesis setup -t astera --auto-deps` | `nemesis setup -t astera --auto-deps --target-repair` |
| Dependency resolver | enabled | enabled |
| Config | frozen, committed `config/targets/astera.yaml` (never rewritten) | same |
| Workspace | wiped before the arm | wiped before the arm |

Both arms ran with the resolver fully enabled (`apt`, `apt-file`, network and
non-interactive `sudo` all available) and **installed 0 packages** — every dependency was
already satisfied. Dependency acquisition is therefore not merely held constant across the
arms, it is *saturated* in both: H1 had nothing left to contribute.

The frozen config selects:

```yaml
make: make -j$(nproc) glfw            # a target inside dep/glfw — a vendored dependency
library_name: dep/glfw/src/libglfw.a  # and even this name is wrong (real: libglfw3.a)
```

## 3. Result

| | Arm A — H1 alone | Arm B — H1 + H2a |
|---|---|---|
| Target repair | — | `make -j$(nproc) glfw` → `make -j$(nproc)`<br>*(`specific_or_subdir_target_bypasses_build_graph`)* |
| Build | **success** | **success** |
| Exit code | **0** | **0** |
| Artifacts in `build_fuzz` | `dep/glfw/src/libglfw3.a` (2 553 012 B) | `dep/glfw/src/libglfw3.a` (2 553 012 B)<br>**`libastera.a` (7 685 422 B)** |
| Project-owned artifact | **none** | `libastera.a` |
| Oracle verdict | **reject** — `only_vendored_artifact` | **accept** — `project_library_present` |
| Genuine T2 | **no** | **yes** |

Arm A's verdict was produced by running the shipped oracle (`nemesis.repair.genuine_oracle`)
against arm A's build directory — not by inspection. Arm A has no oracle of its own, exactly
as in the v1 control.

Both arms also emit `library_not_found` for the configured `dep/glfw/src/libglfw.a`: the
frozen config is wrong about the artifact name *even for the vendored target it chose*.

## 4. Why the tier cannot see the difference

```
        Arm A  (H1)                         Arm B  (H1 + H2a)
   all dependencies present            all dependencies present
            ↓                                     ↓
   make -j$(nproc) glfw                   make -j$(nproc)
            ↓                                     ↓
       build rc 0                            build rc 0        ← identical
            ↓                                     ↓
   only dep/glfw/…/libglfw3.a           libastera.a + libglfw3.a
            ↓                                     ↓
     oracle REJECT                          oracle ACCEPT
   (false success)                        (genuine target)
```

An exit-code-based tier classifies **both** arms as a successful build. The arms are
separable only by the artifact-ownership oracle. This is independent evidence for treating
the oracle as its own contribution rather than as part of target repair.

## 5. Conclusion — the two operators are orthogonal

```
H1   : acquire the build's INPUTS   → gets the project to "it builds something"
H2a  : acquire the build's OUTPUT   → gets the project to "it built the right thing"
```

Neither subsumes the other. On astera, H1 is fully satisfied and still yields a false
success; the correction is attributable to target repair alone. astera's classification as a
**genuine recovery** in `H2a_RESULTS.md` is therefore confirmed, under dependency conditions
that would have favoured the competing explanation.

## 6. Unplanned finding — a constraint on H2a v2

v2 is specified as *"keep a target that is valid; replace one that is invalid"*. astera shows
that **declaredness is not validity**:

| Target | Declared at | Declared? | Correct? |
|---|---|:---:|:---:|
| `glfw` | `dep/glfw/src/CMakeLists.txt:91` — `add_library(glfw …)` | **yes** | **no** — vendored dependency |
| `astera` | `CMakeLists.txt:84` — `add_library(${PROJECT_NAME} STATIC)` | yes, **variable-expanded** | yes |

A v2 validator that accepts a target because a literal `add_library(<name>)` exists would
**keep `glfw`** and hand astera back its false success — while failing to see astera's own
target at all, because it is declared as `${PROJECT_NAME}` and not as a literal string. That
is the same defect class as tiny-AES-c's normalized name, arriving from the opposite side.

So v2's validity predicate needs both halves:

```
valid(target) ≡ declared(target) ∧ owned_by_project(declaring_file)
```

with declaration matching resolved against the project name, not against literal text. Fixing
onomondo/pg_ivm without this would regress astera.

## 7. What this audit does not claim

- **n = 1.** A paired single-repo audit, not a controlled experiment. It supports an
  *attribution* for one repo; it is not a measurement of H1 or H2a.
- **Nothing about H1's value in general.** H1 installed 0 packages here, so this says nothing
  about repos where dependencies are genuinely missing — that is `H1_PROTOCOL.md`'s evidence.
  The finding is that H1 is *insufficient alone*, not that it is unnecessary.
- **No v1 numbers change.** `H2a_RESULTS.md` is frozen; this document is additive.
- The system state still carries the earlier H1 run's packages. That is the intended
  condition here (dependencies saturated), not a confound to be removed.

## 8. Provenance

| | |
|---|---|
| Code | `treatment/h2a-target` @ `e6ca290` (unmodified) |
| First run | 2026-07-24 — `~/audit_A.log`, `~/audit_B.log` |
| Re-run | 2026-07-27 — `~/astera_audit_rerun/`, arms wiped and re-executed, oracle applied programmatically to arm A |
| Reproducibility | both runs produced identical repair actions, artifacts and oracle verdicts |
