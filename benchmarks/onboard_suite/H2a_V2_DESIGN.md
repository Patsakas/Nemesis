# H2a v2 — conservative target validation (pre-registered design)

Written **before** the v2 experiment, as with `H2_PLAN.md`. v1 is frozen and unedited
(`H2a_RESULTS.md`); this document specifies the refinement its evidence mandates, the
rules, the pre-flight verdicts, the limitations, and the conditions under which v2 must
be rejected.

> v2's mission is not "a better heuristic". It is to satisfy the requirements that v1's
> regressions and the astera audit turned into constraints.

## 1. The predicate

`H2a_astera_audit.md` showed that `declared(target)` does **not** imply *project target*:
astera declares `glfw` (a bundled dependency) and its own library, both validly. So
validity is a conjunction, evaluated in two phases because its last term is only
observable after a build:

```
valid_target :=  declared
               ∧ belongs_to_project_build_graph          ← Phase 0 (static, pre-build)
               ∧ produces_non_vendored_project_artifact  ← Phase 2 (oracle, post-build)
```

The division of labour is deliberate:

- the **validator** decides whether a configured target deserves to be *kept or replaced*;
- the **oracle** remains the final judge of *artifact identity*, unchanged from v1.

## 2. Requirements (each derived from an observed failure)

| | Requirement | Forced by | Rule |
|---|---|---|---|
| **R1** | **Conservative replacement** — do not replace an already-valid target | onomondo-uicc (v1 regression) | a declared, project-owned target is kept |
| **R2** | **Ownership-aware validation** — a declared target is not automatically valid | astera (audit) | a target declared only inside a vendored subtree is replaced |
| **R3** | **Build-system awareness** — the replacement must belong to the build system in use | pg_ivm (v1 regression) | the default build is `ninja` for ninja, `make -j$(nproc)` for make; a command that already falls back to its own default is left alone |

### R3 refines v1's diagnosis of pg_ivm

`H2a_RESULTS.md` §5 attributed both regressions to "unconditional default-build preference
over a valid declared target". For onomondo that is exact. For pg_ivm the finer cause,
visible in the frozen config, is different:

```
config : ninja libpg_ivm.a || ninja          # meson project; already self-correcting
v1     : make -j$(nproc)                     # a make command in a meson build directory
result : COMPILE_FAILURE after 15.2 s
```

v1 discarded not only the target but the *build system* and the command's own fallback.
The v1 counts are unaffected (it was a genuine regression either way, and v1 stays
frozen); the cause is recorded more precisely here because it produces requirement R3,
which "replace only invalid targets" alone would not have produced.

The onomondo mechanism is also now concrete: `uicc` is declared at
`src/softsim/uicc/CMakeLists.txt:49`, while the default build additionally builds ~15
test executables (`aes_test`, `btlv_test`, …). **The default build is a superset, and a
superset can fail for reasons unrelated to the library.** That is why "fall back to the
default" cannot be unconditional.

## 3. Decision procedure

Ordered, deterministic, no LLM. First matching rule wins.

```text
build command
      |
      v
recognised build invocation?  --no--> KEEP  (no_recognised_build_command)
      |yes
      v
already the default build, or falls back to it?  --yes--> KEEP
      |no                          (already_default_build / command_falls_back_to_default_build)
      v
declared?  --no--> REPLACE  (undeclared_target)
      |yes
      v
declared inside a vendored subtree?  --yes--> REPLACE  (declared_in_vendored_subtree)
      |no
      v
subdirectory invocation bypasses the build graph?  --yes--> REPLACE
      |no                          (subdir_invocation_bypasses_root_build_graph)
      v
    KEEP  (declared_project_target)
```

**Identity is decided before reachability.** "This target does not exist" is a deeper
defect than "it is reached the wrong way", so when both hold the reported reason is the
former. gifsicle is the case that shows why: it is invoked as `-C src libgifsicle.la`, but
the project declares no such library at all — and `undeclared_target` is what the oracle
later confirms as `no_project_library_artifact`.

The reachability branch is still load-bearing and cannot be folded into declaredness:
gensio's `libgensioglib.la` *is* declared in `glib/Makefile.am`, yet building it via
`-C glib` never builds its parent `lib/`. Being declared does not make a target reachable
through the project's build graph — the second conjunct doing work the first cannot.

**Declaration scanning** covers CMake (`add_library`/`add_executable`), Autotools
(`*_LTLIBRARIES`/`*_LIBRARIES`/`*_PROGRAMS`), Meson (`static_library`/`shared_library`/
`shared_module`/`executable`) and plain Make rules, with:

- **shallow variable resolution** — `${PROJECT_NAME}` from `project(...)`, plus simple
  same-file `set(VAR value)` / `var = 'value'`. astera's own target is declared as
  `add_library(${PROJECT_NAME} STATIC)`, so literal text matching would not see it at all.
- **comment stripping** — astera carries a commented-out `#add_library(...)` directly
  above the real one; a commented declaration declares nothing.
- **no `-`/`_` normalisation** — tiny-AES-c's configured `tiny_AES_c` must *not* match the
  declared `tiny-AES-c`. That mismatch is a real build failure and one of v1's recoveries.
- **artifact/logical aliasing, restricted by declaration kind** — a configured target may
  be a logical name (`uicc`) or an artifact path (`src/libsmk.a`, `libxml2.la`), so
  `libfoo.a` is also matched against a declared library `foo` (standard CMake). But *only*
  against **library** declarations: gifsicle's configured `libgifsicle.la` must not be
  validated by `bin_PROGRAMS = gifsicle`. Without the kind restriction the validator would
  keep a library target the project never declares — the false-KEEP that exit criterion 4
  exists to catch.
- **non-vendored declarations win** over a vendored namesake.

## 4. Pre-flight verdicts (static, no builds)

The validator applied to the 25 frozen configs and their pinned source trees:

| Verdict | Repos |
|---|---|
| **KEEP** — declared project target (9) | bcg729, onomondo_uicc, BotW_BetterVR, H5Z_ZFP, gvm_libs, iris, meatloaf, rp6502, turbovnc |
| **KEEP** — command self-corrects (2) | pg_ivm, smk |
| **REPLACE** — subdir invocation (4) | gensio, libdc, dbmail, fdpp |
| **REPLACE** — vendored declaration (1) | astera |
| **REPLACE** — undeclared (9) | tiny_AES_c, gifsicle, pspsdk, vdi_stream_client, ESCape32, ProcMon_for_Linux, clam, lv_port_pc_vscode, lv_port_stm32f746_disco |

(11 keep / 14 replace.)

### The seven checks the v1 evidence pre-registers

| Repo | v1 outcome | Required v2 verdict | Actual | |
|---|---|---|---|:---:|
| gensio | recovery | replace | replace — subdir | ✅ |
| tiny-AES-c | recovery | replace | replace — undeclared | ✅ |
| libdc | recovery | replace | replace — subdir | ✅ |
| astera | recovery | replace | replace — **vendored declaration** | ✅ |
| gifsicle | oracle-only correction | replace | replace — **undeclared** (no such library) | ✅ |
| onomondo-uicc | **regression** | **keep** | keep — declared at `src/softsim/uicc/CMakeLists.txt` | ✅ |
| pg_ivm | **regression** | **keep** | keep — command self-corrects | ✅ |

bcg729 (v1: maintained) is now *kept* rather than repaired — the same outcome reached
without touching the build.

A verdict table is not a result. It states that v2 *can* satisfy the requirements; whether
it *does* is the experiment.

## 5. Known limitations (declared, not discovered later)

- **L1 — unresolvable target names.** ESCape32 computes its targets at configure time
  (`add_executable(${elf} …)` where `elf` is built from a regex over source text). Static
  scanning cannot resolve these, so they are reported `undeclared_target` → replace. This
  is v1's behaviour for those repos, so it cannot cause a regression relative to v1, but it
  is a false *reason*, not a verified absence of declaration.
- **L2 — ownership is a path heuristic.** Vendoring is inferred from a fixed directory-name
  list (`dep`, `third_party`, `vendor`, …). meatloaf bundles a third-party library under
  `components/libsmb2/`, which the list does not cover, so it is (incorrectly) treated as
  project-owned by *both* the validator and the oracle. A general fix — provenance rather
  than path — is out of scope for v2 and is recorded as future work.
- **L3 — no build-graph reachability check.** "Non-vendored declaration" approximates
  *belongs to the project build graph*. A declaration in a directory that is never
  `add_subdirectory`'d would still be accepted. Resolving this properly requires
  interpreting the build files or querying a configured build directory
  (`make -n <target>`, `ninja -t targets`), which is deliberately not attempted here.

## 6. Experimental protocol and exit criteria

Same invariants as v1: frozen configs, no config regeneration, treatment and control
differ in exactly one variable, runs serialised (the workspace is not concurrency-isolated).

- Control: `run_suite --frozen-configs` (no repair).
- Treatment: `run_suite --frozen-configs --target-repair` (validation on by default).
- Optional ablation: `--no-target-validation` restores unconditional replacement.

**Pre-registered prediction:** genuine T2 = **7** (control's bcg729 + onomondo + pg_ivm,
kept; plus gensio, tiny-AES-c, libdc, astera, recovered), with gifsicle rejected by the
oracle. Control = 3, v1 = 5.

**v2 is rejected or refined if any of the following holds:**

1. any v1 recovery is lost (a KEEP verdict on a target that v1 correctly replaced);
2. any new regression appears on a target the control built genuinely;
3. genuine T2 does not exceed v1's 5;
4. a KEEP verdict is shown to have preserved a *false* success — i.e. the validator
   accepted a target the oracle then rejected.

Condition 4 is the one that would indict the validity predicate itself rather than its
implementation, and is therefore reported separately from the counts.
