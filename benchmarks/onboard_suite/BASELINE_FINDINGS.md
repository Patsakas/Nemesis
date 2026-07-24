# Onboarding benchmark — baseline findings (nemesis-onboard-v1, v0.1)

First unattended baseline of the suite defined in [CRITERIA.md](CRITERIA.md). This
document is written *after* the run and interprets it. The headline metric is fixed and
does not change under any analysis in this file. Everything from **Secondary analysis**
onward is post-hoc root-cause analysis, conducted under a rubric stated before the
failure logs were read.

## Run identity

The results directory is written outside the repository (gitignored) and on ext4 by
design; the identifiers below locate it and let the numbers be re-verified.

| Field | Value |
|-------|-------|
| suite | `nemesis-onboard-v1` |
| run_id | `baseline_b8b7cf70_491eaad8` |
| experiment_id | `b8b7cf70ab005860` (matches `baseline.lock`) |
| benchmark_instance_id | `491eaad8d49c3244` |
| OSS-Fuzz snapshot | tree `1353ef81`, pool digest `b262a0cda406bfdb` |
| NEMESIS commit | `c2647853` |
| onboarder model | `mistralai/mistral-medium-3.5-128b` @ temp 0.1 |
| provider chain head | `openai/gpt-oss-120b` (6-provider chain, frozen in lock) |
| conditions | unattended, `intervention = 0`, cold LLM cache |
| generated | 2026-07-23T20:56:20Z |

## Headline result

> **0 of 25 repositories reached T5 (fuzz-ready)**, unattended, cold cache, at
> intervention level 0.

| Tier | Reached | Count | % |
|------|---------|:-----:|:---:|
| T0 | acquired | 25 | 100.0 |
| T1 | config generated | 25 | 100.0 |
| T2 | library built | 2 | 8.0 |
| T3 | harness generated | 0 | 0.0 |
| T4 | harness compiled | 0 | 0.0 |
| T5 | fuzz-ready | 0 | 0.0 |

This is the benchmark result. It does not change under any analysis below.

## Where the funnel breaks

- **T1 (config generation) succeeded for all 25 (100 %).** This is the LLM-driven
  onboarding step and the most expensive stage by wall-clock (median 481 s/repo). It is
  not the bottleneck.
- **The pipeline then fails at T2 (library build), median 8 s.** 23/25 never build the
  library; the 2 that do fail immediately afterward, when the generated harness is
  compiled.
- **No repository reached T3.** First-failure distribution by class: 9 compile,
  9 configure, 7 dependency.

## Primary observation

The evaluation terminated before the harness-generation stage for **every** repository.

This baseline therefore **does not measure the quality of NEMESIS's harness
generation** — that stage was not reached. It measures build acquisition, and reports
that, for this sample, **build acquisition rather than harness synthesis is the dominant
obstacle**. The suite's tier structure spends two of six tiers on harness generation and
compilation on the implicit expectation that harness synthesis is the hard part; the
measured result is that the pipeline fails, universally, one stage earlier.

Stated precisely: *the benchmark failed before it could evaluate harness-generation
quality.* This is neither a positive nor a negative result about that capability — it is
a statement that the evaluation did not reach it.

## Secondary analysis: failure root-cause classification (post-hoc, rule-first)

**Method.** The rubric below was fixed before any failure log was read, then applied to
the *immediate observed failure* recorded in each repository's failing stage.

> **Caveat that bounds every statement in this section.** The classification describes
> the **first observed failure only**. It does **not** establish that resolving that
> failure would let the build proceed: a repository whose first failure is a missing
> dependency may hit a second, independent failure once that dependency is present.
> Recoverability is therefore reported as **"potentially recoverable"**, and each count
> is an **upper bound**, never a prediction of success.

**Scope rubric** (defined before reading logs):

| Bucket | Rule |
|--------|------|
| **OUT of scope** | a native x86 build is not meaningful in principle: cross-compile-only (ARM/MCU/MIPS toolchain), RTOS / bare-metal, requires hardware, proprietary or platform SDK, C++-only |
| **IN scope** | the immediate observed failure is an environmental or orchestration gap — missing apt/pkg-config dependency, wrong configure flag, CMake option, include path, autotools/libtool issue, uninitialised submodule, missing generated source |
| **Ambiguous** | does not fall cleanly into either; recorded separately rather than forced into a bucket |

**Result of the partition: 15 in-scope · 6 out-of-scope · 4 ambiguous.**

> This partition is **not a new denominator.** The benchmark result remains **0/25**. The
> partition describes the 25 repositories by whether a native build is meaningful; it does
> not re-score them.

**On the 6 out-of-scope repositories.** These are embedded / cross-compile targets
(`sdcc`/8051, ESP-IDF/ESP32, STM32-ARM, `arm-none-eabi`, Pico SDK/RP2040, PSP-MIPS SDK).
They correspond to the `NEMESIS_LIMITATION` category in [schema.py](schema.py), which the
pipeline did **not** assign to them — because scope detection runs at the entry-point /
harness stage, downstream of the build stage where these repositories terminated. The
empty `NEMESIS_LIMITATION` bucket in the run is thus an artifact of failure *ordering*,
not evidence that all 25 repositories are in scope.

## Failure taxonomy (per repository)

Tier reached, the immediate observed failure, the scope verdict, and the root-cause
category. Categories: **DEP** (environmental dependency), **TARGET** (NEMESIS constructs a
build target the project does not define), **HARNESS** (generated-harness include path),
**CODEGEN** (missing submodule / generated source), **EMBEDDED** (out of scope).

| Repository | Reached | Immediate observed failure | Scope | Category |
|------------|:-------:|----------------------------|:-----:|----------|
| BelledonneCommunications/bcg729 | T2 | generated harness: `cng.h` not found | IN | HARNESS |
| Crementif/BotW-BetterVR | T1 | `find_package(OpenXR)` failed | AMB | VR SDK / likely C++ |
| TurboVNC/turbovnc | T1 | `turbojpeg.h` not found | IN | DEP |
| allkern/iris | T1 | submodule `deps/parallel-gs` empty | IN | CODEGEN |
| carlossless/smk | T1 | meson: `sdcc` not found | OUT | EMBEDDED (8051) |
| cminyard/gensio | T1 | no rule for `../lib/libgensio.la` | IN | TARGET |
| dbmail/dbmail | T1 | `gmime` development files missing | IN | DEP |
| dosemu2/fdpp | T1 | `clang.mak:47` make-rule failure | AMB | DOS kernel |
| greenbone/gvm-libs | T1 | `net` / `pcap` library required | IN | DEP |
| idolpx/meatloaf | T1 | `/tools/cmake/project.cmake` (ESP-IDF) | OUT | EMBEDDED (ESP32) |
| kohler/gifsicle | T1 | no rule for `libgifsicle.la` | IN | TARGET |
| kokke/tiny-AES-c | T1 | no rule for `tiny_AES_c` | IN | TARGET |
| llnl/H5Z-ZFP | T1 | `No CMAKE_Fortran_COMPILER` | IN | DEP (gfortran) |
| lvgl/lv_port_pc_vscode | T1 | `find_package(SDL2)` failed | IN | DEP |
| lvgl/lv_port_stm32f746_disco | T1 | `No CMAKE_C/ASM_COMPILER` (ARM) | OUT | EMBEDDED (STM32) |
| mbroemme/vdi-stream-client | T1 | `sdl3 >= 3.2.0` not met | IN | DEP |
| microsoft/ProcMon-for-Linux | T1 | no rule for `ProcMon_for_Linux` | AMB | TARGET, but C++ tool |
| neoxic/ESCape32 | T1 | `arm-none-eabi-gcc` not found | OUT | EMBEDDED (ARM) |
| onomondo/onomondo-uicc | T2 | generated harness: `softsim/file.h` not found | IN | HARNESS |
| picocomputer/rp6502 | T1 | `PICO_SDK_PATH` unset | OUT | EMBEDDED (RP2040) |
| pspdev/pspsdk | T1 | autotools `AC_INIT` / `VERSION` missing | OUT | EMBEDDED (PSP-MIPS SDK) |
| seahorn/clam | T1 | `Boost >= 1.65` not found | AMB | DEP, but C++/LLVM |
| sraoss/pg_ivm | T1 | meson: `pg_config` not found | IN | DEP |
| subsurface/libdc | T1 | `revision.h` not found (generated) | IN | CODEGEN |
| tek256/astera | T1 | `OpenAL` not found | IN | DEP |

## Root-cause distribution (in-scope repositories)

| Category | Repositories | Count |
|----------|--------------|:-----:|
| DEP — environmental dependency | turbovnc, dbmail, gvm-libs, H5Z-ZFP, lv_port_pc_vscode, vdi-stream-client, pg_ivm, astera | 8 |
| TARGET — build target NEMESIS defines but the project does not | gensio, gifsicle, tiny-AES-c | 3 |
| HARNESS — generated-harness include path | bcg729, onomondo-uicc | 2 |
| CODEGEN — submodule / generated source | iris, libdc | 2 |

**Observation.** 11 of the 15 in-scope repositories (73 %) share two dominant root-cause
categories: dependency resolution (8) and target inference (3). The remaining four split
between generated-harness include paths (2) and missing generated sources (2).

The TARGET category is notable because it is a **NEMESIS-internal defect** — the tool
instructs `make` to build a target (`libX.la`, `X`) that the project's own build system
does not define — as distinct from DEP, which is a property of the host environment.

## Threats to validity

- **Immediate-failure classification** (see the boxed caveat above): counts are upper
  bounds on the first observed failure, not on end-to-end recoverability.
- **Post-hoc classification.** The rubric was rule-first, but residual judgement remains
  in the 4 ambiguous cases; they are reported as ambiguous rather than assigned.
- **Single run, no repetition.** T1 is LLM-driven and nondeterministic. The provider
  chain, per-role models, temperatures and prompt hashes are frozen and recorded in
  `baseline.lock`, but a re-run could land on a different config or fallback provider. No
  repeat runs were performed; run-to-run variance is unmeasured.
- **Scope of the claim.** Bounded to the 25 frozen repositories and the CRITERIA.md
  inclusion predicates (C, recent, 50–5000 stars, ≤50 MB, non-OSS-Fuzz, licensed). Not
  representative of "arbitrary C/C++."
- **No external comparison here.** OSS-Fuzz-Gen's ~39 % is a build-script metric, not a
  fuzz-ready metric, and is not directly comparable (see CRITERIA.md).

## Implications for v0.2 (hypotheses, not results)

Each item below is a hypothesis to be **tested by re-running the frozen `repos.yaml`
unattended** and reporting the new N/25 against this 0/25 baseline. The suite is the test;
these are not claimed gains.

- **H1 — dependency resolution.** Automated system-dependency installation addresses the
  immediate observed failure of up to 8 in-scope repositories. Upper bound; downstream
  failures are unknown until the capability is run against the suite.
- **H2 — target inference.** Correcting how NEMESIS derives build targets addresses the
  immediate observed failure of 3 in-scope repositories. This is an internal defect, not
  an environmental gap, so it is independent of the host.
- **H3 — acquisition completeness.** Recursive submodule init and running project code-gen
  steps address the immediate observed failure of 2 in-scope repositories (iris, libdc).
- **H4 — harness include paths.** The 2 repositories that reached T2 (bcg729,
  onomondo-uicc) failed on a generated-harness `-I` path, not on harness logic — the
  smallest observed gap, and the only place this run touched harness output at all.

The before/after against this baseline — not any single figure — is the artifact.

---

*Provenance: analysis over `summary.json` and the per-repository records of run
`baseline_b8b7cf70_491eaad8` (experiment `b8b7cf70ab005860`, instance `491eaad8d49c3244`).
Classification rubric fixed prior to reading `stages.*.detail`.*
