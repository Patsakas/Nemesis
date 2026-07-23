# Onboarding benchmark — baseline findings

First unattended baseline of the frozen onboarding suite. Every number below is from one
run and can be reproduced from the committed suite; the analysis that follows the numbers is
labelled as such and separated from them.

- **experiment_id** `b8b7cf70ab005860` — NEMESIS at commit `33dd9cf` (before the include-path
  and timeout fixes), onboarder `mistralai/mistral-medium-3.5-128b`, provider-chain head
  `openai/gpt-oss-120b`, clang 18.1.3.
- **benchmark_instance_id** `491eaad8d49c3244` — 25 repositories, OSS-Fuzz exclusion snapshot
  `1353ef81`, sampling salt `nemesis-onboard-suite-v1`.
- **intervention** `0` throughout, by construction: the runner has no path to retry, install
  a dependency, or edit a generated artifact.

This measures how far NEMESIS carries an arbitrary C repository unaided. It is the
counterpart to [../../experiments/harness_autonomy/FINDINGS.md](../../experiments/harness_autonomy/FINDINGS.md):
that appendix measures whether a *constructed* harness reaches deeper code, this measures how
often one gets constructed at all.

---

## 1. Observed findings

These are measurements. No interpretation.

### Funnel

| Tier | Reached | P(reached \| previous reached) |
|------|--------:|-------------------------------:|
| T0 acquired | 25 | — |
| T1 config generated | 25 | 100 % |
| T2 library built | 2 | 8 % |
| T3 harness generated | 0 | 0 % |
| T4 harness compiled | 0 | — |
| T5 fuzz-ready | 0 | — |

The two repositories that built their library were `onomondo/onomondo-uicc` and
`BelledonneCommunications/bcg729`. Neither is one of the five parser-like repositories in the
sample; both are non-parsers.

### First-failure distribution

23 of 25 terminated at T2, one at T3, and the two survivors reached T2 and then went no
further inside the run (nothing reached T3 successfully).

| Terminating tier | Failure class | Count |
|------------------|---------------|------:|
| T2 | CONFIGURE_FAILURE | 9 |
| T2 | COMPILE_FAILURE | 7 |
| T2 | DEPENDENCY_FAILURE | 7 |
| T3 | COMPILE_FAILURE | 1 |

### Cost

Median duration of each stage on the runs where it succeeded:

| Stage | Median |
|-------|-------:|
| T1 config generation | 481 s |
| T2 library build | 8 s |

Configuration synthesis — the LLM stage — dominates wall-clock. The library build, where
almost everything failed, failed in seconds.

### Root-cause taxonomy

Each T2 failure was read from its log and, where the cause was not self-evident, confirmed
against the repository's own source tree. Classes:

- **ENV** — an external prerequisite is absent from the environment; no onboarding change can
  supply it.
- **DET** — a deterministic onboarding repair would plausibly fix it (a build step, a clone
  option, a corrected flag), no model call required.
- **PROJECT** — a project-specific incompatibility with no general fix.
- **UTIL** — information NEMESIS already computed but did not propagate to the build.

| Class | Count | Repositories (root cause) |
|-------|------:|---------------------------|
| ENV | 13 | astera (OpenAL), lv_port_pc_vscode (SDL2), vdi-stream-client (sdl3), clam (Boost), BotW-BetterVR (OpenXR), turbovnc (turbojpeg), meatloaf (ESP-IDF), lv_stm32 (arm ASM), ESCape32 (arm-none-eabi-gcc), rp6502 (PICO_SDK_PATH), H5Z-ZFP (Fortran), smk (sdcc), pg_ivm (pg_config) |
| DET | 8 | pspsdk (`./bootstrap` generates VERSION — verified), libdc (`BUILT_SOURCES = revision.h` — verified), iris (`deps/parallel-hashmap` submodule empty — verified), gensio + gifsicle + ProcMon + tiny-AES (`.la` / make-target — has pre-generated `configure`), dbmail (invented `--without-python`; also gmime absent = ENV) |
| PROJECT | 1 | fdpp (custom `clang.mak`) |
| UTIL | 1 (at T3, not T2) | bcg729 (internal header dir not propagated) |

Verified individually from source: pspsdk's `configure.ac` reads
`m4_esyscmd_s([cat VERSION])` and `./bootstrap` writes `VERSION`; libdc's `src/Makefile.am`
declares `revision.h` a `BUILT_SOURCES` target; iris's `.gitmodules` lists
`deps/parallel-hashmap` and the directory is empty after a non-recursive clone.

---

## 2. Validated conclusions

These follow from the findings above and are bounded by this sample and this environment.

- **Configuration synthesis generalised across the sample.** The onboarding stage produced a
  build configuration for all 25 repositories — audio codec, VR mod, VNC server, PS2
  emulator, embedded firmware, meson and autotools projects alike. Failures occurred during
  the library build, not during configuration synthesis.
- **Under this environment, the T2 library build is the dominant bottleneck**, not harness
  generation. 23 of 25 stopped there. The harness pipeline was barely exercised because
  almost nothing reached it.
- **The largest single failure class is a missing external prerequisite (ENV, 13/25).** More
  than half of these repositories require an SDK, cross-compiler or system library that the
  evaluation environment does not provide. This is a property of a deliberately broad sample
  — the predicates never filtered for buildable-in-a-plain-container — not of NEMESIS.
- **Information-propagation failures were rare.** Exactly one repository (bcg729, at T3) lost
  a value the pipeline had already computed. The hypothesis that this was a widespread class
  is not supported: it is a special case.
- **There is no single dominant deterministic fix.** The ~8 deterministic candidates split
  across four or five unrelated patterns (bootstrap, build invocation, recursive clone,
  configure flags), each covering one to three repositories. An earlier guess that an
  autotools-bootstrap step would recover a large family was **wrong** — gensio and gifsicle
  ship a pre-generated `configure` and fail later, at make.

### Two ways to read the pass rate

The raw number and the scope-adjusted analysis are kept separate so the second does not read
as retroactively discarding hard repositories.

- **Raw:** T2 success 2/25; nothing reached a compiled harness.
- **Scope-adjusted:** 13/25 required an external prerequisite absent from the environment. Of
  the remaining 12, roughly 8 look deterministically repairable in onboarding and 1 is a
  project-specific build system. The harness pipeline (T3+) was reached by only one
  repository, so this run says almost nothing about it either way.

---

## 3. Design implications

Roadmap, not results. Ordered by expected impact given the taxonomy.

1. **An environment/prerequisite classifier before the expensive stages.** ENV is the
   largest class and is unfixable by onboarding, yet the run still spent a median 481 s of
   configuration synthesis on repositories that a `pkg-config` / `find_package` probe could
   have rejected in seconds. Detecting an absent prerequisite early and bailing is the single
   highest-impact change, and it *reduces* work rather than adding a model.
2. **Deterministic onboarding repairs, before any AI-driven repair loop.** Small and
   several: an autotools bootstrap step where a project ships no `configure`, recursive clone
   for submodule-bearing repos, and corrected build invocation (the `.la` / make-target
   family). Each is a bounded, testable, no-inference change.
3. **Build-invocation investigation is the highest-value remaining deterministic question.**
   gensio, gifsicle, ProcMon and tiny-AES all failed at make with a missing `.la` or a wrong
   target while holding a working `configure`. If they share one root cause, that is the
   largest single deterministic win; if they do not, the benchmark has shown the failures are
   genuinely heterogeneous. Both answers are useful.
4. **A repair loop is a later step, and its scope is now smaller than it looked.** It should
   target T2 configure/build, classify deterministically before spending a model call, and
   bail on ENV rather than trying to repair it. The one utilization failure (bcg729) is
   already handled deterministically by commit `c234b8e`, outside any loop.

---

## 4. What the baseline changed

The benchmark's value here was not a score. It was disconfirmation. Going in, the working
assumption was that harness generation was the main bottleneck; the baseline located it
earlier, at the library build. Three specific hypotheses were tested and dropped:

- that harness/include propagation was the dominant failure mode — it was one repository;
- that an autotools-bootstrap step would recover a large family — two of the candidates
  already ship `configure`;
- that bcg729 was representative — it is the only utilization failure in the sample.

Development priorities now rest on measured failure classes rather than on the initial
intuition. The treatment run for `c234b8e` is expected to move exactly one repository
(bcg729, T3→T4) on this instance and is scheduled accordingly, as a confirmation of a
correct-but-narrow fix rather than a headline result.
