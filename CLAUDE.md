# CLAUDE.md — NEMESIS

> This file guides Claude Code when working on this repository.
> Read this ENTIRELY before making any changes.

## What Is NEMESIS

**NEMESIS** (Neuro-Symbolic Exploit Mining Engine for Software Insecurities) automates vulnerability discovery in C/C++ libraries by chaining four stages:

```
Stage 1: Recon     → OSS-Fuzz Introspector API + local scan → scored target functions
Stage 2: Neural    → Multi-provider LLM chain → analysis, patches, harnesses (3 variants)
Stage 3: Symbolic  → Z3 + build verification → patch/harness compile + profiling
Stage 4: Fuzzing   → AFL++ (4 instances, persistent mode) → crash triage → CVE candidates
         ↻ Feedback loop: Stage 4 → Stage 2 (up to 3 iterations)
```

**LLM Backend:** Multi-provider chain via OpenAI SDK (auto-fallback on rate limit):
Groq (70b) → NVIDIA NIM (70b) → Cerebras → Gemini → Groq (8b)

Env vars: `GROQ_API_KEY`, `NVIDIA_API_KEY`, `CEREBRAS_API_KEY`, `GOOGLE_AI_KEY`

LLM cache at `workspace/llm_cache/` keyed by `sha256(model:system:prompt)` — changing any system prompt auto-invalidates relevant cache entries.

**Origin:** Solo research project on automated vulnerability discovery.

## Target Configs

| Library | Config | Strategy |
|---------|--------|----------|
| libarchive | `config/targets/libarchive.yaml` | A (harness) + B (patch) |
| libtiff | `config/targets/libtiff.yaml` | A |
| libxml2 | `config/targets/libxml2.yaml` | A |
| brotli | `config/targets/brotli.yaml` | A (indirect_reach) |

## Project Structure

```
nemesis/
├── config/
│   ├── default.yaml              # Default engine parameters
│   └── targets/                  # Per-library YAML overrides
│       ├── libarchive.yaml
│       ├── libtiff.yaml
│       ├── libxml2.yaml
│       └── {library}/harnesses/  # Saved crash-producing harnesses
├── nemesis/                      # Python package
│   ├── cli.py                    # Click CLI entry point
│   ├── config.py                 # Pydantic settings + YAML loading
│   ├── models.py                 # ALL shared data models (Pydantic v2)
│   ├── logging.py                # structlog setup
│   ├── pipeline.py               # Orchestrator + feedback loop (~90 fixes)
│   ├── reporter.py               # findings.yaml management + CVE reports
│   ├── library_memory.py         # Cross-run learned priors per library
│   ├── onboard.py                # `nemesis onboard` — auto-generate target YAML
│   ├── verifier.py               # Verification utilities
│   ├── recon/                    # Stage 1: OSS-Fuzz Introspector + local scan
│   │   └── __init__.py
│   ├── neural/                   # Stage 2: LLM analysis + harness generation
│   │   ├── __init__.py           # NeuralStage, LLMClient, PromptBuilder
│   │   ├── oracle.py             # CodebaseOracle (RAG: libclang + FAISS + NVIDIA NIM)
│   │   └── json_extractor.py     # JSON parsing from LLM responses
│   ├── symbolic/                 # Stage 3: Z3 verification + patch + build
│   │   └── __init__.py           # Z3Verifier, PatchApplicator, InstrumentedBuilder
│   ├── fuzzing/                  # Stage 4: AFL++ orchestration + triage
│   │   └── __init__.py           # AFLOrchestrator, CrashTriager, CoverageAnalyzer
│   └── templates/                # FuzzedDataProvider header, etc.
├── seeds/                        # Seed files per format
├── tests/
├── docker/
├── workspace/                    # Runtime: ~/nemesis_workspace (ext4, avoids OneDrive)
├── findings.yaml                 # Bug database, generated at runtime (use reporter.load_findings(), NOT raw yaml; gitignored)
└── pyproject.toml
```

## Commands

```bash
# Installation
pip install -e ".[dev]"

# Running
nemesis run -t libarchive                    # Full 4-stage pipeline
nemesis run -t libarchive --scan             # Scan mode (15min × 20 targets)
nemesis run -t libarchive --scan --max-targets 5
nemesis run -t libarchive --deep             # Scan → score → deep fuzz top-3 × 4h
nemesis run -t libxml2 --scan --max-targets 7
nemesis recon -t libarchive                  # Stage 1 only
nemesis config -t libarchive --show          # Show resolved config
nemesis onboard --source-root ~/libpng --project-name libpng  # Auto-generate target YAML

# Testing
pytest tests/ -v
ruff check nemesis/ tests/
ruff format nemesis/ tests/
```

## Development Log

**Recent fixes (Fix 113-121, 2026-04-28):**
- Fix 113: `_resolve_link_libs()` — generic linker path resolution for all build types
- Fix 114: `indirect_reach` — planner detects internal funcs reached via public API params
- Fix 115: Encoder seed role detection — `encoder_formats` + `encoder_subdirs` in config
- Fix 116: Bitmap reach fallback — >3% bitmap overrides GDB false negative
- Fix 117: Strip `${...}` cmake vars from syntax check
- Fix 118: Rule 12 — fuzz-derived params (quality/level from input, never hardcoded)
- Fix 119: Preflight skip for indirect_reach targets
- Fix 120: Dynamic time budget — `scan_budget_hours`, `per_target_max_minutes`
- Fix 121: C++ syntax auto-fix in C harness (FuzzedDataProvider, new/delete, std::)

**Fix 135 (2026-04-29) — Sanitizer profiles + differential oracle:**
- `target.sanitizer_profile` (`asan_only` | `asan_ubsan` | `asan_ubsan_strict`) drives the AFL harness compile flags via `nemesis/symbolic/__init__.py::_resolve_sanitizer_flags()`. Default `asan_ubsan` adds `-fno-sanitize-recover=undefined` so UBSan diagnostics actually crash AFL's child instead of merely logging — closes a long-standing blind spot for signed-int overflow / shift overflow / pointer-overflow in compression and parser libs.
- `pinned_func.differential_oracle: true` — round-trip oracle target. The neural-stage prompt builder injects a `<differential_oracle>` block telling the LLM to wrap the harness with `decode(encode(x)) == x` + `abort()` on mismatch. Detects silent-corruption bugs that ASAN/UBSan would never see (the `BrotliEncoderCompress_RoundTrip` target is the reference example).

**Fix 136 (2026-04-29) — Leak detection + output invariants:**
- `target.leak_detection: true` enables a post-fuzz LeakSanitizer pass via `CrashTriager.triage_leaks()`. AFL persistent mode has no clean exit and so cannot drive LSan; this pass instead samples N inputs from the AFL queue and replays them against the single-shot debug binary with `ASAN_OPTIONS=detect_leaks=1`. Every unique `LeakSanitizer:` report becomes a `CWE.MEMORY_LEAK` (CWE-401) `CrashReport`. Sample size: `target.leak_detection_sample_size` (default 30).
- `pinned_func.output_invariants: [str]` — list of plain-C boolean expressions the LLM must encode as `if (!(cond)) abort();` after the operation in the harness loop. The prompt builder injects them as an `<output_invariants>` block. Use this for format-specific safety contracts that are invisible to ASAN/UBSan — e.g. `encoded_size <= BrotliEncoderMaxCompressedSize(input_size)` (encoder violating its own self-declared upper bound = silent heap corruption).

**Fix 154 (2026-05-10) — C++ project awareness in onboard:**
- New helpers in `nemesis/onboard.py`: `_detect_cpp_project(source_root)` (scans for .cpp/.cxx/.cc/.c++/.hpp/.hh/.hxx files; falls back to CMake CXX_STANDARD/CXX_STANDARD/cxx_std_ tokens — strictly unambiguous tokens to avoid false positives like cJSON's set_target_properties), `_detect_findpackage_deps(source_root)` (extracts find_package(X) calls), `_format_findpackage_comment(deps)` (renders apt-install hints in YAML header).
- `detect_library_info` sets `result["is_cpp"]`. `generate_build_commands` accepts `is_cpp` and emits `-DCMAKE_CXX_FLAGS="..."` (mirroring `-DCMAKE_C_FLAGS`) when True. Pure-C projects (cJSON, libtiff, libxml2) keep the existing C-only configure command.
- C++ link_libs baseline: `-lstdc++ -lpthread` prepended automatically. New `_FIND_PACKAGE_MAP` entries: `absl` (fan-out of common absl_* libs), `ICU`. New `_APT_HINT_MAP` translates find_package names → apt package names (`absl` → `libabsl-dev`, `ICU` → `libicu-dev`, `OpenSSL` → `libssl-dev`, etc.). YAML header now lists per-dep apt hints + a one-line bulk install command, and shows `# Language: C` or `# Language: C++` so review-before-run is fast.
- Header discovery extended for non-standard layouts (RE2 ships `re2/re2.h` under `<source_root>/re2/`, not `include/`). Probes `<source_root>/<project_name>/` for each name variant; also scans `.hpp` and `.hh` extensions in addition to `.h`. cjson/libtiff/libxml2 still match their existing layouts (regression-tested via re-onboard).
- The harness_template generated by the architect LLM is automatically C++-aware now because the system prompt includes the resolved headers (e.g. `re2/re2.h`); when the LLM sees an `#include <re2/re2.h>` header, it produces a `extern "C" int LLVMFuzzerTestOneInput`-style C++ harness with `std::string_view`, `re2::RE2`, `-std=c++17` compile flags. No prompt-template change needed.

**Fix 153 (2026-05-10) — Auto-sanitizer selection (LLM rank + top-K passes):**
- New `--auto-sanitizer` CLI flag in `nemesis run` triggers `nemesis/recon/sanitizer_ranker.py::rank_sanitizers()` which scores `asan_ubsan` / `asan_ubsan_strict` / `msan` / `tsan` (0.0–1.0) given the first pinned_func source. Top-K profiles (default K=2, configurable via `--auto-sanitizer-top`) run as separate sequential passes; each pass mutates `cfg.target.sanitizer_profile` and re-invokes the build → execute → triage chain. Findings.yaml dedup is automatic via `reporter.merge_crash_reports`.
- Hard rules apply BEFORE the LLM call: msan score forced to 0 if `msan_supported=false`; tsan score forced to 0 if `tsan_supported=false` OR no threading tokens (pthread, std::thread, _Atomic, omp, GThread, libuv) appear in source. The LLM only ranks remaining candidates; if the LLM is unavailable or returns unparseable JSON, falls back to `{asan_ubsan: 1.0}` so at least one pass always runs.
- `pick_top_k(ranking, k=2, min_score=0.3)` drops profiles below 0.3 confidence and falls back to `['asan_ubsan']` if all are zeroed. Rationale strings from the LLM (and hard-rule overrides) are logged at `auto_sanitizer.rationale` so the user sees WHY each profile was chosen / skipped. CLI multi-pass logic lives in `_execute_one_pass()` (extracted from `_run_single_target()`); profile-selection lives in `_resolve_auto_sanitizer_profiles()`.
- Use case: `nemesis run -t cjson --auto-sanitizer --scan` runs ASAN pass (finds CVE-2023-53154 OOB read) AND MSan pass (finds any uninit reads) in one command — eliminates manually maintaining `cjson_msan.yaml` parallel configs.

**Fix 152 (2026-05-10) — Onboard auto-detection for TSan / MSan candidates:**
- `nemesis onboard` now scans the source tree for threading tokens (pthread.h, `<thread>`, `std::thread`, omp.h, `_Atomic`, `atomic_`, GThread, libuv) and inspects `link_libs` to flag whether the new MSan/TSan profiles are realistic for this library. Result is rendered as a YAML header comment in the generated target file — no schema changes, opt-in remains explicit. Helpers live module-level in `onboard.py` (`_probe_oracle_candidates`, `_scan_threading_evidence`, `_msan_external_deps`, `_format_oracle_hints_comment`) so they're easy to test independently. Scan is bounded (1500 files, 2MB/file) to keep onboard fast on big trees.
- TSan signal: any threading token found → "TSan candidate: YES" with the first 3 evidence files + actionable enable instructions. MSan signal: empty `link_libs` or only `-lm/-ldl/-lpthread/-lrt/-lc` → "MSan candidate: YES"; any other `-l` flag → "MAYBE" with the blocker list, suggesting MSan-rebuild of those deps.

**Fix 151 (2026-05-10) — Oracle cross-config validation gates:**
- New module `nemesis/recon/oracle_validation.py` runs at `pipeline.execute()` startup and emits structured warnings (NOT errors — those stay in `_resolve_sanitizer_flags`) for misconfigurations across the Fix 148-150 oracle modes. Catches:
  1. `sanitizer_profile: tsan` with no `threaded_oracle: true` pinned_func — TSan wastes cycles with no race oracle.
  2. `threaded_oracle: true` pinned_func with non-tsan sanitizer profile — multi-threaded harness runs but only deadlocks-via-timeout get caught.
  3. `differential_reference` pointing to a symbol that does not appear in the source tree — likely undefined-reference at link time. Best-effort grep with file/size budget so startup cost stays trivial.
- Each warning includes a `suggestion` field with the concrete fix. Logged via `log.warning("oracle.config.<key>", ...)`. Adding new soft cross-checks: append a function to the `_CHECKS` tuple in oracle_validation.py.

**Fix 150 (2026-05-10) — TSan profile + threaded harness oracle + race triage:**
- New `sanitizer_profile: "tsan"` value in `_resolve_sanitizer_flags()` produces a ThreadSanitizer-only build (`-fsanitize=thread -fno-sanitize-recover=thread`). Mutually exclusive with ASAN and MSan — runs as a SEPARATE AFL instance. Gated by `target.tsan_supported: true`; `_resolve_sanitizer_flags` raises ValueError otherwise to prevent false-positive floods from libs that just happen to use globals.
- New `pinned_func.threaded_oracle: true` flag triggers a `<threaded_oracle>` prompt block in `nemesis/neural/__init__.py::PromptBuilder.build_harness_prompt`. The block tells the LLM to spawn ≥2 pthread workers inside `LLVMFuzzerTestOneInput`, share the parser/codec instance across them, `pthread_join` before return, and link with `-pthread`. Critically: NO locks around the target call — the point is to expose missing synchronisation INSIDE the library.
- CrashTriager extensions: `ASAN_CWE_MAP` now maps `"data race"`, `"data race on"`, `"lock-order-inversion"`, `"thread leak"`, `"double lock of a mutex"`, `"unlock of an unlocked mutex"` to `CWE.RACE_CONDITION` (CWE-362, new enum value). `_classify_sanitizer` recognises `ThreadSanitizer:` reports and returns `SanitizerClass.TSAN` (also new). `CWE_SEVERITY[CWE.RACE_CONDITION] = MEDIUM`.
- `threaded_oracle` and `sanitizer_profile: tsan` are independent: the threaded harness can run under any sanitizer (won't find races without TSan but exposes deadlocks via timeout). Pair them for full race coverage. Track 3 of the May 2026 Targeted Oracle Expansion — completes the planned MSan/TSan/differential expansion that lifted CVE-space coverage from ~25% to a projected ~45%.

**Fix 149 (2026-05-10) — MSan sanitizer profile + uninit-read coverage:**
- New `sanitizer_profile: "msan"` value drives a MemorySanitizer-only build via `_resolve_sanitizer_flags()`. Mutually exclusive with ASAN (different runtimes) — runs as a SEPARATE AFL instance, not a replacement for the default `asan_ubsan` build. Detects use-of-uninitialized-value reads (CWE-908) that ASAN/UBSan are blind to. Compile flags: `-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-sanitize-recover=memory`. The track-origins=2 setting makes reports actionable (shows where the uninit value was allocated) at ~1.5x runtime cost.
- Gated by `target.msan_supported: true` (default False). Without instrumented deps (libc, libstdc++, third-party libs all built with `-fsanitize=memory`), MSan reports thousands of false positives from external calls. The gate forces explicit user confirmation that the dependency chain has been rebuilt; `_resolve_sanitizer_flags` raises ValueError when `msan` profile is requested without the flag set, preventing wasted runs.
- CrashTriager integration was already in place: `ASAN_CWE_MAP` maps `"use-of-uninitialized-value"` and `"uninitialized value"` to `CWE.UNINITIALIZED_VALUE`, `_classify_sanitizer` detects `MemorySanitizer:` reports, and `CWE_SEVERITY` maps it to MEDIUM. No triage changes needed. Track 2 of the May 2026 Targeted Oracle Expansion (after Fix 148 differential_reference; TSAN race detection still pending).

**Fix 148 (2026-05-10) — Cross-implementation differential oracle:**
- `pinned_func.differential_reference: <name>` generalizes the Fix 135 round-trip oracle into arbitrary cross-implementation comparison. When set to a non-empty string, the neural-stage prompt builder injects a `<differential_reference>` block telling the LLM to call BOTH the target function and the named reference impl on the same fuzz input, then `abort()` on any output / status divergence. Use cases: strict-vs-lenient mode of the same parser (`xmlReadMemoryRecover`), library-vs-library spec compliance (`expat::XML_Parse`), fast-path-vs-reference-impl (`ZSTD_decompress_ref`). May coexist with `differential_oracle: true` for both round-trip AND cross-check on the same target. This is the first track of the May 2026 Targeted Oracle Expansion — adds the bug class "differential logic divergence" to NEMESIS's detection surface, which ASAN/UBSan/round-trip alone cannot see. Audit on 2026-05-10 measured baseline coverage at ~20–25% of CVE-space; Fix 148 is the first of three planned expansions (MSAN + TSAN tracks pending).

**Fix 137 (2026-05-01) — Reference-harness verification for leaks:**
- After `triage_leaks()` collects raw LSan reports, it now rebuilds the saved reference harness at `config/targets/<target>/harnesses/<func>.c` (the high-coverage version Nemesis already validated on a prior run) and replays each leak input against it. Reports that don't reproduce there are dropped as harness-induced false positives — the LLM had an early-return cleanup bug on this run, not a real library leak. Discovered after the brotli campaign: 2 Phase-1 leaks vanished entirely on Phase-2 (where the pipeline regenerated the harness from scratch), confirming both were LLM artefacts. New helper `CrashTriager._build_reference_harness(func_name)` compiles the saved C source against the existing debug build of the library, with `clang -fsanitize=address,undefined`. Falls back to the previous behaviour when no saved harness exists (first run for that target).

**Key metrics to track:**
- Harness compile rate (target: ≥5/7 for any library)
- Target function reach rate (target: ≥3/7 compiled)
- False positive rate (hang standalone verification filters AFL artifacts)
- Brotli encoder line coverage (current best: 53.30%, target: >70%)

## Architecture Decisions (DO NOT VIOLATE)

### 1. Pydantic Models Are The Contract
ALL inter-stage data flows through `nemesis/models.py`. If you add a new data type, add it there. If you change a model, update ALL consumers. Run `grep -r "ModelName" nemesis/` before changing any model.

### 2. Lazy Stage Imports
Stages are imported on first access via `@property` in `NemesisPipeline`. This keeps CLI startup fast. Do NOT import heavy deps (z3, faiss, libclang) at module level.

### 3. Configuration Layering
`config/default.yaml` → `config/targets/{target}.yaml` → `NEMESIS_*` env vars.
Target configs override defaults. Env vars override everything. Never hardcode values that should be configurable.

### 4. LLM Output Is Untrusted
NEVER trust LLM-generated JSON, file paths, or code without validation:
- Use `json_extractor.py` for JSON parsing (handles markdown fences, truncation)
- Use `_resolve_llm_file_path()` for path resolution
- Compile-test harnesses before feeding to AFL
- `_preflight_harness()` checks AFL macros, target func presence, balanced braces
- LLM repair (`repair_harness()`) auto-fixes compile errors (up to 2 retries)

### 5. All Paths From Config
No hardcoded paths. Everything comes from config YAML or is relative to `workspace/`.

### 6. Two-Repository Architecture
Every target has two roots:
- **`source_root`** (e.g. `~/libarchive_clean/`): pristine checkout — **NEVER modified**
- **`work_root`** (e.g. `~/libarchive_work/`): working copy — reset via rsync before each target

Strategy A (harness): builds from `source_root`, never patches.
Strategy B (patch): rsyncs `source_root → work_root`, patches `work_root`, builds from `work_root`.

### 7. NEVER Manually Edit Target Source Repositories
If a build fails due to LLM-induced warnings, fix it in:
- `config/targets/{target}.yaml` → add `-Wno-*` flags to `build.configure`
- `nemesis/symbolic/__init__.py` → harness compile flags or `_patch_is_dangerous()`
- `nemesis/neural/__init__.py` → improve prompts to avoid the bad pattern

### 8. Library-Specific Logic Lives in Config, Not Code
All library-specific rules belong in `config/targets/{library}.yaml`:
- `harness_template`: full system prompt for harness generation (replaces generic prompt)
- `harness_includes`: public headers to scan for API declarations
- `bonus_func_patterns`: function-name scoring bonuses
- `api_func_fixes`: LLM hallucination → correct replacement mapping
- `magic_bytes`: format magic bytes for AFL dictionary
- `encoder_formats` / `encoder_subdirs`: plaintext seed dirs for encoder targets (Fix 115)
- `per_target_max_minutes` / `scan_budget_hours`: dynamic time budgeting (Fix 120)
- `indirect_reach` on `pinned_funcs`: internal funcs reached via public API (Fix 114)

Generic pipeline code (`neural/__init__.py`, `pipeline.py`) must NOT contain library-specific API names, function calls, or patterns.

## Key Subsystems

### Harness Generation Pipeline (unified for both strategies)
1. **Variant selection** (`_select_best_harness_variant()`): generates 3 variants at temperatures [0.2, 0.5, 0.8], profiles each for 2 min with AFL, picks best by corpus_paths
2. **Oracle RAG** (`neural/oracle.py`): libclang AST + FAISS + NVIDIA NIM embeddings → injects relevant source snippets into prompt
3. **Library memory** (`library_memory.py`): cross-run learned priors (API patterns, type→header, forbidden patterns) → injected as `<library_memory>` block
4. **API declarations** (`build_harness_prompt()`): scans `harness_includes` headers → injects `<api_declarations>` block with real function signatures
5. **LLM repair** (`repair_harness()`): auto-fixes compile errors with oracle context
6. **Caller escalation** (`generate_harness_via_caller()`): when direct harnessing fails, targets a higher-level caller

### Recon Scoring
Config-driven via `recon_scoring` in target YAML:
- `bonus_patterns`: filename prefix → score bonus
- `bonus_func_patterns`: function name substring → score bonus (Fix 91)
- `penalty_dirs`, `penalty_files`, `penalty_funcs`: exclusion scoring
- `low_value_files`: variable penalties for text-serialization files
- Coverage-based: peak score at 10-30% coverage (partially explored functions)

### Crash Triage
- Standalone verification filters AFL persistent-mode false positives (sig:13, sig:04)
- Hang verification: 15s timeout, exit=0 standalone → false positive
- ASAN log capture with `symbolize=1:log_path=`
- Signal→CWE fallback: sig:06→CWE-122, sig:11→CWE-476
- `reproduces_in_app`: tests with real binary (bsdtar, tiffinfo, xmllint)

## Adding a New Target Library

1. **Prepare source:** `git clone` → `~/libfoo_clean/`, copy → `~/libfoo_work/`
2. **Auto-generate YAML:** `nemesis onboard --source-root ~/libfoo_clean --project-name libfoo`
3. **Refine `config/targets/libfoo.yaml`:**
   - Set `build.configure` / `build.make` (cmake/autoconf/meson)
   - Set `harness_includes` (public API headers)
   - Set `harness_template` (library-specific harness system prompt with working template)
   - Set `recon_scoring.bonus_func_patterns` (important API functions)
   - Set `api_func_fixes` (known LLM hallucinations → corrections)
   - Set `repro_binary` / `repro_args` (for crash reproduction)
4. **Run:** `nemesis run -t libfoo --scan --max-targets 5`
5. **Iterate:** check compile rate, adjust `harness_template` and `api_func_fixes`

## What NOT To Do

- Do NOT delete `workspace/` — it contains cached LLM responses, crash artifacts, library memory
- Do NOT edit any `source_root` directly
- Do NOT run AFL++ without `AFL_NO_UI=1` in automated contexts
- Do NOT assume LLM JSON output is valid — always validate
- Do NOT use `sudo` in the build pipeline
- Do NOT rewrite pipeline.py from scratch — it has ~90 battle-tested fixes
- Do NOT import heavy libraries at module top level
- Do NOT hardcode library-specific logic in generic pipeline code
- Do NOT use git stash for managing LLM patches — use rsync + two-repo architecture
- Do NOT load findings.yaml with raw `yaml.safe_load()` — use `reporter.load_findings()` (it has a `findings:` wrapper key)

## Critical Lessons (condensed)

| Bug | Impact | Fix |
|-----|--------|-----|
| Uninstrumented library | 0% AFL coverage | Always `rm -f CMakeCache.txt` + `-DCMAKE_C_COMPILER=afl-clang-fast` |
| LLM hallucinates API functions | Compile failure | `<api_declarations>` from real headers (Fix 92) + `api_func_fixes` |
| Harness doesn't reach target | 0 crashes | Variant selection (Fix D) + caller escalation (Fix E) + profiling |
| Static function direct call | Linker error | `is_static` flag + `*** STATIC FUNCTION WARNING` in prompt |
| AFL persistent mode artifacts | False positive hangs/crashes | Standalone verification (sig:13, sig:04 fast-reject) |
| `archive_read_data_skip()` | Bypasses 90% of code | Library-specific rules in `harness_template`, not generic prompt |
| LLM patches function signature | Build failure | Prompt rules + `_patch_is_dangerous()` validation |
| Daily token limit (TPD 429) | 19/20 targets skip | Auto-fallback chain across providers |
| ASAN OOM false positives | Fake crashes | 512KB input cap + `allocator_may_return_null=1` + UBSan |

## Style Guide

- Python 3.11+, type hints everywhere
- Pydantic v2 for all data models
- structlog for all logging (dot-notation events: `log.info("stage.start")`)
- Click for CLI
- ruff for linting/formatting (line-length=100)
- Tests with pytest
- Docstrings on all public methods
