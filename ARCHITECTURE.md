# Architecture

Design notes for anyone working on NEMESIS. [README.md](README.md) explains what the tool
does; this file explains how it is put together and which invariants must not be broken.

## The pipeline

```
Stage 1: Recon     OSS-Fuzz Introspector API + local source scan -> scored target functions
Stage 2: Neural    multi-provider LLM chain -> analysis, harnesses (3 variants), dictionary
Stage 3: Symbolic  Z3 + build verification  -> compile, instrument, pre-fuzz profiling
Stage 4: Fuzzing   AFL++ (parallel, persistent mode) -> crash triage -> candidates
                   feedback loop: Stage 4 -> Stage 2, up to N iterations
```

**LLM backend.** A provider chain behind the OpenAI SDK that falls back on rate limits:
NVIDIA NIM -> Cerebras -> Groq -> Gemini. Providers and per-role models are declared in
`config/default.yaml`; each entry names the env var holding its key (`api_key_env`), so
adding a provider needs no code change.

Responses are cached under `workspace/llm_cache/`, keyed by `sha256(model:system:prompt)` —
editing a system prompt therefore invalidates exactly the entries that depended on it.

## Layout

```
nemesis/
├── config/
│   ├── default.yaml          # engine defaults, provider chain, recon knobs
│   └── targets/              # one YAML per library; everything library-specific lives here
│       └── <library>/harnesses/   # harnesses a previous run validated, reused as references
├── nemesis/
│   ├── cli.py                # Click entry point
│   ├── config.py             # Pydantic settings + YAML layering
│   ├── models.py             # every model crossing a stage boundary
│   ├── pipeline.py           # orchestrator + feedback loop
│   ├── reporter.py           # findings database, disclosure drafts
│   ├── library_memory.py     # priors learned across runs, per library
│   ├── onboard.py            # generates a target config from a source tree
│   ├── recon/                # Stage 1 — Introspector, scoring, seed and mutator synthesis
│   ├── neural/               # Stage 2 — prompts, harness generation, RAG oracle
│   ├── symbolic/             # Stage 3 — Z3, patching, instrumented builds
│   ├── fuzzing/              # Stage 4 — AFL++ orchestration, triage, coverage
│   ├── api/                  # FastAPI backend for the dashboard
│   └── templates/            # harness scaffolding, mutator scaffold + adapters
├── frontend/                 # React dashboard (Vite); built output is served by the API
├── seeds/                    # curated seed corpora per format
└── workspace/                # runtime only: LLM cache, builds, AFL findings, run results
```

`workspace/` should live on a native filesystem. Putting it on a synced or network drive
makes AFL++ and the build steps dramatically slower.

## Invariants

These are the rules that keep the system generic. Breaking one tends to work for a single
library and then quietly rot.

**1. `models.py` is the contract.** Everything crossing a stage boundary is a Pydantic model
defined there. Adding a data type means adding it there; changing one means updating every
consumer — `grep -r "ModelName" nemesis/` before you touch it.

**2. Stages import lazily.** Stages are resolved on first access via `@property` on
`NemesisPipeline`, so the CLI starts fast. Never import z3, faiss or libclang at module
level. The same applies to the API routes.

**3. Configuration layers in one direction.** `config/default.yaml` ->
`config/targets/<name>.yaml` -> `NEMESIS_*` environment variables. Later wins. If a value
could plausibly differ per library, it belongs in the target YAML, not in code.

**4. LLM output is untrusted input.** Never use generated JSON, paths or code unvalidated:
parse JSON through `nemesis/neural/json_extractor.py` (it survives markdown fences and
truncation), resolve paths through `_resolve_llm_file_path()`, and compile-test every
harness before it reaches AFL. `_preflight_harness()` checks the AFL macros, the presence
of the target function and brace balance; `repair_harness()` feeds compile errors back to
the model for a bounded number of retries.

**5. No hardcoded paths.** Everything comes from config or is relative to `workspace/`.

**6. Two roots per target.** `source_root` is a pristine checkout that is *never* modified —
it is what crashes are replayed against, which is the whole basis for rejecting false
positives. `work_root` is a working copy, reset by rsync before each target. The default
harness strategy builds straight from `source_root` and never patches; the patch strategy
is the only thing that writes to `work_root`.

**7. Never hand-edit a target's source tree.** If a build breaks, fix it in the target YAML
(`-Wno-*` in `build.configure`), in the compile flags in `nemesis/symbolic/`, or in the
prompts in `nemesis/neural/` — so the fix survives the next rsync and applies to everyone.

**8. Library-specific knowledge lives in YAML.** `harness_template`, `harness_includes`,
`bonus_func_patterns`, `api_func_fixes`, `magic_bytes`, `encoder_formats`, per-target time
budgets, and `pinned_funcs` (including `indirect_reach` for functions only reachable through
a public API) are all config. Generic pipeline code must contain no library's API names.

## Subsystems

### Harness generation

1. **Variant selection** — three harnesses at temperatures 0.2 / 0.5 / 0.8, each profiled
   briefly under AFL; the one that grows the corpus fastest wins.
2. **RAG oracle** (`neural/oracle.py`) — libclang AST chunks indexed in FAISS, queried for
   the snippets most relevant to the target and injected into the prompt.
3. **Library memory** (`library_memory.py`) — priors accumulated across runs (working API
   patterns, type-to-header mappings, patterns known to fail) injected as `<library_memory>`.
4. **Real API declarations** — `harness_includes` headers are parsed and the true signatures
   are injected, which is what stops the model inventing functions.
5. **Repair** — compile errors go back to the model with oracle context.
6. **Caller escalation** — when a function cannot be driven directly, target a caller instead.

### Recon scoring

Driven by `recon_scoring` in the target YAML: filename and function-name bonuses, directory
and file penalties, and a coverage curve that peaks on partially-explored functions — fully
covered code has been fuzzed already, and completely untouched code is often unreachable.

### Crash triage

Every crash is replayed standalone to filter AFL persistent-mode artifacts, then classified
from the sanitizer report (with a signal-to-CWE fallback), and finally replayed against the
unmodified library. Only what reproduces there is reported. Hangs get the same treatment
with a timeout.

## Adding a target

```bash
git clone https://github.com/some/libfoo ~/libfoo_clean   # onboard scans a real tree
nemesis onboard --source-root ~/libfoo_clean --project-name libfoo
nemesis setup -t libfoo          # work copy + verify the builds compile
nemesis run -t libfoo --scan --max-targets 5
```

Then iterate on `config/targets/libfoo.yaml`: `build.configure`/`make`, `harness_includes`,
`harness_template`, `recon_scoring.bonus_func_patterns`, `api_func_fixes`, and
`repro_binary` for reproduction. Watch the harness compile rate and the fraction that
actually reach the target — those two numbers tell you what to fix next.

## Pitfalls

- Do not delete `workspace/` — it holds the LLM cache, crash artifacts and library memory.
- Do not edit a `source_root`.
- Do not run AFL++ without `AFL_NO_UI=1` in automated contexts.
- Do not import heavy dependencies at module level.
- Do not put library-specific logic in generic pipeline code.
- Do not use `git stash` to manage patches — that is what the two-root layout is for.
- Do not read the findings file with a bare `yaml.safe_load()`; use `reporter.load_findings()`,
  which understands the wrapper key and returns `[]` when the file does not exist.
- `pipeline.py` encodes a long tail of fixes for real failure modes. Change it surgically.

## Lessons that cost time

| Symptom | Cause | Fix |
|---|---|---|
| 0 % AFL coverage | library built without instrumentation | `rm -f CMakeCache.txt` and force `afl-clang-fast` |
| Harness will not compile | model invented API functions | inject real signatures from headers; keep `api_func_fixes` |
| Harness compiles, 0 crashes | it never reaches the target | variant selection, caller escalation, pre-fuzz profiling |
| Linker error on a static function | called directly | `is_static` triggers an explicit warning in the prompt |
| False hangs and crashes | AFL persistent-mode artifacts | standalone replay before anything is reported |
| Coverage plateaus early | a wrapper was pinned, not the workhorse | pin the function with the logic, and measure source coverage |
| Whole run skipped | provider hit its daily token limit | the fallback chain across providers |
| Fake OOM crashes | unbounded allocation from fuzz input | input size cap and `allocator_may_return_null=1` |
| Narrow structural triggers missed | byte flips cannot build valid structure | format-aware mutator synthesis |

## Style

Python 3.11+, type hints throughout. Pydantic v2 for data, Click for the CLI, structlog with
dot-notation events (`log.info("stage.start")`). Tests with pytest, lint with ruff
(line length 120; the ignore list in `pyproject.toml` documents why each rule is off). CI
runs lint and tests on 3.11 and 3.12 plus a dashboard build.
