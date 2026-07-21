# Architecture

Design notes for anyone working on NEMESIS. [README.md](README.md) explains what the tool
does; this file explains how it is put together and which invariants must not be broken.

## Overview

NEMESIS is an automated pipeline for constructing vulnerability-oriented fuzzing harnesses.
It combines deterministic source analysis with optional LLM assistance to identify validation
barriers and generate harness modifications that improve fuzzing reachability — automating a
step (getting a fuzzer past a library's own validation limits) that is otherwise manual expert
work.

The flow that carries the core contribution:

```
Target library source
        |
        v
Source reconnaissance
        |
        +----------------------+
        v                      v
Validation-gate           API / context
extraction                understanding
(deterministic)           (headers, RAG, LLM)
        |                      |
        +----------+-----------+
                   v
          Harness augmentation
                   |
                   v
          Fuzzing execution  (AFL++ / sanitizers)
                   |
                   v
          Crash / oracle evaluation
```

Everything else in this document — the four-stage pipeline, the invariants, the subsystems —
is how that flow is implemented and kept library-agnostic. The evidence for the claim is the
scientific appendix, [experiments/harness_autonomy/FINDINGS.md](experiments/harness_autonomy/FINDINGS.md).

## Scope boundaries

NEMESIS does **not** claim:

- autonomous vulnerability discovery,
- to replace or out-perform a fuzzer,
- general semantic reasoning about program behaviour.

It automates a previously manual step: constructing harnesses that expose deeper execution
states. The measured capability boundary (see FINDINGS.md) is deliberate: the deterministic
analyzer handles idiomatically-named limit setters; the LLM extends that to relaxation
mechanisms *visible in the code* (flags, options); mechanisms **not expressed in the code**
are not inferred — that was tested and does not work, and the documentation says so rather
than implying otherwise.

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

### Validation-gate extraction & harness augmentation

The core mechanism. `recon/validation_gates.py` statically scans the target's `.c` files for
public-API limit-relaxation setters — functions whose names match limit-relaxer idioms
(`_set_user`, `_set_*_max`, `_set_*_limit`, …), filtering out format-specific chunk/tag
setters. It is deterministic and needs no LLM: on raw libpng it recovers `png_set_user_limits`
unaided. `ContextBuilder` injects the result as section 0 of the architect context.

Two consumers, one pure-symbolic and one LLM-assisted:

- `render_validation_gates_block()` renders the extracted setters into the harness-generation
  prompt as a directive `<validation_gates>` block, and the LLM emits the calls.
- `inject_setter_calls()` rewrites a generated harness to add the setter calls at max-permissive
  values directly, with **no LLM at all** — the pure-symbolic path (comments are stripped before
  the idempotency check so a setter merely named in a comment is not skipped).

Either way the effect is a harness that raises the library's restrictive defaults so the fuzzer
can reach code those defaults gate off. The heuristic is scoped, by design, to the "restrictive
default + idiomatically-named setter" shape (the libpng family). Relaxation levers expressed as
flags/options rather than named setters are the LLM's job during harness generation; mechanisms
not expressed in the code at all are out of scope (see Scope boundaries). Regression tests live
in `tests/test_validation_gates.py`.

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

On top of that, `recon/git_history.py` adds two signals from a single `git log` pass:
**churn** (code changed recently has had less review exposure) and **past fixes** (bugs
cluster — a file that already needed an out-of-bounds fix is where the next one lives).
The same index fills `AnalysisContext.git_history`, so prior fix commits reach the analysis
prompt. Both are file-granular by design: recon ranks hundreds of candidates and a
per-function `git log -L` would dominate stage-1 runtime. No-ops on a non-git source tree.

### Byte-influence inference

`recon/byte_influence.py` works out which input bytes actually steer the program,
by measuring rather than by reading a spec or asking a model. Run the seed to get a
baseline edge map, substitute probe values at each offset, and attribute any edge
that moves to that byte. Adjacent bytes with similar edge sets are one field.

The output is a `fieldspec` — the same JSON `fieldspec_seedgen.py` already
interprets — so this is a new *producer* for an existing pipeline, not a new
subsystem. Fields carry `source: "coverage"` and a confidence; the interpreter
ignores unknown keys, so that metadata costs nothing.

It recovers **structure** (offsets, widths, groupings), never **semantics**. A
measured 2-byte integer is reported as an integer; whether it is a length prefix,
an element count or a checksum cannot be derived from control flow, and guessing
would produce seeds that are confidently wrong. `len` is deliberately never
emitted — that inference belongs to the LLM reading this spec.

Three things were measured, not assumed, against a target with known layout:

- **A single bit-flip is not enough.** It found 2 of the 3 observable bytes of a
  4-byte integer; flipping a middle byte often keeps the value in the same range.
  Hence several probe values per offset.
- **Some bytes are invisible in principle.** No value of the low byte of that
  integer changes any branch — `0x100` and `0x1FF` compare the same way. Mitigated,
  not solved, by snapping a 3-byte run up to 4; snapped fields record
  `observed_size` and take a confidence penalty so a measurement is
  distinguishable from an inference.
- **Clustering needs Jaccard similarity.** Equality of edge sets splits real
  fields (a middle byte can reach branches the high bytes cannot); non-empty
  intersection merges unrelated ones (the magic gates everything downstream, so it
  shares an edge with every later field). The correct layout is recovered for any
  threshold in `[0.15, 0.30]`; the default sits inside that window rather than on
  its edge, and is a parameter because one target is one datapoint.

Every stage writes its own artifact (`baseline.json`, `probes.json`,
`fields.json`, `fieldspec.json`) — when a real target yields a poor spec the
question is always *which* stage failed, and the final JSON cannot answer it.

**Probe the probe binary, not the fuzzing binary.** NEMESIS harnesses are AFL++
persistent mode with shared-memory test cases; outside `afl-fuzz` the runtime
disables that path and the harness receives no input at all, so every probe
returns an identical map and nothing looks influential. Measured on cJSON: a flat
9 edges for valid JSON, deep nesting and garbage alike, 0 of 11 bytes influential.

`recon/probe_build.py` builds the analysis-time twin: same harness source, same
library, same sanitizer flags, but the persistent macros `#undef`'d and replaced
by a one-shot stdin stub, compiled with `afl-clang-fast` so instrumentation is
kept. That turns the flat 9 edges into 4-93 by input, and 0% influential bytes
into 100%. Binaries are cached on a fingerprint of source + library mtime/size +
link line, so a rebuilt library invalidates them but a repeated probe does not
recompile.

This is not the debug build — that one drops AFL instrumentation entirely and so
has no coverage map to read. It is a third artifact alongside fuzz and debug.

Two traps are encoded there because both cost real time to find: the `#undef`s
are required (afl-clang-fast defines those macros itself and wins otherwise,
silently reverting to shared-memory mode), and the link line needs the library's
`-fsanitize=address` (without it you get `undefined reference to
__asan_report_load4`, which reads like an AFL problem and is not).

The second half of the trap is input delivery: a stdin-reading target handed a
path on argv also parses nothing, and looks exactly like a target whose bytes do
not matter. `ShowmapRunner` therefore detects the mode instead of assuming it
(cJSON: argv 4 edges, stdin 91).

The same blindness makes the pre-fuzz `afl-cmin` step a no-op on persistent
binaries — it reports 0 unique tuples and keeps no seeds, then the caller falls
back to the unminimised corpus, so no seeds are lost but the step does nothing.
Pre-existing bug, fixable the same way.

Results are bounded by what the seed reaches. An LZ4 seed that failed the frame
magic yielded exactly one influential byte, because parsing stopped there — the
method correctly reporting that nothing past byte 0 executed. Check
`baseline_edges` before reading a shallow result as "this format has no
structure".

### Structure-aware mutation

`templates/mutator/mutator_scaffold.h` provides the AFL custom-mutator entry points, RNG,
CRC32 and strategy dispatch; each adapter in `templates/mutator/adapters/` is a
self-contained TU implementing four hooks (`has_signature`, `parse`, `fix_integrity`,
`apply_targeted`). Hand-written adapters cover PNG, RIFF/WavPack, tar, ZIP, ASN.1/DER and
protobuf; the rest are LLM-synthesised per target from the PNG reference
(`recon/mutator_synthesis.py`).

Whether `fix_integrity` repairs a checksum is a per-format decision, not an oversight:
PNG's CRC is recomputed (a bad CRC is rejected before any mutated field is read), while
ZIP's is deliberately left broken (it covers uncompressed data, and the error path it
triggers is itself worth reaching). ASN.1, protobuf and tar payloads carry no checksum at
all — tar's header checksum is repaired, since a bad one fails the entry outright.

Adapters are exercised, not just compiled: `tests/mutator_harness.c` runs each one for
thousands of rounds under ASAN/UBSan. It calls the hooks directly against exactly-sized
buffers as well as through `afl_custom_fuzz`, because the scaffold's 1 MB scratch buffer
otherwise masks semantic overflows the same way a large static buffer masked them in
harnesses (see Lessons).

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
