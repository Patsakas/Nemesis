# Onboarding benchmark — selection criteria

**Frozen before any repository was inspected and before any run.** The point of writing
this first is that the sample cannot be adjusted after seeing which repositories NEMESIS
happens to handle well.

## What this benchmark measures

How often, and how quickly, NEMESIS turns an *arbitrary* C project into something a fuzzer
can actually run — with no human help. It measures **breadth and effort**, not bug-finding.
Whether the resulting harness reaches interesting code is a different question, answered by
[experiments/harness_autonomy/FINDINGS.md](../../experiments/harness_autonomy/FINDINGS.md).

## Independence from NEMESIS

The candidate pool is built from the GitHub API against fixed, mechanical predicates.
**`nemesis scout` is deliberately not used to select repositories.** Scout ranks targets by
how promising they look *to NEMESIS*, so using it here would let the tool under evaluation
choose its own exam. Scout may be run afterwards to attach metadata, never to include or
exclude a repository.

## Inclusion predicates

Applied in order. Every predicate is checkable from the GitHub API without cloning, so the
pool is reproducible from `build_pool.py` alone.

| # | Predicate | Rationale |
|---|-----------|-----------|
| 1 | `language == C` | The onboarder targets C/C++; C keeps the sample homogeneous. C++ is a separate run. |
| 2 | not a fork, not archived | Forks duplicate parents; archived repos cannot be reported to. |
| 3 | `pushed_at` within 24 months | Dead projects are not a realistic onboarding workload. |
| 4 | `stargazers_count` in [50, 5000] | Below 50 sweeps up abandoned toys; above 5000 is dominated by projects already fuzzed. |
| 5 | repo `size` ≤ 50 MB | Proxy for "small library" at pool-build time. Exact LOC is measured at run time and recorded, not used to filter. |
| 6 | has a recognised build entry point | `CMakeLists.txt`, `configure.ac`, `Makefile.am`, or `meson.build` in the repo root. |
| 7 | **not** an OSS-Fuzz project | Fetched live from `google/oss-fuzz/projects`. Matched on repo name *and* on the `main_repo` URL in each project's `project.yaml`. |
| 8 | has a non-empty license | Needed before any finding could be reported upstream. |

Deliberately **not** filtered on: whether the project looks like a parser, whether it has a
single input entry point, whether it has existing tests, or anything else correlated with
NEMESIS's strengths. Those are *outcomes* to measure, not entry conditions.

## Sampling

The full filtered pool is written to `pool.json` — every candidate, not just the chosen
ones — so the sampling can be re-checked independently.

Selection from the pool is **deterministic and content-addressed**: each candidate is
ranked by `sha256(full_name + SALT)` and the lowest 25 are taken, with `SALT` fixed in
`build_pool.py`. This has the properties that matter here: it does not depend on API result
ordering, it is reproducible by anyone from the pool file, and it cannot be nudged by
re-running until a friendlier draw appears.

## The suite is frozen

`repos.yaml` pins each repository at an **exact commit SHA**. That file does not change.
Every NEMESIS version runs against the same 25 repositories at the same commits, so the
numbers are comparable over time:

```
v0.1  ->  N/25 onboarded
v0.2  ->  M/25 onboarded
```

Adding or swapping repositories invalidates the comparison. If a repository disappears
upstream, it stays in the file and is scored as an infrastructure failure for that run
rather than being replaced.

## Metrics

Six outcome tiers, each strictly harder than the last. The exact vocabulary is frozen in
`schema.py`:

| Tier | Reached when |
|------|--------------|
| `T0_acquired` | the pinned commit was cloned |
| `T1_config_generated` | `nemesis onboard` produced a target config |
| `T2_library_built` | the instrumented and debug library builds compiled |
| `T3_harness_generated` | harness **source** was emitted |
| `T4_harness_compiled` | the harness compiled **and linked** into a binary |
| `T5_fuzz_ready` | that binary ran and consumed at least one input |

Two of those splits are deliberate and cost a tier each:

- **T3 vs T4** — emitting C that never links is the failure mode benchmarks most often
  score as a success. A generated file is not a harness.
- **T2 as its own tier** — the library must build before anything can link against it, so
  a missing system dependency and a badly generated harness would otherwise be
  indistinguishable in the results.

Recorded alongside, per repository:

- **wall-clock per tier** — the direct measure of the "reduces manual effort" claim.
- **human intervention**, `schema.Intervention` — `0` fully unattended, `1` environment fix
  or rerun only, `2` supplied a dependency or build flag, `3` edited the generated harness
  or config, `4` modified the target's source, `5` not completable. Each level is defined
  by what was physically done, never by how hard it felt. **The suite runs at `0` by
  construction:** the runner cannot retry, install, or edit. Assisted runs are written to a
  separate results file and are never mixed into the unattended baseline.
- **failure locality** — the first stage that broke: `clone`, `build_system_detection`,
  `dependency_resolution`, `configure`, `compile`, `link`, `harness_generation`, `runtime`.
- **failure class** — one of twelve frozen categories, including `NEMESIS_LIMITATION` for
  repositories the tool correctly declines (no fuzzable entry point, C++-only, credentialed
  build). Without that category every out-of-scope repository reads as a bug and the
  remaining engineering work looks larger than it is.

**Effort proxies, not effort estimates.** Harness LOC and binary/source counts are
recorded because they are measured. No "estimated manual equivalent in hours" is emitted:
that number would be a guess printed beside measurements, and this project retracts those
rather than ships them. Anyone wanting such an estimate can compute it from the recorded
quantities with a stated multiplier of their own.

## Run protocol

Fixed order. Steps 1-3 happen before any NEMESIS code is touched, so nothing downstream
can be tuned to the result.

1. **Freeze the sample** — `build_pool.py --stage pool`, then `--stage sample`. Produces
   `pool.json` (every candidate) and `repos.yaml` (the 25, pinned to commits).
2. **Profile the sample** — `characterise.py`. Writes `SAMPLE_PROFILE.md` with the build
   system, size, age and parser-likeness distribution, and a mechanically generated list
   of scope caveats. Run *before* the baseline so the scoping cannot be written to fit the
   outcome. If the draw is lopsided, that is reported, not redrawn.
3. **Freeze the environment** — `run_suite.py` writes `environment.json` before the first
   clone: OS, clang/gcc/ld/cmake/meson/AFL++ versions, Python, and the NEMESIS commit.
   "Why did it fail for you and not for me" is the first question this benchmark will be
   asked. Credentials are never recorded — key-shaped variables are reduced to `<set>`,
   so the file is safe to commit.

   Three parts of that snapshot are load-bearing and easy to get wrong:

   - **Dirty state, not just the SHA.** A commit says which version; it does not say which
     *state*. When the tree is dirty the diff is fingerprinted (`diff_hash` + `--stat`)
     rather than stored, so two runs can be proven identical without committing scratch
     files.
   - **The LLM configuration is frozen.** The full ordered provider chain with model IDs,
     plus the per-role models (`onboarder`, `architect`, `debugger`) with temperature and
     token limits. Without this, a re-run months later cannot separate "NEMESIS improved"
     from "the provider changed the model behind an alias" — the most likely way this
     benchmark's history becomes uninterpretable. The chain *position* is recorded too: a
     run served by the fourth fallback is not the same experiment as one served by the
     first.
   - **Prompts and templates are content-hashed.** They decide what the model is asked,
     they change results without changing any Python, and they are routinely uncommitted
     while being tuned — so a git SHA does not pin them. The file contents do.
4. **Run the baseline unattended** and record it whatever it shows.
5. **Only then** change NEMESIS, and re-run against the same `repos.yaml`.

The baseline is the artifact. A low first number is not a reason to fix code before
recording it — the before/after is worth more than any single figure.

### T5 is three measurements, not one

"The harness ran" hides three different engineering problems, so they are scored apart:

| Signal | Distinguishes |
|--------|---------------|
| `fuzzer_started` | AFL++ came up at all — otherwise it is our infrastructure, not the harness |
| `executions > 0` | the harness consumed input — a harness can build, start, and process nothing |
| `executions >= 1000` in 120 s | it is worth fuzzing — below this the per-exec cost is ~100 ms+, usually re-initialisation per input |

The 1000-execution floor is a judgement call and is stated here so it can be argued with,
rather than buried in the runner.

## Comparison to prior work

Google's OSS-Fuzz-Gen reports ~39 % (88/225) on agent-based build generation. **These
numbers are not directly comparable and must not be presented as such:** that figure counts
a valid build script only, and the OSS-Fuzz-Gen write-up explicitly declines to report how
many of those 88 yielded a usable harness. The `config` tier here is the nearest analogue,
and the three tiers past it are strictly stronger requirements. Any write-up should say
"modeled after the OSS-Fuzz-Gen evaluation" and state the tier definitions.
