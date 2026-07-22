# libnmea — end-to-end harness construction

First run where every link of the NEMESIS chain is separately evidenced on a
library with **no existing fuzzing infrastructure**: no OSS-Fuzz project, no
in-tree harness, no ClusterFuzzLite config.

Target: [jacketizer/libnmea](https://github.com/jacketizer/libnmea) — NMEA 0183
marine/GNSS sentence parser, pure C, ~2.9k LOC.

This benchmark is about **harness construction**, not vulnerability discovery.
No crashes were found and none were expected in 15 minutes.

## What was demonstrated

| link | evidence |
|---|---|
| entry-point discovery | `nmea_parse` ranked #1 with **no pinning** and no hand-written config |
| harness generation | `harnesses/nmea_parse.c`, drives 4 public API functions from the fuzz buffer |
| compilation | built against the AFL++/ASan library unmodified |
| execution | **47,863,002** executions, 4 instances, 900 s |
| input influence | probe binary yields distinct coverage maps per input (15/28/28/26/28 tuples over 5 seeds) |
| coverage measurement | full 1498-input replay on a clean `-fcoverage-mapping` build |
| triage | 0 crashes, 0 hangs |

## Numbers

AFL++ (`artifacts/fuzz_stats.json`), 4 instances × 900 s:

| | |
|---|---|
| executions | 47,863,002 |
| exec/sec (aggregate) | 53,178 |
| corpus | 370–379 per instance |
| max depth | 4–7 |
| crashes / hangs | 0 / 0 |

Coverage (`artifacts/coverage_report.txt`), clean rebuild, all 1498 corpus
inputs replayed:

| metric | covered / total | % |
|---|---|---|
| regions | 269 / 298 | 90.27 |
| lines | 328 / 367 | 89.37 |
| functions | 23 / 26 | 88.46 |
| branches | 147 / 180 | 81.67 |

Per public API function:

| function | regions | lines |
|---|---|---|
| `nmea_validate` | 94.29% | 89.47% |
| `nmea_parse` | 85.71% | 81.82% |
| `nmea_get_type` | 85.71% | 80.00% |
| `nmea_get_checksum` | 100% | 100% |
| `nmea_has_checksum` | 100% | 100% |
| `nmea_cleanup` | 0% | 0% |

`nmea_cleanup` is 0% because the harness uses `nmea_free`; it is never called.

## Scope of the coverage number — read before quoting it

**These percentages cover 4 of libnmea's 11 source files**, not the whole
library: `src/nmea/nmea.c`, `src/nmea/parser_static.c`, `src/parsers/parse.c`,
`src/parsers/gpgga.c`.

The six other sentence parsers (`gpgll`, `gpgsa`, `gpgsv`, `gprmc`, `gptxt`,
`gpvtg`) carry **no coverage mapping**, so they are absent from both numerator
and denominator. They *are* linked — all seven `nmea_gp*_parse` symbols are
present in the binary — and all seven are compiled with the same coverage flags
via `target_sources(nmea PRIVATE ${PARSERS_SRCS})`.

The cause is in libnmea's own build: every parser object goes through a
`PRE_LINK` step

```cmake
COMMAND ${CMAKE_OBJCOPY} --redefine-sym parse=nmea_${PARSER}_parse ${PARSER}.c.o
```

which rewrites the object and detaches its LLVM coverage mapping. That is the
only step distinguishing these files from the ones that kept mapping. A further
consequence: all seven parsers define the same generic `parse`/`init`/… names,
so the profile that *is* attributed lands on the alphabetically first source
file — **`gpgga.c: parse` at 100% is almost certainly the merged execution of
all seven parsers**, not gpgga alone.

This is a property of the target's build system, not of NEMESIS. Quote the
number as *"~89% line coverage over the instrumented core parser path"*, never
as *"89% of libnmea"*.

## The regression artifact

`harnesses/nmea_load_parsers.BROKEN.c` is kept deliberately. It is what the
pipeline produced **before** the recon fixes, for the target it selected then:

```c
/* We don't actually feed file contents; instead we set NMEA_PARSER_PATH ... */
(void)buf; (void)len;          /* suppress unused warnings */
int rv = nmea_load_parsers();  /* takes zero arguments */
```

It compiles, links, launches AFL++, and reports success at every stage while
consuming no fuzz input at all — `int nmea_load_parsers();` accepts none.
afl-cmin collapsed 240 seeds to 2 because every input produced identical
coverage. This is the failure mode the whole exercise exists to make
detectable: **a fuzzing pipeline green on every operational metric while doing
no fuzzing.**

Five defects were found and fixed getting from that file to `nmea_parse.c`:

1. recon scored "looks dangerous" (pointer arithmetic, `malloc`/`memcpy`,
   branch density) and never asked whether a function can receive
   attacker-controlled bytes.
2. `_find_enclosing_function` searched back 50 lines while
   `_find_function_start_line` searched 100 — any function longer than 50 lines
   got a valid start index and a `None` name, and was dropped before scoring.
   `nmea_parse` sits 54 lines above its first gate-matching line.
3. `^(\w+)\s*\(` matched call sites, so `printf`, `free`, `memcpy` and `sizeof`
   were ranked as fuzz targets.
4. The same regex only matched K&R layout. libnmea happens to use it; minmea and
   embedded-nmea-0183 do not, and produced **zero real candidates** — for minmea
   the top-ranked target was `memcpy`. The local scan is the only target source
   for projects outside OSS-Fuzz, i.e. exactly the class this tool is for.
5. `analysis_binary()` resolved the archive as `build_dir / library_name` while
   every other path used `_find_library`. libnmea sets
   `ARCHIVE_OUTPUT_DIRECTORY`, so the probe build failed with `undefined
   reference to nmea_parse`, `analysis_binary()` returned `None`, and afl-cmin
   silently fell back to the AFL binary and minimised nothing.

Regression tests: `tests/test_recon_entry_point_score.py`,
`tests/test_recon_candidate_extraction.py`,
`tests/test_recon_harness_exclusion.py`,
`tests/test_analysis_binary_library_resolution.py`. 33 of the 34 recon tests
fail against the pre-fix commit.

## Known limitations of this run

- afl-cmin did not work during the fuzzing run (defect 5 was found afterwards),
  so AFL started from an unminimised ~243-file seed set. This costs calibration
  time; it does not invalidate the coverage or crash results.
- The harness requires the input to already end in `\r\n` rather than appending
  it. AFL solved this from coverage feedback — 361 of 366 queue entries end in
  CRLF — but it wastes startup time and all initial seeds were rejected.
- The harness caps input at `NMEA_MAX_LENGTH` (82), so over-long-sentence
  over-reads cannot be found. Defensible as contract fuzzing; it is a policy
  choice the LLM made unprompted, not a deliberate one.
- The in-pipeline coverage metric samples 20 corpus files and reported 72.73%
  for `nmea_parse`; the full replay gives 81.82%. `harness.quality_score` is
  computed from the sampled figure and under-reports.

## The decision trace

`artifacts/decision_trace.json` is the evidence for the *autonomous* half of the
claim: the same recon code run against a clean libnmea checkout with a bare
config, once at the pre-fix commit and once at the fixed tree, with nothing else
varying.

| function | rank before | score before | rank after | score after |
|---|---|---|---|---|
| `nmea_parse` | — | — | **1** | 23.50 |
| `_get_so_files` | 2 | 12.50 | 2 | 16.50 |
| `nmea_date_parse` | 4 | 9.30 | 3 | 16.30 |
| `nmea_load_parsers` | **1** | 15.10 | 6 | 15.10 |
| `printf` | 3 | 10.50 | — | — |

`nmea_parse` has no "before" row because it was not a candidate at all.

## Reproducing

```sh
./reproduce.sh [minutes]        # default 15, matching the reference run
```

It checks prerequisites (including WSL's `core_pattern`, which reverts to a
piped handler on every boot and makes AFL refuse to start), asserts the target
selection *before* spending the fuzzing budget, runs, collects, and compares
against `thresholds.json`.

The thresholds are **bounds, not equalities**. Target selection is deterministic
given the source tree, but harness text is LLM-generated and AFL++ throughput
depends on the machine, so asserting the reference numbers would only produce
false failures. The bounds sit well below the reference run; passing means the
pipeline still works end to end.

Two of the nine checks are the ones that matter — `analysis quality` and
`input influence`. A run reproducing the pre-fix failure passes the other seven,
including 89% coverage and 47M executions, and fails those two:

```
PASS  line coverage %      got 89.37  (need >= 70.0)
PASS  total executions     got 47,863,002  (need >= 5,000,000)
PASS  crashes              got 0
FAIL  analysis quality     got degraded (probe_build_failed)
FAIL  input influence      got 0 distinct maps over 0 inputs  (need >= 2)
```

That is the whole point of this benchmark: operational metrics alone cannot
tell you whether any fuzzing happened.

`analysis_quality` comes from the pipeline itself, not from this script. When
the probe binary cannot be built, `AFLOrchestrator` records a reason and the
steps that depend on per-input coverage — afl-cmin, corpus minset — are now
**skipped and logged** rather than run against the AFL binary, which answers
identically for every input and so reports a successful no-op. The reference run
predates that change and shows what it cost: `seeds.cmin_empty_result` with
nothing to indicate the probe had failed three times.

`artifacts/input_influence.json` uses a target-agnostic schema, so the same
shape is emitted for every benchmark:

```json
{
  "method": "probe_binary",
  "inputs_tested": 40,
  "distinct_execution_maps": 14,
  "minimum_required": 2,
  "input_influence": true,
  "analysis_quality": "ok",
  "probe_available": true,
  "degraded_reason": null
}
```

## Contents

```
reproduce.sh                          re-run and validate
thresholds.json                       acceptance bounds, with the reference run recorded
collect.py                            clean coverage rebuild, replay, stats, influence probe
check_thresholds.py                   bounds checker (exit 1 on any failure)
libnmea.yaml                          generated by `nemesis onboard`, unedited
harnesses/nmea_parse.c                the harness this run fuzzed
harnesses/nmea_load_parsers.BROKEN.c  pre-fix regression artifact
corpus/                               370 queue entries (main instance)
artifacts/decision_trace.json         candidate ranking, pre-fix vs fixed
artifacts/coverage_report.txt         llvm-cov report, clean rebuild
artifacts/coverage_summary.json       totals, with the scope caveat inline
artifacts/coverage.json               llvm-cov export
artifacts/fuzz_stats.json             per-instance and aggregate AFL++ stats
artifacts/input_influence.json        14 distinct coverage maps over 40 corpus inputs
```
