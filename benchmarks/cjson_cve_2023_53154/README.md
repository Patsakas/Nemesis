# CVE-2023-53154 — cJSON heap-buffer-overflow

A validated benchmark target: a real, reproducible vulnerability with a crash
input, a build recipe, and a differential oracle. This is the ground truth a
vulnerability-rediscovery experiment needs — without it, "NEMESIS found the CVE"
has no definition.

## The bug

Heap-buffer-overflow (out-of-bounds read of one byte) in `parse_string`, reached
from `parse_object`, at `cJSON.c:786`. Triggered by an object with a trailing
comma and nothing after it — `{"1":1,` — parsed through `cJSON_ParseWithLength`,
which unlike `cJSON_Parse` does not require a trailing NUL, so the parser reads
one byte past the buffer while looking for the next member.

- Fixed in cJSON **1.7.18**, commit `3ef4e4e` ("Fix heap buffer overflow", #800).
- Affects all versions **before 1.7.18**.
- Upstream added `tests/parse_examples.c::test15_should_not_heap_buffer_overflow`
  with exactly this input; `crash_input.json` here is that case.

## Files

| file | what it is |
|------|-----------|
| `crash_input.json` | the 7-byte trigger, `{"1":1,` |
| `build_asan.sh` | build a standalone ASan reproducer from a cJSON checkout |
| `oracle.sh` | per-input verdict: CVE-HIT / CVE-MISS |
| `reproduce.sh` | full differential validation (run this first) |

## Validate

```bash
benchmarks/cjson_cve_2023_53154/reproduce.sh ~/cjson_work
```

Builds the vulnerable checkout and 1.7.18 (via `git worktree`) and confirms the
crash input hits the first and is clean on the second, while a well-formed input
is clean on both. All four must pass.

## Two things that are not obvious, and cost time to find

**Use a tight heap copy, not the fuzzing or debug harness.** The AFL fuzzing
binary receives no input outside `afl-fuzz`. The debug harness parses out of a
1 MB static buffer, so a one-byte over-read at the end of the input lands in
valid zeroed memory and ASan stays silent — the same masking that made NEMESIS
heap-copy inputs before parsing (Fix 139). `build_asan.sh` copies the input to a
`malloc` of exactly its length, putting the redzone at `buf[len]`.

**Do not rely on symbolized stack frames on WSL.** ASan's `llvm-symbolizer`
hangs whenever stdout is not a terminal — which is every `$(...)` capture and
every pipe an automated oracle uses — so frames come back unnamed and a
`parse_string:786` match silently fails. The oracle instead matches the
symbol-free fingerprint (heap-buffer-overflow + READ of size 1) and relies on
the differential in `reproduce.sh` to make it specific to this CVE.

## Using it in a rediscovery experiment

`oracle.sh` is the success criterion: run it on each input a campaign saves,
count a run as a rediscovery only on CVE-HIT. Because the AFL crash directory on
a piped-`core_pattern` host contains timeouts mislabelled as crashes (see
`scripts/check_crash_reporting.sh`), the oracle — a real ASan reproduction — is
what separates a genuine finding from an artefact.

The full evaluation workflow — a differential-oracle framework, not a
rediscovery *engine* — is:

1. `reproduce.sh` — validate the target (differential: crashes vulnerable, clean fixed).
2. `scripts/qualify_benchmark.sh` — check the CVE is discriminating (not found instantly,
   not never found) before spending hours. A CVE the baseline finds in under a
   second cannot separate two seed strategies, so qualification is a precondition,
   not a conclusion.
3. `scripts/cve_sweep.sh` — per-run rediscovery verdict over AFL's queue + crashes.

For **this** CVE, step 2 returns TOO EASY: the baseline finds it in well under a
second, so it is a valid target but not a discriminating benchmark for comparing
seed strategies. That is a property of the bug's reachability, not of any tool.
