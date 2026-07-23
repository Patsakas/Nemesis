# Sample profile — nemesis-onboard-v1

25 repositories drawn from a pool of 1210 (2.1 %). Generated 2026-07-23T13:38:29+00:00, before the baseline run.

## Composition

| Dimension | Value |
|-----------|-------|
| build system `CMakeLists.txt` | 16 |
| build system `Makefile.am` | 6 |
| build system `meson.build` | 3 |
| parser-like (heuristic) | 5 (20.0 %) |
| repo size KB (median) | 4184 |
| stars (median) | 240 |
| days since last push (median) | 8.1 |

## Scope caveats

- No single dimension dominates the sample.

## Artifact integrity

```
PASS  pool passes every freeze-gate check    1210 candidates
PASS  OSS-Fuzz snapshot pinned               1366 projects, tree 1353ef81
PASS  freeze-time leakage re-check ran       independent re-query at freeze time, not a re-read of pool.json
PASS  every selected repo has a commit SHA   25/25 pinned
PASS  benchmark instance identified          491eaad8d49c3244
```

Any claim from this suite is bounded by the above. It measures onboarding within this scope, not onboarding of arbitrary C/C++ repositories.
