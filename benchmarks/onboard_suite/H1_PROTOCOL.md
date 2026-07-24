# H1 — automated dependency recovery: pre-registered protocol

Written **before** the H1 rerun, for the same reason the sample and the baseline
metrics were frozen before they were measured: a hypothesis test that defines its
own success criterion after seeing the result is not a test. This file fixes the
hypothesis, the intervention, the comparison, and the metrics. It is committed
before the treatment run is executed.

Baseline this is measured against: [BASELINE_FINDINGS.md](BASELINE_FINDINGS.md)
(run `baseline_b8b7cf70_491eaad8`, 0/25 fuzz-ready, wall at T2 build).

## Hypothesis

> Build acquisition — not harness synthesis — is the dominant barrier to automated
> fuzzing on this sample, and automated dependency recovery moves repositories
> **further through the pipeline**.

This is deliberately *not* "NEMESIS is better" and *not* "N more repositories become
fuzz-ready". The claim under test is that the baseline's dominant failure class
(dependency resolution, 8 of 15 in-scope repositories) is genuinely recoverable by
installing the missing system dependency — i.e. that these were *environmental*
failures, as classified, and not something deeper.

## Intervention (the only change)

`nemesis setup --auto-deps` at tier T2. Concretely:

```yaml
dependencies:
  auto_install: true
  resolver: curated+apt-file    # curated table, apt-file fallback, allow-list gated
  max_attempts: 4               # bound on install→retry cycles per build step
```

Nothing else changes: same `repos.yaml`, same commits, same onboarder model and
provider chain, same tiers. Because NEMESIS changed, the run carries a **new
`experiment_id`** and `matches_baseline: false` — expected, and the point. The
`--auto-deps` flag is appended to every recorded T2 command string, so the results
are self-documenting.

## Comparison

| | experiment_id | condition |
|---|---|---|
| Control | `b8b7cf70ab005860` (baseline) | `auto_install: false` |
| Treatment | new (recorded at run time) | `auto_install: true`, curated+apt-file |

Same 25 repositories, same instance `491eaad8d49c3244`.

## Metrics (defined now, computed after)

**Primary — build acquisition delta:**

- `T2_library_built`: count before (baseline: **2/25**) vs after.
- Of the 8 DEP-class in-scope repositories specifically (turbovnc, dbmail, gvm-libs,
  H5Z-ZFP, lv_port_pc_vscode, vdi-stream-client, pg_ivm, astera): how many now reach
  T2, or reach a **different, later** failure than the dependency one.

**Secondary — downstream reach (a dependency can unblock more than its own tier):**

- `T3_harness_generated`, `T4_harness_compiled`, `T5_fuzz_ready` counts, before vs after.

**Dependency-resolution metrics (from `setup.dep_resolution` / `setup.dep_summary`
log events):**

- `packages_installed` — total, and per repository (with provenance curated/apt-file,
  and `apt_file_db` snapshot marker for apt-file resolutions).
- `recovered` — installs after which the build step progressed (`step_recovered`).
- `false_positive_installs` — installed a package, but the same missing artifact still
  appears in the final error (`false_positive_install`). This is the honesty guard: it
  is what prevents "installed 10 packages, still failed" from reading as success.
- `unresolved` — a T2 failure that mapped to no allow-listed package (correct for the
  6 out-of-scope embedded targets: they must stay unresolved).
- `new_failure_stage_reached` — a repository whose dependency was resolved and now fails
  *later*. This counts as **support** for the hypothesis (moved further), not failure.

## Interpretation rules (fixed now)

- The hypothesis is **supported** to the extent that DEP-class repositories move past
  their dependency failure — reaching T2, or a new later failure stage. Reaching T5 is
  **not** required; "moved further through the pipeline" is the claim.
- The hypothesis is **weakened** if repositories install packages but the same artifact
  error persists (high `false_positive_installs`), or if T2 does not move despite
  installs — that would mean the failures were mis-classified as environmental.
- The 6 out-of-scope repositories are expected to remain unresolved. If auto-deps
  installs anything for them, that is a resolver defect to investigate, not progress.

## Known threats to this test

- **apt DB drift.** `apt-file` can map a header to a different package after a DB
  refresh; each apt-file resolution records an `apt_file_db` marker so the mapping is
  checkable later. Curated resolutions are drift-free by construction.
- **SDL3 (vdi-stream-client).** `libsdl3-dev` may not exist in the runner's apt
  release. If so the install fails and is recorded — it counts against the upper bound
  honestly, turning "up to 8" into a measured number.
- **Second-order dependencies.** Installing one dependency can reveal another;
  `max_attempts: 4` allows a short chain, but a repository needing more will still fail
  at T2 — recorded as progress (new failure stage), not as recovery.
- **Runner capability.** `--auto-deps` gates on apt + passwordless sudo + network
  before the run (`auto_deps_requested` capability block); a degraded runner aborts
  rather than silently recording 25 failed installs.

## Sequence

H1 (this) → rerun → analysis against the metrics above → **then** H2 (target
inference) → H3 (harness-generation evaluation, the stage this run may finally reach).
