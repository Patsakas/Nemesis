"""Centralised feature-flag checks for NEMESIS Tier 0/1/2 capabilities.

Why this exists
---------------
We keep adding LLM-driven prompt-injection / synthesis features (format
specs, CVE history, progress predicates, mutator synthesis, seed
generators). To run rigorous A/B tests measuring the contribution of
each feature on benchmark CVE rediscovery, we need to be able to turn
each feature OFF without editing code.

Convention
----------
Each feature has an env-var of the form `NEMESIS_DISABLE_<FEATURE>`.
Setting the var to `1`, `true`, `yes`, or `on` (case-insensitive) turns
the feature OFF. Default is enabled. We use disable-flags rather than
enable-flags so that production behaviour matches an unset environment.

Adding a new feature
--------------------
1. Pick a name in `_FEATURES`.
2. Call `is_enabled("<name>")` at the injection site.
3. Document the flag here.

Current features
----------------
* `format_spec`        — Tier 0. Inject `<format_spec>` block in
                          mutator_synthesis prompt. Disable to fall back
                          to plain LLM training-data recall.
* `bug_history`        — Tier 1 #1. Inject `<bug_history>` CVE block in
                          mutator_synthesis prompt.
* `validation_gates`   — Pre-existing. Auto-inject permissive setters
                          into LLM-generated harness body.
* `predicates`         — Tier 1 #2. Locus-style progress predicates
                          injected as `if (!cond) continue;` gates.
* `mutator_synthesis`  — Pre-existing. Synthesise AFL custom mutator
                          .so. Disable to use vanilla AFL havoc only.
* `seedgen`            — Tier 2 #3. SeedMind-style LLM-emitted Python
                          seed generator (added with seedgen.py).
* `bit_cursor`         — Tier 2 #4. Bit-packed adapter scaffold.
* `dict_extract`       — Seed pipeline #4. Auto-extract an AFL `-x`
                          dictionary (magic bytes, format tokens, header
                          constants) from the target source. Disable to
                          run AFL with no dictionary.
* `roundtrip`          — Seed pipeline #1. Synthesise a C *seed producer*
                          that calls the library WRITE/ENCODE API to emit
                          structurally-perfect inputs, then run it N times.
                          Disable to fall back to byte-level seed sources.
* `z3_seedgen`         — Seed pipeline #2. Light-concolic seed synthesis:
                          solve magic-value branch constraints near the
                          pinned function with Z3 and place the solved
                          constant at the right byte offset.
* `seed_evolve`        — Seed pipeline #3. Coverage-feedback evolution
                          loop: keep only seeds that reach the pinned
                          function, then breed variations of the winners.
"""

from __future__ import annotations

import os

# Canonical feature names. Keep this set synced with the docstring above
# and the consumers across the codebase.
_FEATURES: frozenset[str] = frozenset({
    "format_spec",
    "bug_history",
    "validation_gates",
    "predicates",
    "mutator_synthesis",
    "seedgen",
    "bit_cursor",
    "dict_extract",
    "roundtrip",
    "z3_seedgen",
    "seed_evolve",
})


_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _envvar_for(feature: str) -> str:
    return f"NEMESIS_DISABLE_{feature.upper()}"


def is_enabled(feature: str) -> bool:
    """Return True iff the named feature is enabled in the current env.

    Unknown names raise KeyError to catch typos at the call site.
    """
    if feature not in _FEATURES:
        raise KeyError(
            f"unknown NEMESIS feature {feature!r}; "
            f"valid: {sorted(_FEATURES)}"
        )
    raw = os.environ.get(_envvar_for(feature), "").strip().lower()
    return raw not in _TRUTHY


def disabled_features() -> list[str]:
    """Return the sorted names of features that are currently DISABLED.

    Useful for run-summary logging — emit once at pipeline start so logs
    record the A/B configuration that produced the run.
    """
    return sorted(f for f in _FEATURES if not is_enabled(f))
