"""Result schema for the onboarding benchmark — frozen before the first run.

Fixing the vocabulary up front is the point. Failure categories invented while
reading logs get shaped by whatever happened to fail that day, and a tier list
written after seeing results tends to land wherever the tool already reaches.

Two rules this file exists to enforce:

  A generated file is not a working harness. `HARNESS_GENERATED` and
  `HARNESS_COMPILED` are separate tiers because emitting C source that never
  links is the failure mode benchmarks most often score as success.

  Not every failure is a NEMESIS bug. `NEMESIS_LIMITATION` covers repositories
  the tool correctly declines — no fuzzable entry point, C++-only, a build that
  needs credentials. Folding those into `COMPILE_FAILURE` would overstate how
  much engineering is left to do.
"""

from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    """Outcome tiers, each strictly harder than the last.

    The library must build before a harness can link against it, so it gets its
    own tier rather than being folded into harness compilation — otherwise a
    dependency failure and a bad generated harness score identically.
    """

    ACQUIRED = "T0_acquired"                  # pinned commit cloned
    CONFIG_GENERATED = "T1_config_generated"  # nemesis onboard wrote a target YAML
    LIBRARY_BUILT = "T2_library_built"        # instrumented + debug builds compiled
    HARNESS_GENERATED = "T3_harness_generated"  # harness source emitted
    HARNESS_COMPILED = "T4_harness_compiled"  # harness compiled AND linked to a binary
    FUZZ_READY = "T5_fuzz_ready"              # binary ran and consumed >= 1 input

    @property
    def index(self) -> int:
        return list(Tier).index(self)


class Status(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_RUN = "not_run"       # an earlier tier failed, so this never started
    SKIPPED = "skipped"       # deliberately excluded, e.g. --only


class FailureClass(str, Enum):
    """Fixed vocabulary. Do not extend after the baseline run without noting it
    in the write-up — the distribution across categories is the whole output."""

    CLONE_FAILURE = "CLONE_FAILURE"
    BUILD_SYSTEM_UNKNOWN = "BUILD_SYSTEM_UNKNOWN"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    CONFIGURE_FAILURE = "CONFIGURE_FAILURE"
    COMPILE_FAILURE = "COMPILE_FAILURE"
    LINK_FAILURE = "LINK_FAILURE"
    HARNESS_VALIDATION_FAILURE = "HARNESS_VALIDATION_FAILURE"
    RUNTIME_FAILURE = "RUNTIME_FAILURE"
    # T5 splits into three distinguishable failures. Collapsing them loses the
    # difference between "AFL never came up" (our infrastructure), "AFL came up
    # and the harness consumed nothing" (a dead harness that still compiles), and
    # "it ran below the benchmark's execution-activity floor". The last is a
    # threshold this suite defines, not a verdict on whether fuzzing was useful.
    FUZZER_START_FAILURE = "FUZZER_START_FAILURE"
    ZERO_EXECUTIONS = "ZERO_EXECUTIONS"
    BELOW_ACTIVITY_THRESHOLD = "BELOW_ACTIVITY_THRESHOLD"
    TIMEOUT = "TIMEOUT"
    INFRA_FAILURE = "INFRA_FAILURE"        # our environment, not the target: disk, WSL, API
    LLM_FAILURE = "LLM_FAILURE"            # provider error, quota, unparseable response
    NEMESIS_LIMITATION = "NEMESIS_LIMITATION"  # working as designed; repo out of scope


class Locality(str, Enum):
    """Where the first failure happened. Aims engineering effort."""

    CLONE = "clone"
    BUILD_SYSTEM_DETECTION = "build_system_detection"
    DEPENDENCY_RESOLUTION = "dependency_resolution"
    CONFIGURE = "configure"
    COMPILE = "compile"
    LINK = "link"
    HARNESS_GENERATION = "harness_generation"
    RUNTIME = "runtime"


class Intervention(int, Enum):
    """Human effort required. The benchmark is run at NONE by construction: the
    runner never retries, never edits, never installs a missing dependency.

    Anything above NONE is recorded from a *separate, explicitly flagged* run —
    never silently mixed into the unattended numbers. A subjective scale would
    invite exactly the dispute this benchmark exists to avoid, so each level is
    defined by what was physically done, not by how hard it felt.
    """

    NONE = 0              # fully unattended
    ENV_ONLY = 1          # rerun, or a fix to our environment; target untouched
    BUILD_HINT = 2        # supplied a dependency or a build flag
    HARNESS_EDIT = 3      # edited the generated harness or config
    CODE_CHANGE = 4       # modified the target's own source
    UNABLE = 5            # not completable at any level


# Which failure class to assume when a tier fails without a more specific signal.
DEFAULT_FAILURE: dict[Tier, FailureClass] = {
    Tier.ACQUIRED: FailureClass.CLONE_FAILURE,
    Tier.CONFIG_GENERATED: FailureClass.BUILD_SYSTEM_UNKNOWN,
    Tier.LIBRARY_BUILT: FailureClass.COMPILE_FAILURE,
    Tier.HARNESS_GENERATED: FailureClass.HARNESS_VALIDATION_FAILURE,
    Tier.HARNESS_COMPILED: FailureClass.COMPILE_FAILURE,
    Tier.FUZZ_READY: FailureClass.RUNTIME_FAILURE,
}

TIER_LOCALITY: dict[Tier, Locality] = {
    Tier.ACQUIRED: Locality.CLONE,
    Tier.CONFIG_GENERATED: Locality.BUILD_SYSTEM_DETECTION,
    Tier.LIBRARY_BUILT: Locality.COMPILE,
    Tier.HARNESS_GENERATED: Locality.HARNESS_GENERATION,
    Tier.HARNESS_COMPILED: Locality.LINK,
    Tier.FUZZ_READY: Locality.RUNTIME,
}

# Ordered: first match wins, so put the specific patterns above the generic ones.
# Matched case-insensitively against combined stdout+stderr.
LOG_PATTERNS: list[tuple[str, FailureClass, Locality]] = [
    # gcc/clang put the header *before* the message:
    #   fatal error: zlib.h: No such file or directory
    (r"\.h(pp|xx)?:\s*no such file or directory", FailureClass.DEPENDENCY_FAILURE,
     Locality.DEPENDENCY_RESOLUTION),
    (r"could not find|package .* not found|no package '.*' found",
     FailureClass.DEPENDENCY_FAILURE, Locality.DEPENDENCY_RESOLUTION),
    (r"undefined reference to|undefined symbol|ld returned \d+ exit status",
     FailureClass.LINK_FAILURE, Locality.LINK),
    (r"cmake error|configure: error|meson\.build:\d+:\d+: error",
     FailureClass.CONFIGURE_FAILURE, Locality.CONFIGURE),
    (r"error: |fatal error:", FailureClass.COMPILE_FAILURE, Locality.COMPILE),
    (r"rate limit|quota exceeded|api key|401 unauthorized|invalid_api_key",
     FailureClass.LLM_FAILURE, Locality.HARNESS_GENERATION),
    (r"no space left|permission denied|cannot allocate memory",
     FailureClass.INFRA_FAILURE, Locality.CLONE),
    (r"no fuzzable|no suitable entry point|c\+\+ project|unsupported",
     FailureClass.NEMESIS_LIMITATION, Locality.BUILD_SYSTEM_DETECTION),
]
