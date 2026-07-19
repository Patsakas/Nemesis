"""
NEMESIS shared data models.

Every inter-stage data transfer uses these typed models,
ensuring type safety and enabling JSON serialization for
logging, caching, and debugging.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, computed_field, field_validator

# ── Enums ───────────────────────────────────────────────────


class CWE(str, Enum):
    NULL_DEREF = "CWE-476"
    HEAP_OVERFLOW = "CWE-122"
    STACK_OVERFLOW = "CWE-121"
    USE_AFTER_FREE = "CWE-416"
    INTEGER_OVERFLOW = "CWE-190"
    OUT_OF_BOUNDS_READ = "CWE-125"
    RESOURCE_CONSUMPTION = "CWE-770"
    OUT_OF_BOUNDS_WRITE = "CWE-787"
    DOUBLE_FREE = "CWE-415"
    # Additional weakness classes
    STACK_USE_AFTER_SCOPE = "CWE-562"   # stack variable used outside its scope
    UNINITIALIZED_VALUE = "CWE-908"     # use of uninitialized memory (MSan/Valgrind)
    DIVIDE_BY_ZERO = "CWE-369"          # division by zero (UBSan)
    FORMAT_STRING = "CWE-134"           # format string bug
    BUFFER_UNDERWRITE = "CWE-124"       # buffer underflow / underwrite
    UNDEFINED_BEHAVIOR = "CWE-758"     # UBSan: pointer-overflow, shift-exponent, misaligned access
    MEMORY_LEAK = "CWE-401"            # LeakSanitizer: missing release of memory after lifetime
    RACE_CONDITION = "CWE-362"         # ThreadSanitizer: data race on shared resource (Fix 150)
    UNKNOWN = "CWE-unknown"


class SanitizerClass(str, Enum):
    """Which sanitizer detected a crash."""
    ASAN = "asan"           # AddressSanitizer (memory safety)
    UBSAN = "ubsan"         # UndefinedBehaviorSanitizer
    MSAN = "msan"           # MemorySanitizer (uninitialized reads)
    TSAN = "tsan"           # ThreadSanitizer (data races, Fix 150)
    SIGNAL = "signal"       # Raw signal (no sanitizer output)
    HANG = "hang"           # Timeout / infinite loop
    UNKNOWN = "unknown"


class AppReproStatus(str, Enum):
    """Whether a crash reproduces in the real application binary (repro_binary).

    Splits the old ``reproduces_in_app: bool`` into three distinct states so an
    unverifiable finding is no longer indistinguishable from a disproven one:

    - CONFIRMED      — replayed against repro_binary and it crashed.
    - NOT_REPRODUCED — replayed against repro_binary and it ran clean
                       (artifact-suspect: likely a harness-induced false positive).
    - NOT_TESTABLE   — no repro_binary configured or the binary is missing, so
                       reproduction cannot be judged either way (e.g. fuzz-target-only
                       libraries with no CLI wrapper to test against).
    """

    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not_reproduced"
    NOT_TESTABLE = "not_testable"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BlockerType(str, Enum):
    MACRO = "macro"
    RUNTIME_CHECK = "runtime_check"
    FORMAT_REQUIREMENT = "format_requirement"
    ENVIRONMENT = "environment"
    BUILD_FLAG = "build_flag"


class RiskLevel(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"


class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Stage 1: Recon models ──────────────────────────────────


class CoverageTarget(BaseModel):
    """A function identified as having low/zero fuzzing coverage."""

    func_name: str
    file_path: str
    line: int
    coverage_pct: float
    caller_count: int = 0
    has_memory_ops: bool = False
    has_pointer_arith: bool = False
    complexity: int = 0  # cyclomatic complexity if available
    priority_score: float = 0.0  # computed ranking score
    harness_hint: str = ""  # target-specific harness guidance (from pinned_funcs config)
    force_no_blocker: bool = False  # if True, pipeline skips patch generation entirely
    is_static: bool = False  # True if function has static linkage → cannot be called directly
    # Fix 114: target is reached indirectly via public API with specific parameters
    indirect_reach: bool = False
    # Fix 123: harness calls function directly using internal headers
    direct_internal: bool = False
    # Fix 135: differential-oracle target — round-trip wrapped with memcmp invariant.
    differential_oracle: bool = False
    # Fix 148: cross-implementation reference comparison — name of a reference
    # impl to call alongside the target; any output divergence = abort().
    differential_reference: str = ""
    # Fix 150: threaded-oracle target — harness must drive the function from
    # multiple threads sharing state, so TSAN can detect data races.
    threaded_oracle: bool = False
    # Fix 136: format-specific invariants the harness must enforce as abort()s.
    output_invariants: list[str] = Field(default_factory=list)
    needed_headers: list[str] = Field(default_factory=list)  # from Introspector enrichment
    existing_harness_path: str = ""  # OSS-Fuzz harness source path


class Blocker(BaseModel):
    """A condition preventing a code path from being reached."""

    condition: str
    file_path: str
    line: int = 0
    blocker_type: BlockerType
    bypass_strategy: str = ""
    confidence: float = 0.0  # LLM confidence in bypass strategy


class CallChain(BaseModel):
    """Call chain from entry point to target function."""

    entry_point: str
    chain: list[str]
    blockers: list[Blocker] = Field(default_factory=list)
    target: CoverageTarget
    depth: int = 0  # number of hops from entry


class AnalysisContext(BaseModel):
    """Full context package sent to the LLM for analysis."""

    target: CoverageTarget
    call_chain: CallChain
    source_snippets: dict[str, str] = Field(default_factory=dict)
    macro_env: dict[str, str] = Field(default_factory=dict)
    build_config: str = ""
    git_history: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)


# ── Stage 2: Neural models ─────────────────────────────────


class VulnerabilityAnalysis(BaseModel):
    """LLM's analysis of a potential vulnerability."""

    vulnerability_type: str
    cwe: CWE
    root_cause: str
    attack_vector: str
    confidence: float = 0.0
    missing_checks: list[dict[str, str | int | float | bool]] = Field(default_factory=list)
    # Blocker assessment: does reaching this function require bypassing a guard?
    # True  → compile-time macro / format magic / runtime check blocks the path
    #         → Stage 3 must apply a patch before fuzzing
    # False → function is already reachable; no patch needed
    #         → skip patch generation + Stage 3, go straight to harness + fuzzing
    has_blocker: bool = True
    blocker_description: str = ""  # human-readable explanation of the blocker (or "none")
    blocker_class: str = "runtime"  # "compile_time" | "runtime" — determines bypass strategy


class PatchProposal(BaseModel):
    """A proposed source-level patch to expose hidden code."""

    file_path: str
    line: int
    original: str
    replacement: str
    justification: str
    risk_level: RiskLevel = RiskLevel.SAFE
    patch_type: str = ""  # "null_guard", "bounds_check", "blocker_bypass", etc.


class InputParam(BaseModel):
    """A single parameter extracted from harness buf[] reads (Fix 122)."""

    name: str               # "quality", "lgwin", "flags"
    offset: int             # byte offset in buf
    size: int = 1           # 1, 2, or 4 bytes
    type: str = "uint8"     # uint8 | uint16 | uint32 | int32
    transform: str = ""     # "mod 12", "mod 15 + 10", "" (identity)
    range: list[int] = Field(default_factory=list)  # [min, max] post-transform
    enum_values: list[int] = Field(default_factory=list)

    @field_validator("range")
    @classmethod
    def _validate_range(cls, v: list[int]) -> list[int]:
        """Fix 126: ensure range is either empty or exactly [min, max]."""
        if v and len(v) != 2:
            return []
        if len(v) == 2 and v[0] > v[1]:
            return [v[1], v[0]]
        return v


class InputSpec(BaseModel):
    """Structured description of how the harness consumes fuzz input (Fix 122).

    Extracted from harness c_code buf[] layout by the LLM alongside the harness.
    Used by SeedSynthesizer to auto-generate targeted seeds — zero extra LLM calls.
    """

    params: list[InputParam] = Field(default_factory=list)
    data_offset: int = 0          # byte where payload begins
    data_type: str = "raw"        # raw | compressed | text | dictionary | structured
    min_size: int = 1
    max_size: int = 262144
    magic_bytes: dict | None = None  # {"offset": 0, "value": "504b0304"}
    interesting_sizes: list[int] = Field(default_factory=list)


class HarnessSpec(BaseModel):
    """Specification for an AFL++ fuzzing harness."""

    target_func: str
    input_format: str
    c_code: str
    seed_commands: list[str] = Field(default_factory=list)
    compile_flags: str = ""
    requires_formats: list[str] = Field(default_factory=list)
    requires_filters: list[str] = Field(default_factory=list)
    dictionary_entries: list[str] = Field(default_factory=list)
    # Fix 95: static functions cannot be called directly — preflight skips name check
    is_static: bool = False
    # Fix 119: target function is reached indirectly via public API with specific parameters.
    # When True, preflight skips the "target function not called" check.
    indirect_reach: bool = False
    # Fix 123: harness calls internal function directly via internal headers + -I flags
    direct_internal: bool = False
    # Fix C: path to CMPLOG-instrumented binary (AFL_LLVM_CMPLOG=1).
    # When set, AFL main instance uses -c {cmplog_binary} for RedQueen auto-solving.
    cmplog_binary: str | None = None
    # Fix 122: structured input layout spec for deterministic seed synthesis.
    # When set, SeedSynthesizer generates ~25 targeted seeds from param boundaries.
    input_spec: InputSpec | None = None


class LLMCallRecord(BaseModel):
    """Tracks a single LLM API call for cost/audit purposes."""

    timestamp: datetime = Field(default_factory=datetime.now)
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    cache_hit: bool = False
    stage: str = ""
    target_func: str = ""


# ── Stage 3: Symbolic models ───────────────────────────────


class PathConstraint(BaseModel):
    """A constraint on an execution path, extracted for Z3."""

    variable: str
    operator: str  # "==", "!=", ">", "<", "&&", "||"
    value: str
    source: str = ""  # "ast" or "angr"


class VerificationResult(BaseModel):
    """Result of Z3 path satisfiability check."""

    is_satisfiable: bool
    model: dict[str, str] | None = None
    unsat_core: list[str] | None = None
    solve_time_ms: float = 0.0
    constraints_count: int = 0


# ── Stage 4: Fuzzing models ────────────────────────────────


class AFLStats(BaseModel):
    """Statistics from an AFL++ fuzzing run."""

    exec_per_sec: float = 0.0
    total_paths: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    duration_seconds: int = 0
    map_density_pct: float = 0.0
    stability_pct: float = 0.0


class CVEAssessment(BaseModel):
    """LLM-generated CVE assessment for a confirmed crash."""

    is_known_cve: bool = False
    cve_id: str = ""
    cve_confidence: float = 0.0  # 0-1, how confident the LLM is in CVE match
    rationale: str = ""
    affected_versions: str = ""
    cvss_estimate: float = 0.0  # 0-10
    root_cause_analysis: str = ""
    suggested_mitigation: str = ""
    similar_cves: list[str] = Field(default_factory=list)


class CrashReport(BaseModel):
    """A confirmed crash with full analysis."""

    input_file: str
    crash_location: str  # file:line
    stack_trace: list[str] = Field(default_factory=list)
    cwe: CWE
    severity: Severity
    asan_output: str = ""
    # Reproduction against the real application binary (repro_binary). Three-state:
    # NOT_TESTABLE is the default because most fuzz-target-only libraries have no
    # app wrapper — that is "unverified", not "disproven".
    app_repro: AppReproStatus = AppReproStatus.NOT_TESTABLE
    minimized_input: str | None = None
    proposed_fix: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    # Unpatched verification: True = patch created the bug (false positive),
    # False = bug exists in original code (real CVE candidate), None = not checked
    patch_induced: bool | None = None
    cve_assessment: CVEAssessment | None = None
    # Sanitizer classification: which sanitizer detected this crash
    detected_by: SanitizerClass = SanitizerClass.UNKNOWN
    # Multi-build verification: crash reproducibility across build configurations
    reproduces_clean: bool | None = None   # crashes in normal build (no sanitizer)?
    reproduces_asan: bool | None = None    # crashes under ASAN?
    reproduces_ubsan: bool | None = None   # crashes under UBSan?
    # Upstream freshness of the fuzzed checkout (nemesis/upstream.py):
    # "up_to_date" = bug reproduces on the latest upstream code (candidate novel);
    # "behind" = checkout is stale, bug may already be fixed upstream; "unknown".
    upstream_status: str = "unknown"
    upstream_detail: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reproduces_in_app(self) -> bool:
        """Back-compat view of app_repro: True only when confirmed in the app binary.

        Preserves the old boolean semantics for existing consumers (reporter status
        gate, pipeline verified-crash check, findings.yaml). NOT_REPRODUCED and
        NOT_TESTABLE both read as False here — use app_repro to tell them apart.
        """
        return self.app_repro == AppReproStatus.CONFIRMED


class CoverageSnapshot(BaseModel):
    """Coverage data at a point in time."""

    timestamp: datetime = Field(default_factory=datetime.now)
    function_coverage: dict[str, float] = Field(default_factory=dict)
    line_coverage_pct: float = 0.0      # NOTE: populated with AFL bitmap_cvg in some contexts
    branch_coverage_pct: float = 0.0    # NOTE: populated with AFL bitmap_cvg in some contexts
    bitmap_coverage_pct: float = 0.0    # Fix 126: explicit AFL bitmap field
    total_functions: int = 0
    covered_functions: int = 0


class CoverageDelta(BaseModel):
    """Difference between two coverage snapshots."""

    before: CoverageSnapshot
    after: CoverageSnapshot
    expanded_functions: dict[str, float] = Field(default_factory=dict)
    total_expansion_pct: float = 0.0
    success: bool = False


# ── Feedback Loop models ───────────────────────────────────


class HarnessExecutionDiagnostics(BaseModel):
    """Structured execution-state snapshot for LLM-based harness refinement.

    Replaces free-text failure_reason with bounded, unambiguous fields so the
    LLM receives execution state (not a description of it) — no interpretation
    required, no free-text leakage.
    """

    # Build phase
    compiled: bool = False
    compile_error_type: str = ""  # "unknown_type" | "missing_symbol" | "link_error" | ""

    # Runtime phase
    function_reached: bool = False
    function_coverage_pct: float = -1.0  # -1 = not measured

    # Input consumption signal (derived from AFL corpus stats)
    corpus_paths: int = 0          # AFL total_paths after run
    map_density_pct: float = 0.0   # AFL map density after run
    input_size_bytes: int = 0      # Size of the seed/corpus file used for profiling

    # Derived: early-exit proxy (corpus didn't grow and density is near-zero)
    @property
    def likely_early_exit(self) -> bool:
        return self.corpus_paths <= 1 and self.map_density_pct < 1.0


class FeedbackContext(BaseModel):
    """Context sent back from Stage 4 to Stage 2 for refinement."""

    original_proposal: PatchProposal | None = None
    coverage_delta: CoverageDelta
    afl_stats: AFLStats
    error_log: str = ""
    iteration: int = 1
    failure_reason: str = ""  # "no_coverage" | "build_failed" | "timeout" | "low_function_coverage"
    harness_code: str = ""  # The C harness that was compiled and run
    # Structured execution diagnostics (replaces free-text for LLM interpretation)
    diagnostics: HarnessExecutionDiagnostics | None = None
    # gcov line-level coverage annotation around target function (Feature B)
    gcov_annotation: str = ""


# ── Pipeline-level models ──────────────────────────────────


class TargetResult(BaseModel):
    """Complete result for a single target function."""

    target: CoverageTarget
    status: PipelineStatus = PipelineStatus.PENDING
    analysis: VulnerabilityAnalysis | None = None
    patch: PatchProposal | None = None
    harness: HarnessSpec | None = None
    verification: VerificationResult | None = None
    afl_stats: AFLStats | None = None
    crashes: list[CrashReport] = Field(default_factory=list)
    feedback_iterations: int = 0
    total_llm_cost_usd: float = 0.0
    duration_seconds: float = 0.0
    # Fix C: % of sampled AFL corpus inputs that reach the target function (post-fuzz).
    # -1.0 means "not yet measured". 0.0 means measured and 0 of N samples hit the function.
    function_coverage_pct: float = -1.0
    # Composite harness quality score [0.0–1.0]: compiled + function reached + paths + density.
    # -1.0 = not yet computed. Used for target scheduling and experiment evaluation.
    harness_quality_score: float = -1.0
    # Real source-line coverage (%) of the target function, measured via LLVM source coverage.
    # -1.0 = not measured. Comparable with OSS-Fuzz Introspector's runtime_coverage_percent.
    source_coverage_pct: float = -1.0


class PipelineRun(BaseModel):
    """A complete pipeline execution across all targets."""

    run_id: str
    # Library this run targeted (config.target.name). Lets per-target dashboard
    # queries (e.g. /api/coverage/{target}) select the right run instead of the
    # newest one globally. Empty on legacy runs written before this field existed.
    target_name: str = ""
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    config_hash: str = ""
    status: PipelineStatus = PipelineStatus.PENDING
    # Non-fatal degradations (oracle/context/recon failures etc.) — surfaced so a
    # run that silently ran without key subsystems doesn't look fully healthy.
    degraded_reasons: list[str] = Field(default_factory=list)
    targets_processed: int = 0
    targets_successful: int = 0
    total_crashes: int = 0
    total_cves: int = 0
    total_llm_cost_usd: float = 0.0
    results: list[TargetResult] = Field(default_factory=list)
