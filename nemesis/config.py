"""
NEMESIS configuration management.

Loads default.yaml, merges with target-specific overrides,
and validates everything through Pydantic models.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ── Sub-models ──────────────────────────────────────────────


class EngineConfig(BaseModel):
    max_feedback_iterations: int = 3
    coverage_threshold: float = 0.05
    work_dir: Path = Path("./workspace")
    log_level: str = "INFO"
    log_format: str = "console"  # "console" or "json"
    auto_discover_limit: int = Field(
        default=3,
        description="Max 0%-cov targets to auto-promote via planner (0=disabled)",
    )


class ProviderConfig(BaseModel):
    """A single LLM provider in the fallback chain."""
    name: str                       # "groq", "cerebras", "gemini"
    base_url: str                   # API endpoint (OpenAI-compatible)
    api_key_env: str                # env var name for API key
    model: str                      # model ID
    json_mode: str = "json_object"  # response_format type
    # OpenAI-style reasoning cap (gpt-oss): "low" | "medium" | "high". Empty =
    # don't send it. "low" keeps gpt-oss-120b from hanging on large prompts
    # (measured: low ~37s vs high >5min on an 18K-token prompt).
    reasoning_effort: str = ""


class RoleModelConfig(BaseModel):
    """Configuration for a role-specific model (Architect or Debugger)."""
    name: str
    base_url: str = "https://integrate.api.nvidia.com/v1"
    api_key_env: str = "NVIDIA_API_KEY"
    model: str
    max_tokens: int = 4096
    temperature: float = 0.2
    enable_thinking: bool = False
    reasoning_budget: int = 0            # 0 = disabled; >0 = token budget for reasoning
    # OpenAI-style reasoning cap (gpt-oss): "low" | "medium" | "high". Empty =
    # not sent. Passed as top-level extra_body.reasoning_effort (NOT inside
    # chat_template_kwargs). "low" stops gpt-oss-120b timing out on big prompts.
    reasoning_effort: str = ""
    context_budget_tokens: int = 0       # 0 = default 800K; >0 = max input tokens for context_builder
    context_window: int = 0              # 0 = unknown; >0 = model's total context window in tokens
    timeout: int = 120                   # HTTP timeout in seconds per request
    # Fix 147: per-vendor chat-template kwargs override. Different families use
    # different keys: Mistral/Qwen want `enable_thinking`, DeepSeek uses
    # `thinking` (boolean) + `reasoning_effort` ("low"|"medium"|"high"). When
    # set, this dict is passed verbatim as `extra_body.chat_template_kwargs`,
    # overriding the auto-built one. Example for DeepSeek-V4-Flash debugger:
    #   chat_template_kwargs:
    #     thinking: true
    #     reasoning_effort: "high"
    chat_template_kwargs: dict = Field(default_factory=dict)


class LLMConfig(BaseModel):
    providers: list[ProviderConfig] = Field(default_factory=list)
    architect: Optional[RoleModelConfig] = None   # iteration 0: initial harness gen
    debugger: Optional[RoleModelConfig] = None     # iterations 1+: repair & refinement
    onboarder: Optional[RoleModelConfig] = None    # one-shot per library (nemesis onboard)
    # Legacy fields (used if providers list is empty)
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    fallback_model: str = "claude-opus-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.2
    cache_enabled: bool = True
    cache_dir: Path = Path("./workspace/llm_cache")
    track_costs: bool = True


class FuzzingConfig(BaseModel):
    strategy: str = "harness"  # "harness" (Strategy A: no patches — DEFAULT) or "patch" (bypass blockers)
    fuzzer: str = "afl++"
    sanitizer: str = "asan"
    instances: int = 4
    strategies: list[str] = Field(
        default_factory=lambda: ["havoc", "splice", "deterministic", "explore"]
    )
    timeout_hours: float = 0.02
    # Fix 120: Per-target time cap (minutes). Prevents one slow target from starving others.
    # 0 = no cap (use timeout_hours for all targets). Otherwise hard-kill AFL after this many minutes.
    per_target_max_minutes: float = 0
    # Fix 120: Total scan budget in hours. When set, dynamically divides among targets.
    scan_budget_hours: float = 0
    # Path to custom AFL++ mutator C source file (compiled and loaded via AFL_CUSTOM_MUTATOR_LIBRARY).
    # When set, the mutator is compiled at build time and combined with AFL's default mutations.
    custom_mutator_source: str = ""
    afl_env: dict[str, str] = Field(default_factory=lambda: {
        "AFL_AUTORESUME": "1",
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_FAST_CAL": "1",
    })


class SymbolicConfig(BaseModel):
    solver: str = "z3"
    timeout_seconds: int = 30
    use_angr: bool = False
    angr_timeout: int = 120


class IntrospectorConfig(BaseModel):
    api_url: str = "https://introspector.oss-fuzz.com/api"
    coverage_threshold_pct: float = 5.0
    prioritize_memory_ops: bool = True
    exclude_files: list[str] = Field(default_factory=lambda: ["fuzz_*.c"])
    exclude_dirs: list[str] = Field(default_factory=lambda: ["test", "contrib", "build"])
    enable_enrichment: bool = True
    enrichment_batch_size: int = 10


class BuildConfig(BaseModel):
    configure: str = ""
    make: str = "make -j$(nproc)"
    debug_configure: str = ""   # ASAN build without AFL (for unpatched verification)
    debug_make: str = "make -j$(nproc) archive"
    ubsan_configure: str = ""   # UBSan-only build (no ASAN, pointer-overflow + undefined)
    ubsan_make: str = ""        # UBSan make command (defaults to debug_make if empty)
    coverage_configure: str = ""  # LLVM source-based coverage build (clang -fprofile-instr-generate)
    coverage_make: str = ""       # Coverage build make command (defaults to debug_make if empty)


class GroundTruthBug(BaseModel):
    id: str
    file: str
    line: int
    cwe: str
    function: str
    status: str = "unknown"


class KnownBlocker(BaseModel):
    condition: str
    file: str
    line: Optional[int] = None
    type: str  # "macro", "runtime_check", "format_requirement"
    description: str = ""


class PatchEntry(BaseModel):
    file: str
    description: str
    diff: str


class PinnedFunc(BaseModel):
    """A function pinned directly into the pipeline, bypassing recon heuristics."""
    func_name: str
    file_path: str
    line: int = 0
    has_memory_ops: bool = True
    has_pointer_arith: bool = True
    harness_hint: str = ""  # target-specific harness generation guidance
    force_no_blocker: bool = False  # if True, skip patch generation (function is directly reachable)
    # Fix 114: function is reached indirectly via public API with parameter control
    indirect_reach: bool = False
    # Fix 123: call function directly using internal headers (not via public API)
    direct_internal: bool = False
    # Fix 134: headers the harness MUST include (injected as <required_includes>)
    needed_headers: list[str] = Field(default_factory=list)
    # Fix 135: differential-oracle target. When True, the harness wraps the
    # round-trip operation (e.g. encode→decode) with a memcmp invariant —
    # any decode(encode(x)) ≠ x triggers abort(). Detects silent-corruption
    # bugs that don't manifest as memory unsafety. Bug class beyond ASAN/UBSan.
    differential_oracle: bool = False
    # Fix 148: cross-implementation differential oracle. When non-empty, the
    # harness MUST call BOTH the target function and the reference impl named
    # here on the same input, then assert byte-equal outputs (or matching
    # error/no-error status). Any divergence = abort(). Generalizes Fix 135
    # beyond round-trip into spec-vs-impl, strict-vs-lenient, fast-vs-reference
    # comparisons. Examples:
    #   "xmlReadMemoryRecover"  — compare libxml2 strict vs recovery mode
    #   "expat::XML_Parse"      — compare libxml2 vs expat for the same XML
    #   "ZSTD_decompress_ref"   — compare optimized vs reference codec path
    # May coexist with differential_oracle=True (round-trip AND cross-check).
    differential_reference: str = ""
    # Fix 150: threaded-oracle target. When True, the neural prompt builder
    # injects a `<threaded_oracle>` block telling the LLM to wrap the harness
    # in an N-thread pattern (default 2) where each thread calls the target
    # on shared state. ThreadSanitizer then catches data races / lock-order
    # violations / atomicity bugs (CWE-362) that single-threaded harnesses
    # never reach. Pair with `target.sanitizer_profile: tsan` to enable TSAN
    # instrumentation; otherwise the threaded harness still runs but TSAN
    # cannot report races. Useful for libraries that document thread-safe
    # APIs (e.g. SSL contexts, codec instances, allocator pools).
    threaded_oracle: bool = False
    # Fix 156: explicit priority override for ordering pinned_funcs in
    # `--max-targets N` selection. When 0.0 (default), uses the historical
    # baseline: 105.0 for direct_internal pins, 100.0 for everything else.
    # Set to a positive value (e.g. 200.0) to force this pin to the top of
    # the queue regardless of the direct_internal flag — useful when an
    # Introspector signal (high complexity + 0% coverage) makes one pin
    # the strategic priority for a campaign. Higher values run earlier.
    priority_score: float = 0.0
    # Fix 136: extra format-specific invariants the harness MUST encode as
    # `if (!cond) abort();` checks. Each entry is a plain-C boolean expression
    # using the same identifiers the harness already binds (e.g.
    # "encoded_size <= BrotliEncoderMaxCompressedSize(input_size)"). Useful
    # for catching logic bugs that ASAN can't see — e.g. encoder that
    # writes more bytes than its self-declared upper bound.
    output_invariants: list[str] = Field(default_factory=list)
    # Fix 145 (Strategy A+B Hybrid): visibility-only patch. When True, the
    # pipeline strips `static` from the function definition in `work_root`
    # before building the fuzz binary. The harness can then call the function
    # directly. The clean `source_root` stays pristine, so verification
    # (`_verify_crash_standalone`) reproduces every crash on the unpatched
    # debug binary — only crashes that survive that gate are counted as
    # rediscoveries. Honest because `static` is a visibility-only attribute:
    # removing it doesn't change runtime semantics, only linker-symbol
    # exposure. Use this for indirect_reach pins where the natural code path
    # is too narrow for vanilla AFL mutation (e.g. deep DTD recursion in
    # expat::build_node).
    auto_expose: bool = False


class TargetConfig(BaseModel):
    name: str = ""
    oss_fuzz_project: str = ""
    # source_root: the CLEAN, unmodified source checkout — NEVER patched directly.
    # All LLM patches go into work_root (a separate copy that is reset per target).
    source_root: Path = Path(".")
    # work_root: working copy where LLM patches are applied.
    # Reset to source_root via rsync before each target.
    # If empty, falls back to source_root (legacy behaviour).
    work_root: Path = Path("")
    build_dir: Path = Path("./build_fuzz")       # AFL binary — inside work_root
    debug_build_dir: Path = Path("./build_debug") # ASAN binary — inside source_root, built once
    ubsan_build_dir: Path = Path("")              # UBSan binary — inside source_root, built once
    coverage_build_dir: Path = Path("")           # LLVM coverage binary — inside source_root, built once
    build: BuildConfig = BuildConfig()
    repro_binary: str = "bin/bsdtar"
    repro_args: list[str] = Field(default_factory=lambda: ["-tf"])
    pinned_funcs: list[PinnedFunc] = Field(default_factory=list)
    # Generalization fields — move target-specific logic into config
    source_subdir: str = ""           # e.g. "libarchive", "src", "" (root)
    include_subdir: str = ""          # e.g. "libarchive" (for -I flag), "" = auto-detect
    library_name: str = "lib*.a"      # e.g. "libarchive.a", "libgpac.a"
    link_libs: str = ""               # e.g. "-lz -lbz2 -llzma ..."
    harness_includes: list[str] = Field(default_factory=list)
    # Fix 123: internal header dirs for direct internal function harnessing (e.g. ["c/enc", "c/common"])
    internal_include_dirs: list[str] = Field(default_factory=list)
    harness_template: str = ""  # Full harness system prompt (replaces HARNESS_SYSTEM)
    # Fix 135: sanitizer profile for the AFL harness compile.
    # Profiles:
    #   "asan_only"        — ASAN only (legacy, no UBSan)
    #   "asan_ubsan"       — ASAN + UBSan with `-fno-sanitize-recover=undefined`
    #                        so UBSan diagnostics actually crash AFL's child.
    #                        (current default, replaces the historical hardcoded
    #                        "-fsanitize=address,undefined" without recover-off)
    #   "asan_ubsan_strict"— Like asan_ubsan plus `-fsanitize=integer,implicit-conversion`
    #                        for unsigned-int-overflow / lossy implicit casts.
    #                        Higher false-positive rate; use on libraries known
    #                        to be careful with arithmetic (compression, parsers).
    #   "msan"             — Fix 149: MemorySanitizer ONLY (mutually exclusive with
    #                        ASAN). Catches use-of-uninitialized-value reads that
    #                        ASAN/UBSan never see. REQUIRES every linked dependency
    #                        (libc++, third-party libs) to be MSan-instrumented or
    #                        false positives flood the queue. Gate behind
    #                        `msan_supported: true`. Coexists by running as a
    #                        SEPARATE AFL instance, not a replacement.
    #   "tsan"             — Fix 150: ThreadSanitizer ONLY (mutually exclusive with
    #                        ASAN/MSAN). Catches data races (CWE-362) when paired
    #                        with a multi-threaded harness (`threaded_oracle: true`
    #                        on the pinned_func). REQUIRES tsan_supported=true and
    #                        a library that documents thread-safe APIs. Same parallel-
    #                        instance pattern as MSan: separate build, separate AFL.
    sanitizer_profile: str = "asan_ubsan"
    # Fix 149: opt-in confirmation that this target's dependency chain has been
    # built with `-fsanitize=memory`. MSan reports "uninitialized value" for ANY
    # uninstrumented memory write/read, so on a default Linux distro you'll see
    # thousands of false positives from libc/libstdc++. Set True only after
    # rebuilding deps with MSan (or for self-contained libs like cJSON that don't
    # link external runtimes). When False, `sanitizer_profile: msan` is rejected
    # in `_resolve_sanitizer_flags` to prevent wasted runs.
    msan_supported: bool = False
    # Fix 150: opt-in confirmation that this target documents thread-safe APIs
    # AND the dependency chain is TSan-instrumented (or self-contained). TSan
    # raises "data race" on any unsynchronised access, so single-threaded libs
    # that just happen to use globals will produce noise. Set True only when:
    #   (a) the library exposes a thread-safe parsing/codec API, AND
    #   (b) deps that share state across threads are also instrumented.
    # When False, `sanitizer_profile: tsan` is rejected in
    # `_resolve_sanitizer_flags` to prevent wasted runs. Also gates the
    # threaded_oracle prompt block from emitting on otherwise-quiet targets.
    tsan_supported: bool = False
    # Fix 136: post-fuzz leak detection (CWE-401). Disabled by default — LSan
    # cannot run during AFL persistent mode (no clean exit), so this triggers
    # an extra triage pass that runs the debug binary in single-shot mode on
    # a sample of corpus inputs with ASAN_OPTIONS=detect_leaks=1.
    leak_detection: bool = False
    # Fix 136: how many corpus inputs to sample for the leak detection pass.
    leak_detection_sample_size: int = 30
    # Crash reproducer minimization — wires CrashReport.minimized_input. After a
    # unique crash is confirmed, delta-debug the input down to the smallest byte
    # sequence that still crashes at the SAME site (same sanitizer class + fault
    # frame), so findings ship a minimal reproducer for coordinated disclosure.
    # Runs the single-shot debug binary; bounded by minimize_max_bytes (skip huge
    # inputs) and minimize_timeout_s (wall-clock budget per crash).
    minimize_crashes: bool = True
    minimize_max_bytes: int = 65536
    minimize_timeout_s: int = 60
    # Reproduce-on-latest-upstream check. At triage time, compare source_root's
    # git HEAD against the upstream branch tip (read-only ls-remote — no fetch/
    # checkout). Stamps each finding with upstream_status so "reproduces now" can
    # be qualified as "reproduces on latest" (up_to_date) vs "checkout stale, may
    # be fixed upstream" (behind). upstream_branch empty = resolve origin/HEAD.
    upstream_check: bool = True
    upstream_branch: str = ""
    api_func_fixes: dict[str, str] = Field(default_factory=dict)
    # harness_helpers: static C helper functions that must be present if referenced.
    # Key = function name (detection token), Value = full C definition to inject.
    # Injected before main() if the name appears in the code but no definition is found.
    harness_helpers: dict[str, str] = Field(default_factory=dict)
    # harness_conditional_includes: inject a #include if a token appears in the code.
    # Key = token (function/type name), Value = #include directive to inject.
    harness_conditional_includes: dict[str, str] = Field(default_factory=dict)
    magic_bytes: dict[str, list[str]] = Field(default_factory=dict)
    # Regex to derive format-specific API call from filename (group 1 = func name)
    format_enforcement_re: str = ""
    # Template string for the format call, e.g. "{func}(a)" — {func} replaced with group 1
    format_enforcement_template: str = ""

    @property
    def effective_work_root(self) -> Path:
        """Return work_root if set, else source_root (legacy fallback)."""
        if self.work_root and str(self.work_root) not in ("", "."):
            return self.work_root
        return self.source_root


# ── Top-level config ────────────────────────────────────────


class ReconScoringConfig(BaseModel):
    """Target-specific scoring adjustments for recon stage."""
    bonus_patterns: dict[str, float] = Field(default_factory=dict)
    bonus_func_patterns: dict[str, float] = Field(default_factory=dict)
    penalty_patterns: dict[str, float] = Field(default_factory=dict)
    penalty_dirs: list[str] = Field(default_factory=list)
    penalty_files: list[str] = Field(default_factory=list)
    penalty_funcs: list[str] = Field(default_factory=list)
    # High-complexity but low-value files (e.g. text serialization)
    low_value_files: dict[str, float] = Field(default_factory=dict)  # filename → penalty


class SeedsConfig(BaseModel):
    """Seed directories per format."""
    # Generic format→path mapping (preferred for new targets)
    formats: dict[str, str] = Field(default_factory=dict)
    format_aliases: dict[str, str] = Field(default_factory=dict)  # e.g. "tar" -> "pax"
    # Fix 115: Dual seed directories for encoder/producer vs decoder/consumer roles.
    # encoder_formats: maps format→plaintext seed dir (for targets that PRODUCE output)
    # When target is in enc/ subdir or planner says "encoder", use encoder seeds.
    encoder_formats: dict[str, str] = Field(default_factory=dict)
    # Subdirs that indicate the target produces/encodes (vs consumes/decodes)
    encoder_subdirs: list[str] = Field(
        default_factory=lambda: ["enc", "encode", "compress", "write", "output"]
    )
    oss_fuzz_corpus: str = ""  # OSS-Fuzz corpus directory (thousands of valid inputs)
    oss_fuzz_fuzzer_names: list[str] = Field(default_factory=list)  # fuzzer names to try
    # Legacy per-format fields (backward compat with existing libarchive config)
    pax: str = ""
    all_formats: str = ""
    uu: str = ""
    acl_text: str = ""
    cab: str = ""
    rar5: str = ""
    sevenzip: str = ""
    lha: str = ""
    zip: str = ""
    xar: str = ""
    iso: str = ""

    model_config = {"extra": "allow"}


class NemesisConfig(BaseSettings):
    """Top-level configuration — assembled from YAML files."""

    engine: EngineConfig = EngineConfig()
    llm: LLMConfig = LLMConfig()
    fuzzing: FuzzingConfig = FuzzingConfig()
    symbolic: SymbolicConfig = SymbolicConfig()
    introspector: IntrospectorConfig = IntrospectorConfig()
    target: TargetConfig = TargetConfig()
    known_blockers: list[KnownBlocker] = Field(default_factory=list)
    ground_truth: list[GroundTruthBug] = Field(default_factory=list)
    patches: list[PatchEntry] = Field(default_factory=list)
    seeds: SeedsConfig = SeedsConfig()
    recon_scoring: ReconScoringConfig = ReconScoringConfig()

    model_config = {"env_prefix": "NEMESIS_"}


# ── Config loading ──────────────────────────────────────────


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_dotenv_file(
    path: Optional[Path] = None,
    *,
    override: bool = False,
) -> int:
    """Load ``KEY=VALUE`` pairs from a ``.env`` file into ``os.environ``.

    Zero-dependency (no python-dotenv required). Lines may be blank, ``#``
    comments, or ``KEY=VALUE`` (an optional ``export `` prefix and matching
    surrounding quotes are stripped). A real shell env var is NEVER clobbered
    unless ``override=True`` — preserving architecture rule #3 (env vars win).

    Search order when ``path`` is None: ``$NEMESIS_ENV_FILE``, then ``.env`` in
    the cwd, then ``.env`` at the package root. Silently no-ops if absent.
    Returns the number of keys set.
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path))
    else:
        env_override = os.environ.get("NEMESIS_ENV_FILE")
        if env_override:
            candidates.append(Path(env_override))
        candidates.append(Path(".env"))
        candidates.append(Path(__file__).resolve().parent.parent / ".env")

    target = next((c for c in candidates if c.is_file()), None)
    if target is None:
        return 0

    set_count = 0
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = val
            set_count += 1
    return set_count


def load_config(
    default_path: Path = Path("config/default.yaml"),
    target_path: Optional[Path] = None,
) -> NemesisConfig:
    """
    Load and merge configuration from YAML files.

    Args:
        default_path: Path to default.yaml
        target_path: Optional path to target-specific YAML (e.g., config/targets/libarchive.yaml)

    Returns:
        Validated NemesisConfig instance
    """
    # Make LLM provider keys (.env at project root) available before any
    # $VAR expansion or LLMClient construction. A real shell export still wins.
    load_dotenv_file()

    data: dict[str, Any] = {}

    if default_path.exists():
        with open(default_path) as f:
            data = yaml.safe_load(f) or {}

    if target_path and target_path.exists():
        with open(target_path) as f:
            target_data = yaml.safe_load(f) or {}
        data = _deep_merge(data, target_data)

    return NemesisConfig(**_expand_env_vars(data))


def _expand_env_vars(obj: Any) -> Any:
    """Recursively expand $VAR and ~ in all string values of a dict/list."""
    if isinstance(obj, str):
        return os.path.expanduser(os.path.expandvars(obj))
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(i) for i in obj]
    return obj
