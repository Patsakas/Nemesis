"""
NEMESIS Stage 2 — Neural (LLM-based analysis).

Multi-provider LLM client (Groq → Cerebras → Gemini → Groq-8b) for:
1. Blocker analysis — why is a function unreachable?
2. Patch generation — minimal source patches to expose hidden code
3. Harness generation — AFL++ fuzzing harnesses
4. Refinement — incorporate feedback from failed fuzzing runs
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import (
    CWE,
    AnalysisContext,
    CrashReport,
    CVEAssessment,
    FeedbackContext,
    HarnessSpec,
    InputSpec,
    LLMCallRecord,
    PatchProposal,
    RiskLevel,
    VulnerabilityAnalysis,
)
from nemesis.neural.json_extractor import extract_json

if TYPE_CHECKING:  # forward refs only — these are imported lazily at runtime
    from nemesis.neural.context_builder import ContextBuilder
    from nemesis.neural.oracle import CodebaseOracle


class ModelRole(str, enum.Enum):
    """Which role-specific model to use for an LLM call."""
    ARCHITECT = "architect"    # iteration 0: initial harness generation
    DEBUGGER = "debugger"      # iterations 1+: repair & refinement
    ONBOARDER = "onboarder"    # one-shot per library (nemesis onboard)
    DEFAULT = "default"        # existing provider chain


def _extract_best_code_block(text: str) -> str | None:
    """Return the most harness-like fenced code block in an LLM response.

    Reasoning models often emit a prose/diff fence BEFORE the real corrected
    harness, so grabbing the first ``` block can return an explanation snippet.
    Pick the block with the most harness markers (#include / fuzzer entrypoint /
    AFL macros / main), tie-broken by length.
    """
    import re as _re
    blocks = _re.findall(r"```(?:c|cpp|c\+\+|cc)?\s*\n(.*?)```", text, _re.DOTALL)
    if not blocks:
        return None
    markers = ("#include", "LLVMFuzzerTestOneInput", "__AFL", "int main", "main(")

    def _score(b: str) -> tuple[int, int]:
        return (sum(10 for m in markers if m in b), len(b))

    return max(blocks, key=_score)


def _resolve_llm_file_path(raw: str, source_root: Path, log) -> str:
    """
    Resolve an LLM-provided file path against the actual source tree.

    The LLM may return a bare filename ("Ppmd8.c") or a wrong relative path.
    Tries progressively looser matches:
      1. Exact relative path from source_root
      2. Case-insensitive filename match
      3. Actual stem ends with LLM stem  (e.g. "archive_ppmd8" ends with "ppmd8")
      4. Actual stem contains LLM stem
    Returns the best resolved relative path, or raw unchanged with a warning.
    """
    if not raw:
        return raw

    if (source_root / raw).exists():
        return raw

    llm_name = Path(raw).name.lower()
    llm_stem = Path(raw).stem.lower()

    # Fix 126: cache file list per source_root to avoid repeated rglob
    _cache_key = str(source_root)
    if not hasattr(_resolve_llm_file_path, "_file_cache"):
        _resolve_llm_file_path._file_cache = {}
    if _cache_key not in _resolve_llm_file_path._file_cache:
        _resolve_llm_file_path._file_cache[_cache_key] = (
            list(source_root.rglob("*.c")) + list(source_root.rglob("*.h"))
        )
    candidates = _resolve_llm_file_path._file_cache[_cache_key]

    # 2. Exact filename match (case-insensitive)
    exact = [f for f in candidates if f.name.lower() == llm_name]
    if len(exact) == 1:
        resolved = str(exact[0].relative_to(source_root))
        log.warning("path.resolved_exact", raw=raw, resolved=resolved)
        return resolved

    # 3. Stem suffix match  ("ppmd8" → "archive_ppmd8")
    suffix = [f for f in candidates if f.stem.lower().endswith(llm_stem)]
    if len(suffix) == 1:
        resolved = str(suffix[0].relative_to(source_root))
        log.warning("path.resolved_suffix", raw=raw, resolved=resolved)
        return resolved

    # 4. Stem contains match
    contains = [f for f in candidates if llm_stem in f.stem.lower()]
    if len(contains) == 1:
        resolved = str(contains[0].relative_to(source_root))
        log.warning("path.resolved_contains", raw=raw, resolved=resolved)
        return resolved

    log.warning("path.unresolved", raw=raw, candidates=len(candidates))
    return raw


class NeuralStage:
    """Stage 2 orchestrator — manages all LLM interactions."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("neural")
        self.client = LLMClient(config)
        self.session_cost = 0.0
        self._oracle: CodebaseOracle | None = None  # type: ignore[type-arg]
        self._context_builder: ContextBuilder | None = None  # type: ignore[type-arg]

    def set_oracle(self, oracle: CodebaseOracle) -> None:  # type: ignore[type-arg]
        """Wire in the codebase oracle for RAG-based context injection."""
        self._oracle = oracle

    def set_context_builder(self, builder: ContextBuilder) -> None:  # type: ignore[type-arg]
        """Wire in the context builder for Two-Brain Architect model."""
        self._context_builder = builder

    def analyze(self, context: AnalysisContext) -> VulnerabilityAnalysis:
        """Analyze a target for potential vulnerabilities."""
        self.log.info("analyze.start", func=context.target.func_name)

        prompt = PromptBuilder.build_analysis_prompt(context)
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.ANALYSIS_SYSTEM,
            stage="blocker_analysis",
            target_func=context.target.func_name,
        )
        self.session_cost += self.client.last_cost

        return self._parse_analysis(response)

    def analyze_for_harness(self, context: AnalysisContext) -> VulnerabilityAnalysis:
        """Analyze a target for Strategy A (harness-driven, no patches).

        Uses a harness-focused prompt that asks how to REACH the function
        through the public API, not how to bypass blockers.
        Forces has_blocker=False so no patch is ever generated.
        """
        self.log.info("analyze_harness.start", func=context.target.func_name)

        prompt = PromptBuilder.build_analysis_prompt(context)
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.HARNESS_ANALYSIS_SYSTEM,
            stage="harness_analysis",
            target_func=context.target.func_name,
        )
        self.session_cost += self.client.last_cost

        analysis = self._parse_analysis(response)
        analysis.has_blocker = False  # Never generate patches in Strategy A
        return analysis

    def plan_harness(
        self,
        target_func: str,
        source_snippet: str,
        oracle_context: str = "",
    ) -> tuple[str, bool]:
        """Generate a harness recipe/hint for a target function using the Debugger model.

        Returns a tuple (hint_string, indirect_reach) describing the API sequence
        needed to reach the target, or ("", False) if the function is simple.
        Uses the LLM cache — repeated calls for the same function are free.

        Fix 114: Also returns indirect_reach flag when the target requires parameter-
        controlled reaching via public API (internal functions, non-public types).

        Args:
            target_func: Name of the target function
            source_snippet: Source code of the function (capped at 3000 chars)
            oracle_context: Optional RAG context from codebase oracle

        Returns:
            Tuple of (hint string, indirect_reach bool)
        """
        self.log.info("plan_harness.start", func=target_func)

        # Cap source snippet to avoid token waste
        snippet = source_snippet[:3000]

        prompt_parts = [
            f"Target function: {target_func}",
            "",
            "<source_code>",
            snippet,
            "</source_code>",
        ]
        if oracle_context:
            prompt_parts.append("")
            prompt_parts.append(oracle_context)

        prompt_parts.append(
            "\nAnalyze this function and produce a harness recipe. "
            "If it simply takes a buffer/memory input with no special setup, "
            'return {"harness_hint": "", "indirect_reach": false}.'
        )
        prompt = "\n".join(prompt_parts)

        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.HARNESS_PLANNER_SYSTEM,
            stage="harness_planner",
            target_func=target_func,
            role=ModelRole.DEBUGGER,
        )
        self.session_cost += self.client.last_cost

        # Parse JSON response
        indirect_reach = False
        try:
            data = extract_json(response)
            hint = data.get("harness_hint", "") if isinstance(data, dict) else ""
            indirect_reach = bool(data.get("indirect_reach", False)) if isinstance(data, dict) else False
        except Exception:
            self.log.warning("plan_harness.parse_failed", func=target_func)
            hint = ""

        if hint:
            self.log.info(
                "plan_harness.generated",
                func=target_func,
                hint_len=len(hint),
                indirect_reach=indirect_reach,
            )
        else:
            self.log.debug("plan_harness.simple_function", func=target_func)

        return hint, indirect_reach

    def generate_patch(
        self,
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
    ) -> PatchProposal:
        """Generate a source-level patch based on analysis."""
        self.log.info("patch.start", func=context.target.func_name)

        prompt = PromptBuilder.build_patch_prompt(analysis, context)
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.PATCH_SYSTEM,
            stage="patch_generation",
            target_func=context.target.func_name,
        )
        self.session_cost += self.client.last_cost

        return self._parse_patch(response, known_file_path=context.target.file_path)

    def generate_harness(
        self,
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
        library_memory_snippet: str = "",
    ) -> HarnessSpec:
        """Generate an AFL++ fuzzing harness."""
        format_call = PromptBuilder._derive_format_func(context.target.file_path, self.config)
        self.log.info(
            "harness.start",
            func=context.target.func_name,
            format_func=format_call,
        )

        # Query codebase oracle for relevant source context (RAG)
        oracle_context = ""
        if self._oracle and self._oracle.is_built():
            first_snippet = next(iter(context.source_snippets.values()), "")
            query = f"{context.target.func_name}\n{first_snippet[:300]}"
            oracle_context = self._oracle.query(query, k=8)
            self.log.debug("oracle.queried", func=context.target.func_name)

        # Use target-specific harness template if configured, else default
        harness_system = (
            self.config.target.harness_template
            or PromptBuilder.HARNESS_SYSTEM
        )
        if library_memory_snippet:
            harness_system = harness_system + "\n\n" + library_memory_snippet

        prompt = PromptBuilder.build_harness_prompt(
            analysis, context, oracle_context=oracle_context, config=self.config,
        )
        response = self.client.complete(
            prompt=prompt,
            system=harness_system,
            stage="harness_generation",
            target_func=context.target.func_name,
        )
        self.session_cost += self.client.last_cost

        harness = self._parse_harness(response)

        # Retry once (bypassing cache) if c_code is empty — LLM may have returned
        # a response without JSON or with a missing c_code field
        if not harness.c_code:
            self.log.warning("harness.empty_retry", func=context.target.func_name)
            # Disable cache for the retry so we get a fresh response
            orig_cache = self.config.llm.cache_enabled
            self.config.llm.cache_enabled = False
            try:
                response2 = self.client.complete(
                    prompt=prompt,
                    system=harness_system,
                    stage="harness_generation_retry",
                    target_func=context.target.func_name,
                )
                self.session_cost += self.client.last_cost
                harness = self._parse_harness(response2)
            finally:
                self.config.llm.cache_enabled = orig_cache

            if harness.c_code:
                self.log.info("harness.retry_success", func=context.target.func_name)
            else:
                self.log.error("harness.retry_failed", func=context.target.func_name)

        # Post-process: enforce correct format function in generated code
        # Only applies when _derive_format_func matched a specific format (not generic)
        if harness.c_code and format_call and "format_all" not in format_call:
            import re as _re
            old_code = harness.c_code
            # Replace archive_read_support_format_all(a) with the correct one
            harness.c_code = _re.sub(
                r"archive_read_support_format_all\s*\(\s*a\s*\)",
                format_call,
                harness.c_code,
            )
            if harness.c_code != old_code:
                self.log.info(
                    "harness.format_enforced",
                    func=context.target.func_name,
                    format_func=format_call,
                )
            # For filter targets, also add format_raw if not present
            if "filter" in format_call and "format_raw" not in harness.c_code:
                harness.c_code = harness.c_code.replace(
                    format_call,
                    f"archive_read_support_format_raw(a);\n        {format_call}",
                    1,
                )

        return harness

    def generate_harness_strategy_a(
        self,
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
        library_memory_snippet: str = "",
    ) -> HarnessSpec:
        """Generate a smart harness for Strategy A (no patches).

        Uses HARNESS_STRATEGY_A_SYSTEM prompt focused on reaching the target
        through legitimate API usage. Same retry + format enforcement logic
        as generate_harness().
        """
        format_call = PromptBuilder._derive_format_func(context.target.file_path, self.config)
        self.log.info(
            "harness_a.start",
            func=context.target.func_name,
            format_func=format_call,
        )

        # Two-Brain routing: use Architect with full codebase context if available.
        # 2026-05-08 audit: cache the codebase_context block on the AnalysisContext
        # so feedback retries reuse it instead of rebuilding the full ~30K-token
        # block (which dominated the cjson_v3 retry prompt that blew to 45.5K
        # input tokens and crashed Mistral's response down to 123 tokens).
        # ContextBuilder.build() is deterministic given target + source_root, so
        # caching is safe within one pipeline run.
        oracle_context = ""
        role = ModelRole.DEFAULT
        if self._context_builder is not None:
            cache_key = (
                context.target.func_name,
                getattr(context.target, "file_path", ""),
            )
            cached = getattr(context, "_oracle_context_cache", {})
            if cache_key in cached:
                oracle_context = cached[cache_key]
                self.log.debug(
                    "two_brain.architect.cached_context",
                    func=context.target.func_name,
                    cached_chars=len(oracle_context),
                )
            else:
                oracle_context = self._context_builder.build(context.target, context)
                if not isinstance(cached, dict):
                    cached = {}
                cached[cache_key] = oracle_context
                # Stash on the context for cross-call reuse. Pydantic models
                # may forbid arbitrary attribute writes; fall back gracefully.
                try:
                    context._oracle_context_cache = cached  # type: ignore[attr-defined]
                except (AttributeError, TypeError):
                    pass
                self.log.debug("two_brain.architect", func=context.target.func_name)
            role = ModelRole.ARCHITECT
        elif self._oracle and self._oracle.is_built():
            first_snippet = next(iter(context.source_snippets.values()), "")
            query = f"{context.target.func_name}\n{first_snippet[:300]}"
            oracle_context = self._oracle.query(query, k=8)
            self.log.debug("oracle.queried", func=context.target.func_name)

        # Proactive caller hints for static functions
        caller_context = ""
        if context.target.is_static and self._oracle and self._oracle.is_built():
            callers = self._oracle.find_callers(context.target.func_name, k=3)
            if callers:
                caller_context = "\n".join(
                    f"- {c.name}() in {c.file_path}" for c in callers[:3]
                )
                self.log.debug(
                    "harness_a.caller_hints",
                    func=context.target.func_name,
                    callers=[c.name for c in callers[:3]],
                )

        prompt = PromptBuilder.build_harness_prompt(
            analysis, context, oracle_context=oracle_context, config=self.config,
            caller_context=caller_context,
        )
        # Use target-specific harness template if available, else generic Strategy A prompt
        system = self.config.target.harness_template or PromptBuilder.HARNESS_STRATEGY_A_SYSTEM
        # Append library memory priors (cross-run learned patterns) if available
        if library_memory_snippet:
            system = system + "\n\n" + library_memory_snippet
        response = self.client.complete(
            prompt=prompt,
            system=system,
            stage="harness_generation_a",
            target_func=context.target.func_name,
            role=role,
        )
        self.session_cost += self.client.last_cost

        harness = self._parse_harness(response)

        # Retry once if c_code is empty
        if not harness.c_code:
            self.log.warning("harness_a.empty_retry", func=context.target.func_name)
            orig_cache = self.config.llm.cache_enabled
            self.config.llm.cache_enabled = False
            try:
                response2 = self.client.complete(
                    prompt=prompt,
                    system=system,
                    stage="harness_generation_a_retry",
                    target_func=context.target.func_name,
                )
                self.session_cost += self.client.last_cost
                harness = self._parse_harness(response2)
            finally:
                self.config.llm.cache_enabled = orig_cache

        # Post-process: enforce correct format function (same as generate_harness)
        if harness.c_code and format_call and "format_all" not in format_call:
            import re as _re
            old_code = harness.c_code
            harness.c_code = _re.sub(
                r"archive_read_support_format_all\s*\(\s*a\s*\)",
                format_call,
                harness.c_code,
            )
            if harness.c_code != old_code:
                self.log.info(
                    "harness_a.format_enforced",
                    func=context.target.func_name,
                    format_func=format_call,
                )
            if "filter" in format_call and "format_raw" not in harness.c_code:
                harness.c_code = harness.c_code.replace(
                    format_call,
                    f"archive_read_support_format_raw(a);\n        {format_call}",
                    1,
                )

        return harness

    def repair_harness(
        self,
        harness_code: str,
        compile_errors: str,
        target_func: str = "",
    ) -> str:
        """Use LLM to fix compile errors in a harness.

        Receives the full harness source + clang stderr.
        Returns the fixed C source code, or empty string on failure.
        This is a short, cheap LLM call (~1-2K tokens).
        Cache is disabled — each repair attempt has unique errors.
        """
        self.log.info("repair_harness.start", func=target_func)

        # Query oracle for types/functions referenced in compile errors
        oracle_context = ""
        if self._oracle and self._oracle.is_built():
            import re as _re
            unknowns = _re.findall(r"unknown type name ['\"](\w+)['\"]", compile_errors)
            undecl = _re.findall(r"['\"](\w+)['\"] undeclared", compile_errors)
            query_terms = " ".join(set(unknowns + undecl)) or target_func
            oracle_context = self._oracle.query(query_terms, k=5)

        orig_cache = self.config.llm.cache_enabled
        self.config.llm.cache_enabled = False
        try:
            oracle_block = f"\n\n{oracle_context}" if oracle_context else ""
            # Fix 91: When the error is "target function not called", give a specific instruction
            target_hint = ""
            if target_func and "target function" in compile_errors and "not called" in compile_errors:
                target_hint = (
                    f"\n\nCRITICAL: The harness must call {target_func}() directly. "
                    f"Add a direct call to {target_func}() in the harness body."
                )
            prompt = (
                f"<compile_errors>\n{compile_errors[:3000]}\n</compile_errors>\n\n"
                f"<harness_source>\n{harness_code[:6000]}\n</harness_source>"
                f"{oracle_block}{target_hint}\n\n"
                "Fix ALL compile errors in the harness. "
                "Return the complete fixed C source."
            )
            response = self.client.complete(
                prompt=prompt,
                system=PromptBuilder.HARNESS_REPAIR_SYSTEM,
                stage="harness_repair",
                target_func=target_func,
                role=ModelRole.DEBUGGER,
            )
            self.session_cost += self.client.last_cost
        finally:
            self.config.llm.cache_enabled = orig_cache

        # Parse response — expect {"c_code": "..."}
        try:
            data = self._extract_json(response)
            if data and data.get("c_code"):
                self.log.info("repair_harness.success", func=target_func)
                return str(data["c_code"])
        except Exception:
            pass

        # Fallback: extract the most harness-like C code block from the raw
        # response if JSON parsing fails (not just the first fence, which on
        # reasoning models is often a prose/diff explanation).
        best = _extract_best_code_block(response)
        if best:
            self.log.info("repair_harness.success_raw_extract", func=target_func)
            return best

        self.log.warning("repair_harness.failed", func=target_func)
        return ""

    def generate_harness_variants(
        self,
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
        n: int = 3,
        library_memory_snippet: str = "",
    ) -> list[HarnessSpec]:
        """Generate N harness variants with increasing temperature (Fix D).

        Each variant uses a different temperature to explore the harness design space.
        Returns a list of HarnessSpec (may be shorter than n if some retries fail).
        Cache is disabled per call so each variant gets a fresh LLM response.
        """
        temps = [0.2, 0.5, 0.8][:n]
        variants: list[HarnessSpec] = []

        format_call = PromptBuilder._derive_format_func(context.target.file_path, self.config)
        # Two-Brain routing: use Architect for all variants (iteration 0)
        oracle_context = ""
        role = ModelRole.DEFAULT
        if self._context_builder is not None:
            oracle_context = self._context_builder.build(context.target, context)
            role = ModelRole.ARCHITECT
        elif self._oracle and self._oracle.is_built():
            first_snippet = next(iter(context.source_snippets.values()), "")
            query = f"{context.target.func_name}\n{first_snippet[:300]}"
            oracle_context = self._oracle.query(query, k=8)

        system = self.config.target.harness_template or PromptBuilder.HARNESS_STRATEGY_A_SYSTEM
        if library_memory_snippet:
            system = system + "\n\n" + library_memory_snippet

        orig_cache = self.config.llm.cache_enabled
        self.config.llm.cache_enabled = False

        try:
            for i, temp in enumerate(temps):
                # Cache-bust via variant comment appended to prompt
                prompt = PromptBuilder.build_harness_prompt(
                    analysis, context, oracle_context=oracle_context,
                    config=self.config,
                )
                prompt += f"\n// VARIANT {i} (temperature={temp})"

                try:
                    response = self.client.complete(
                        prompt=prompt,
                        system=system,
                        stage=f"harness_variant_{i}",
                        target_func=context.target.func_name,
                        temperature=temp,
                        role=role,
                    )
                    self.session_cost += self.client.last_cost
                    harness = self._parse_harness(response)

                    # Post-process: enforce format function
                    if harness.c_code and format_call and "format_all" not in format_call:
                        import re as _re
                        harness.c_code = _re.sub(
                            r"archive_read_support_format_all\s*\(\s*a\s*\)",
                            format_call,
                            harness.c_code,
                        )
                        if "filter" in format_call and "format_raw" not in harness.c_code:
                            harness.c_code = harness.c_code.replace(
                                format_call,
                                f"archive_read_support_format_raw(a);\n        {format_call}",
                                1,
                            )

                    if harness.c_code:
                        variants.append(harness)
                        self.log.info(
                            "harness_variant.generated",
                            func=context.target.func_name,
                            variant=i,
                            temp=temp,
                        )
                    else:
                        self.log.warning(
                            "harness_variant.empty", func=context.target.func_name, variant=i,
                        )
                except Exception as exc:
                    self.log.warning(
                        "harness_variant.failed",
                        func=context.target.func_name, variant=i, error=str(exc),
                    )
        finally:
            self.config.llm.cache_enabled = orig_cache

        return variants

    def generate_harness_via_caller(
        self,
        target_func: str,
        callers: list,
        context: AnalysisContext,
        previous_harness_code: str = "",
    ) -> HarnessSpec:
        """Generate a harness that reaches target_func via a higher-level caller (Fix E).

        Used when direct harnessing of target_func fails due to deep call graph position.
        The LLM is instructed to target the caller so that target_func is exercised indirectly.
        Cache is disabled to ensure a fresh generation.

        Fix 102: Now receives previous_harness_code and harness_template context so the
        Debugger model can see the proven working pattern instead of guessing from scratch.
        """
        self.log.info(
            "caller_escalation.start",
            func=target_func,
            callers=[c.name for c in callers[:3]],
        )

        oracle_context = ""
        if self._oracle and self._oracle.is_built():
            oracle_context = self._oracle.query(target_func, k=5)

        # Fix 102: pass harness_template + previous harness so LLM has working context
        harness_template = self.config.target.harness_template or ""
        prompt = PromptBuilder.build_caller_escalation_prompt(
            target_func, callers, oracle_context, context,
            harness_template=harness_template,
            previous_harness_code=previous_harness_code,
        )

        orig_cache = self.config.llm.cache_enabled
        self.config.llm.cache_enabled = False
        try:
            response = self.client.complete(
                prompt=prompt,
                system=PromptBuilder.HARNESS_CALLER_ESCALATION_SYSTEM,
                stage="caller_escalation",
                target_func=target_func,
                role=ModelRole.DEBUGGER,
            )
            self.session_cost += self.client.last_cost
        finally:
            self.config.llm.cache_enabled = orig_cache

        harness = self._parse_harness(response)
        if harness.c_code:
            self.log.info("caller_escalation.success", func=target_func)
        else:
            self.log.warning("caller_escalation.empty", func=target_func)
        return harness

    def generate_targeted_seeds(
        self,
        target_func: str,
        context: AnalysisContext,
        n_seeds: int = 3,
    ) -> list[bytes]:
        """Ask LLM to generate hex-encoded seed inputs designed to reach target_func.

        The LLM sees the source code and understands which validation checks
        must pass. Returns up to n_seeds binary inputs.
        """
        self.log.info("seeds.targeted.start", func=target_func, n=n_seeds)

        sections = [
            f"<target_function>{target_func}</target_function>",
            "",
            "<call_chain>",
            " → ".join(context.call_chain.chain),
            "</call_chain>",
        ]
        target_snippet = context.source_snippets.get(target_func, "")
        if target_snippet:
            sections.extend([
                "",
                "<source_code>",
                target_snippet[:3000],
                "</source_code>",
            ])
        sections.extend([
            "",
            f"<task>Generate {n_seeds} minimal binary seed inputs (hex-encoded) "
            f"that will pass format validation checks and reach {target_func}.</task>",
        ])

        prompt = "\n".join(sections)
        try:
            response = self.client.complete(
                prompt=prompt,
                system=PromptBuilder.SEED_SYNTHESIS_SYSTEM,
                stage="seed_synthesis",
                target_func=target_func,
            )
            self.session_cost += self.client.last_cost
        except Exception as exc:
            self.log.warning("seeds.targeted.llm_error", error=str(exc))
            return []

        try:
            data = extract_json(response)
            if isinstance(data, dict) and "seeds" in data:
                raw_seeds = data["seeds"]
            elif isinstance(data, list):
                raw_seeds = data
            else:
                self.log.warning("seeds.targeted.bad_json")
                return []

            result = []
            for hex_str in raw_seeds[:n_seeds]:
                if not isinstance(hex_str, str):
                    continue
                hex_clean = hex_str.strip().replace(" ", "").replace("\n", "")
                try:
                    seed_bytes = bytes.fromhex(hex_clean)
                    if 1 <= len(seed_bytes) <= 4096:
                        result.append(seed_bytes)
                except ValueError:
                    pass

            self.log.info("seeds.targeted.generated", func=target_func, count=len(result))
            return result
        except Exception:
            self.log.warning("seeds.targeted.parse_error", func=target_func)
            return []

    def refine_harness(
        self,
        context: AnalysisContext,
        feedback: FeedbackContext,
    ) -> VulnerabilityAnalysis:
        """Refine analysis for Strategy A based on harness-focused feedback.

        Like refine() but uses harness-focused prompt (no patch info)
        and forces has_blocker=False.
        """
        self.log.info(
            "refine_harness.start",
            func=context.target.func_name,
            iteration=feedback.iteration,
            reason=feedback.failure_reason,
        )

        prompt = PromptBuilder.build_harness_refinement_prompt(context, feedback)
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.HARNESS_REFINEMENT_SYSTEM,
            stage="harness_refinement",
            target_func=context.target.func_name,
            role=ModelRole.DEBUGGER,
        )
        self.session_cost += self.client.last_cost

        analysis = self._parse_analysis(response)
        analysis.has_blocker = False  # Never generate patches in Strategy A
        return analysis

    def refine(
        self,
        context: AnalysisContext,
        feedback: FeedbackContext,
    ) -> VulnerabilityAnalysis:
        """
        Refine analysis based on fuzzing feedback.

        This is the neural component of the self-healing loop.
        The LLM receives:
        - Original analysis + patch that failed
        - Coverage data showing what didn't work
        - AFL++ stats and error logs
        And produces a revised strategy.
        """
        self.log.info(
            "refine.start",
            func=context.target.func_name,
            iteration=feedback.iteration,
            reason=feedback.failure_reason,
        )

        prompt = PromptBuilder.build_refinement_prompt(context, feedback)
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.REFINEMENT_SYSTEM,
            # Refinement uses primary (Sonnet) — Opus only for initial complex analysis
            stage="refinement",
            target_func=context.target.func_name,
        )
        self.session_cost += self.client.last_cost

        return self._parse_analysis(response)

    def analyze_cve(
        self,
        crash: CrashReport,
        library_name: str,
        source_file: str = "",
        source_context: str = "",
    ) -> CVEAssessment:
        """Analyze a crash for CVE matching and generate a structured assessment."""
        self.log.info(
            "cve_analysis.start",
            location=crash.crash_location,
            cwe=crash.cwe.value,
        )

        prompt = PromptBuilder.build_cve_analysis_prompt(
            crash, library_name, source_file, source_context,
        )
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.CVE_ANALYSIS_SYSTEM,
            stage="cve_analysis",
            target_func=crash.crash_location,
        )
        self.session_cost += self.client.last_cost

        return self._parse_cve_assessment(response)

    def generate_onboard_template(
        self,
        project_name: str,
        headers_content: str,
    ) -> tuple[str, dict, list[str], dict]:
        """
        Call the LLM to generate a harness_template system prompt, magic_bytes dict,
        minimal harness_includes list, and bonus_func_patterns for recon scoring.

        Returns (harness_template, magic_bytes, harness_includes, bonus_func_patterns).
        Falls back to empty values on parse failure — caller should handle gracefully.
        """
        self.log.info("onboard_template.start", project=project_name)
        prompt = f"Library: {project_name}\n\nPublic API headers:\n{headers_content}"
        response = self.client.complete(
            prompt=prompt,
            system=PromptBuilder.ONBOARD_SYSTEM,
            stage="onboard",
            target_func=project_name,
            role=ModelRole.ONBOARDER,
        )
        self.session_cost += self.client.last_cost

        try:
            data = self._extract_json(response)
            if data is None:
                raise ValueError("JSON extraction returned None")
            harness_template = str(data.get("harness_template", ""))
            magic_bytes = data.get("magic_bytes", {})
            harness_includes = data.get("harness_includes", [])
            bonus_func_patterns = data.get("bonus_func_patterns", {})
            if not isinstance(bonus_func_patterns, dict):
                bonus_func_patterns = {}
            self.log.info(
                "onboard_template.ok",
                project=project_name,
                includes=harness_includes,
                magic_formats=list(magic_bytes.keys()) if isinstance(magic_bytes, dict) else [],
                bonus_patterns=list(bonus_func_patterns.keys())[:10],
            )
            return harness_template, magic_bytes, harness_includes, bonus_func_patterns
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            self.log.warning("onboard_template.parse_failed", error=str(exc))
            return "", {}, [], {}

    def _parse_cve_assessment(self, response: str) -> CVEAssessment:
        """Parse LLM response into CVEAssessment."""
        import re as _re
        try:
            data = self._extract_json(response)
            if data is None:
                raise ValueError("JSON extraction returned None")

            # Clamp CVSS to 0-10
            cvss = float(data.get("cvss_estimate", 0.0))
            cvss = max(0.0, min(10.0, cvss))

            # Validate CVE ID format if provided
            cve_id = str(data.get("cve_id", ""))
            if cve_id and not _re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
                cve_id = ""

            # Confidence threshold: below 80% → not a known CVE
            confidence = float(data.get("cve_confidence", 0.0))
            is_known = bool(data.get("is_known_cve", False))
            if confidence < 0.8:
                is_known = False

            return CVEAssessment(
                is_known_cve=is_known,
                cve_id=cve_id if is_known else "",
                cve_confidence=confidence,
                rationale=str(data.get("rationale", "")),
                affected_versions=str(data.get("affected_versions", "")),
                cvss_estimate=cvss,
                root_cause_analysis=str(data.get("root_cause_analysis", "")),
                suggested_mitigation=str(data.get("suggested_mitigation", "")),
                similar_cves=data.get("similar_cves", []),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.log.warning("parse.cve_assessment_failed", error=str(e))
            return CVEAssessment(
                rationale=f"Parse error: {e}",
            )

    # ── Response parsers ────────────────────────────────────

    def _parse_analysis(self, response: str) -> VulnerabilityAnalysis:
        """Parse LLM response into VulnerabilityAnalysis."""
        try:
            data = self._extract_json(response)
            if data is None:
                raise ValueError("JSON extraction returned None")
            # Handle LLM returning multiple CWEs like "CWE-476, CWE-122" — take first
            raw_cwe = data.get("cwe", "CWE-unknown")
            if isinstance(raw_cwe, str) and "," in raw_cwe:
                raw_cwe = raw_cwe.split(",")[0].strip()
            try:
                cwe_val = CWE(raw_cwe)
            except ValueError:
                cwe_val = CWE.UNKNOWN
            return VulnerabilityAnalysis(
                vulnerability_type=data.get("vulnerability_type", "unknown"),
                cwe=cwe_val,
                root_cause=data.get("root_cause", ""),
                attack_vector=data.get("attack_vector", ""),
                confidence=data.get("confidence", 0.5),
                missing_checks=data.get("missing_checks", []),
                has_blocker=data.get("has_blocker", True),
                blocker_description=data.get("blocker_description", ""),
                blocker_class=data.get("blocker_class", "runtime"),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.log.warning("parse.analysis_failed", error=str(e))
            return VulnerabilityAnalysis(
                vulnerability_type="parse_error",
                cwe=CWE.UNKNOWN,
                root_cause=response[:500],
                attack_vector="",
                has_blocker=True,  # safe default: assume blocker, don't skip patch
            )

    def _parse_patch(self, response: str, known_file_path: str = "") -> PatchProposal:
        """Parse LLM response into PatchProposal."""
        try:
            data = self._extract_json(response)
            if data is None:
                raise ValueError("JSON extraction returned None")
            source_root = Path(self.config.target.source_root)
            raw_path = data.get("file_path", "")
            resolved_path = _resolve_llm_file_path(raw_path, source_root, self.log)
            # If resolver failed and we have a known path (from pinned_funcs), use it
            if resolved_path == raw_path and known_file_path and raw_path != known_file_path:
                self.log.warning(
                    "path.fallback_to_known",
                    raw=raw_path,
                    known=known_file_path,
                )
                resolved_path = known_file_path
            return PatchProposal(
                file_path=resolved_path,
                line=data.get("line", 0),
                original=data.get("original", ""),
                replacement=data.get("replacement", ""),
                justification=data.get("justification", ""),
                risk_level=RiskLevel(data.get("risk_level", "safe")),
                patch_type=data.get("patch_type", ""),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.log.warning("parse.patch_failed", error=str(e))
            return PatchProposal(
                file_path="", line=0, original="", replacement="",
                justification=f"Parse error: {e}",
            )

    @staticmethod
    def _sanitize_target_func(raw: str) -> str:
        """Validate target_func is a valid C identifier; return "" if garbled."""
        import re as _re
        if not raw or len(raw) > 200:
            return ""
        # Valid C identifier: [A-Za-z_][A-Za-z0-9_]*
        if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw):
            return raw
        # Fix 108: LLM may prefix with ":" or other garbage — extract first C identifier.
        m = _re.search(r"[A-Za-z_][A-Za-z0-9_]{2,}", raw)
        if m:
            return m.group(0)
        return ""

    def _parse_harness(self, response: str) -> HarnessSpec:
        """Parse LLM response into HarnessSpec."""
        try:
            # Strip any thinking tags that may have leaked into the response
            import re as _re
            cleaned = _re.sub(r"<think>.*?</think>\s*", "", response, flags=_re.DOTALL)
            data = self._extract_json(cleaned)
            if data is None:
                raise ValueError("JSON extraction returned None")
            raw_func = data.get("target_func", "")
            sanitized_func = self._sanitize_target_func(raw_func)
            if raw_func and not sanitized_func:
                self.log.warning(
                    "parse.garbled_target_func",
                    raw=raw_func[:80],
                )
            # Fix 102B: Safety unescape — some LLMs double-encode newlines in JSON
            # strings, leaving literal \n (two chars) instead of real newlines.
            # When C code is on one line, // comments kill everything after them
            # → "undefined reference to main" linker error.
            c_code = data.get("c_code", "")
            if c_code and "\n" not in c_code and "\\n" in c_code:
                c_code = c_code.replace("\\n", "\n").replace("\\t", "\t")
            # Fix 109: LLM may return null for string fields — coerce to empty string.
            # Fix 111: LLM may return seed_commands as newline-separated string
            raw_seeds = data.get("seed_commands") or []
            if isinstance(raw_seeds, str):
                raw_seeds = [s.strip() for s in raw_seeds.split("\n") if s.strip()]
            # Fix 122: Parse input_spec for deterministic seed synthesis
            parsed_input_spec = None
            raw_spec = data.get("input_spec")
            if raw_spec and isinstance(raw_spec, dict):
                try:
                    parsed_input_spec = InputSpec(**raw_spec)
                except (ValueError, TypeError, KeyError) as exc:
                    # Fix 126: log specific error instead of silently swallowing
                    self.log.warning("parse.input_spec_failed", error=str(exc)[:120])
                    pass  # graceful fallthrough — input_spec is optional
            return HarnessSpec(
                target_func=sanitized_func,
                input_format=data.get("input_format") or "",
                c_code=c_code,
                seed_commands=raw_seeds,
                compile_flags=data.get("compile_flags") or "",
                dictionary_entries=data.get("dictionary_entries") or [],
                input_spec=parsed_input_spec,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.log.warning("parse.harness_failed", error=str(e))
            return HarnessSpec(
                target_func="", input_format="", c_code="",
            )
    def _extract_json(self, text: str) -> dict | None:
        """Extract JSON from LLM response (delegates to json_extractor module)."""
        return extract_json(text)

class LLMClient:
    """
    Multi-provider LLM client using the OpenAI-compatible API.

    Supports Groq, Cerebras, Gemini, and any OpenAI-compatible endpoint.
    Auto-fallback: when a provider hits TPD/rate limit, tries the next in chain.
    All providers use the same `openai` SDK with different `base_url`.
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("neural.client")
        self.last_cost = 0.0
        self.call_history: list[LLMCallRecord] = []
        self._clients: dict[str, object] = {}
        # Track providers that have exhausted their daily token budget this session
        self._exhausted_providers: set[str] = set()
        self._providers = self._build_provider_chain()

        # Two-Brain: role-specific model configs
        self._role_clients: dict[str, object] = {}
        self._architect_config = config.llm.architect
        self._debugger_config = config.llm.debugger
        self._onboarder_config = config.llm.onboarder

        # Setup cache directory
        if config.llm.cache_enabled:
            self.cache_dir = Path(config.llm.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _build_provider_chain(self) -> list[dict]:
        """Build ordered list of available providers from config.

        Each entry: {name, base_url, api_key_env, model, json_mode}.
        Only includes providers whose API key env var is set.
        Falls back to legacy Groq-only config if providers list is empty.
        """
        import os as _os

        chain = []
        if self.config.llm.providers:
            for p in self.config.llm.providers:
                key = _os.environ.get(p.api_key_env, "")
                if key:
                    chain.append({
                        "name": p.name,
                        "base_url": p.base_url,
                        "api_key_env": p.api_key_env,
                        "model": p.model,
                        "json_mode": p.json_mode,
                        "reasoning_effort": getattr(p, "reasoning_effort", ""),
                    })
                else:
                    self.log.debug("provider.skip_no_key", name=p.name, env=p.api_key_env)

        # Legacy fallback: if no providers configured, use old Groq-only setup
        if not chain:
            groq_key = _os.environ.get("GROQ_API_KEY", "")
            if groq_key:
                chain.append({
                    "name": "groq",
                    "base_url": "https://api.groq.com/openai/v1",
                    "api_key_env": "GROQ_API_KEY",
                    "model": self.config.llm.model,
                    "json_mode": "json_object",
                })
                if self.config.llm.fallback_model:
                    chain.append({
                        "name": "groq-fallback",
                        "base_url": "https://api.groq.com/openai/v1",
                        "api_key_env": "GROQ_API_KEY",
                        "model": self.config.llm.fallback_model,
                        "json_mode": "json_object",
                    })

        self.log.info(
            "provider.chain",
            providers=[p["name"] for p in chain],
            count=len(chain),
        )
        return chain

    def _get_client(self, provider: dict) -> object:
        """Lazy-initialize an OpenAI client for a provider."""
        import os as _os

        name = provider["name"]
        if name not in self._clients:
            try:
                import httpx
                from openai import OpenAI
                self._clients[name] = OpenAI(
                    base_url=provider["base_url"],
                    api_key=_os.environ[provider["api_key_env"]],
                    # 60s timeout prevents hanging on NVIDIA/Cerebras 504s
                    http_client=httpx.Client(timeout=60.0),
                    max_retries=1,
                )
            except ImportError:
                self.log.error("openai SDK not installed — run: pip install openai")
                raise
        return self._clients[name]

    def complete(
        self,
        prompt: str,
        system: str = "",
        model_override: str | None = None,
        stage: str = "",
        target_func: str = "",
        temperature: float | None = None,
        role: ModelRole = ModelRole.DEFAULT,
    ) -> str:
        """
        Send a completion request, auto-falling back through provider chain.

        Args:
            prompt: User message content
            system: System prompt
            model_override: Use a different model (overrides provider's default)
            stage: Pipeline stage name (for logging)
            target_func: Target function name (for logging)
            temperature: Override config temperature (Fix D: variant generation)
            role: Model role for Two-Brain routing (ARCHITECT/DEBUGGER/DEFAULT)

        Returns:
            Model response text
        """
        last_error = None
        cache_key = None
        # Effective temperature: caller override > config default
        effective_temp = temperature if temperature is not None else self.config.llm.temperature

        # ── Two-Brain: try role-specific model first ──
        role_config = None
        if role == ModelRole.ARCHITECT and self._architect_config:
            role_config = self._architect_config
        elif role == ModelRole.DEBUGGER and self._debugger_config:
            role_config = self._debugger_config
        elif role == ModelRole.ONBOARDER and self._onboarder_config:
            role_config = self._onboarder_config

        if role_config:
            result = self._try_role_model(
                role_config, prompt, system, stage, target_func, effective_temp,
            )
            if result is not None:
                return result
            self.log.warning("role_model.fallback", role=role.value)
        # ── Fall through to existing provider chain ──

        for provider in self._providers:
            pname = provider["name"]

            # Skip exhausted providers
            if pname in self._exhausted_providers:
                continue

            model = model_override or provider["model"]

            # Check cache (keyed by model + prompt, shared across providers with same model)
            if self.config.llm.cache_enabled:
                cache_key = self._cache_key(prompt, system, model)
                cached = self._cache_get(cache_key)
                if cached:
                    self.log.debug("cache.hit", stage=stage, func=target_func)
                    self.last_cost = 0.0
                    self.call_history.append(LLMCallRecord(
                        model=model, cache_hit=True,
                        stage=stage, target_func=target_func,
                    ))
                    return cached

            # Make API call
            self.log.info(
                "api.call", provider=pname, model=model,
                stage=stage, func=target_func,
            )

            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            # Fix 147: Groq quirk — when response_format is "json_object",
            # the message text MUST contain the literal word "json" (case-
            # insensitive) somewhere, otherwise Groq returns
            # 400 "messages must contain the word 'json' in some form".
            # Other providers don't care, but a sentinel comment is harmless.
            if (
                provider["json_mode"] == "json_object"
                and pname == "groq"
                and not any(
                    "json" in (m.get("content") or "").lower() for m in messages
                )
            ):
                messages.append({
                    "role": "system",
                    "content": "Output strictly as a valid json object.",
                })

            # RPM retry loop: up to 4 attempts with sleep on throttle.
            # TPD exhaustion or other errors break out to the next provider.
            _try_next_provider = False
            # gpt-oss reasoning cap for chain calls — top-level reasoning_effort.
            _chain_extra = {}
            if provider.get("reasoning_effort"):
                _chain_extra["extra_body"] = {"reasoning_effort": provider["reasoning_effort"]}

            for _rpm_attempt in range(4):
                try:
                    client = self._get_client(provider)
                    response = client.chat.completions.create(
                        model=model,
                        max_tokens=self.config.llm.max_tokens,
                        temperature=effective_temp,
                        messages=messages,
                        response_format={"type": provider["json_mode"]},
                        **_chain_extra,
                    )

                    text = response.choices[0].message.content or ""
                    usage = response.usage
                    input_tokens = usage.prompt_tokens if usage else 0
                    output_tokens = usage.completion_tokens if usage else 0

                    record = LLMCallRecord(
                        model=model,
                        prompt_tokens=input_tokens,
                        completion_tokens=output_tokens,
                        cost_usd=0.0,
                        stage=stage,
                        target_func=target_func,
                    )
                    self.call_history.append(record)
                    self.log.info(
                        "api.complete",
                        provider=pname,
                        tokens_in=input_tokens,
                        tokens_out=output_tokens,
                        cost="$0.00 (free tier)",
                    )

                    # Cache response
                    if self.config.llm.cache_enabled and cache_key:
                        self._cache_set(cache_key, text)

                    return text

                except Exception as e:
                    import time as _time
                    err_str = str(e)
                    last_error = e

                    if "429" in err_str:
                        is_daily_limit = any(kw in err_str.lower() for kw in (
                            "tokens per day", "daily", "exceeded your", "quota",
                        ))
                        if is_daily_limit:
                            self.log.warning(
                                "provider.tpd_exhausted", name=pname, error=err_str[:120],
                            )
                            self._exhausted_providers.add(pname)
                            _try_next_provider = True
                            break

                        # RPM throttle — extract Retry-After header or default to 60s
                        retry_after = 60
                        try:
                            retry_after = int(
                                getattr(e, "response", None)
                                and e.response.headers.get("retry-after", 60)
                                or 60
                            )
                        except Exception:
                            pass
                        self.log.warning(
                            "provider.rpm_throttle",
                            name=pname, attempt=_rpm_attempt + 1,
                            sleep_seconds=retry_after,
                        )
                        _time.sleep(retry_after)
                        continue  # retry same provider after sleep

                    # Fix 73: Recover from json_validate_failed (400) errors.
                    if "400" in err_str and "json_validate_failed" in err_str:
                        recovered = self._recover_failed_json(e)
                        if recovered is not None:
                            self.log.warning(
                                "api.json_recovered",
                                provider=pname, model=model,
                                stage=stage, func=target_func,
                            )
                            if self.config.llm.cache_enabled and cache_key:
                                self._cache_set(cache_key, recovered)
                            return recovered
                        self.log.warning(
                            "provider.json_failed", name=pname, model=model,
                        )
                        _try_next_provider = True
                        break

                    # 413 payload too large — oracle context inflates prompts beyond
                    # small model context limits (e.g. groq-8b: 6K TPM).
                    # Strip <codebase_oracle> block and retry once.
                    if "413" in err_str and _rpm_attempt == 0:
                        import re as _re
                        stripped = _re.sub(
                            r"<codebase_oracle>.*?</codebase_oracle>\n?",
                            "",
                            messages[-1]["content"],
                            flags=_re.DOTALL,
                        )
                        if stripped != messages[-1]["content"]:
                            self.log.warning(
                                "provider.prompt_too_large",
                                name=pname, stripped_oracle=True,
                            )
                            messages[-1] = {"role": "user", "content": stripped}
                            continue  # retry same provider without oracle context

                    self.log.error("api.error", provider=pname, error=err_str)
                    _try_next_provider = True
                    break

            if _try_next_provider:
                continue  # outer provider loop

        # All providers failed
        self.log.error(
            "provider.all_failed",
            exhausted=list(self._exhausted_providers),
        )
        self.last_cost = 0.0
        if last_error:
            raise last_error
        raise RuntimeError("No LLM providers available (check API keys in env)")

    # ── Two-Brain: role-specific model support ──────────────

    def _get_role_client(self, role_config) -> object | None:
        """Lazy-initialize an OpenAI client for a role-specific model.

        Returns None if the API key is not set.
        Uses a 120s timeout (longer than the 60s provider chain timeout)
        since 1M-context calls are slower.
        """
        import os as _os

        name = role_config.name
        if name in self._role_clients:
            return self._role_clients[name]

        api_key = _os.environ.get(role_config.api_key_env, "")
        if not api_key:
            self.log.debug("role_model.no_key", name=name, env=role_config.api_key_env)
            return None

        try:
            import httpx
            from openai import OpenAI
            # Fix 127: max_retries=0 — no automatic SDK retry on 504/502.
            # Role models have a dedicated fallback (provider chain), so retrying
            # the same overloaded server wastes 10+ min per retry for nothing.
            client = OpenAI(
                base_url=role_config.base_url,
                api_key=api_key,
                http_client=httpx.Client(timeout=float(role_config.timeout)),
                max_retries=0,
            )
            self._role_clients[name] = client
            return client
        except ImportError:
            self.log.error("openai SDK not installed — run: pip install openai")
            return None

    def _try_role_model(
        self,
        role_config,
        prompt: str,
        system: str,
        stage: str,
        target_func: str,
        temperature: float,
    ) -> str | None:
        """Try role-specific model. Returns None on any failure → triggers fallback."""
        # Fix 127: circuit breaker — if this role model already failed with a server
        # error (504/502/timeout), skip it for the rest of the session. Avoids wasting
        # 10+ minutes per variant on a model that's clearly overloaded/down.
        if not hasattr(self, "_role_circuit_breaker"):
            self._role_circuit_breaker: set[str] = set()
        if role_config.name in self._role_circuit_breaker:
            self.log.info(
                "role_model.circuit_breaker_skip",
                name=role_config.name,
                model=role_config.model,
                stage=stage,
                hint="skipped: previous server error, using fallback chain",
            )
            return None

        client = self._get_role_client(role_config)
        if client is None:
            return None

        model = role_config.model
        name = role_config.name

        # Check cache first (shared key space with provider chain)
        cache_key = None
        if self.config.llm.cache_enabled:
            cache_key = self._cache_key(prompt, system, model)
            cached = self._cache_get(cache_key)
            if cached:
                self.log.debug("cache.hit", stage=stage, func=target_func, role=name)
                self.last_cost = 0.0
                self.call_history.append(LLMCallRecord(
                    model=model, cache_hit=True,
                    stage=stage, target_func=target_func,
                ))
                return cached

        self.log.info(
            "api.call", provider=name, model=model,
            stage=stage, func=target_func, role=name,
        )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Build extra_body for thinking mode.
        # Fix 147: prefer the explicit `chat_template_kwargs` from yaml over
        # auto-construction. Different vendors use different keys:
        #   - Mistral/Qwen:        {"enable_thinking": True}
        #   - DeepSeek/Kimi (Moonshot): {"thinking": True, "reasoning_effort": "high"}
        # The yaml-supplied dict wins as-is.
        extra_body: dict = {}
        explicit_template_kwargs = getattr(
            role_config, "chat_template_kwargs", None,
        ) or {}
        if explicit_template_kwargs:
            extra_body["chat_template_kwargs"] = dict(explicit_template_kwargs)
        elif role_config.enable_thinking:
            extra_body["chat_template_kwargs"] = {"enable_thinking": True}
            if role_config.reasoning_budget > 0:
                extra_body["chat_template_kwargs"]["reasoning_budget"] = (
                    role_config.reasoning_budget
                )
        # gpt-oss reasoning cap — top-level extra_body.reasoning_effort (NOT
        # nested in chat_template_kwargs). "low" stops the planner/large-context
        # calls from hanging until timeout.
        if getattr(role_config, "reasoning_effort", ""):
            extra_body["reasoning_effort"] = role_config.reasoning_effort

        # Use role-specific temperature and max_tokens
        effective_temp = role_config.temperature if temperature == self.config.llm.temperature else temperature
        max_tokens = role_config.max_tokens

        try:
            kwargs: dict = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": effective_temp,
                "messages": messages,
            }
            if extra_body:
                kwargs["extra_body"] = extra_body

            # Thinking models CANNOT use JSON mode — it blocks <think> token
            # generation, causing the server to hang until timeout. Detect
            # thinking via either the legacy `enable_thinking` flag or the
            # explicit `chat_template_kwargs.thinking` (DeepSeek / Kimi
            # convention).
            template_kwargs = extra_body.get("chat_template_kwargs", {}) or {}
            thinking_active = (
                role_config.enable_thinking
                or bool(template_kwargs.get("thinking"))
                or bool(template_kwargs.get("enable_thinking"))
            )
            if thinking_active:
                response = client.chat.completions.create(**kwargs)
            else:
                try:
                    kwargs["response_format"] = {"type": "json_object"}
                    response = client.chat.completions.create(**kwargs)
                except Exception as json_err:
                    # Fix 127: don't retry without JSON mode on server errors (504/502).
                    # The server is overloaded — removing response_format won't help.
                    json_err_str = str(json_err)
                    if any(c in json_err_str for c in ("504", "502", "503")):
                        raise  # let outer except handle it + trip circuit breaker
                    kwargs.pop("response_format", None)
                    response = client.chat.completions.create(**kwargs)

            text = response.choices[0].message.content or ""

            # Strip any thinking tags that leak into content
            text = self._strip_thinking_tags(text)

            usage = response.usage
            input_tokens = usage.prompt_tokens if usage else 0
            output_tokens = usage.completion_tokens if usage else 0

            record = LLMCallRecord(
                model=model,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                cost_usd=0.0,
                stage=stage,
                target_func=target_func,
            )
            self.call_history.append(record)
            self.log.info(
                "api.complete",
                provider=name,
                tokens_in=input_tokens,
                tokens_out=output_tokens,
                cost="$0.00 (free tier)",
                role=name,
            )

            # Cache response
            if self.config.llm.cache_enabled and cache_key:
                self._cache_set(cache_key, text)

            return text

        except Exception as e:
            err_str = str(e)[:200]
            self.log.warning(
                "role_model.error", name=name, model=model,
                stage=stage, error=err_str,
            )
            # Fix 127: trip circuit breaker on server errors (504, 502, timeout).
            # These indicate server overload — retrying for subsequent variants is futile.
            if any(code in err_str for code in ("504", "502", "503", "Timeout", "timeout", "timed out")):
                self._role_circuit_breaker.add(name)
                self.log.warning(
                    "role_model.circuit_breaker_tripped",
                    name=name,
                    hint="server error detected, skipping this model for remaining calls",
                )
            return None

    @staticmethod
    def _strip_thinking_tags(text: str) -> str:
        """Remove <think>...</think> or similar thinking tag patterns from content.

        Safety net — reasoning should be in a separate field, but some providers
        may leak it into the content field.
        """
        import re as _re
        # <think>...</think> pattern
        text = _re.sub(r"<think>.*?</think>\s*", "", text, flags=_re.DOTALL)
        # <|channel>thought\n...<channel|> pattern
        text = _re.sub(
            r"<\|channel>thought\n.*?<channel\|>\s*", "", text, flags=_re.DOTALL
        )
        return text.strip()

    @staticmethod
    def _recover_failed_json(exc: Exception) -> str | None:
        """Extract usable JSON from a json_validate_failed error.

        When small models (8b) produce almost-valid JSON (e.g. markdown fences
        inside string values), the provider rejects it server-side but includes
        the raw generation in ``exc.body['error']['failed_generation']``.
        We extract that string, isolate the ``c_code`` value (which contains
        unescaped quotes from C string literals like ``"mem"``), and rebuild
        valid JSON.  Works for any C/C++ library — no target-specific logic.
        """
        import re as _re

        # Access the structured error body (Groq/OpenAI SDK parses it for us)
        body = getattr(exc, "body", None)
        if not isinstance(body, dict):
            return None

        error_obj = body.get("error", {})
        if error_obj.get("code") != "json_validate_failed":
            return None

        raw = error_obj.get("failed_generation", "")
        if not raw:
            return None

        # The c_code value is wrapped in ```c\n...\n``` markdown fences.
        # Inside it, C string literals like "mem" have unescaped quotes
        # which break JSON parsing.  Strategy: extract c_code separately,
        # replace with placeholder, parse the rest, then re-insert.
        c_code = None
        code_match = _re.search(
            r'"c_code"\s*:\s*"```c?\\n(.*?)\\n```(?:\\n```)?"',
            raw,
            _re.DOTALL,
        )
        if code_match:
            c_code = code_match.group(1)
            # Unescape \\n → real newlines, \\t → real tabs in the C code
            c_code = c_code.replace("\\n", "\n").replace("\\t", "\t")
            # Replace the problematic c_code with a safe placeholder
            raw = (
                raw[: code_match.start()]
                + '"c_code": "__RECOVERED__"'
                + raw[code_match.end() :]
            )

        # Also strip any remaining markdown fences outside c_code
        raw = raw.replace("```", "")

        # Try parsing with our robust extractor
        parsed = extract_json(raw)
        if parsed is not None:
            if c_code is not None:
                parsed["c_code"] = c_code
            return json.dumps(parsed)

        return None

    def _cache_key(self, prompt: str, system: str, model: str) -> str:
        """Generate a deterministic cache key."""
        content = f"{model}:{system}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _cache_get(self, key: str) -> str | None:
        """Retrieve from file-based cache (None on any read error)."""
        cache_file = self.cache_dir / f"{key}.json"
        try:
            if cache_file.exists():
                return cache_file.read_text()
        except OSError as exc:
            self.log.warning("cache.read_failed", key=key, error=str(exc))
        return None

    def _cache_set(self, key: str, value: str) -> None:
        """Store in file-based cache atomically.

        Write to a temp file then os.replace() so an interrupt mid-write can't
        leave a truncated cache file that a later run reads back as a (corrupt)
        LLM response.
        """
        import os as _os
        cache_file = self.cache_dir / f"{key}.json"
        tmp = cache_file.with_suffix(f".json.tmp.{_os.getpid()}")
        try:
            tmp.write_text(value)
            _os.replace(tmp, cache_file)
        except OSError as exc:
            self.log.warning("cache.write_failed", key=key, error=str(exc))
            try:
                tmp.unlink()
            except OSError:
                pass


class PromptBuilder:
    """Builds structured prompts for each LLM task."""

    ANALYSIS_SYSTEM = """You are a senior security researcher analyzing C/C++ code for
unreachable code paths in fuzzing. You specialize in identifying:
- NULL pointer dereferences (CWE-476)
- Heap buffer overflows (CWE-122)
- Use-after-free (CWE-416)
- Missing bounds checks before pointer arithmetic

CRITICAL — you must also determine whether a BLOCKER prevents a fuzzer from reaching
this function. A blocker is one of:
  1. Compile-time macro guard: `#ifdef HAVE_ZSTD`, `#if defined(__STDC_ISO_10646__)`, etc.
  2. Magic-byte / format requirement: function only reachable if input starts with specific bytes (e.g. MSCF for CAB, PK for ZIP)
  3. Runtime environment check: only triggered in specific OS/platform conditions

If a blocker exists, has_blocker=true and a patch must bypass it before fuzzing.
If the function is already reachable by a fuzzer (just not yet triggered), has_blocker=false — no patch is needed.

BLOCKER CLASSIFICATION — if has_blocker=true, you MUST also classify the blocker:
  - "compile_time": The blocker is a preprocessor directive (#ifdef, #if defined, #ifndef).
    The code is literally not compiled. Commenting it out WILL expose real bugs.
  - "runtime": The blocker is a runtime check (magic bytes, format validation, length check,
    strcmp, memcmp). The code IS compiled but not reached with random input. Commenting out
    the check creates FALSE POSITIVE crashes. For these, the fuzzer needs proper seeds/dictionary.

Analyze the provided source code and call chain. Output ONLY valid JSON with:
{
  "vulnerability_type": "description of the bug pattern",
  "cwe": "CWE-XXX",
  "root_cause": "detailed explanation of why this is vulnerable",
  "attack_vector": "how to trigger the vulnerability",
  "confidence": 0.0-1.0,
  "missing_checks": [{"file": "...", "line": N, "description": "..."}],
  "has_blocker": true or false,
  "blocker_class": "compile_time" or "runtime",
  "blocker_description": "what blocks the fuzzer from reaching this code, or 'none' if has_blocker=false"
}"""

    PATCH_SYSTEM = """You are a security researcher generating minimal patches to BYPASS BLOCKERS
that prevent a fuzzer from reaching vulnerable code. Your patches must:

PURPOSE: Bypass compile-time guards, magic-byte checks, and format requirements so that
AFL++ can reach and exercise the target function. You are NOT fixing security vulnerabilities —
you are removing artificial barriers so the fuzzer can trigger them.

1. MINIMAL — prefer #if 0 && over deletion; change as little as possible
2. REVERSIBLE — easy to undo
3. BYPASS BLOCKERS ONLY — do NOT add null guards, bounds checks, or error handling;
   these would PREVENT the fuzzer from triggering the vulnerability

FORBIDDEN (these would hide the bug from the fuzzer):
- Adding NULL pointer checks (if (ptr == NULL) return)
- Adding bounds checks (if (len > size) return)
- Adding early returns that skip the vulnerable code
- Changing the algorithm to be safer

ALLOWED (these expose the vulnerable code to the fuzzer):
- Replacing `#if defined(SOME_MACRO)` with `#if 0 && defined(SOME_MACRO)` to bypass compile guard
- Replacing magic byte check (MSCF, PNG header) with `1` to accept any input
- Replacing `if (format != VALID) return ERROR` with a no-op to skip format requirement

CRITICAL CONSTRAINTS:
- Do NOT patch the function signature or declaration line
- Only patch code INSIDE the function body — executable statements after the opening brace
- The "original" field must match a complete statement or expression in the source

COMPILE SAFETY — THE BUILD USES -Werror (every warning is a fatal compile error):

The prompt will give you a <variables_at_risk> section listing local variables near the patch.
If any of those variables are ONLY used in the code you are removing/disabling, they become
"unused" after your patch → -Wunused-variable → compile error → build fails.

MISTAKE 1 — removing/replacing a condition that uses local variables:
  Original: `if (magic_check(sig, sig_len)) return ERROR;`  (uses sig, sig_len)
  BAD replacement: `if (1) {` or delete the line  → sig, sig_len now unused → error
  BAD replacement: `if (0 && magic_check(sig, sig_len))` → same problem + -Wunused-value
  GOOD replacement:
    `#if 0\n\tif (magic_check(sig, sig_len)) return ERROR;\n#endif`
    (wraps the ENTIRE statement as dead code — all variables still count as "referenced")

MISTAKE 2 — #if 0 && ... (mixing preprocessor with C):
  BAD: `#if 0 && (sig_len > 4) {`  ← preprocessor directive containing C code → syntax error
  GOOD: `#if 0\n\tif (sig_len > 4) { return ERROR; }\n#endif`

GOLDEN RULE: Always use `#if 0 ... #endif` to disable entire statements.
  - Wrap the FULL original statement (condition + body), not just the condition.
  - This is ALWAYS compile-safe — dead code never causes unused-variable warnings.

OTHER RULES:
- NEVER disable memory allocation NULL checks — harness will crash before reaching target
- If bypassing a check leaves a variable uninitialized, initialize it explicitly first

Output ONLY valid JSON with:
{
  "file_path": "relative/path/to/file.c",
  "line": 1179,
  "original": "the original code to replace (must be inside function body, not the signature)",
  "replacement": "the new code that bypasses the blocker",
  "justification": "which blocker this bypasses and why",
  "risk_level": "safe|caution|dangerous",
  "patch_type": "blocker_bypass"
}"""

    HARNESS_SYSTEM = """You are a fuzzing engineer generating AFL++ harnesses for C libraries.

CRITICAL RULES:
1. Use the library's PUBLIC API — never call internal/static functions directly
2. NEVER copy-paste struct definitions — use the library's public headers via #include
3. Use AFL++ persistent mode (__AFL_LOOP) and deferred forkserver (__AFL_FUZZ_INIT)
4. Read input from __AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN
5. ALWAYS include: stdio.h, stdlib.h, string.h, stdint.h, unistd.h
6. STATELESS ITERATIONS: close and free ALL handles every loop body — never reuse across iterations
7. SPLIT FUZZ INPUT: use distinct buf offsets for independent parameters, not buf[0..len] for everything
8. MINIMAL SCOPE: enable only the specific format parser needed, NOT archive_read_support_format_all
9. Study the <call_chain> to understand how to reach the target function via the public API
10. The harness must feed the fuzz input to the library in a way that exercises the target function

## FuzzedDataProvider
When the target takes multiple typed parameters, include `#include "fuzz_data_provider.h"` and use
FuzzDataProvider to slice the buffer into independent typed parameters:

```c
FuzzDataProvider fdp;
fdp_init(&fdp, buf, (size_t)len);
uint32_t flags  = fdp_consume_u32(&fdp);   // 4 bytes → flags param
uint8_t  mode   = fdp_consume_u8(&fdp);    // 1 byte  → mode param
size_t   rem    = fdp_remaining(&fdp);     // rest    → raw format data
const uint8_t *data = fdp_consume_bytes(&fdp, rem);
// pass data/rem to library parser
```
Use fdp for TYPED PARAMS (flags, enums, sizes). Pass the remainder as raw format data.
CMPLOG HINT: AFL++ RedQueen records every comparison operand. Use typed integers (fdp_consume_u32)
for enum/flag params — CMPLOG auto-discovers magic values. Do NOT mask byte patterns.

## Statelessness Checklist (inside every __AFL_LOOP body):
  ✓ Fresh handle created INSIDE the loop (NOT reused from outer scope)
  ✓ Handle set to NULL after free
  ✓ No static mutable state accumulated across iterations
  ✓ __AFL_FUZZ_TESTCASE_BUF is read-only — never write to it

## Heavy One-Time Init (LLVMFuzzerInitialize pattern):
For global setup (codec registries, logging init) that must run once:
```c
__attribute__((constructor))
static void harness_init(void) {
    /* one-time global initialization — runs before main() */
}
```

Here is a GENERIC AFL++ PERSISTENT MODE TEMPLATE — adapt it for the target library:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
/* Add library-specific headers here (see the prompt for required includes) */

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8) continue;

        /* 1. Initialize: create library handle/context */
        /* 2. Feed data: pass buf/len to the library's input function */
        /* 3. Process: drive the library through the code path that reaches the target */
        /* 4. Cleanup: free all resources */
    }

    return 0;
}
```

Follow the <call_chain> to determine:
- Which public API function to call to reach the target function
- How to feed the fuzz input (memory buffer, file descriptor, callbacks, etc.)
- What setup/configuration is needed before feeding data

Output ONLY valid JSON with:
{
  "target_func": "function_name",
  "input_format": "format description (e.g., TIFF image, CAB archive, MP4 container)",
  "c_code": "complete C harness source code",
  "seed_commands": ["shell commands to generate seed files for this format"],
  "compile_flags": "-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined",
  "input_spec": {
    "params": [
      {"name": "param_name", "offset": 0, "size": 1, "type": "uint8", "transform": "mod N", "range": [0, 11]}
    ],
    "data_offset": 1,
    "data_type": "raw",
    "min_size": 2,
    "max_size": 262144,
    "interesting_sizes": [1024, 4096, 65536]
  }
}

input_spec rules:
- List EVERY buf[] byte read as a param (name, offset, size, type).
- transform: describe the arithmetic (e.g., "mod 12", "mod 15 + 10", "" for identity).
- range: [min, max] of the POST-transform value the library sees.
- data_offset: first byte index where the variable-length payload starts.
- data_type: "raw" (binary), "compressed" (e.g., brotli/zlib stream), "text" (XML/JSON/CSV).
- For opaque decoders (input is compressed data), use params=[], data_type="compressed".
- enum_values: if the param selects from a known set, list them."""

    REFINEMENT_SYSTEM = """You are a security researcher debugging a failed fuzzing campaign.
The previous patch and harness did not achieve coverage expansion.
Analyze the failure data and propose a REVISED strategy.

Common failure reasons:
- Wrong input format (e.g., needed PAX tar, used USTAR)
- Patch didn't bypass the actual blocker
- Harness didn't reach the target code path
- Build configuration issue

Output ONLY valid JSON with the same schema as the original analysis,
but with a revised strategy based on the failure data."""

    # ── Strategy A prompts (harness-driven, no patches) ─────────

    HARNESS_ANALYSIS_SYSTEM = """You are a senior security researcher analyzing C/C++ code to determine
how to REACH a target function through the library's PUBLIC API for fuzzing.

You are NOT looking for blockers to bypass. Instead, focus on:
1. What is the PUBLIC API entry point that leads to this function?
2. What input structure/format does the library expect?
3. What initialization sequence is needed (create handle, set options, etc.)?
4. What call chain connects the public API to the target function?
5. Are there any format-specific requirements (magic bytes, headers)?

Your goal is to help build a SMART HARNESS that legitimately exercises
the target function through normal library usage — no patches, no bypasses.

Analyze the provided source code and call chain. Output ONLY valid JSON with:
{
  "vulnerability_type": "description of the bug pattern",
  "cwe": "CWE-XXX",
  "root_cause": "detailed explanation of why this is vulnerable",
  "attack_vector": "how to trigger the vulnerability through the public API",
  "confidence": 0.0-1.0,
  "missing_checks": [{"file": "...", "line": N, "description": "..."}],
  "has_blocker": false,
  "blocker_class": "runtime",
  "blocker_description": "none — Strategy A uses smart harnesses instead of patches"
}"""

    HARNESS_STRATEGY_A_SYSTEM = """You are a fuzzing engineer generating SMART AFL++ harnesses that
reach deep into C library internals through the PUBLIC API — no source patches needed.

Your harness must LEGITIMATELY exercise the target function by:
1. Using the correct public API initialization sequence
2. Providing well-structured input that passes format validation
3. Driving the library through the exact code path to the target
4. Including magic bytes / headers so the parser enters the right branch

KEY PRINCIPLES:
- The library source is UNMODIFIED — all validation checks are active
- Your harness must produce input that PASSES validation, not bypass it
- Study the <call_chain> to understand the exact path from API to target
- Include dictionary_entries with magic bytes and key constants
- Use ONLY functions declared in <api_declarations> — do NOT invent API functions
- SPLIT FUZZ INPUT: use distinct byte offsets for independent parameters
  (e.g., first 4 bytes = size field, bytes 4–256 = header, rest = payload)
  Never alias the same buf[0..len] for multiple independent library fields
- STATELESS ITERATIONS: each __AFL_LOOP body must be 100% independent
  Close/free ALL handles, reset ALL state — never reuse objects across iterations
- MINIMAL SCOPE: ONE direct API path to the target function per harness

## FuzzedDataProvider (use when target has typed parameters)
Include `#include "fuzz_data_provider.h"` and use typed slices:
```c
FuzzDataProvider fdp;
fdp_init(&fdp, buf, (size_t)len);
uint32_t flags = fdp_consume_u32(&fdp);   /* 4 bytes → flags param */
uint8_t  mode  = fdp_consume_u8(&fdp);   /* 1 byte  → mode enum */
size_t   rem   = fdp_remaining(&fdp);    /* rest    → raw format data */
const uint8_t *payload = fdp_consume_bytes(&fdp, rem);
```

## CMPLOG-Awareness (AFL++ RedQueen)
AFL++ records every comparison operand (RedQueen). Benefits:
- Use fdp_consume_u32/u64 for enum/flag params → CMPLOG auto-discovers magic values
- Do NOT mask byte patterns (e.g., byte & 0x0F) — CMPLOG needs the full value
- Use typed integers for protocol fields: length, offset, version, type codes

## Precondition Pruning (MANDATORY — prune invalid inputs early):
Add these guards at the TOP of each __AFL_LOOP body, BEFORE any library call:
```c
while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    /* 1. Prune undersized inputs immediately */
    if (len < MIN_SIZE) continue;
    /* 2. Cap oversized inputs to prevent ASAN OOM false positives */
    if (len > 512 * 1024) continue;
    /* 3. Format magic check (if format has fixed header bytes) */
    /* if (memcmp(buf, MAGIC, sizeof(MAGIC)) != 0) continue; */
    /* ... library calls ... */
}
```
Set MIN_SIZE to the minimum valid input for the format (e.g., 12 for a header).

## Statelessness Checklist (inside every __AFL_LOOP body):
  ✓ Fresh handle/context created INSIDE the loop (NOT reused from outer scope)
  ✓ Handle set to NULL after free
  ✓ No static mutable state accumulated across iterations
  ✓ __AFL_FUZZ_TESTCASE_BUF is read-only — never write to it

## Heavy One-Time Init (LLVMFuzzerInitialize pattern):
For global setup (codec registries, logging suppression) that must run once:
```c
__attribute__((constructor))
static void harness_global_init(void) {
    /* suppress library error output to avoid terminal spam */
}
```

## STATELESS CLEANUP PATTERN:
```c
while (__AFL_LOOP(10000)) {
    /* Always create a fresh context/handle — never reuse across iterations */
    void *ctx = library_create_context();
    /* ... feed fuzz data and process ... */
    library_destroy_context(ctx);
    ctx = NULL;                /* prevent accidental reuse */
}
```

CRITICAL RULES:
1. Use the library's PUBLIC API — never call internal/static functions directly
2. NEVER copy-paste struct definitions — use the library's public headers via #include
3. Use AFL++ persistent mode (__AFL_LOOP) and deferred forkserver (__AFL_FUZZ_INIT)
4. Read input from __AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN
5. ALWAYS include: stdio.h, stdlib.h, string.h, stdint.h, unistd.h
6. Clean up ALL resources between iterations — close handles, free memory, zero pointers
7. Consider prepending magic bytes/headers before the fuzz input to help pass validation
8. Enforce a format-appropriate minimum input size (not just generic 8 bytes)
9. The TARGET FUNCTION must appear in your c_code as a direct call. If the target is
   "xmlParseMemory", your code MUST contain "xmlParseMemory(" somewhere. Do NOT replace
   it with a generic wrapper — the whole point is to exercise THAT specific function.
10. AFL++ loop syntax: MUST be `while (__AFL_LOOP(10000)) {` — NEVER `__AFL_LOOP(10000) {`
11. NEVER use pipe() + write() for fd-based APIs (xmlCtxtReadFd, etc.) in a single-threaded
    harness. The write() blocks when input > 64KB (Linux pipe buffer limit) and the reader
    hasn't started → deadlock. Instead: write to a tmpfile(), lseek(fd, 0, SEEK_SET), then
    pass the fd. Or use the memory-based API variant (e.g. xmlCtxtReadMemory instead of
    xmlCtxtReadFd).
12. (Fix 118) FUZZ-DERIVED PARAMETERS: When the library has a mode/quality/level/format
    parameter that controls which code path executes, ALWAYS derive it from the fuzz input
    (e.g. `int quality = buf[0] % MAX_QUALITY;`). NEVER hardcode a single value. This
    maximizes path diversity — a fixed quality=6 only covers one encoder path, while
    `buf[0]%12` covers ALL paths in a single harness.
13. OUTPUT PURE C (C99) ONLY. No C++ syntax: no `ClassName obj(args)` constructors,
    no `new`/`delete`, no `std::`, no `namespace::`, no templates, no `auto`.
    If you need to initialize a struct, use C99 designated initializers or memset.

SPLIT INPUT PATTERN (when target takes multiple independent parameters):
```c
while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 32) continue;
    /* Slice fuzz bytes into independent regions */
    uint32_t size_param = *(uint32_t *)buf;         /* bytes 0-3: size field */
    const uint8_t *header_data = buf + 4;           /* bytes 4-20: format header */
    const uint8_t *payload     = buf + 20;          /* bytes 20+: actual content */
    int payload_len = len - 20;
    /* Use each slice independently */
}
```

Output ONLY valid JSON with:
{
  "target_func": "function_name",
  "input_format": "format description",
  "c_code": "complete C harness source code",
  "seed_commands": ["shell commands to generate seed files"],
  "compile_flags": "-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined",
  "dictionary_entries": ["magic bytes", "key strings for this format"],
  "input_spec": {
    "params": [
      {"name": "param_name", "offset": 0, "size": 1, "type": "uint8", "transform": "mod N", "range": [0, 11]}
    ],
    "data_offset": 1,
    "data_type": "raw",
    "min_size": 2,
    "max_size": 262144,
    "interesting_sizes": [1024, 4096, 65536]
  }
}

input_spec rules:
- List EVERY buf[] byte read as a param (name, offset, size, type).
- transform: describe the arithmetic (e.g., "mod 12", "mod 15 + 10", "" for identity).
- range: [min, max] of the POST-transform value the library sees.
- data_offset: first byte index where the variable-length payload starts.
- data_type: "raw" (binary), "compressed" (e.g., brotli/zlib stream), "text" (XML/JSON/CSV).
- For opaque decoders (input is compressed data), use params=[], data_type="compressed".
- enum_values: if the param selects from a known set, list them."""

    HARNESS_PLANNER_SYSTEM = """You are an API expert analyzing a C library function to produce a harness RECIPE.
Do NOT write code. Produce a short structured plan that a harness generator will follow.

Given the function name, source snippet, and any oracle context, determine:
1. PREREQUISITES: What library objects/contexts must be created before calling this function?
   (e.g., "need xmlSchemaPtr from xmlSchemaParse() which needs xmlSchemaParserCtxtPtr")
2. INPUT STRATEGY: What should the fuzz input represent?
   - "fuzz_input_is_primary_data" = the raw fuzz bytes ARE the main data to process
   - "fuzz_input_is_secondary" = fuzz bytes are the document, but a hardcoded config/schema is needed too
3. API SEQUENCE: Ordered list of API calls from init to cleanup
   (e.g., "xmlSchemaNewMemParserCtxt(hardcoded_xsd) → xmlSchemaParse → xmlSchemaNewValidCtxt(schema) → xmlReadMemory(fuzz_buf) → xmlSchemaValidateDoc(ctxt, doc) → free in reverse")
4. CLEANUP ORDER: Reverse-order free/destroy calls
5. INDIRECT REACH (Fix 114): If the target function is INTERNAL (uses internal types not in
   public headers, is static, or requires structs not available to harness code), specify:
   - Which PUBLIC API function to call instead
   - Which PARAMETERS to set to force execution through the target function
   - Example: "Call BrotliEncoderCompressStream with BROTLI_PARAM_QUALITY=1 to reach BrotliCompressFragmentTwoPass"
   Set "indirect_reach": true in output when this applies.

For SIMPLE functions that just take a buffer (e.g., xmlReadMemory, xmlParseMemory), return empty hint.

Output ONLY valid JSON:
{
  "harness_hint": "multiline string with the recipe, or empty string for simple functions",
  "indirect_reach": false
}"""

    HARNESS_REPAIR_SYSTEM = """You are fixing compile errors in an AFL++ fuzzing harness for a C library.

TASK: Fix ALL compile errors and return the complete corrected harness source.

REQUIREMENTS (non-negotiable):
1. AFL++ persistent mode MUST be present: __AFL_FUZZ_INIT(), __AFL_LOOP(10000), __AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN
2. Use the library's PUBLIC API only — never call static/internal functions directly
   EXCEPTION: If the harness has <internal_declarations> or #includes internal headers,
   it is a DIRECT INTERNAL harness (Fix 123) — calling internal functions IS correct.
   For direct internal harnesses: if <caller_context> is provided, you MUST match
   the buffer allocation formulas and parameter initialisation from the caller (Fix 128).
3. Include ALL required headers: stdio.h, stdlib.h, string.h, stdint.h, unistd.h
4. Clean up ALL resources in each loop iteration (no memory leaks)
5. For library-specific types — use the exact type from the library headers, check <oracle_context> if available

COMMON FIXES:
- Unknown type: check the <oracle_context> for the correct #include header — do NOT guess headers from other libraries
- Unused variable: add (void)varname; after its declaration
- Implicit function declaration: ensure the correct header is included
- Missing return: add return 0; at end of main()
- Wrong function name: check the compiler error for the exact symbol that failed
- __AFL_LOOP syntax: MUST be `while (__AFL_LOOP(10000)) {` — NEVER bare `__AFL_LOOP(10000) {`
- Target function not called: the harness MUST call the target function directly

Output ONLY valid JSON:
{
  "c_code": "complete fixed C harness source code"
}"""

    HARNESS_REFINEMENT_SYSTEM = """You are a fuzzing engineer debugging a harness that failed to reach
the target function. The library source is UNMODIFIED (no patches) — you must improve
the HARNESS to reach deeper into the code.

You will receive a <diagnostics> block with structured execution measurements. Use them:
- compiled=false → harness has build errors; check compile_error_type
- compiled=true, function_reached=false, likely_early_exit=true
  (corpus_paths<=1, map_density<1%) → harness exits BEFORE reaching the library:
  wrong format magic, missing init, input too short, or harness-level logic error
- compiled=true, function_reached=false, likely_early_exit=false
  (some paths explored) → harness enters the library but takes wrong code path
- function_reached=true, function_coverage_pct<20% → function reached but exercises
  only the fast-exit paths; need better input structure to hit deeper branches

Common fixes:
1. WRONG FORMAT: parser expects specific magic bytes → prepend format header bytes
2. INSUFFICIENT INIT: missing setup calls before feeding data
3. WRONG API PATH: using the wrong API function for the target's layer
   → study the call chain — is the target in parsing, processing, or output?
   → use the API call that exercises the correct layer
4. TOO SHORT INPUT: raise minimum length; prepend valid header structure
5. MISSING LAYER: target is deep in the processing pipeline but harness only sets up parsing
   → add the intermediate setup calls needed to reach the target's layer
6. STATEFUL LEAK: global state from previous iteration bleeds in
   → ensure ALL handles are closed/freed and set to NULL each iteration
7. MONOLITHIC HARNESS: enabling all features dilutes coverage of the specific target
   → use only the specific API path that leads to the target function
8. TYPED PARAMS: if target takes multiple parameters, use FuzzedDataProvider
   → #include "fuzz_data_provider.h" and slice buf into typed fields
   → this gives AFL++ CMPLOG (RedQueen) independent control over each param
9. SKIPPING DATA PROCESSING: calling a "skip" or "close" variant instead of
   actually reading/processing data → bypasses the code where bugs live
   → ALWAYS use the read/process API, not skip/discard
10. NO INPUT SIZE CAP → ASAN OOM false positives
    → Add: if (len > 512 * 1024) continue; after the minimum size check

If a <line_coverage> block is present, study the execution counts carefully:
- Numbers (e.g. "12:") = executed that many times
- "#####" = NEVER executed across any corpus input
- Find the FIRST ##### line after executed lines — that's where the code path diverges.
- The check/branch just BEFORE the ##### block is what rejects all inputs.
- Fix the input structure or harness setup to pass that specific check.
This is your most precise signal — use it before guessing.

Focus on WHY the harness didn't reach the target and HOW to fix the call sequence.

Output ONLY valid JSON with the same schema as the original analysis,
but with a revised strategy based on the failure data."""

    CVE_ANALYSIS_SYSTEM = """You are a vulnerability researcher analyzing an AFL++ crash found in a \
C/C++ library. Your task is to determine whether this crash matches a known CVE and produce a \
structured vulnerability assessment.

You will receive:
- Library name and version info
- CWE classification from ASAN
- ASAN sanitizer output (crash type, location)
- Stack trace (GDB backtrace)
- Source code context around the crash location

Your analysis should:
1. Search your knowledge for known CVEs matching this crash signature (library + CWE + function + \
crash pattern). Consider the crash location, root cause, and affected code path.
2. If you find a match with >=80% confidence, set is_known_cve=true and provide the CVE ID.
3. If no confident match, set is_known_cve=false — this may be a novel vulnerability.
4. Estimate CVSS v3.1 base score (0-10) based on the vulnerability class and exploitability.
5. Analyze the root cause: why does this code path lead to a crash?
6. Suggest a mitigation (e.g., bounds check, NULL guard, size validation).
7. List similar CVEs in the same library or same vulnerability class.

IMPORTANT: Only set is_known_cve=true if you are >=80% confident. False positives waste time.
When in doubt, mark as potentially novel — a new CVE is more valuable than a misidentified known one.

Output ONLY valid JSON:
{
  "is_known_cve": true/false,
  "cve_id": "CVE-YYYY-NNNNN" or "",
  "cve_confidence": 0.0-1.0,
  "rationale": "Why this matches (or doesn't match) a known CVE",
  "affected_versions": "Version range affected (e.g., '<3.7.0')",
  "cvss_estimate": 0.0-10.0,
  "root_cause_analysis": "Detailed explanation of the bug root cause",
  "suggested_mitigation": "How to fix this vulnerability",
  "similar_cves": ["CVE-YYYY-NNNNN", ...]
}"""

    ONBOARD_SYSTEM = """You are a senior fuzzing engineer onboarding a new C library to AFL++. \
You are given the library's public API headers. Your output is consumed by another LLM that \
will generate harnesses, so the harness_template you produce must be a SYSTEM PROMPT that \
contains a working C harness skeleton plus library-specific rules — NOT a natural-language \
explanation of what to do.

The harness_template MUST follow this exact structure (a string, with embedded C inside ```c blocks):

  Line 1: "You are a fuzzing engineer generating AFL++ harnesses for <library>."
  Then a "CRITICAL RULES:" numbered list (5-10 items) covering:
      - How to feed fuzz input into the library (in-memory buffer? FILE*? custom callbacks?)
      - Whether the library can read raw memory or needs a handle/context object
      - Mandatory init / cleanup pairing (open/close, alloc/free, init/shutdown)
      - Forbidden patterns that produce harness-induced false positives
        (e.g. allocating attacker-controlled sizes without internal bounds checks)
      - Required #include list
      - AFL++ persistent mode requirements: __AFL_FUZZ_INIT, __AFL_LOOP(10000),
        __AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN
  Then — IF the library has a private/internal header (e.g. tiffiop.h, xmlinternals.h)
  separate from the public one — a "FORBIDDEN INTERNAL FUNCTIONS:" section explicitly
  listing 5-10 internal helpers/macros (with parens, e.g. `TIFFSetFilePointer()`,
  `TIFFSeekFile()`) that look callable from the source but are NOT in the public
  headers. The harness_template must say "NEVER call these even if you see them used
  inside the target function source — they will fail to link." This is a critical
  guard: harness LLMs read the target function's body via context_builder and copy
  internal helper calls verbatim, producing `error: undeclared function` builds.
  Then a "PROVEN WORKING TEMPLATE:" section with a complete, compilable C harness inside ```c fences:
      - All needed #include directives at the top
      - **Place `__AFL_FUZZ_INIT();` at FILE SCOPE immediately after the includes, BEFORE
        any function or callback definitions.** The expansion of the AFL persistent-mode
        macros (`__AFL_FUZZ_TESTCASE_BUF`, `__AFL_FUZZ_TESTCASE_LEN`) references symbols
        declared by `__AFL_FUZZ_INIT()`; if a callback defined above the init line tries
        to use those macros, compile fails with `error: use of undeclared identifier
        '__afl_fuzz_ptr'`.
      - If the library needs custom I/O callbacks (read/write/seek/close), the cleanest
        pattern is a struct passed via `thandle_t` (e.g. `typedef struct { const uint8_t
        *data; size_t size; size_t offset; } mem_buf_t;`). Callbacks then read from the
        struct, NOT from the AFL globals — this keeps callbacks decoupled from AFL and
        avoids ordering pitfalls. main() builds the struct from `__AFL_FUZZ_TESTCASE_BUF`
        / `__AFL_FUZZ_TESTCASE_LEN` inside the `__AFL_LOOP` body and passes its address
        as `thandle_t` to TIFFClientOpen / archive_read_open2 / etc.
      - main(int argc, char **argv) with `__AFL_INIT()` (the entry-point variant, separate
        from `__AFL_FUZZ_INIT()`) and the `__AFL_LOOP(10000)` body
      - One concrete API call sequence that exercises a representative target function
      - Inline `/* TODO: adapt for target function X */` comments showing where the next
        LLM should swap in different API calls
  Then — MANDATORY, do NOT omit — a closing "Output ONLY valid JSON with:" block listing the
  exact schema the next-stage harness LLM must return. Without this terminal mandate, the next
  LLM continues the C code pattern instead of wrapping it in JSON, and the entire pipeline breaks.
  The closing block MUST be exactly this (no -l<library> in compile_flags — the build wrapper
  already links the static archive):

      Output ONLY valid JSON with:
      {
        "target_func": "function_name",
        "input_format": "<library>-specific input description",
        "c_code": "complete C harness source code using the template above",
        "seed_commands": ["shell commands to generate seed files"],
        "compile_flags": "-g -O1 -fno-omit-frame-pointer"
      }

CRITICAL OUTPUT RULES — VIOLATIONS WILL BREAK THE PIPELINE:
  - The harness_template value is a JSON string. C code lives inside ```c ... ``` fences inside that string.
  - DO NOT include any natural-language preamble outside the JSON object (no "Here is...", no "Sure,...").
  - DO NOT wrap the entire JSON output in ```json fences — emit raw JSON.
  - C identifiers in the template must compile as-is. No pseudocode, no "...", no placeholders that aren't real syntax.
  - If the library needs custom callbacks, write them out fully (memory-backed read/seek/close), do NOT stub them with NULL.

magic_bytes: file format magic bytes found in the headers, keyed by format name:
  Dict mapping format_name → list of magic byte strings (use \\x escapes for hex, e.g. "MM\\x00*").
  Leave {} if the library is not a file-format parser.

harness_includes: minimum public headers a harness must #include, in order. Strip "internal", \
"priv", "private" headers — only real public API headers (e.g. ["png.h"], ["tiffio.h"]).

bonus_func_patterns: substrings of public API function names that score HIGH during recon \
(promising fuzz targets — typically parsing/decoding/decompression entry points). \
Dict mapping substring → score (positive int, 5-15 typical). \
Skip purely setup/getter/setter functions.

Output ONLY raw JSON (no markdown fence, no preamble, no trailing prose):
{
  "harness_template": "You are a fuzzing engineer generating AFL++ harnesses for <lib>.\\n\\nCRITICAL RULES:\\n1. ...\\n\\nPROVEN WORKING TEMPLATE:\\n```c\\n#include <...>\\n__AFL_FUZZ_INIT();\\nint main(int argc, char **argv) { ... }\\n```\\n",
  "magic_bytes": {"format_name": ["MM\\x00*", "II*\\x00"]},
  "harness_includes": ["header.h"],
  "bonus_func_patterns": {"parse_": 10, "decode_": 10, "read_": 5}
}"""

    HARNESS_CALLER_ESCALATION_SYSTEM = """You are a fuzzing engineer generating an AFL++ harness that
reaches a DEEP target function by going through its higher-level CALLER function.

CONTEXT: The target function cannot be reached directly (it is deep in the call graph).
Instead of harnessing the target directly, you will harness a CALLER that eventually
invokes the target. The target function will be exercised indirectly through normal
library usage of the caller.

RULES:
1. Your harness CALLS the caller function (shown in <callers>), NOT the deep target
2. The caller function will in turn call the target — this is the intended path
3. Use the library's PUBLIC API to reach the caller function
4. Structure the fuzz input so that execution flows through the caller INTO the target
5. All statelessness/FDP/precondition rules from the base harness apply here too
6. Include dictionary_entries with values that help exercise the deep code path

CALLER ESCALATION PATTERN:
```c
while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < MIN_SIZE) continue;
    /* Call the CALLER function — it will invoke the deep target internally */
    /* Do NOT call the deep target directly */
}
```

Output ONLY valid JSON with:
{
  "target_func": "caller_function_name",
  "input_format": "format description",
  "c_code": "complete C harness source code targeting the CALLER",
  "seed_commands": ["shell commands to generate seed files"],
  "compile_flags": "-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined",
  "dictionary_entries": ["magic bytes and key constants for the deep code path"]
}"""

    SEED_SYNTHESIS_SYSTEM = """You are generating SEED FILES for AFL++ fuzzing. The goal is to create \
minimal binary inputs that PASS format validation and reach the target function.

Study the <source_code> and <call_chain>:
1. Identify ALL validation checks (magic bytes, size fields, checksums)
2. Construct an input that passes each check in sequence
3. Use the MINIMUM viable input — AFL++ will mutate from here

Return ONLY valid JSON — an array of hex-encoded seeds:
{"seeds": ["4d534346...", "504b0304..."]}

Each seed should be:
- Valid enough to pass format detection (magic bytes correct)
- Structured enough to reach the target function's code path
- Small (< 4KB) to allow efficient AFL mutation
- Hex-encoded (lowercase, no spaces, no 0x prefix)

If the target processes text (XML, JSON, etc.), hex-encode the text bytes.
Example: "Hello" → "48656c6c6f"

If you cannot determine the format, provide generic minimal seeds:
{"seeds": ["00000000"]}"""

    @staticmethod
    def build_caller_escalation_prompt(
        target_func: str,
        callers: list,
        oracle_context: str,
        context: AnalysisContext,
        harness_template: str = "",
        previous_harness_code: str = "",
    ) -> str:
        """Build prompt for caller-escalation harness generation (Fix E + Fix 102)."""
        sections = [
            f"<deep_target>{target_func}</deep_target>",
            "",
            f"Target file: {context.target.file_path}",
            "",
            "<call_chain>",
            " → ".join(context.call_chain.chain),
            "</call_chain>",
            "",
            "<callers>",
        ]
        for c in callers[:5]:
            sections.append(f"// {c.file_path}:{c.line} [{c.kind}]")
            sections.append(c.content[:800])
            sections.append("---")
        sections.append("</callers>")
        sections.append("")

        if oracle_context:
            sections.append(oracle_context)
            sections.append("")

        # Include source of the deep target itself
        target_snippet = context.source_snippets.get(target_func, "")
        if target_snippet:
            sections.extend([
                "<deep_target_source>",
                target_snippet[:2000],
                "</deep_target_source>",
                "",
            ])

        # Fix 102: inject proven working harness template so LLM uses correct patterns
        if harness_template:
            sections.extend([
                "<proven_harness_template>",
                "IMPORTANT: Use the AFL++ macros and patterns shown below. "
                "Do NOT invent your own AFL includes or redefine AFL functions. "
                "Use __AFL_FUZZ_INIT(), __AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN, "
                "and while (__AFL_LOOP(10000)) exactly as shown.",
                "",
                harness_template[:3000],
                "</proven_harness_template>",
                "",
            ])

        # Fix 102: show previous harness that compiled but didn't reach the target
        if previous_harness_code:
            sections.extend([
                "<previous_harness>",
                "This harness COMPILED and ran but DID NOT reach the target function. "
                "The AFL++ macros and boilerplate in this harness are CORRECT — keep them. "
                "The problem is that the fuzz input needs specific content (e.g. PAX extended "
                "attributes in a tar file) to trigger the code path to the target function. "
                "Modify the harness to construct or require input that will reach the target.",
                "",
                previous_harness_code[:3000],
                "</previous_harness>",
                "",
            ])

        # Warn if callers are also static — LLM must go through public API
        static_callers = [c.name for c in callers[:5] if "static" in (c.kind or "")]
        if static_callers:
            sections.append(
                f"*** WARNING: The caller(s) {static_callers} are ALSO declared `static`. "
                "You CANNOT call them directly from the harness — the linker will fail. "
                "You MUST use the library's PUBLIC API (e.g. archive_read_open_memory, "
                "xmlReadMemory, TIFFOpen) and set up the input so that execution flows "
                "through the public API → into the static caller → into the deep target. "
                "Study the <call_chain> to find the public entry point."
            )
            sections.append("")

        sections.append(
            f"The function '{target_func}' is too deep to reach directly. "
            "Generate a harness targeting one of the <callers> above that will "
            f"cause '{target_func}' to be exercised indirectly. "
            "Pick the caller that is easiest to drive via the public API "
            "and most likely to exercise the full code path of the target. "
            "IMPORTANT: Do NOT call any `static` function directly — "
            "use ONLY the library's public API as the harness entry point. "
            "IMPORTANT: Use the EXACT AFL++ macro pattern from <proven_harness_template> — "
            "do NOT include afl-fuzz.h or redefine AFL internals."
        )
        return "\n".join(sections)

    @staticmethod
    def build_cve_analysis_prompt(
        crash: CrashReport,
        library_name: str,
        source_file: str = "",
        source_context: str = "",
    ) -> str:
        """Build the CVE analysis prompt from crash data."""
        sections = [
            "<library>",
            f"Name: {library_name}",
            "</library>",
            "",
            "<crash>",
            f"CWE: {crash.cwe.value}",
            f"Severity: {crash.severity.value}",
            f"Location: {crash.crash_location}",
            "</crash>",
            "",
        ]

        if crash.stack_trace:
            sections.append("<stack_trace>")
            for frame in crash.stack_trace[:20]:
                sections.append(f"  {frame}")
            sections.append("</stack_trace>")
            sections.append("")

        if crash.asan_output:
            sections.append("<asan_output>")
            sections.append(crash.asan_output[-2000:])
            sections.append("</asan_output>")
            sections.append("")

        if source_file:
            sections.append(f"<source_file>{source_file}</source_file>")
            sections.append("")

        if source_context:
            sections.append("<source_context>")
            sections.append(source_context)
            sections.append("</source_context>")
            sections.append("")

        sections.extend([
            "<task>",
            "Analyze this crash and determine:",
            "1. Does it match a known CVE? If so, which one and why?",
            "2. What is the root cause of this crash?",
            "3. What is the estimated CVSS score?",
            "4. How should this be fixed?",
            "5. What similar CVEs exist in this library or vulnerability class?",
            "</task>",
        ])

        return "\n".join(sections)

    @staticmethod
    def _derive_format_func(file_path: str, config=None) -> str:
        """Derive the correct format-specific API call from the target filename.

        Feature D2: Check config-driven regex first (format_enforcement_re),
        then fall back to hardcoded libarchive pattern for backward compat.

        e.g. archive_read_support_format_tar.c  → archive_read_support_format_tar(a)
             archive_read_support_filter_gzip.c → archive_read_support_filter_gzip(a)
        Falls back to archive_read_support_format_all(a) for libarchive targets,
        or empty string for non-libarchive targets (no format enforcement).
        """
        import os
        import re
        basename = os.path.basename(file_path)

        # Feature D2: Config-driven regex takes priority
        if config and config.target.format_enforcement_re:
            m = re.match(config.target.format_enforcement_re, basename)
            if m:
                func = m.group(1)
                template = config.target.format_enforcement_template or "{func}(a)"
                return template.format(func=func)

        # Match archive_read_support_{format,filter}_XXXX.c (libarchive pattern)
        m = re.match(r"(archive_read_support_(?:format|filter)_\w+)\.c$", basename)
        if m:
            return f"{m.group(1)}(a)"

        # Only default to format_all for files that look like libarchive
        if basename.startswith("archive_"):
            return "archive_read_support_format_all(a)"

        # Non-libarchive target — no format function to derive
        return ""

    @staticmethod
    def _read_internal_declarations(
        target_func: str,
        file_path: str,
        source_root: Path,
        internal_include_dirs: list[str],
    ) -> str:
        """Fix 123+130: Read internal header declarations for direct function harnessing.

        Derives the header path from the source file (stem → .h), searches
        internal_include_dirs, reads struct/typedef definitions and the function
        signature.  Fix 130: follows #include chains (1 level) to extract
        struct definitions, init function signatures, and key constants from
        dependency headers (e.g. hash.h → memory.h).

        Returns a formatted block (capped at ~250 lines) or "" if not found.
        """
        import os
        import re
        stem = os.path.splitext(os.path.basename(file_path))[0]  # e.g. "block_splitter"

        # Search internal dirs for a matching .h file
        header_path = None
        for idir in internal_include_dirs:
            candidate = source_root / idir / f"{stem}.h"
            if candidate.exists():
                header_path = candidate
                break

        if not header_path:
            return ""

        try:
            content = header_path.read_text(errors="replace")
        except OSError:
            return ""

        lines = content.splitlines()
        # Extract: #include directives, struct/typedef/enum, and the target function signature
        includes = []
        declarations = []
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith("#include"):
                includes.append(stripped)
            elif any(kw in stripped for kw in ("typedef ", "struct ", "enum ", target_func)) or stripped.startswith("BROTLI_INTERNAL") or stripped.startswith("BROTLI_"):
                declarations.append(stripped)

        if not declarations:
            # Fallback: include entire header (capped)
            declarations = [ln.rstrip() for ln in lines[:60]]

        parts = []
        rel = str(header_path.relative_to(source_root))
        parts.append(f"// Internal header: {rel}")
        if includes:
            parts.append("// Dependencies:")
            parts.extend(includes[:10])
        parts.append("")
        parts.extend(declarations[:70])

        # ── Fix 130: Follow dependency #includes to extract struct defs & init funcs ──
        # Resolve each #include to a real path and extract struct/typedef blocks
        dep_parts: list[str] = []
        dep_budget = 180  # lines budget for dependency extractions
        _include_re = re.compile(r'#include\s+"([^"]+)"')
        visited: set[str] = {str(header_path)}

        for inc_line in includes[:8]:
            m = _include_re.search(inc_line)
            if not m:
                continue
            inc_rel = m.group(1)
            # Resolve relative to header's own directory first, then source_root
            dep_path = (header_path.parent / inc_rel).resolve()
            if not dep_path.exists():
                # Try from source_root + internal_include_dirs
                for idir in internal_include_dirs:
                    alt = (source_root / idir / os.path.basename(inc_rel)).resolve()
                    if alt.exists():
                        dep_path = alt
                        break
            if not dep_path.exists() or str(dep_path) in visited:
                continue
            visited.add(str(dep_path))

            try:
                dep_content = dep_path.read_text(errors="replace")
            except OSError:
                continue

            dep_lines = dep_content.splitlines()
            # Extract struct/typedef blocks (multi-line) and function signatures
            extracted: list[str] = []
            dep_rel = inc_rel
            try:
                dep_rel = str(dep_path.relative_to(source_root))
            except ValueError:
                pass

            i = 0
            in_block = False
            brace_depth = 0
            while i < len(dep_lines):
                ln = dep_lines[i]
                stripped = ln.strip()

                # Capture struct/typedef/enum blocks (multi-line with braces)
                if not in_block and any(
                    kw in stripped
                    for kw in ("typedef struct", "typedef union", "typedef enum")
                ):
                    in_block = True
                    brace_depth = stripped.count("{") - stripped.count("}")
                    extracted.append(ln.rstrip())
                    if brace_depth <= 0 and "}" in stripped:
                        in_block = False
                    i += 1
                    continue
                if in_block:
                    extracted.append(ln.rstrip())
                    brace_depth += stripped.count("{") - stripped.count("}")
                    if brace_depth <= 0:
                        in_block = False
                    # Cap individual block at 30 lines to avoid huge structs
                    if len(extracted) > 30 and in_block:
                        extracted.append("  /* ... truncated ... */")
                        # Skip to closing brace
                        while i + 1 < len(dep_lines):
                            i += 1
                            if "}" in dep_lines[i] and dep_lines[i].strip().endswith(";"):
                                extracted.append(dep_lines[i].rstrip())
                                break
                        in_block = False
                    i += 1
                    continue

                # Capture BROTLI_INTERNAL function declarations (1-3 lines)
                if "BROTLI_INTERNAL" in stripped and "(" in stripped:
                    sig = ln.rstrip()
                    j = i + 1
                    while j < min(len(dep_lines), i + 4) and ";" not in sig:
                        sig += " " + dep_lines[j].strip()
                        j += 1
                    extracted.append(sig)
                    i = j
                    continue

                # Capture static inline init/setup/destroy function SIGNATURES
                if "static" in stripped and "BROTLI_INLINE" in stripped:
                    func_name_match = re.search(
                        r"(Init|Setup|Destroy|Reset|Choose|Sanitize|Compute)\w*\s*\(",
                        stripped,
                    )
                    if func_name_match:
                        sig = ln.rstrip()
                        j = i + 1
                        while j < min(len(dep_lines), i + 4) and "{" not in sig:
                            sig += " " + dep_lines[j].strip()
                            j += 1
                        # Truncate at opening brace — show signature only
                        brace_pos = sig.find("{")
                        if brace_pos > 0:
                            sig = sig[:brace_pos].rstrip() + " { ... }"
                        extracted.append(sig)
                        i = j
                        continue

                # Capture key #define constants (sizes, counts)
                if stripped.startswith("#define") and any(
                    kw in stripped
                    for kw in ("_SIZE", "_CODES", "_BITS", "_MAX", "_MIN", "_SLOTS")
                ):
                    extracted.append(stripped)

                i += 1

            if extracted:
                dep_parts.append(f"\n// From dependency: {dep_rel}")
                lines_left = dep_budget - sum(
                    1 for p in dep_parts if not p.startswith("//")
                )
                dep_parts.extend(extracted[: max(lines_left, 20)])

        if dep_parts:
            parts.append("\n// ── Dependency type definitions (Fix 130) ──")
            parts.extend(dep_parts[:dep_budget])

        return "\n".join(parts)

    @staticmethod
    def _extract_caller_context(
        target_func: str,
        file_path: str,
        source_root: Path,
    ) -> str:
        """Fix 128: Extract how the public API calls a direct_internal function.

        Searches .c files for call sites of *target_func*, excludes the
        function's own definition file, and returns ~40 lines of surrounding
        context from the best caller.  This shows the LLM the correct buffer
        allocation, parameter initialisation, and precondition patterns.

        Returns a formatted block or "" if no caller found.
        """
        import os
        import subprocess as _sp

        own_basename = os.path.basename(file_path)  # e.g. "compress_fragment_two_pass.c"

        # Fast grep for call sites of the function across the source tree
        try:
            grep_result = _sp.run(
                [
                    "grep", "-rn", "--include=*.c",
                    f"{target_func}(", str(source_root),
                ],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            return ""

        if not grep_result.stdout.strip():
            return ""

        # Parse grep results: file:line:content
        # Prefer callers in different files (public API wrappers like encode.c)
        candidates: list[tuple[str, int]] = []  # (file_path, line_number)
        for line in grep_result.stdout.strip().splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            gfile, gline_s = parts[0], parts[1]
            # Skip the function's own file (its definition, not a caller)
            if os.path.basename(gfile) == own_basename:
                continue
            # Skip header files and test files
            if gfile.endswith(".h") or "/test" in gfile:
                continue
            try:
                gline = int(gline_s)
            except ValueError:
                continue
            candidates.append((gfile, gline))

        if not candidates:
            return ""

        # Prefer files that look like the main encoder/decoder entry (e.g. encode.c)
        # Sort: public-API-like files first, then by line number
        def _caller_priority(item: tuple[str, int]) -> tuple[int, str]:
            f = item[0]
            bn = os.path.basename(f)
            # Heuristic: files named encode/decode/compress/main are public API
            if any(kw in bn for kw in ("encode", "decode", "compress", "main", "api")):
                return (0, bn)
            return (1, bn)

        candidates.sort(key=_caller_priority)
        best_file, best_line = candidates[0]

        # Read context: 50 lines before call, 10 lines after call
        try:
            with open(best_file, errors="replace") as fh:
                all_lines = fh.readlines()
        except OSError:
            return ""

        start = max(0, best_line - 51)
        end = min(len(all_lines), best_line + 10)
        snippet_lines = all_lines[start:end]

        try:
            rel = os.path.relpath(best_file, source_root)
        except ValueError:
            rel = best_file

        result_parts = [
            f"// Caller: {rel}:{best_line}",
            f"// This is how the public API calls {target_func}().",
            "// Follow the SAME buffer allocation and parameter patterns.",
            "",
        ]
        for i, ln in enumerate(snippet_lines, start=start + 1):
            marker = " >>>" if i == best_line else "    "
            result_parts.append(f"{marker} {i:4d} | {ln.rstrip()}")

        # Fix 130: Also search for initialization patterns of parameter types
        # in the SAME file (e.g. HasherInit, HasherSetup, MemoryManager init)
        init_keywords = [
            "HasherInit", "HasherSetup", "MemoryManager",
            "BrotliInitMemoryManager", "BrotliInitSharedEncoderDictionary",
            "BrotliInitDistanceParams", "SanitizeParams", "ComputeLgBlock",
            "ChooseHasher", "ChooseDistanceParams", "dist_cache",
        ]
        init_hits: list[tuple[int, str]] = []
        for idx, ln in enumerate(all_lines, start=1):
            # Skip lines already in the snippet
            if start + 1 <= idx <= end:
                continue
            stripped = ln.strip()
            if any(kw in stripped for kw in init_keywords):
                # Avoid comments and header guards
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
                    continue
                init_hits.append((idx, ln.rstrip()))

        if init_hits:
            result_parts.append("")
            result_parts.append(
                f"// Initialization patterns in {rel} "
                "(shows how parameters are set up):"
            )
            # Show up to 25 init lines, dedup nearby lines
            shown = 0
            prev_line = -10
            for idx, ln in init_hits:
                if shown >= 25:
                    break
                if idx - prev_line <= 1:
                    result_parts.append(f"     {idx:4d} | {ln}")
                else:
                    result_parts.append(f"  .. {idx:4d} | {ln}")
                prev_line = idx
                shown += 1

        return "\n".join(result_parts)

    @staticmethod
    def build_analysis_prompt(context: AnalysisContext) -> str:
        """Build the blocker analysis prompt."""
        sections = []

        sections.append("<target_function>")
        sections.append(f"Function: {context.target.func_name}")
        sections.append(f"File: {context.target.file_path}:{context.target.line}")
        sections.append(f"Coverage: {context.target.coverage_pct}%")
        sections.append(f"Has memory ops: {context.target.has_memory_ops}")
        sections.append(f"Has pointer arithmetic: {context.target.has_pointer_arith}")
        sections.append("</target_function>")

        sections.append("<call_chain>")
        sections.append(" → ".join(context.call_chain.chain))
        if context.call_chain.blockers:
            sections.append("\nBlockers found:")
            for b in context.call_chain.blockers:
                sections.append(f"  - [{b.blocker_type.value}] {b.condition} at {b.file_path}:{b.line}")
        sections.append("</call_chain>")

        sections.append("<source_code>")
        for name, code in context.source_snippets.items():
            sections.append(f"--- {name} ---")
            sections.append(code)
        sections.append("</source_code>")

        if context.macro_env:
            sections.append("<macro_environment>")
            for k, v in context.macro_env.items():
                sections.append(f"#define {k} {v}")
            sections.append("</macro_environment>")

        if context.build_config:
            sections.append(f"<build_config>\n{context.build_config}\n</build_config>")

        # Past bug fixes to this file say what has historically gone wrong here,
        # which is a strong prior on what is still wrong. Recency says how much
        # review exposure the code has had.
        if context.git_history:
            sections.append("<git_history>")
            sections.append(
                "Recent commits touching this file (bug-fix commits first):"
            )
            sections.extend(context.git_history)
            sections.append("</git_history>")

        sections.append("<task>")
        sections.append(
            "Analyze this function and its call chain for potential vulnerabilities.\n"
            "1. Why does this function have 0% fuzzing coverage?\n"
            "2. Are there missing NULL checks or bounds checks?\n"
            "3. Can malformed input trigger a crash?\n"
            "4. What is the minimal change to make this code reachable by a fuzzer?"
        )
        sections.append("</task>")

        return "\n".join(sections)

    @staticmethod
    def build_patch_prompt(
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
    ) -> str:
        """Build the patch generation prompt."""
        sections = [
            "<analysis>",
            f"Vulnerability type: {analysis.vulnerability_type}",
            f"CWE: {analysis.cwe.value}",
            f"Root cause: {analysis.root_cause}",
            f"Attack vector: {analysis.attack_vector}",
            "</analysis>",
            "",
            # Explicitly state the target file so the LLM returns the correct path
            "<target>",
            f"Function: {context.target.func_name}",
            f"File (use EXACTLY this path in your JSON response): {context.target.file_path}",
            f"Bug/target line: {context.target.line}  ← patch the code AT OR NEAR THIS LINE, inside the function body",
            "</target>",
            "",
            "<source_code>",
        ]
        for name, code in context.source_snippets.items():
            sections.append(f"--- {name} ---")
            sections.append(code)
        sections.append("</source_code>")
        sections.append("")
        # Include exact source lines around target line so the LLM can copy-paste
        # verbatim instead of approximating whitespace/indentation.
        func_snippet = context.source_snippets.get(context.target.func_name, "")
        if func_snippet:
            snippet_lines = func_snippet.splitlines()
            # Snippet starts at max(0, target.line - CONTEXT_LINES); CONTEXT_LINES=150
            snippet_start = max(1, context.target.line - 150)
            target_offset = context.target.line - snippet_start  # 0-based in snippet
            win_lo = max(0, target_offset - 8)
            win_hi = min(len(snippet_lines), target_offset + 8)
            exact_lines = []
            for i, ln in enumerate(snippet_lines[win_lo:win_hi], start=win_lo + snippet_start):
                marker = "  ← PATCH HERE" if i == context.target.line else ""
                exact_lines.append(f"{i:5d}: {ln}{marker}")
            sections.append("<exact_source_lines>")
            sections.append(
                "These are VERBATIM lines from the source file with their line numbers.\n"
                "Use one of these lines (or a consecutive block) as your \"original\" field.\n"
                "Copy the text EXACTLY — do NOT include the line-number prefix (e.g. '1081: ')."
            )
            sections.append("\n".join(exact_lines))
            sections.append("</exact_source_lines>")
            sections.append("")

            # Extract local variable names from a wider window around the patch site.
            # These are variables that might become unused after the patch → -Wunused-variable.
            import re as _re
            _decl_pat = _re.compile(
                r'^\s+'                      # indented (inside function body, not global)
                r'(?:(?:const|volatile|static|unsigned|signed|struct|enum|union)\s+)*'
                r'(?:\w+\s*[\*\s]+)*'        # type (possibly pointer)
                r'(\w{2,})'                  # variable name (≥2 chars to skip 'r', 'i', etc.)
                r'\s*[;=\[]',               # ends with ; = or [
                _re.MULTILINE,
            )
            var_window_lo = max(0, target_offset - 40)
            var_window_hi = min(len(snippet_lines), target_offset + 5)
            var_window_text = "\n".join(snippet_lines[var_window_lo:var_window_hi])
            at_risk = list(dict.fromkeys(
                m.group(1) for m in _decl_pat.finditer(var_window_text)
                # filter out C keywords and common false positives
                if m.group(1) not in {
                    "if", "for", "while", "return", "else", "do", "switch",
                    "case", "break", "continue", "sizeof", "typedef",
                    "int", "char", "void", "size", "long", "short",
                }
            ))
            if at_risk:
                sections.append("<variables_at_risk>")
                sections.append(
                    "Local variables declared near the patch site. If your patch removes the "
                    "code that references any of these, they become UNUSED → -Wunused-variable "
                    "→ compile error.\n"
                    f"At-risk variables: {', '.join(at_risk)}\n"
                    "SOLUTION: Wrap the ENTIRE original statement with #if 0 ... #endif "
                    "(keeps all variables as dead code, always compile-safe)."
                )
                sections.append("</variables_at_risk>")
                sections.append("")

        sections.append(
            "Generate a minimal, reversible source patch that either:\n"
            "1. Fixes the vulnerability (adds missing NULL/bounds check), OR\n"
            "2. Bypasses a compile-time blocker to expose the code to fuzzing.\n"
            "The patch should be applicable via text replacement.\n"
            f"IMPORTANT: set file_path to exactly \"{context.target.file_path}\" in your JSON.\n"
            "CRITICAL: The \"original\" text you provide MUST be a statement INSIDE the function body.\n"
            "DO NOT use the function signature (e.g., the line with the function name and parameters) as \"original\".\n"
            "DO NOT patch the function declaration. Patch executable code within the function."
        )
        return "\n".join(sections)

    @staticmethod
    def build_harness_prompt(
        analysis: VulnerabilityAnalysis,
        context: AnalysisContext,
        oracle_context: str = "",
        config: NemesisConfig | None = None,
        caller_context: str = "",
    ) -> str:
        """Build the harness generation prompt."""
        sections = [
            f"Target function: {context.target.func_name}",
            f"File: {context.target.file_path}",
            f"Vulnerability: {analysis.vulnerability_type} ({analysis.cwe.value})",
            f"Attack vector: {analysis.attack_vector}",
            "",
            "<call_chain>",
            " → ".join(context.call_chain.chain),
            "</call_chain>",
            "",
            "<source_code>",
        ]
        for name, code in context.source_snippets.items():
            sections.append(f"--- {name} ---")
            sections.append(code)
        sections.append("</source_code>")
        sections.append("")

        # Inject oracle RAG context (additional relevant source snippets)
        if oracle_context:
            sections.append(oracle_context)
            sections.append("")

        # Fix 101: If context contains unit test examples, add explicit instruction
        if oracle_context and "<test_suite_examples>" in oracle_context:
            sections.append(
                "*** UNIT TEST REFERENCE (CRITICAL): The <test_suite_examples> above "
                "contain REAL working code from the library developers. These tests show "
                "the CORRECT API initialization sequence, call order, and cleanup pattern. "
                "You MUST base your harness on these proven patterns — do NOT invent your "
                "own API sequence. Specifically:\n"
                "  1. Copy the exact struct creation → format setup → open → read loop → "
                "cleanup sequence from the tests\n"
                "  2. Ensure ALL resources are freed inside the AFL loop (no state leaks)\n"
                "  3. Use archive_read_data() to actually read data blocks (not skip)\n"
                "  4. The tests show which API calls are needed to reach the target function"
            )
            sections.append("")

        # Inject public API declarations from harness_includes headers
        if config is not None:
            api_decls: list[str] = []
            src_root = Path(config.target.source_root)
            inc_sub = config.target.include_subdir or ""
            build_dir = Path(config.target.build_dir)
            for inc in config.target.harness_includes:
                hdr = src_root / inc_sub / inc
                if not hdr.exists():
                    hdr = build_dir / inc  # cmake-generated
                if not hdr.exists():
                    # Try in source root directly
                    hdr = src_root / inc
                if hdr.exists():
                    try:
                        lines = hdr.read_text(errors="replace").splitlines()
                    except OSError:
                        continue
                    # Extract function declarations (extern, library-specific macros)
                    _api_kw = (
                        "XMLPUBFUN", "XMLPUBVAR", "extern ",
                        "TIFF_DLL", "LIBXML_", "__ARCHIVE_",
                        "XMLCALL", "LIBPNG_", "PNG_EXPORT",
                    )
                    decls = [
                        ln.strip()
                        for ln in lines
                        if any(kw in ln for kw in _api_kw) and "(" in ln
                    ]
                    if decls:
                        api_decls.append(f"// {inc}")
                        # Was 40 — too low for libraries with rich public APIs
                        # (libtiff: 193 externs in tiffio.h). Truncating made the
                        # LLM hallucinate internal helpers (TIFFSeekFile etc.).
                        # 250 is a safe upper bound; tokens add up to <8K which
                        # fits comfortably in any architect context budget.
                        api_decls.extend(decls[:250])
            if api_decls:
                sections.append("<api_declarations>")
                sections.append(
                    "Available public API functions — use ONLY these. Any function "
                    "you see called inside the <source_code> snippets below but NOT "
                    "listed here is an INTERNAL helper (lives in a *iop.h or similar "
                    "private header) and will fail to link. This includes macros and "
                    "static helpers. NEVER invoke such symbols from the harness — "
                    "even if the target function calls them internally, your harness "
                    "must not. If you need rewind/seek behaviour, do it via your own "
                    "memory-IO callbacks (the read/seek/close functions you defined "
                    "for TIFFClientOpen / archive_read_open2 / etc.), not by calling "
                    "library internals."
                )
                sections.extend(api_decls)
                sections.append("</api_declarations>")
                sections.append("")

        # Fix 134: inject <required_includes> when PinnedFunc specifies needed_headers
        if hasattr(context.target, 'needed_headers') and context.target.needed_headers:
            sections.append("<required_includes>")
            sections.append("Your harness MUST #include these headers:")
            for h in context.target.needed_headers:
                sections.append(f'  #include <{h}>')
            sections.append("</required_includes>")
            sections.append("")

        # Fix 123: inject internal declarations for direct internal function harnessing
        if (
            config is not None
            and getattr(context.target, "direct_internal", False)
            and config.target.internal_include_dirs
        ):
            src_root = Path(config.target.source_root) if config else Path(".")
            internal_decls = PromptBuilder._read_internal_declarations(
                context.target.func_name,
                context.target.file_path,
                src_root,
                config.target.internal_include_dirs,
            )
            sections.append("<internal_declarations>")
            sections.append(
                "*** DIRECT INTERNAL HARNESSING (Fix 123) ***\n"
                f"Call `{context.target.func_name}` DIRECTLY. "
                "It IS linkable from the static .a archive.\n"
                "Include the internal headers below. "
                "Construct arguments from fuzz input.\n"
                "Do NOT use the public API to reach this function indirectly."
            )
            if internal_decls:
                sections.append(internal_decls)
            sections.append("</internal_declarations>")
            sections.append("")

            # Fix 128: Automatic caller context extraction — show the LLM how
            # the public API calls this function (correct buffer sizes, param
            # init, preconditions).  This prevents harness bugs like undersized
            # output buffers.
            auto_caller = PromptBuilder._extract_caller_context(
                context.target.func_name,
                context.target.file_path,
                src_root,
            )
            if auto_caller:
                sections.append("<caller_context>")
                sections.append(
                    "*** CRITICAL — BUFFER SIZING & PARAMETER CONTRACT (Fix 128) ***\n"
                    "The code below shows how the library's OWN public API calls "
                    f"`{context.target.func_name}()`.  You MUST follow these patterns:\n"
                    "  1. Allocate output/storage buffers using the SAME formula as the caller\n"
                    "  2. Initialise parameters (table_size, storage_ix, etc.) the SAME way\n"
                    "  3. Read the REQUIRES comments in the header for preconditions\n"
                    "  4. If the caller allocates `2 * size + N`, you MUST do the same — "
                    "do NOT use `size + 32` or any smaller formula\n"
                    "  5. Auxiliary buffers (command_buf, literal_buf, etc.) must be at "
                    "least as large as the caller allocates\n"
                    "Violating these contracts causes heap-buffer-overflow false positives."
                )
                sections.append(auto_caller)
                sections.append("</caller_context>")
                sections.append("")

        # Inject Introspector enrichment: needed headers for target function
        if context.target.needed_headers:
            sections.append("<introspector_headers>")
            sections.append(
                "Headers needed to use this function (from OSS-Fuzz Introspector):"
            )
            for hdr in context.target.needed_headers:
                sections.append(f"  #include {hdr}")
            sections.append("</introspector_headers>")
            sections.append("")

        # Hint if function is already fuzzed in OSS-Fuzz
        if context.target.existing_harness_path:
            sections.append(
                f"NOTE: This function is already fuzzed in OSS-Fuzz by: "
                f"{context.target.existing_harness_path}. "
                "Study its approach but generate a DIFFERENT harness that exercises "
                "different code paths or input patterns to maximize coverage."
            )
            sections.append("")

        # --- Format-specific harness instruction (libarchive targets only) ---
        format_call = PromptBuilder._derive_format_func(context.target.file_path)
        if format_call:
            sections.append(
                f"*** FORMAT REQUIREMENT: You MUST use `{format_call}` in the harness — "
                "do NOT use archive_read_support_format_all(a). "
                "Using the wrong format parser wastes coverage on irrelevant code paths."
            )
            if "filter" in format_call:
                sections.append(
                    "This is a filter/compression target. Also add "
                    "`archive_read_support_format_raw(a)` so the filter is exercised."
                )
            sections.append("")

        if context.target.is_static:
            chain_str = " → ".join(context.call_chain.chain) if context.call_chain.chain else "N/A"
            sections.append("")
            sections.append(
                f"*** STATIC FUNCTION WARNING: `{context.target.func_name}` is declared with "
                f"`static` linkage in {context.target.file_path}. "
                "It is NOT an exported symbol — you CANNOT call it by name from the harness. "
                "The compiler will error with 'call to undeclared function'. "
                "You MUST exercise it INDIRECTLY via the library's public API. "
                "Study the <call_chain> to find the public entry point that eventually calls "
                f"this function: {chain_str}. "
                "Call the FIRST function in the chain (the public API entry point) and set up "
                "the input so that execution flows through to the target function."
            )
            if caller_context:
                sections.append("")
                sections.append(
                    "Recommended public callers (from codebase analysis):"
                )
                sections.append(caller_context)
                sections.append(
                    "Use one of these as the harness entry point instead of calling "
                    f"`{context.target.func_name}` directly."
                )
        # indirect_reach analogue of the is_static warning. Triggered when the
        # YAML pinned_funcs entry sets indirect_reach=true OR the planner LLM
        # decides the target is internal-by-API-shape (uses internal struct
        # types, not declared in any public header). The function may have
        # external linkage but is unusable from the harness without internal
        # headers — so we MUST route through a public caller.
        elif getattr(context.target, "indirect_reach", False):
            chain_str = " → ".join(context.call_chain.chain) if context.call_chain.chain else "N/A"
            sections.append("")
            sections.append(
                f"*** INDIRECT-REACH TARGET: `{context.target.func_name}` is INTERNAL — its"
                " parameters use types that live in private headers (HuffmanCode, png_structp"
                " internals, brotli internal contexts, ...). Calling it directly will require"
                " #including internal headers, which leads to ABI mismatch and undeclared-"
                " identifier errors that you have already seen in earlier failed attempts."
                " DO NOT ATTEMPT a direct call."
                f"\n  - Pick ONE public API function that ultimately reaches `{context.target.func_name}`"
                f" (study <codebase_context>'s call_chain: {chain_str})."
                "\n  - Pass the AFL fuzz input as the data argument to that public API."
                "\n  - Free / cleanup any returned resources at end of each loop iteration."
                "\n  - Include ONLY the public header(s) listed in <api_declarations> — never"
                " an internal `src/.../*.h` header."
            )
            if caller_context:
                sections.append("")
                sections.append(
                    "Recommended public callers (from codebase analysis):"
                )
                sections.append(caller_context)
                sections.append(
                    "Use one of these as the harness entry point instead of calling "
                    f"`{context.target.func_name}` directly."
                )
            # Fix 142 (A+B): caller-graph BFS up to first public-API gateway.
            # The architect gets the full chain + the gateway's signature and
            # documentation comment. With this, the architect can deduce which
            # parser flags / parameters the gateway needs to reach the target,
            # without us leaking the CVE description.
            if config is not None:
                try:
                    from nemesis.recon.caller_graph import build_reach_path
                    src_root = Path(
                        os.path.expandvars(config.target.source_root)
                    ).expanduser().resolve()
                    inc_subdir = (
                        config.target.include_subdir
                        if config.target.include_subdir else ""
                    )
                    inc_dir = src_root / inc_subdir if inc_subdir else src_root
                    headers: list[Path] = []
                    for h in (config.target.harness_includes or []):
                        candidate = inc_dir / h
                        if candidate.exists():
                            headers.append(candidate)
                    if headers and src_root.exists():
                        rp = build_reach_path(
                            pinned_func=context.target.func_name,
                            pinned_file=context.target.file_path,
                            source_root=src_root,
                            public_headers=headers,
                        )
                        block = rp.render_block()
                        if block:
                            sections.append("")
                            sections.append(block)
                        # Fix 144 (D): bug-class classifier — read the pinned
                        # function source and its caller names (already
                        # gathered above), classify the trigger pattern, and
                        # inject a <trigger_pattern> block. NO CVE info fed in
                        # — this is honest static analysis the architect would
                        # do anyway. Cached on context across variants.
                        bc_cache = getattr(
                            context, "_bug_class_cache", None,
                        )
                        if not isinstance(bc_cache, dict):
                            bc_cache = {}
                        bc_key = (
                            context.target.func_name,
                            getattr(context.target, "file_path", ""),
                        )
                        bc = bc_cache.get(bc_key)
                        if bc is None:
                            from nemesis.recon.bug_class import (
                                classify_bug_class,
                            )
                            # Read the pinned function body. file_path may be
                            # relative to source_root.
                            fp_str = context.target.file_path
                            fp_path = Path(fp_str) if fp_str else Path()
                            if fp_path and not fp_path.is_absolute():
                                fp_path = src_root / fp_path
                            func_src = ""
                            if fp_path and fp_path.exists():
                                try:
                                    text = fp_path.read_text(errors="replace")
                                    # Take the function body around the pin
                                    # line. We don't have the exact line in
                                    # build_harness_prompt, so use the
                                    # whole-file fallback truncated to ~6KB.
                                    func_src = text
                                except OSError:
                                    func_src = ""
                            caller_names = [
                                h.func_name for h in rp.hops
                            ][:8]
                            from nemesis.neural import LLMClient as _LlmClient
                            _client = _LlmClient(config)
                            bc = classify_bug_class(
                                func_name=context.target.func_name,
                                func_source=func_src,
                                caller_names=caller_names,
                                client=_client,
                                log=get_logger("neural.bug_class"),
                            )
                            bc_cache[bc_key] = bc
                            try:
                                context._bug_class_cache = bc_cache  # type: ignore[attr-defined]
                            except (AttributeError, TypeError):
                                pass
                        bc_block = bc.render_block()
                        if bc_block:
                            sections.append("")
                            sections.append(bc_block)
                except Exception as _rp_exc:  # noqa: BLE001
                    # never fail harness gen because of caller-graph errors
                    pass
            # Fix 145: hybrid Strategy A+B — when this pinned function has
            # auto_expose set in YAML, the build-time visibility patch made
            # it externally linkable. Tell the architect it can now be
            # called directly with crafted state, while the verification
            # gate (clean unpatched debug binary) keeps the rediscovery
            # honest.
            if config is not None and getattr(config.target, "pinned_funcs", None):
                fn = context.target.func_name
                exposed = any(
                    getattr(p, "func_name", "") == fn
                    and getattr(p, "auto_expose", False)
                    for p in (config.target.pinned_funcs or [])
                )
                if exposed:
                    # Collect all auto_expose'd function names in this run.
                    # The architect should prefer the SIMPLEST callable —
                    # typically the non-recursive caller of the pinned
                    # function — to avoid having to construct internal
                    # state by hand.
                    all_exposed: list[str] = [
                        getattr(p, "func_name", "") for p in
                        (config.target.pinned_funcs or [])
                        if getattr(p, "auto_expose", False)
                        and getattr(p, "func_name", "")
                    ]
                    other_exposed = [n for n in all_exposed if n != fn]
                    sections.append("")
                    sections.append(
                        f"<exposed_function>\n"
                        f"BUILD-TIME VISIBILITY PATCH ACTIVE for `{fn}`.\n"
                        f"\n"
                        f"================ CRITICAL ORDER ================\n"
                        f"  STEP 1: parser/codec setup\n"
                        f"  STEP 2: feed AFL input through public API\n"
                        f"          (e.g. XML_Parse, png_read_info, ...)\n"
                        f"  STEP 3: call `{fn}(...)` — AFTER step 2\n"
                        f"  STEP 4: cleanup\n"
                        f"\n"
                        f"Calling `{fn}` BEFORE step 2 makes it read "
                        f"zero-initialised state. This produces 0% "
                        f"meaningful coverage — the harness is then "
                        f"WORSE than a plain public-API harness, and "
                        f"the build pipeline will REJECT it.\n"
                        f"================================================\n"
                        f"\n"
                        f"The `static` keyword has been stripped from the "
                        f"definition of `{fn}` in the work-tree copy used "
                        f"for the fuzz build. The symbol is now externally "
                        f"linkable. The harness MUST exploit this by "
                        f"calling `{fn}` DIRECTLY at least once per "
                        f"`__AFL_LOOP` iteration — otherwise the visibility "
                        f"patch is wasted and the harness reduces to a "
                        f"plain public-API harness.\n"
                        f"\n"
                        f"HARD RULES (a violation = compile failure):\n"
                        f"  1. Forward-declare `{fn}` at file scope WITHOUT "
                        f"the `static` qualifier. Just `<return-type> "
                        f"{fn}(<args>);` — the visibility patch already "
                        f"made it extern.\n"
                        f"  2. Do NOT `#include` any internal header "
                        f"(`internal.h`, `xmltok.h`, anything under "
                        f"`src/`, `lib/internal/`, etc.). They redefine "
                        f"types that conflict with the public header and "
                        f"break the build. The forward declaration alone "
                        f"is enough for the linker.\n"
                        f"  3. Use ONLY the public types declared in the "
                        f"<api_declarations> block. If `{fn}` takes a "
                        f"struct that is forward-declared as opaque in "
                        f"the public header (e.g. `XML_Content`), pass it "
                        f"as an opaque pointer — do NOT redefine the "
                        f"struct.\n"
                        f"\n"
                        f"MANDATORY ORDERING (a violation = the call to "
                        f"`{fn}` is wasted because the function reads "
                        f"internal state that has not been built yet):\n"
                        f"  a. Construct the parser/codec object via the "
                        f"public API.\n"
                        f"  b. **FIRST** feed the AFL input through the "
                        f"natural public entry point (e.g. XML_Parse, "
                        f"png_read_info, etc.). This step BUILDS the "
                        f"internal scaffolding (DTD scaffold, Huffman "
                        f"table, decoder context, ...) that `{fn}` then "
                        f"reads.\n"
                        f"  c. **SECOND, AFTER (b) completes**, call "
                        f"`{fn}` on the now-populated context. The order "
                        f"is critical: calling `{fn}` BEFORE the public "
                        f"API leaves you reading zero-initialised state, "
                        f"which produces no useful coverage and no crash.\n"
                        f"  d. Output buffer arguments to `{fn}` MUST be "
                        f"properly allocated and INITIALISED (non-NULL, "
                        f"non-uninitialised stack memory). If `{fn}` "
                        f"writes through a pointer-to-pointer, allocate "
                        f"the underlying buffer with malloc and pass its "
                        f"address. NEVER pass NULL or uninitialised "
                        f"stack variables — these produce trivial "
                        f"crashes that are NOT the bug we are fuzzing "
                        f"for and will be filtered out at verification.\n"
                        f"  e. Free / cleanup at end of iteration.\n"
                        f"\n"
                        f"Honesty contract: every crash this harness finds "
                        f"is later replayed against the UNPATCHED debug "
                        f"binary built from `source_root`. If the crash "
                        f"does not reproduce there, it is rejected. So "
                        f"this is purely a fuzzing convenience, not a "
                        f"semantic change to the library.\n"
                        + (
                            f"\nALSO EXPOSED: {', '.join(other_exposed)}\n"
                            f"These functions in the same call chain have ALSO "
                            f"been visibility-patched. PREFER calling whichever "
                            f"one takes the SIMPLEST argument list (typically "
                            f"only the opaque parser/codec object) — that lets "
                            f"the library's own internal logic walk the "
                            f"populated scaffold and reach the deeper recursive "
                            f"target for you. You do NOT have to construct "
                            f"internal struct fields yourself.\n"
                            f"For example, if the pinned target is the deep-"
                            f"recursive helper but its non-recursive caller is "
                            f"also exposed and takes only the parser as "
                            f"argument, call the CALLER after the public-API "
                            f"setup — it triggers the recursion path through "
                            f"the library's own glue code.\n"
                            if other_exposed else ""
                        )
                        + "</exposed_function>"
                    )
        # Fix 134: allow harness_hint + internal_declarations coexistence.
        # (Fix 123 originally suppressed hints for direct_internal, but complex
        # internal targets like CreatePreparedDictionary need BOTH.)
        if context.target.harness_hint:
            sections.append("")
            sections.append(
                "CRITICAL REQUIREMENT — You MUST follow these exact instructions for this target:"
            )
            sections.append("<target_specific_hint>")
            sections.append(context.target.harness_hint)
            sections.append("</target_specific_hint>")
            sections.append(
                "IMPORTANT: Implement EXACTLY the pattern shown above. Do NOT use a different "
                "approach. The hint above is based on empirical analysis of what actually reaches "
                "the vulnerable code. Deviating from it will fail to exercise the target function."
            )
            sections.append("")

        # Fix 135: differential-oracle target. The harness must run a round-trip
        # operation (encode→decode, serialize→parse, compress→decompress, …) and
        # assert byte-equality of the result against the input. Any divergence is
        # a logic bug that would never surface as a memory-safety violation, so
        # ASAN/UBSan alone would miss it. abort() turns the divergence into a
        # crash AFL can pick up.
        if getattr(context.target, "differential_oracle", False):
            sections.append("")
            sections.append("<differential_oracle>")
            sections.append(
                "DIFFERENTIAL ORACLE TARGET — this harness MUST be a round-trip oracle:"
            )
            sections.append(
                "  1. Apply the forward operation to the fuzz input "
                "(encode / serialize / compress)."
            )
            sections.append(
                "  2. Apply the inverse operation to the output "
                "(decode / deserialize / decompress)."
            )
            sections.append(
                "  3. Assert `decoded_size == input_size && memcmp(input, decoded, input_size) == 0`."
            )
            sections.append(
                "  4. On mismatch, call `abort()` — that turns the silent corruption into "
                "an AFL-visible crash."
            )
            sections.append(
                "  5. Skip — `continue` — only when the forward op fails (returns 0/error). "
                "Never silently accept a successful forward op with a non-matching round-trip."
            )
            sections.append(
                "  6. Cap input length so encoded output fits in a generously-sized buffer; "
                "free both buffers on every iteration."
            )
            sections.append("</differential_oracle>")
            sections.append("")

        # Fix 148: cross-implementation differential oracle. When configured,
        # the harness MUST call BOTH the target function and a named reference
        # implementation on the same fuzz input, then assert their outputs (or
        # success/failure status) match byte-for-byte. Generalizes Fix 135
        # beyond round-trip: spec-vs-impl, strict-vs-lenient, fast-vs-reference.
        # Any divergence is a logic bug invisible to ASAN/UBSan; abort() turns
        # it into an AFL-visible crash.
        ref_impl = (getattr(context.target, "differential_reference", "") or "").strip()
        if ref_impl:
            sections.append("")
            sections.append("<differential_reference>")
            sections.append(
                f"CROSS-IMPLEMENTATION DIFFERENTIAL ORACLE — reference impl: `{ref_impl}`"
            )
            sections.append(
                "  1. On each iteration, run the SAME fuzz input through BOTH the target "
                "function AND the reference implementation named above."
            )
            sections.append(
                "  2. Compare their outputs deterministically. The exact comparison depends "
                "on the function's contract:"
            )
            sections.append(
                "     - Parsers/decoders: same success/failure status AND, when both succeed, "
                "byte-equal output buffers (memcmp + length match)."
            )
            sections.append(
                "     - Predicates / validators: identical boolean / status code."
            )
            sections.append(
                "     - Hash / checksum / digest: identical digest bytes."
            )
            sections.append(
                "  3. On ANY divergence (one succeeds and the other fails, OR both succeed "
                "with non-equal outputs), call `abort()`. That divergence is a logic bug — "
                "one of the two implementations violates the shared spec."
            )
            sections.append(
                "  4. If the reference impl needs a separate header / link, include it. If it "
                "lives in another library, link against that library too — the build system "
                "will accept extra `-l` flags via the existing harness-link path."
            )
            sections.append(
                "  5. Free every buffer on every iteration; do not let the reference call leak "
                "or you'll trip leak detection on a non-target codepath."
            )
            sections.append(
                "  6. NEVER mask divergence as 'expected' — if the two impls disagree on a "
                "well-formed input that's a real bug worth crashing on. Only suppress "
                "when both reject the input identically."
            )
            sections.append("</differential_reference>")
            sections.append("")

        # Fix 150: threaded oracle. The harness must drive the target function
        # from multiple threads sharing state, so ThreadSanitizer can detect
        # data races / lock-order issues / atomicity bugs (CWE-362) — bug
        # classes that single-threaded harnesses categorically cannot reach.
        # Prompt-only: relies on `target.sanitizer_profile: tsan` for actual
        # race detection; without TSan the multi-threaded harness still runs
        # but races stay silent.
        if getattr(context.target, "threaded_oracle", False):
            sections.append("")
            sections.append("<threaded_oracle>")
            sections.append(
                "THREADED ORACLE TARGET — this harness MUST exercise the target "
                "function CONCURRENTLY from multiple threads:"
            )
            sections.append(
                "  1. Include <pthread.h>. Spawn at least 2 worker threads (4 is "
                "better) inside `LLVMFuzzerTestOneInput`."
            )
            sections.append(
                "  2. Each worker calls the SAME target function on either:"
            )
            sections.append(
                "     - the SAME shared input buffer (read-only race detection), OR"
            )
            sections.append(
                "     - a SHARED parser/codec instance created once before the threads "
                "start (this is the case that finds the most bugs — concurrent state "
                "mutation through a public 'thread-safe' API)."
            )
            sections.append(
                "  3. `pthread_join` every thread before returning from "
                "`LLVMFuzzerTestOneInput` so the next AFL iteration starts clean."
            )
            sections.append(
                "  4. Do NOT add your own locks around the target call. The whole "
                "point is to expose missing synchronisation INSIDE the library."
            )
            sections.append(
                "  5. If the library exposes a 'create N-thread context' API (e.g. "
                "OpenMP, libuv work queues), prefer that over raw pthreads — it "
                "exercises the library's own threading code paths."
            )
            sections.append(
                "  6. Free shared state after the join, on every iteration. "
                "Persistent-mode fuzzing will leak otherwise."
            )
            sections.append(
                "  7. Cap thread count at 8 — more threads slow AFL throughput "
                "without finding new races."
            )
            sections.append(
                "  8. Link with `-pthread`. This must appear in the build invocation; "
                "the existing harness-link path accepts extra link flags."
            )
            sections.append("</threaded_oracle>")
            sections.append("")

        # Fix 136: format-specific output invariants. The LLM must encode each
        # listed invariant as `if (!(cond)) abort();` inside the harness loop.
        # Use this to catch logic bugs that don't manifest as memory unsafety
        # (e.g. encoder that emits more bytes than its self-declared maximum).
        invariants = list(getattr(context.target, "output_invariants", []) or [])
        if invariants:
            sections.append("")
            sections.append("<output_invariants>")
            sections.append(
                "OUTPUT INVARIANTS — after each iteration of the fuzzing loop, the "
                "harness MUST verify the following boolean conditions hold and call "
                "`abort()` if any of them is false. These invariants encode "
                "format-specific safety properties beyond ASAN/UBSan reach."
            )
            for inv in invariants:
                sections.append(f"  - {inv}")
            sections.append(
                "Each check should be expressed as `if (!(condition)) abort();` "
                "and placed AFTER the operation that establishes the condition's "
                "operands. Do NOT skip these checks even if the operation 'looks' "
                "successful — the goal is exactly to catch silent violations."
            )
            sections.append("</output_invariants>")
            sections.append("")

        # Inject FDP header path hint so LLM knows the header is available
        templates_dir = Path(__file__).parent.parent / "templates"
        fdp_header = templates_dir / "fuzz_data_provider.h"
        if fdp_header.exists():
            sections.append(
                f"<fdp_header>{fdp_header}</fdp_header>\n"
                "FuzzedDataProvider is available via #include \"fuzz_data_provider.h\". "
                "Use it to slice the fuzz buffer into typed parameters."
            )
            sections.append("")

        # Inject magic_bytes for the target's input format (Fix B: precondition pruning)
        magic_bytes_map = getattr(context, "_magic_bytes_map", {})
        if not magic_bytes_map and hasattr(context.target, "_config"):
            magic_bytes_map = getattr(context.target._config, "magic_bytes", {})
        if magic_bytes_map:
            # Pick the most relevant format based on target file path
            fmt_guess = ""
            for fmt in magic_bytes_map:
                if fmt.lower() in context.target.file_path.lower():
                    fmt_guess = fmt
                    break
            if fmt_guess and magic_bytes_map.get(fmt_guess):
                magic_vals = magic_bytes_map[fmt_guess]
                if isinstance(magic_vals, list):
                    magic_str = ", ".join(repr(m) for m in magic_vals[:4])
                else:
                    magic_str = repr(magic_vals)
                sections.append(
                    f"<magic_bytes format=\"{fmt_guess}\">{magic_str}</magic_bytes>\n"
                    f"Use these magic bytes in your precondition guard: "
                    f"if (memcmp(buf, ..., N) != 0) continue;"
                )
                sections.append("")

        sections.append(
            "Generate an AFL++ persistent-mode fuzzing harness in C that:\n"
            "1. Reads from __AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN\n"
            "2. Follows the EXACT pattern specified in <target_specific_hint> above\n"
            "3. Cleans up all allocations between iterations\n"
            "4. Uses __AFL_LOOP(10000) for the main loop\n"
            "Also provide seed generation commands."
        )
        return "\n".join(sections)

    @staticmethod
    def build_refinement_prompt(
        context: AnalysisContext,
        feedback: FeedbackContext,
    ) -> str:
        """Build the refinement prompt with failure context."""
        sections = [
            f"<iteration>{feedback.iteration}</iteration>",
            f"<failure_reason>{feedback.failure_reason}</failure_reason>",
            "",
        ]

        # Target context — give the LLM the source code it's reasoning about
        sections.extend([
            "<target_function>",
            f"Function: {context.target.func_name}",
            f"File: {context.target.file_path}:{context.target.line}",
            "</target_function>",
            "",
            "<call_chain>",
            " → ".join(context.call_chain.chain),
        ])
        if context.call_chain.blockers:
            sections.append("Blockers:")
            for b in context.call_chain.blockers:
                sections.append(
                    f"  - [{b.blocker_type.value}] {b.condition} at {b.file_path}:{b.line}"
                )
        sections.append("</call_chain>")

        # Source snippets (primary target function only, capped to avoid token bloat)
        target_snippet = context.source_snippets.get(context.target.func_name, "")
        if target_snippet:
            sections.extend([
                "",
                "<source_code>",
                target_snippet[:3000],
                "</source_code>",
            ])

        # Full patch diff — not just file:line, show original → replacement
        p = feedback.original_proposal
        if p is not None:
            sections.extend([
                "",
                "<patch_that_failed>",
                f"File: {p.file_path}:{p.line}",
                f"Type: {p.patch_type}",
                f"Justification: {p.justification}",
                f"Risk: {p.risk_level.value}",
                "--- original",
                p.original,
                "+++ replacement",
                p.replacement,
                "</patch_that_failed>",
            ])

        # Harness that was compiled and run
        if feedback.harness_code:
            sections.extend([
                "",
                "<harness_that_failed>",
                feedback.harness_code[:2000],
                "</harness_that_failed>",
            ])

        # Coverage result
        sections.extend([
            "",
            "<coverage_result>",
            f"Expansion: {feedback.coverage_delta.total_expansion_pct:.2f}%",
            f"Success: {feedback.coverage_delta.success}",
            "</coverage_result>",
        ])

        # Full AFL stats
        s = feedback.afl_stats
        sections.extend([
            "",
            "<afl_stats>",
            f"Exec/sec: {s.exec_per_sec}",
            f"Total paths: {s.total_paths}",
            f"Unique crashes: {s.unique_crashes}",
            f"Unique hangs: {s.unique_hangs}",
            f"Duration: {s.duration_seconds}s",
            f"Map density: {s.map_density_pct:.1f}%",
            f"Stability: {s.stability_pct:.1f}%",
            "</afl_stats>",
        ])

        if feedback.error_log:
            sections.extend([
                "",
                "<error_log>",
                feedback.error_log[:2000],
                "</error_log>",
            ])

        sections.extend([
            "",
            "<task>",
            "The previous strategy FAILED. Analyze WHY using the data above and propose a revised approach.",
            "Key questions:",
            "1. Did the patch actually bypass the blocker? (check original→replacement)",
            "2. Does the harness reach the target code path?",
            "3. Is the input format correct for the target function?",
            "4. Are there other blockers in the call chain not yet addressed?",
            "Common issues: wrong input format, incomplete blocker bypass, missing library init,",
            "harness exits too early, AFL map density too low (harness not reaching code).",
            "</task>",
        ])

        return "\n".join(sections)

    @staticmethod
    def build_harness_refinement_prompt(
        context: AnalysisContext,
        feedback: FeedbackContext,
    ) -> str:
        """Build the harness refinement prompt for Strategy A (no patch info)."""
        sections = [
            f"<iteration>{feedback.iteration}</iteration>",
            f"<failure_reason>{feedback.failure_reason}</failure_reason>",
            "",
            "<target_function>",
            f"Function: {context.target.func_name}",
            f"File: {context.target.file_path}:{context.target.line}",
            "</target_function>",
            "",
            "<call_chain>",
            " → ".join(context.call_chain.chain),
        ]
        if context.call_chain.blockers:
            sections.append("Blockers in call chain:")
            for b in context.call_chain.blockers:
                sections.append(
                    f"  - [{b.blocker_type.value}] {b.condition} at {b.file_path}:{b.line}"
                )
        sections.append("</call_chain>")

        # Source snippets (target function only)
        target_snippet = context.source_snippets.get(context.target.func_name, "")
        if target_snippet:
            sections.extend([
                "",
                "<source_code>",
                target_snippet[:3000],
                "</source_code>",
            ])

        # Structured execution diagnostics (unambiguous execution state for the LLM)
        if feedback.diagnostics:
            d = feedback.diagnostics
            sections.extend([
                "",
                "<diagnostics>",
                f"compiled: {d.compiled}",
                f"compile_error_type: {d.compile_error_type!r}",
                f"function_reached: {d.function_reached}",
                f"function_coverage_pct: {d.function_coverage_pct:.1f}",
                f"corpus_paths: {d.corpus_paths}",
                f"map_density_pct: {d.map_density_pct:.2f}",
                f"input_size_bytes: {d.input_size_bytes}",
                f"likely_early_exit: {d.likely_early_exit}",
                "</diagnostics>",
            ])

        # Feature B: gcov line-level coverage annotation
        if feedback.gcov_annotation:
            sections.extend([
                "",
                "<line_coverage>",
                "Lines marked ##### were NEVER executed. Lines with counts were executed.",
                "Focus on WHY the ##### lines are not reached — which branch/check blocks them?",
                feedback.gcov_annotation[:4000],
                "</line_coverage>",
            ])

        # Harness that was compiled and run (key for Strategy A refinement)
        if feedback.harness_code:
            sections.extend([
                "",
                "<harness_that_failed>",
                feedback.harness_code[:2000],
                "</harness_that_failed>",
            ])

        # Coverage result
        sections.extend([
            "",
            "<coverage_result>",
            f"Expansion: {feedback.coverage_delta.total_expansion_pct:.2f}%",
            f"Success: {feedback.coverage_delta.success}",
            "</coverage_result>",
        ])

        # AFL stats
        s = feedback.afl_stats
        sections.extend([
            "",
            "<afl_stats>",
            f"Exec/sec: {s.exec_per_sec}",
            f"Total paths: {s.total_paths}",
            f"Unique crashes: {s.unique_crashes}",
            f"Unique hangs: {s.unique_hangs}",
            f"Duration: {s.duration_seconds}s",
            f"Map density: {s.map_density_pct:.1f}%",
            f"Stability: {s.stability_pct:.1f}%",
            "</afl_stats>",
        ])

        if feedback.error_log:
            sections.extend([
                "",
                "<error_log>",
                feedback.error_log[:2000],
                "</error_log>",
            ])

        sections.extend([
            "",
            "<task>",
            "The previous HARNESS failed to reach the target function adequately.",
            "The library source is UNMODIFIED — no patches. You must improve the harness.",
            "Use the <diagnostics> block above as your primary signal:",
            "  compiled=false → fix build errors (compile_error_type gives the category)",
            "  function_reached=false + likely_early_exit=true → harness exits before library",
            "  function_reached=false + likely_early_exit=false → wrong code path inside library",
            "  function_reached=true + function_coverage_pct<20% → need richer input structure",
            "Also check:",
            "1. Is the harness using the correct public API entry point?",
            "2. Is the input format correct? Does it include required magic bytes/headers?",
            "3. Is the initialization sequence complete (all required setup calls)?",
            "4. Is each AFL_LOOP iteration fully stateless (handles closed/freed/nulled)?",
            "5. Is a split-input pattern needed for targets that take multiple parameters?",
            "Propose a revised analysis with a better approach to reach the target function.",
            "</task>",
        ])

        return "\n".join(sections)
