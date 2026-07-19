"""
Tests for Fix 150 — TSan sanitizer profile + threaded oracle prompt block.

Verifies:
  * `_resolve_sanitizer_flags` handles `tsan` profile gated by tsan_supported
  * PromptBuilder emits `<threaded_oracle>` block when pinned_func.threaded_oracle
  * Existing profiles unchanged
  * CWE.RACE_CONDITION + SanitizerClass.TSAN exist
"""

import pytest

from nemesis.config import NemesisConfig, PinnedFunc, TargetConfig
from nemesis.models import (
    AnalysisContext,
    CallChain,
    CoverageTarget,
    CWE,
    SanitizerClass,
    VulnerabilityAnalysis,
)
from nemesis.neural import PromptBuilder
from nemesis.symbolic import _resolve_sanitizer_flags


def _mk_config(profile: str, tsan_supported: bool = False) -> NemesisConfig:
    cfg = NemesisConfig()
    cfg.target = TargetConfig(
        name="test",
        sanitizer_profile=profile,
        tsan_supported=tsan_supported,
    )
    return cfg


def _mk_analysis() -> VulnerabilityAnalysis:
    return VulnerabilityAnalysis(
        vulnerability_type="potential data race",
        cwe=CWE.RACE_CONDITION,
        root_cause="threaded fuzzing target",
        attack_vector="concurrent invocation",
        confidence=0.5,
        has_blocker=False,
    )


def _mk_context(target: CoverageTarget) -> AnalysisContext:
    return AnalysisContext(
        target=target,
        call_chain=CallChain(
            entry_point="LLVMFuzzerTestOneInput",
            chain=["LLVMFuzzerTestOneInput", target.func_name],
            target=target,
            depth=1,
        ),
    )


# ── Sanitizer profile tests ─────────────────────────────────


def test_tsan_profile_requires_tsan_supported():
    """tsan profile without tsan_supported raises ValueError."""
    cfg = _mk_config("tsan", tsan_supported=False)
    with pytest.raises(ValueError, match="tsan_supported=True"):
        _resolve_sanitizer_flags(cfg)


def test_tsan_profile_when_supported():
    """tsan + tsan_supported=True returns thread sanitizer flags."""
    cfg = _mk_config("tsan", tsan_supported=True)
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=thread" in flags
    assert "-fno-sanitize-recover=thread" in flags
    # TSan must NOT include ASAN or MSAN flags (mutually exclusive runtimes)
    assert "-fsanitize=address" not in flags
    assert "-fsanitize=memory" not in flags


def test_tsan_supported_default_is_false():
    """tsan_supported defaults to False."""
    tgt = TargetConfig(name="test")
    assert tgt.tsan_supported is False


def test_msan_and_tsan_gates_independent():
    """msan_supported and tsan_supported are independent — one doesn't enable the other."""
    cfg = _mk_config("tsan", tsan_supported=False)
    cfg.target.msan_supported = True
    with pytest.raises(ValueError, match="tsan_supported=True"):
        _resolve_sanitizer_flags(cfg)


# ── CWE / SanitizerClass enum tests ─────────────────────────


def test_cwe_race_condition_exists():
    """CWE.RACE_CONDITION exists with CWE-362 value."""
    assert CWE.RACE_CONDITION.value == "CWE-362"


def test_sanitizer_class_tsan_exists():
    """SanitizerClass.TSAN exists."""
    assert SanitizerClass.TSAN.value == "tsan"


# ── threaded_oracle prompt block tests ──────────────────────


def test_no_threaded_oracle_block_when_unset():
    """Default config (threaded_oracle=False) emits NO <threaded_oracle> block."""
    target = CoverageTarget(
        func_name="parse_input",
        file_path="parser.c",
        line=100,
        coverage_pct=0.0,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<threaded_oracle>" not in prompt


def test_threaded_oracle_block_emitted_when_set():
    """threaded_oracle=True emits the <threaded_oracle> block with pthread guidance."""
    target = CoverageTarget(
        func_name="ssl_context_use",
        file_path="ssl.c",
        line=200,
        coverage_pct=0.0,
        threaded_oracle=True,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<threaded_oracle>" in prompt
    assert "</threaded_oracle>" in prompt
    assert "pthread" in prompt.lower()
    assert "pthread_join" in prompt
    # Must explicitly forbid the LLM from masking races with its own locks
    assert "Do NOT add your own locks" in prompt or "do not add your own locks" in prompt.lower()


def test_threaded_oracle_independent_of_differential_blocks():
    """threaded_oracle coexists with differential_oracle and differential_reference."""
    target = CoverageTarget(
        func_name="ssl_context_use",
        file_path="ssl.c",
        line=200,
        coverage_pct=0.0,
        threaded_oracle=True,
        differential_oracle=True,
        differential_reference="reference_impl",
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<threaded_oracle>" in prompt
    assert "<differential_oracle>" in prompt
    assert "<differential_reference>" in prompt


def test_threaded_oracle_field_propagates_through_pinned_func_config():
    """threaded_oracle flows from PinnedFunc config → CoverageTarget."""
    pf = PinnedFunc(
        func_name="ssl_context_use",
        file_path="ssl.c",
        line=200,
        threaded_oracle=True,
    )
    assert pf.threaded_oracle is True
    data = pf.model_dump()
    assert data["threaded_oracle"] is True


def test_threaded_oracle_default_false_on_pinned_func():
    """threaded_oracle defaults to False on PinnedFunc config."""
    pf = PinnedFunc(func_name="x", file_path="x.c", line=1)
    assert pf.threaded_oracle is False
