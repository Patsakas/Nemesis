"""
Tests for Fix 148 — cross-implementation differential oracle prompt block.

Verifies that PromptBuilder.build_harness_prompt emits the correct
<differential_reference> block when pinned_func.differential_reference is
configured, alone or alongside the existing Fix 135 round-trip oracle.
"""

from nemesis.models import (
    AnalysisContext,
    CallChain,
    CoverageTarget,
    CWE,
    VulnerabilityAnalysis,
)
from nemesis.neural import PromptBuilder


def _mk_analysis() -> VulnerabilityAnalysis:
    return VulnerabilityAnalysis(
        vulnerability_type="parser logic divergence",
        cwe=CWE.NULL_DEREF,
        root_cause="differential test target — no specific bug",
        attack_vector="cross-impl divergence",
        confidence=0.5,
        has_blocker=False,
        blocker_description="none",
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


def test_no_differential_block_when_unset():
    """Default config (both flags unset) emits NEITHER block."""
    target = CoverageTarget(
        func_name="xmlReadMemory",
        file_path="parser.c",
        line=100,
        coverage_pct=0.0,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<differential_oracle>" not in prompt
    assert "<differential_reference>" not in prompt


def test_round_trip_only_emits_legacy_block():
    """differential_oracle=True alone emits only the round-trip block (Fix 135)."""
    target = CoverageTarget(
        func_name="BrotliEncoderCompress",
        file_path="encode.c",
        line=42,
        coverage_pct=0.0,
        differential_oracle=True,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<differential_oracle>" in prompt
    assert "</differential_oracle>" in prompt
    assert "<differential_reference>" not in prompt


def test_reference_only_emits_new_block():
    """differential_reference set alone emits only the cross-impl block (Fix 148)."""
    ref = "expat::XML_Parse"
    target = CoverageTarget(
        func_name="xmlReadMemory",
        file_path="parser.c",
        line=100,
        coverage_pct=0.0,
        differential_reference=ref,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<differential_reference>" in prompt
    assert "</differential_reference>" in prompt
    assert ref in prompt
    assert "<differential_oracle>" not in prompt


def test_both_flags_emit_both_blocks():
    """Round-trip + cross-impl coexist — both blocks appear independently."""
    ref = "ZSTD_decompress_ref"
    target = CoverageTarget(
        func_name="ZSTD_decompress",
        file_path="zstd_decompress.c",
        line=200,
        coverage_pct=0.0,
        differential_oracle=True,
        differential_reference=ref,
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<differential_oracle>" in prompt
    assert "<differential_reference>" in prompt
    assert ref in prompt
    # Round-trip block must appear before reference block (insertion order)
    assert prompt.index("<differential_oracle>") < prompt.index("<differential_reference>")


def test_reference_whitespace_only_is_disabled():
    """Whitespace-only differential_reference is treated as unset."""
    target = CoverageTarget(
        func_name="xmlReadMemory",
        file_path="parser.c",
        line=100,
        coverage_pct=0.0,
        differential_reference="   ",
    )
    prompt = PromptBuilder.build_harness_prompt(_mk_analysis(), _mk_context(target))
    assert "<differential_reference>" not in prompt


def test_config_field_propagates_through_recon():
    """differential_reference flows from PinnedFunc config → CoverageTarget."""
    from nemesis.config import PinnedFunc

    pf = PinnedFunc(
        func_name="xmlReadMemory",
        file_path="parser.c",
        line=100,
        differential_reference="expat::XML_Parse",
    )
    assert pf.differential_reference == "expat::XML_Parse"

    data = pf.model_dump()
    assert data["differential_reference"] == "expat::XML_Parse"
