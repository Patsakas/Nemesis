"""Basic tests for NEMESIS configuration and models."""

from pathlib import Path

from nemesis.config import NemesisConfig, load_config
from nemesis.models import (
    AppReproStatus,
    CoverageTarget,
    CallChain,
    PatchProposal,
    CrashReport,
    CWE,
    Severity,
    RiskLevel,
    PipelineRun,
)


def test_default_config():
    """Config loads with sane defaults even without YAML files."""
    cfg = NemesisConfig()
    assert cfg.engine.max_feedback_iterations == 3
    assert cfg.llm.model == "claude-sonnet-4-20250514"
    assert cfg.fuzzing.instances == 4
    assert cfg.symbolic.solver == "z3"


def test_config_from_yaml(tmp_path):
    """Config loads and merges YAML files."""
    default = tmp_path / "default.yaml"
    default.write_text("""
engine:
  max_feedback_iterations: 5
  log_level: DEBUG
llm:
  model: claude-sonnet-4-20250514
""")

    target = tmp_path / "target.yaml"
    target.write_text("""
target:
  name: libarchive
  source_root: /tmp/libarchive
engine:
  max_feedback_iterations: 10
""")

    cfg = load_config(default_path=default, target_path=target)
    assert cfg.engine.max_feedback_iterations == 10  # overridden
    assert cfg.engine.log_level == "DEBUG"  # from default
    assert cfg.target.name == "libarchive"  # from target


def test_coverage_target_model():
    """CoverageTarget model validates correctly."""
    target = CoverageTarget(
        func_name="cab_checksum_finish",
        file_path="archive_read_support_format_cab.c",
        line=1155,
        coverage_pct=0.0,
        has_memory_ops=False,
        has_pointer_arith=True,
    )
    assert target.func_name == "cab_checksum_finish"
    assert target.has_pointer_arith is True

    # Serialization roundtrip
    data = target.model_dump()
    restored = CoverageTarget(**data)
    assert restored == target


def test_crash_report_model():
    """CrashReport model with Bug 3 ground truth data."""
    report = CrashReport(
        input_file="/tmp/crash_cab",
        crash_location="archive_read_support_format_cab.c:1179",
        stack_trace=[
            "cab_checksum_finish at cab.c:1179",
            "cab_minimum_consume_cfdata at cab.c:1906",
        ],
        cwe=CWE.NULL_DEREF,
        severity=Severity.MEDIUM,
        asan_output="SIGILL on unknown address",
        app_repro=AppReproStatus.CONFIRMED,
        proposed_fix="Add NULL check for cfdata->memimage",
    )
    assert report.cwe == CWE.NULL_DEREF
    assert report.reproduces_in_app is True

    # JSON serialization
    json_str = report.model_dump_json()
    assert "CWE-476" in json_str


def test_patch_proposal_model():
    """PatchProposal for Bug 3 fix."""
    patch = PatchProposal(
        file_path="libarchive/archive_read_support_format_cab.c",
        line=1179,
        original="cfdata->memimage + CFDATA_cbData",
        replacement=(
            "if (cfdata->memimage == NULL) return ARCHIVE_FATAL;\n"
            "cfdata->memimage + CFDATA_cbData"
        ),
        justification="Prevent NULL pointer arithmetic",
        risk_level=RiskLevel.SAFE,
        patch_type="null_guard",
    )
    assert patch.risk_level == RiskLevel.SAFE
    assert patch.patch_type == "null_guard"


def test_pipeline_run_serialization():
    """PipelineRun serializes to JSON for persistence."""
    run = PipelineRun(
        run_id="test123",
        targets_processed=3,
        targets_successful=2,
        total_crashes=5,
    )
    json_str = run.model_dump_json(indent=2)
    assert "test123" in json_str
    assert '"total_crashes": 5' in json_str


def test_cwe_enum_values():
    """CWE enum has correct string values."""
    assert CWE.NULL_DEREF.value == "CWE-476"
    assert CWE.HEAP_OVERFLOW.value == "CWE-122"
    assert CWE("CWE-476") == CWE.NULL_DEREF
