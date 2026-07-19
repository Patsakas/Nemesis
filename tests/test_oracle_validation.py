"""
Tests for Fix 151 — cross-config oracle validation.
"""

from pathlib import Path

from nemesis.config import NemesisConfig, PinnedFunc, TargetConfig
from nemesis.recon.oracle_validation import (
    OracleWarning,
    validate_oracle_config,
)


def _mk_config(
    profile: str = "asan_ubsan",
    pinned: list[PinnedFunc] | None = None,
    source_root: Path | None = None,
    msan_supported: bool = False,
    tsan_supported: bool = False,
) -> NemesisConfig:
    cfg = NemesisConfig()
    cfg.target = TargetConfig(
        name="test",
        sanitizer_profile=profile,
        pinned_funcs=pinned or [],
        source_root=source_root or Path("."),
        msan_supported=msan_supported,
        tsan_supported=tsan_supported,
    )
    return cfg


def _has_warning(warnings: list[OracleWarning], key: str) -> bool:
    return any(w.key == key for w in warnings)


def test_default_config_is_clean():
    """Default config produces no oracle warnings."""
    cfg = _mk_config()
    assert validate_oracle_config(cfg) == []


def test_tsan_without_any_threaded_oracle_warns():
    """TSan profile with no threaded_oracle pin → warning."""
    cfg = _mk_config(
        profile="tsan",
        tsan_supported=True,
        pinned=[PinnedFunc(func_name="foo", file_path="x.c", line=1)],
    )
    warnings = validate_oracle_config(cfg)
    assert _has_warning(warnings, "tsan_without_threaded_oracle")


def test_tsan_with_threaded_oracle_is_clean():
    """TSan profile with at least one threaded_oracle pin → no warning."""
    cfg = _mk_config(
        profile="tsan",
        tsan_supported=True,
        pinned=[
            PinnedFunc(func_name="foo", file_path="x.c", line=1, threaded_oracle=True),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert not _has_warning(warnings, "tsan_without_threaded_oracle")


def test_threaded_oracle_without_tsan_warns():
    """threaded_oracle pin under non-tsan profile → warning."""
    cfg = _mk_config(
        profile="asan_ubsan",
        pinned=[
            PinnedFunc(func_name="foo", file_path="x.c", line=1, threaded_oracle=True),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert _has_warning(warnings, "threaded_oracle_without_tsan")
    msg = next(w for w in warnings if w.key == "threaded_oracle_without_tsan").message
    assert "foo" in msg


def test_threaded_oracle_with_tsan_is_clean():
    """threaded_oracle pin under tsan profile → no mismatch warning."""
    cfg = _mk_config(
        profile="tsan",
        tsan_supported=True,
        pinned=[
            PinnedFunc(func_name="foo", file_path="x.c", line=1, threaded_oracle=True),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert not _has_warning(warnings, "threaded_oracle_without_tsan")


def test_differential_reference_missing_symbol_warns(tmp_path: Path):
    """differential_reference pointing to a non-existent symbol → warning."""
    src_file = tmp_path / "lib.c"
    src_file.write_text("int real_func(void) { return 0; }\n")
    cfg = _mk_config(
        source_root=tmp_path,
        pinned=[
            PinnedFunc(
                func_name="foo",
                file_path="x.c",
                line=1,
                differential_reference="totally_made_up_symbol",
            ),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert _has_warning(warnings, "differential_reference_not_found")


def test_differential_reference_found_in_tree_is_clean(tmp_path: Path):
    """differential_reference symbol present in source → no warning."""
    src_file = tmp_path / "lib.c"
    src_file.write_text("int reference_impl(void) { return 0; }\n")
    cfg = _mk_config(
        source_root=tmp_path,
        pinned=[
            PinnedFunc(
                func_name="foo",
                file_path="x.c",
                line=1,
                differential_reference="reference_impl",
            ),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert not _has_warning(warnings, "differential_reference_not_found")


def test_namespaced_reference_strips_namespace(tmp_path: Path):
    """C++-style namespaced reference 'expat::XML_Parse' is checked by bare name."""
    src_file = tmp_path / "lib.c"
    src_file.write_text("int XML_Parse(void) { return 0; }\n")
    cfg = _mk_config(
        source_root=tmp_path,
        pinned=[
            PinnedFunc(
                func_name="foo",
                file_path="x.c",
                line=1,
                differential_reference="expat::XML_Parse",
            ),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert not _has_warning(warnings, "differential_reference_not_found")


def test_warning_includes_actionable_suggestion():
    """Every emitted OracleWarning carries a non-empty suggestion."""
    cfg = _mk_config(
        profile="asan_ubsan",
        pinned=[
            PinnedFunc(func_name="foo", file_path="x.c", line=1, threaded_oracle=True),
        ],
    )
    warnings = validate_oracle_config(cfg)
    assert warnings, "expected at least one warning"
    for w in warnings:
        assert w.suggestion.strip(), f"warning {w.key} missing suggestion"
