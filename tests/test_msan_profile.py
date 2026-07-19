"""
Tests for Fix 149 — MSan sanitizer profile.

Verifies _resolve_sanitizer_flags() correctly handles the new 'msan' profile,
gates it behind target.msan_supported, and leaves existing profiles unchanged.
"""

import pytest

from nemesis.config import NemesisConfig, TargetConfig
from nemesis.symbolic import _resolve_sanitizer_flags


def _mk_config(profile: str, msan_supported: bool = False) -> NemesisConfig:
    cfg = NemesisConfig()
    cfg.target = TargetConfig(
        name="test",
        sanitizer_profile=profile,
        msan_supported=msan_supported,
    )
    return cfg


def test_default_profile_is_asan_ubsan():
    """Empty profile string falls back to asan_ubsan with recover-off."""
    cfg = _mk_config("")
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=address,undefined" in flags
    assert "-fno-sanitize-recover=undefined" in flags
    assert "-fsanitize=memory" not in flags


def test_asan_only_profile():
    """asan_only returns ASAN without UBSan."""
    cfg = _mk_config("asan_only")
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=address" in flags
    assert "undefined" not in flags
    assert "memory" not in flags


def test_asan_ubsan_strict_profile():
    """asan_ubsan_strict adds integer + implicit-conversion checks."""
    cfg = _mk_config("asan_ubsan_strict")
    flags = _resolve_sanitizer_flags(cfg)
    assert "integer" in flags
    assert "implicit-conversion" in flags
    assert "-fno-sanitize-recover=undefined,integer,implicit-conversion" in flags


def test_msan_profile_requires_msan_supported():
    """msan profile without msan_supported raises ValueError."""
    cfg = _mk_config("msan", msan_supported=False)
    with pytest.raises(ValueError, match="msan_supported=True"):
        _resolve_sanitizer_flags(cfg)


def test_msan_profile_when_supported():
    """msan + msan_supported=True returns MSan flags with track-origins."""
    cfg = _mk_config("msan", msan_supported=True)
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=memory" in flags
    assert "-fsanitize-memory-track-origins=2" in flags
    assert "-fno-sanitize-recover=memory" in flags
    # MSan must NOT include ASAN flags (mutually exclusive runtimes)
    assert "-fsanitize=address" not in flags
    assert "undefined" not in flags


def test_msan_supported_default_is_false():
    """msan_supported defaults to False to prevent accidental MSan runs."""
    tgt = TargetConfig(name="test")
    assert tgt.msan_supported is False


def test_msan_supported_alone_does_not_change_default_profile():
    """Setting msan_supported=True without sanitizer_profile=msan keeps default."""
    cfg = _mk_config("asan_ubsan", msan_supported=True)
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=address,undefined" in flags
    assert "memory" not in flags


def test_unknown_profile_falls_through_to_default():
    """An unrecognized profile string falls through to the asan_ubsan default."""
    cfg = _mk_config("not_a_real_profile")
    flags = _resolve_sanitizer_flags(cfg)
    assert "-fsanitize=address,undefined" in flags
