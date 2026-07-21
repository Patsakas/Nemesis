"""Tests for the validation-gate extractor and setter injector.

Covers the analyzer-loop behaviour exercised by
experiments/harness_autonomy/libpng/ — in particular the comment-matching bug
in inject_setter_calls' idempotency check, found while running that experiment.
"""
from pathlib import Path

from nemesis.recon.validation_gates import (
    ValidationGate,
    extract_validation_gates,
    inject_setter_calls,
)

# A minimal libpng-like setter, named idiomatically so it is injectable.
_GATE = ValidationGate(
    setter_name="png_set_user_limits",
    prototype="void png_set_user_limits(png_structrp png_ptr, png_uint_32 w, png_uint_32 h);",
    source_file="pngset.c",
)

_NAIVE = """int main(void){
  png_structp png_ptr = png_create_read_struct(V, 0, 0, 0);
  if (!png_ptr) return 2;
  png_read_info(png_ptr, info);
  return 0;
}
"""


def test_inject_adds_setter_to_naive_harness():
    out = inject_setter_calls(_NAIVE, [_GATE])
    assert "png_set_user_limits(png_ptr, 0x7FFFFFFFU, 0x7FFFFFFFU);" in out


def test_comment_mention_does_not_suppress_injection():
    """A setter named only in a COMMENT must not count as 'already present'."""
    commented = _NAIVE.replace(
        "png_read_info", "/* unlike png_set_user_limits() */ png_read_info"
    )
    out = inject_setter_calls(commented, [_GATE])
    # The real call must still be injected despite the comment mention.
    assert "png_set_user_limits(png_ptr, 0x7FFFFFFFU" in out


def test_real_call_present_is_idempotent():
    """If the setter is actually CALLED, injection must skip it (no duplicate)."""
    called = _NAIVE.replace(
        "png_read_info(png_ptr, info);",
        "png_set_user_limits(png_ptr, 100, 100);\n  png_read_info(png_ptr, info);",
    )
    out = inject_setter_calls(called, [_GATE])
    assert out.count("png_set_user_limits(") == 1


def test_extractor_finds_idiomatic_setter(tmp_path: Path):
    """extract_validation_gates picks up a _set_user_* definition, skips chunks."""
    (tmp_path / "pngset.c").write_text(
        "void png_set_user_limits(png_structrp p, png_uint_32 w, png_uint_32 h){ p->w=w; }\n"
        "void png_set_IHDR(png_structrp p, int x){ /* chunk setter, must be skipped */ }\n"
    )
    names = {g.setter_name for g in extract_validation_gates(tmp_path)}
    assert "png_set_user_limits" in names
    assert "png_set_IHDR" not in names  # PNG chunk suffix filtered out
