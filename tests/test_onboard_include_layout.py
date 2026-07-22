"""
Tests for include_subdir / header detection in the onboarder.

Header detection is load-bearing: when it finds nothing, `detect_library_info`
returns harness_includes=[] and the onboarder logs `onboard.no_headers` and
leaves harness_template as a TODO — the LLM is never even called, so the run
"succeeds" in 6 seconds and produces an unusable config. That failure is silent
from the exit code's point of view, which is why each supported layout gets a
test here.

The `inc/` case came from probing embedded-nmea-0183 (maritime NMEA 0183
parser), whose public headers sit at inc/nmea.h. That is the dominant
convention in firmware/RTOS trees, so it matters for the whole embedded target
class, not just this one library.
"""

from pathlib import Path

from nemesis.onboard import TargetOnboarder

LIB_C = "int foo(void) { return 0; }\n"


def _mk(tmp_path: Path, header_dir: str, header: str = "nmea.h") -> Path:
    """Minimal cmake project whose only public header lives at header_dir/."""
    (tmp_path / "CMakeLists.txt").write_text("add_library(nmea nmea.c)\n")
    (tmp_path / "nmea.c").write_text(LIB_C)
    d = tmp_path / header_dir if header_dir else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    (d / header).write_text("int foo(void);\n")
    return tmp_path


# ── inc/ (embedded convention) ──────────────────────────────


def test_inc_dir_detected(tmp_path: Path):
    """embedded-nmea-0183 layout: headers at inc/, no include/ at all.

    Before this was supported the onboarder reported no_headers and skipped
    harness_template generation entirely.
    """
    info = TargetOnboarder().detect_library_info(_mk(tmp_path, "inc"), "nmea")
    assert info["include_subdir"] == "inc"
    assert "nmea.h" in info["harness_includes"]


def test_inc_capitalised_detected(tmp_path: Path):
    """ST/CubeMX-style trees capitalise it as Inc/."""
    info = TargetOnboarder().detect_library_info(_mk(tmp_path, "Inc"), "nmea")
    assert info["include_subdir"] == "Inc"


def test_inc_name_variant_subdir(tmp_path: Path):
    """inc/{project}/ nests one level deeper, like include/{project}/."""
    info = TargetOnboarder().detect_library_info(_mk(tmp_path, "inc/nmea"), "nmea")
    assert info["include_subdir"] == "inc/nmea"


# ── precedence ──────────────────────────────────────────────


def test_include_wins_over_inc(tmp_path: Path):
    """A project shipping both keeps the standard include/ path: inc/ is the
    fallback convention, not the preferred one."""
    root = _mk(tmp_path, "include")
    (root / "inc").mkdir()
    (root / "inc" / "nmea.h").write_text("int foo(void);\n")
    info = TargetOnboarder().detect_library_info(root, "nmea")
    assert info["include_subdir"] == "include"


def test_inc_wins_over_src(tmp_path: Path):
    """inc/ ranks above src/ — src/ holds implementation headers far more often
    than public ones, so preferring it would pick the wrong API surface."""
    root = _mk(tmp_path, "inc")
    (root / "src").mkdir()
    (root / "src" / "nmea_internal.h").write_text("int bar(void);\n")
    info = TargetOnboarder().detect_library_info(root, "nmea")
    assert info["include_subdir"] == "inc"


# ── regression guard for the layouts that already worked ────


def test_existing_layouts_still_detected(tmp_path: Path):
    """inc/ was inserted mid-list; make sure it did not displace include/."""
    info = TargetOnboarder().detect_library_info(_mk(tmp_path, "include"), "nmea")
    assert info["include_subdir"] == "include"
