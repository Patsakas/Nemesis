"""
Tests for project-specific cmake option() detection in the onboarder.

The onboarder emits `-D<OPT>=OFF` for options that build things we never fuzz
(tests, examples, tools, docs) and `-D<OPT>=ON` for the ones that give us a
static archive. Getting this wrong is not cosmetic: a default-ON test option
frequently drags in an external dependency, and cmake then fails at *configure*
time, so the target never builds at all.

The `_TESTING` suffix came from probing minmea, whose MINMEA_ENABLE_TESTING is
default-ON and calls pkg_check_modules(CHECK REQUIRED check) — configure aborts
on any machine without libcheck, even though nothing in the fuzzing path needs
it.
"""

from pathlib import Path

from nemesis.onboard import TargetOnboarder


def _flags(tmp_path: Path, cmake_body: str) -> list[str]:
    (tmp_path / "CMakeLists.txt").write_text(cmake_body)
    (tmp_path / "foo.c").write_text("int foo(void) { return 0; }\n")
    (tmp_path / "foo.h").write_text("int foo(void);\n")
    info = TargetOnboarder().detect_library_info(tmp_path, "foo")
    return info["extra_cmake_flags"].split()


# ── testing options ─────────────────────────────────────────


def test_enable_testing_turned_off(tmp_path: Path):
    """minmea: MINMEA_ENABLE_TESTING default-ON pulls in libcheck."""
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(MINMEA_ENABLE_TESTING "" ON)\n')
    assert "-DMINMEA_ENABLE_TESTING=OFF" in flags


def test_stock_build_testing_turned_off(tmp_path: Path):
    """cmake's own BUILD_TESTING, as used by CTest."""
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(BUILD_TESTING "" ON)\n')
    assert "-DBUILD_TESTING=OFF" in flags


def test_singular_test_suffix_turned_off(tmp_path: Path):
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(FOO_BUILD_TEST "" ON)\n')
    assert "-DFOO_BUILD_TEST=OFF" in flags


# ── singular example / benchmark suffixes ───────────────────


def test_singular_example_and_benchmark(tmp_path: Path):
    flags = _flags(
        tmp_path,
        "add_library(foo foo.c)\n"
        'option(FOO_BUILD_EXAMPLE "" ON)\n'
        'option(FOO_BENCHMARK "" ON)\n',
    )
    assert "-DFOO_BUILD_EXAMPLE=OFF" in flags
    assert "-DFOO_BENCHMARK=OFF" in flags


# ── false-positive guards ───────────────────────────────────


def test_latest_is_not_a_test_option(tmp_path: Path):
    """`_LATEST` ends in "TEST" but not in "_TEST" — it must not be disabled."""
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(FOO_USE_LATEST "" ON)\n')
    assert not any("FOO_USE_LATEST" in f for f in flags)


def test_static_still_turned_on(tmp_path: Path):
    """The ON branch must survive the additions to the OFF branch."""
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(FOO_BUILD_STATIC "" OFF)\n')
    assert "-DFOO_BUILD_STATIC=ON" in flags


def test_shared_and_examples_still_turned_off(tmp_path: Path):
    """Regression guard for the suffixes that already worked."""
    flags = _flags(
        tmp_path,
        "add_library(foo foo.c)\n"
        'option(FOO_SHARED "" ON)\n'
        'option(FOO_BUILD_EXAMPLES "" ON)\n'
        'option(FOO_TESTS "" ON)\n',
    )
    assert "-DFOO_SHARED=OFF" in flags
    assert "-DFOO_BUILD_EXAMPLES=OFF" in flags
    assert "-DFOO_TESTS=OFF" in flags


def test_build_shared_libs_left_alone(tmp_path: Path):
    """Handled by the standard configure line — must not be re-emitted here."""
    flags = _flags(tmp_path, 'add_library(foo foo.c)\noption(BUILD_SHARED_LIBS "" ON)\n')
    assert not any("BUILD_SHARED_LIBS" in f for f in flags)
