"""
Tests for Fix 154 — C++ project detection + find_package extraction.

Critical regression target: cJSON-style projects (only .c sources + heavy use
of set_target_properties) MUST stay detected as C, otherwise the build emits
-DCMAKE_CXX_FLAGS that nothing in the project compiles.
"""

from pathlib import Path

from nemesis.onboard import (
    _APT_HINT_MAP,
    _detect_cpp_project,
    _detect_findpackage_deps,
    _format_findpackage_comment,
)

# ── _detect_cpp_project ─────────────────────────────────────


def test_cpp_detected_via_cpp_source(tmp_path: Path):
    """A single .cpp file flips the project to C++."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.cpp").write_text("int main(){}\n")
    assert _detect_cpp_project(tmp_path) is True


def test_cpp_detected_via_cc_source(tmp_path: Path):
    """RE2-style .cc files count too."""
    (tmp_path / "re2.cc").write_text("namespace re2{}\n")
    assert _detect_cpp_project(tmp_path) is True


def test_lone_hpp_without_cmake_does_not_signal_cpp(tmp_path: Path):
    """Headers alone (.hpp/.hh/.hxx) are not enough — they false-positive
    on pure-C libraries that ship convenience C++ wrapper headers (see
    libsndfile/src/sndfile.hh wrapping the C API). Header-only C++ libs
    that genuinely want detection must declare CMAKE_CXX_STANDARD or
    cxx_std_NN in their CMakeLists. Without that declaration we stay
    conservative and treat the project as C."""
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.hpp").write_text("namespace x {}\n")
    assert _detect_cpp_project(tmp_path) is False


def test_header_only_cpp_via_cmake_signal(tmp_path: Path):
    """Header-only C++ project DOES still detect as C++ when CMakeLists
    declares CMAKE_CXX_STANDARD — the cmake-token fallback covers this
    case so genuine header-only C++ libs (Catch2-style) aren't lost."""
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.hpp").write_text("namespace x {}\n")
    (tmp_path / "CMakeLists.txt").write_text(
        'set(CMAKE_CXX_STANDARD 17)\n'
        'add_library(api INTERFACE)\n'
    )
    assert _detect_cpp_project(tmp_path) is True


def test_c_lib_with_cpp_wrapper_header_stays_c(tmp_path: Path):
    """REGRESSION (libsndfile): C library that ships a single .hh wrapper
    next to the C API header must stay detected as C, otherwise the build
    emits -lstdc++ and the LLM gets a misleading 'C++ project' signal in
    the prompt. Concretely: src/sndfile.h.in + src/sndfile.hh from
    libsndfile 1.0.28."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sndfile.h.in").write_text(
        "int sf_open(const char *path);\n"
    )
    (tmp_path / "src" / "sndfile.hh").write_text(
        "class SndfileHandle {};\n"
    )
    (tmp_path / "src" / "sndfile.c").write_text(
        "int sf_open(const char *p){return 0;}\n"
    )
    assert _detect_cpp_project(tmp_path) is False


def test_programs_dir_cpp_does_not_signal_cpp(tmp_path: Path):
    """REGRESSION (libsndfile): a single .cpp consumer in programs/ —
    `programs/sndfile-play-beos.cpp` — must not flip the LIBRARY to
    C++. Same applies to tools/, cli/, octave/, python/, bindings/."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "core.c").write_text("int x(){return 0;}\n")
    for binding_dir in ("programs", "Octave", "python", "bindings"):
        (tmp_path / binding_dir).mkdir()
        (tmp_path / binding_dir / "consumer.cpp").write_text(
            "int main(){return 0;}\n"
        )
    assert _detect_cpp_project(tmp_path) is False


def test_c_lib_with_inline_cxx_wrapper_stays_c(tmp_path: Path):
    """REGRESSION (libtiff): the core source dir ships one C++ wrapper
    next to many C files — libtiff/tif_stream.cxx alongside 50+ .c files.
    The ratio heuristic must keep this detected as C, otherwise build
    emits -DCMAKE_CXX_FLAGS that nothing uses + -lstdc++ in link_libs."""
    core = tmp_path / "libtiff"
    core.mkdir()
    # 30 .c files (well above the 10x threshold for 1 .cxx)
    for i in range(30):
        (core / f"tif_{i}.c").write_text(f"int f_{i}(){{return {i};}}\n")
    # One C++ wrapper of the C API — must NOT flip the project to C++
    (core / "tif_stream.cxx").write_text(
        "extern \"C\" {\n#include \"tiffio.h\"\n}\n"
        "class TiffStream {};\n"
    )
    assert _detect_cpp_project(tmp_path) is False


def test_balanced_c_cxx_does_signal_cpp(tmp_path: Path):
    """When .cpp/.cc/.cxx are NOT vastly outnumbered by .c (ratio < 10),
    treat as C++. This is what flatbuffers/abseil-style mixed-language
    libraries look like — they want -lstdc++ on the link line."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"a_{i}.c").write_text("int x(){return 0;}\n")
    for i in range(5):
        (src / f"b_{i}.cpp").write_text("int y(){return 0;}\n")
    assert _detect_cpp_project(tmp_path) is True


def test_build_artefact_cpp_does_not_signal_cpp(tmp_path: Path):
    """REGRESSION: CMake drops CMakeCXXCompilerId.cpp into every
    CMakeFiles/<ver>/ tree under build_*/ — even for pure-C projects.
    These NEMESIS-created subtrees must not flip language detection."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.c").write_text("int f(){return 0;}\n")
    for build_dir in ("build_debug", "build_ubsan", "build_coverage"):
        cmf = tmp_path / build_dir / "CMakeFiles" / "3.28.3" / "CompilerIdCXX"
        cmf.mkdir(parents=True)
        (cmf / "CMakeCXXCompilerId.cpp").write_text("int main(){return 0;}\n")
    assert _detect_cpp_project(tmp_path) is False


def test_pure_c_project_not_cpp(tmp_path: Path):
    """cJSON-style: only .c + .h files, no C++."""
    (tmp_path / "cJSON.c").write_text("int parse(){return 0;}\n")
    (tmp_path / "cJSON.h").write_text("int parse(void);\n")
    assert _detect_cpp_project(tmp_path) is False


def test_cmake_set_target_properties_alone_does_not_signal_cpp(tmp_path: Path):
    """REGRESSION: cJSON uses set_target_properties heavily. Must stay C."""
    (tmp_path / "main.c").write_text("int main(){return 0;}\n")
    (tmp_path / "CMakeLists.txt").write_text(
        'project(cjson C)\n'
        'add_library(cjson STATIC main.c)\n'
        'set_target_properties(cjson PROPERTIES OUTPUT_NAME "cjson")\n'
        'set_target_properties(cjson PROPERTIES PREFIX "lib")\n'
    )
    assert _detect_cpp_project(tmp_path) is False


def test_cmake_cxx_standard_signals_cpp(tmp_path: Path):
    """Explicit CMAKE_CXX_STANDARD is unambiguous C++."""
    (tmp_path / "main.c").write_text("int main(){return 0;}\n")  # red herring
    (tmp_path / "CMakeLists.txt").write_text(
        'set(CMAKE_CXX_STANDARD 17)\n'
        'add_executable(app main.c)\n'
    )
    assert _detect_cpp_project(tmp_path) is True


def test_cmake_cxx_std_target_feature_signals_cpp(tmp_path: Path):
    """target_compile_features(... cxx_std_17) is unambiguous C++."""
    (tmp_path / "CMakeLists.txt").write_text(
        'add_library(x x.c)\n'
        'target_compile_features(x PUBLIC cxx_std_17)\n'
    )
    assert _detect_cpp_project(tmp_path) is True


def test_skips_test_dirs(tmp_path: Path):
    """C++ files inside test/ should not flip a pure-C project."""
    (tmp_path / "lib.c").write_text("int parse(){return 0;}\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "tests.cpp").write_text("int main(){}\n")
    assert _detect_cpp_project(tmp_path) is False


def test_nonexistent_source_root(tmp_path: Path):
    """Missing source root returns False without raising."""
    assert _detect_cpp_project(tmp_path / "does_not_exist") is False


# ── _detect_findpackage_deps ────────────────────────────────


def test_findpackage_extracts_from_cmakelists(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        'find_package(absl REQUIRED)\n'
        'find_package(ICU REQUIRED)\n'
        'find_package(Threads REQUIRED)\n'
    )
    deps = _detect_findpackage_deps(tmp_path)
    assert "absl" in deps
    assert "ICU" in deps
    assert "Threads" in deps


def test_findpackage_dedups(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text('find_package(ZLIB REQUIRED)\n')
    (tmp_path / "cmake").mkdir()
    (tmp_path / "cmake" / "deps.cmake").write_text('find_package(ZLIB REQUIRED)\n')
    deps = _detect_findpackage_deps(tmp_path)
    assert deps.count("ZLIB") == 1


def test_findpackage_skips_test_dirs(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "CMakeLists.txt").write_text('find_package(GTest REQUIRED)\n')
    deps = _detect_findpackage_deps(tmp_path)
    assert "GTest" not in deps


def test_findpackage_empty_for_no_cmake(tmp_path: Path):
    (tmp_path / "lib.c").write_text("int x;\n")
    assert _detect_findpackage_deps(tmp_path) == []


# ── _format_findpackage_comment ─────────────────────────────


def test_comment_renders_known_pkgs():
    text = _format_findpackage_comment(["absl", "ICU"])
    assert "External dependencies" in text
    assert "libabsl-dev" in text
    assert "libicu-dev" in text
    assert "Bulk install" in text


def test_comment_skips_threads_builtin():
    """Threads is in libc — should not appear in apt install hint."""
    text = _format_findpackage_comment(["Threads"])
    assert "Threads" not in text or "(builtin)" not in text  # filtered out
    assert "Bulk install" not in text  # no apt pkgs to install


def test_comment_handles_unknown_pkg():
    """Unknown find_package targets get a generic hint."""
    text = _format_findpackage_comment(["WeirdLib"])
    assert "WeirdLib" in text
    assert "no apt hint" in text


def test_comment_empty_when_no_deps():
    assert _format_findpackage_comment([]) == ""


# ── _APT_HINT_MAP coverage check ────────────────────────────


def test_apt_hint_map_covers_common_deps():
    """All entries in _FIND_PACKAGE_MAP should also exist in _APT_HINT_MAP
    so the user always sees an install hint."""
    from nemesis.onboard import _FIND_PACKAGE_MAP
    for pkg in _FIND_PACKAGE_MAP:
        # CMath is "(builtin)" via libm in libc — no separate dev package
        if pkg == "CMath":
            continue
        assert pkg in _APT_HINT_MAP, f"{pkg} missing apt hint"
