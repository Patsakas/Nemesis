"""
Tests for the meson build path in the onboarder.

`detect_build_system` already returned "meson" before this work, but nothing
consumed it — `generate_build_commands` raised NotImplementedError and the
generated YAML carried a "# TODO" placeholder instead of build commands, so a
meson-only project onboarded successfully and then failed at the first build.

Critical invariants:
  - meson is only chosen when cmake and autotools are both absent (cmake stays
    the most-exercised path);
  - the emitted setup command uses --buildtype=plain, otherwise meson appends
    its own -O flags after ours and the coverage build silently loses -O0;
  - disable flags are emitted ONLY for options the project actually declares,
    because meson aborts setup on an unknown -Doption.
"""

from pathlib import Path

from nemesis.onboard import TargetOnboarder

# ── detect_build_system ─────────────────────────────────────


def test_meson_only_project_detected(tmp_path: Path):
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    assert TargetOnboarder().detect_build_system(tmp_path) == "meson"


def test_cmake_wins_over_meson(tmp_path: Path):
    """A project shipping both takes the cmake path — it is the most-exercised
    branch, and meson support exists for meson-ONLY projects."""
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    (tmp_path / "CMakeLists.txt").write_text("add_library(foo foo.c)\n")
    assert TargetOnboarder().detect_build_system(tmp_path) == "cmake"


def test_autoconf_wins_over_meson(tmp_path: Path):
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    (tmp_path / "configure.ac").write_text("AC_INIT([foo],[1.0])\n")
    assert TargetOnboarder().detect_build_system(tmp_path) == "autoconf"


# ── _detect_meson_lib ───────────────────────────────────────


def test_meson_lib_from_root(tmp_path: Path):
    (tmp_path / "meson.build").write_text(
        "project('foo', 'c')\n"
        "libfoo = library('foo', 'foo.c')\n"
    )
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("", "foo")


def test_meson_lib_in_subdir(tmp_path: Path):
    """Library declared in src/meson.build → the archive lands at src/libfoo.a
    in the build tree, because meson mirrors the source layout."""
    (tmp_path / "meson.build").write_text("project('foo', 'c')\nsubdir('src')\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "meson.build").write_text(
        "libfoo = static_library('foo', 'foo.c')\n"
    )
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("src", "foo")


def test_meson_lib_computed_name_falls_back_to_project(tmp_path: Path):
    """`library(meson.project_name(), ...)` is a very common meson idiom. The
    name isn't a string literal, so we resolve it from project()."""
    (tmp_path / "meson.build").write_text("project('webp', 'c')\nsubdir('src')\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "meson.build").write_text(
        "libwebp = library(meson.project_name(), sources)\n"
    )
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("src", "webp")


def test_meson_lib_prefers_topmost(tmp_path: Path):
    """Shortest path wins → the core library, not a helper sublib."""
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "meson.build").write_text("library('core', 'a.c')\n")
    (tmp_path / "src" / "helper").mkdir()
    (tmp_path / "src" / "helper" / "meson.build").write_text(
        "library('helper', 'h.c')\n"
    )
    assert TargetOnboarder()._detect_meson_lib(tmp_path)[1] == "core"


def test_meson_lib_skips_test_dirs(tmp_path: Path):
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "meson.build").write_text("library('testhelper', 't.c')\n")
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("", "")


def test_meson_lib_skips_subprojects(tmp_path: Path):
    """subprojects/ holds vendored deps (meson's wrap system) — never the
    library we're onboarding."""
    (tmp_path / "meson.build").write_text("project('foo', 'c')\n")
    vendored = tmp_path / "subprojects" / "zlib"
    vendored.mkdir(parents=True)
    (vendored / "meson.build").write_text("library('z', 'z.c')\n")
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("", "")


def test_meson_lib_none_when_no_library_call(tmp_path: Path):
    """An executable-only meson project has nothing to link a harness against."""
    (tmp_path / "meson.build").write_text(
        "project('tool', 'c')\nexecutable('tool', 'main.c')\n"
    )
    assert TargetOnboarder()._detect_meson_lib(tmp_path) == ("", "")


# ── _detect_meson_disable_flags ─────────────────────────────


def test_meson_disable_flags_boolean_and_feature(tmp_path: Path):
    (tmp_path / "meson_options.txt").write_text(
        "option('tests', type: 'boolean', value: true)\n"
        "option('docs', type: 'feature', value: 'auto')\n"
    )
    flags = TargetOnboarder()._detect_meson_disable_flags(tmp_path)
    assert "-Dtests=false" in flags
    assert "-Ddocs=disabled" in flags


def test_meson_disable_flags_reads_new_filename(tmp_path: Path):
    """meson >=1.1 renamed meson_options.txt to meson.options."""
    (tmp_path / "meson.options").write_text(
        "option('examples', type: 'boolean', value: true)\n"
    )
    assert "-Dexamples=false" in (
        TargetOnboarder()._detect_meson_disable_flags(tmp_path)
    )


def test_meson_disable_flags_ignores_undeclared_options(tmp_path: Path):
    """CRITICAL: meson aborts setup with "Unknown options" on a -D for an
    option the project never declared. Only declared options may be emitted."""
    (tmp_path / "meson_options.txt").write_text(
        "option('tests', type: 'boolean', value: true)\n"
    )
    flags = TargetOnboarder()._detect_meson_disable_flags(tmp_path)
    assert flags == ["-Dtests=false"]


def test_meson_disable_flags_skips_untyped_combo(tmp_path: Path):
    """combo/string/array options have project-specific legal values — guessing
    one would abort setup, so they're skipped."""
    (tmp_path / "meson_options.txt").write_text(
        "option('docs', type: 'combo', choices: ['none', 'html'])\n"
    )
    assert TargetOnboarder()._detect_meson_disable_flags(tmp_path) == []


def test_meson_disable_flags_empty_without_options_file(tmp_path: Path):
    assert TargetOnboarder()._detect_meson_disable_flags(tmp_path) == []


# ── generate_build_commands (meson branch) ──────────────────


def _meson_cmds(**kw):
    return TargetOnboarder().generate_build_commands(
        kw.pop("target", "foo"), "meson", **kw
    )


def test_meson_build_commands_no_longer_raise():
    """Regression against the original gap: meson used to hit the
    NotImplementedError branch and produce a "# TODO" placeholder config."""
    cmds = _meson_cmds()
    assert "meson setup" in cmds["configure"]
    assert not cmds["configure"].startswith("# TODO")


def test_meson_configure_is_out_of_tree():
    """cwd is the build dir, so source is `..` — same convention as `cmake ..`
    and `../configure` in the other two branches."""
    assert "meson setup . .." in _meson_cmds()["configure"]


def test_meson_configure_uses_buildtype_plain():
    """CRITICAL: any other buildtype appends meson's own -O flags AFTER ours,
    overriding the -O0 the coverage build needs and the -O1 debug wants."""
    cmds = _meson_cmds()
    for key in ("configure", "debug_configure", "ubsan_configure",
                "coverage_configure"):
        assert "--buildtype=plain" in cmds[key], key


def test_meson_configure_forces_static():
    """Static archive is what the AFL+ASAN harness links against — meson's
    equivalent of -DBUILD_SHARED_LIBS=OFF."""
    assert "--default-library=static" in _meson_cmds()["configure"]


def test_meson_fuzz_build_uses_afl_compiler():
    cmds = _meson_cmds()
    assert "export CC=afl-clang-fast" in cmds["configure"]
    # Only the fuzz build is AFL-instrumented; the oracle builds use plain clang
    for key in ("debug_configure", "ubsan_configure", "coverage_configure"):
        assert "CC=clang" in cmds[key], key
        assert "afl-clang-fast" not in cmds[key], key


def test_meson_sanitizer_flags_reach_each_variant():
    cmds = _meson_cmds()
    assert "-fsanitize=address" in cmds["configure"]
    assert "-fsanitize=address,undefined" in cmds["debug_configure"]
    assert "-fsanitize=undefined" in cmds["ubsan_configure"]
    assert "-fprofile-instr-generate" in cmds["coverage_configure"]


def test_meson_configure_is_idempotent_via_wipe():
    """A build dir meson already configured rejects a plain `meson setup`;
    --wipe reconfigures in place. --wipe on a fresh dir fails instead, hence
    plain-first with a fallback. `A || B && C` groups as `(A || B) && C`, so
    the make step still runs iff either setup succeeded."""
    configure = _meson_cmds()["configure"]
    assert " || " in configure
    assert configure.endswith("--wipe")


def test_meson_make_targets_library_path():
    """Meson's ninja target for a static lib is its path relative to the build
    dir, mirroring the source layout."""
    cmds = _meson_cmds(source_subdir="src")
    assert cmds["make"].startswith("ninja src/libfoo.a")


def test_meson_make_falls_back_to_full_build():
    """Unusual name_prefix/name_suffix overrides make the guessed archive name
    wrong — build everything rather than failing the run outright."""
    assert _meson_cmds(source_subdir="src")["make"] == "ninja src/libfoo.a || ninja"


def test_meson_make_without_subdir():
    assert _meson_cmds()["make"] == "ninja libfoo.a || ninja"


def test_meson_make_without_target():
    assert _meson_cmds(target="")["make"] == "ninja"


def test_meson_disable_flags_reach_configure():
    cmds = _meson_cmds(meson_disable_flags=["-Dtests=false", "-Ddocs=disabled"])
    assert "-Dtests=false" in cmds["configure"]
    assert "-Ddocs=disabled" in cmds["coverage_configure"]


def test_meson_werror_disabled():
    """Projects that set `werror: true` in project() would otherwise fail the
    build on warnings the sanitizer flags provoke. -Dwerror is a builtin option,
    so it is always accepted."""
    assert "-Dwerror=false" in _meson_cmds()["configure"]


def test_unknown_build_system_still_raises():
    """The NotImplementedError path must survive for genuinely unsupported
    systems (bazel, scons) so the YAML gets a visible TODO placeholder."""
    import pytest
    with pytest.raises(NotImplementedError):
        TargetOnboarder().generate_build_commands("foo", "bazel")
