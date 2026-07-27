"""H2a build-target repair — deterministic tests.

Phase-1 cases are the REAL make commands from the frozen configs of the three
probe repos (tiny-AES-c, gifsicle, gensio). Phase-2 cases reproduce the three
oracle verdicts the probe established: accept (tiny-AES-c/gensio), reject-no-lib
(gifsicle), reject-vendored (astera).
"""

from __future__ import annotations

from nemesis.repair import (
    correct_target,
    genuine_oracle,
    parse_build_command,
    target_is_specific,
    validate_target,
)


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


class TestPhase1TargetCorrection:
    def test_default_build_is_not_specific(self):
        assert target_is_specific("make -j$(nproc)") is False

    def test_bare_target_is_specific(self):
        # tiny-AES-c: onboarder used the normalized name as a CMake target
        assert target_is_specific("make -j$(nproc) tiny_AES_c") is True

    def test_subdir_target_is_specific(self):
        # gifsicle / gensio: -C subdir bypasses the top-level build graph
        assert target_is_specific("make -j$(nproc) -C src libgifsicle.la") is True
        assert target_is_specific("make -j$(nproc) -C glib libgensioglib.la") is True

    def test_correct_replaces_specific_targets(self):
        for cmd in ("make -j$(nproc) tiny_AES_c",
                    "make -j$(nproc) -C src libgifsicle.la",
                    "make -j$(nproc) -C glib libgensioglib.la"):
            rec = correct_target(cmd)
            assert rec.action == "replace_invalid_target"
            assert rec.after == "make -j$(nproc)"
            assert rec.before == cmd
            assert rec.reason == "specific_or_subdir_target_bypasses_build_graph"

    def test_correct_keeps_default(self):
        rec = correct_target("make -j$(nproc)")
        assert rec.action == "keep_target"
        assert rec.after == "make -j$(nproc)"


class TestPhase2GenuineOracle:
    def test_accept_when_project_library_present(self, tmp_path):
        # gensio-like: a real project library under lib/.libs/
        d = tmp_path / "lib" / ".libs"
        d.mkdir(parents=True)
        (d / "libgensio.a").write_bytes(b"\x00" * 100)
        rec = genuine_oracle(tmp_path, build_ok=True)
        assert rec.oracle == "accept"
        assert rec.reason == "project_library_present"
        assert rec.artifact.endswith("libgensio.a")

    def test_reject_when_no_library_only_executable(self, tmp_path):
        # gifsicle-like: build succeeds but produces no library at all
        (tmp_path / "gifsicle").write_bytes(b"\x7fELF")   # an executable, not a .a
        rec = genuine_oracle(tmp_path, build_ok=True)
        assert rec.oracle == "reject"
        assert rec.reason == "no_project_library_artifact"

    def test_reject_when_only_vendored_artifact(self, tmp_path):
        # astera-like: only a bundled dependency library was built
        d = tmp_path / "dep" / "glfw" / "src"
        d.mkdir(parents=True)
        (d / "libglfw.a").write_bytes(b"\x00" * 100)
        rec = genuine_oracle(tmp_path, build_ok=True)
        assert rec.oracle == "reject"
        assert rec.reason == "only_vendored_artifact"

    def test_na_when_build_failed(self, tmp_path):
        rec = genuine_oracle(tmp_path, build_ok=False)
        assert rec.oracle == "n/a"
        assert rec.reason == "build_failed"
        assert rec.build_exit == 1


class TestBuildCommandParsing:
    """v2 requirement 3 — the operator must know which build system it is looking at."""

    def test_make_default_build(self):
        p = parse_build_command("make -j$(nproc)")
        assert (p.build_system, p.target, p.subdir) == ("make", "", "")
        assert p.has_default_segment is True

    def test_make_specific_target(self):
        p = parse_build_command("make -j$(nproc) uicc")
        assert (p.build_system, p.target) == ("make", "uicc")
        assert p.has_default_segment is False

    def test_subdir_is_extracted(self):
        p = parse_build_command("make -j$(nproc) -C glib libgensioglib.la")
        assert (p.subdir, p.target) == ("glib", "libgensioglib.la")

    def test_separate_jobs_count_is_not_a_target(self):
        assert parse_build_command("make -j 4 tiff").target == "tiff"

    def test_variable_override_is_not_a_target(self):
        assert parse_build_command("make CC=clang libfoo.a").target == "libfoo.a"

    def test_ninja_is_recognised(self):
        # pg_ivm/smk build with meson+ninja; v1 substituted `make` here and broke them
        p = parse_build_command("ninja libpg_ivm.a || ninja")
        assert p.build_system == "ninja"
        assert p.segments == 2
        assert p.has_default_segment is True

    def test_unrecognised_command(self):
        assert parse_build_command("/bin/true").build_system == "unknown"

    def test_correct_target_uses_the_right_default(self):
        # the pg_ivm regression: a make command substituted into a ninja build dir
        assert correct_target("ninja src/libsmk.a").after == "ninja"
        assert correct_target("make -j$(nproc) tiff").after == "make -j$(nproc)"


class TestPhase0Validation:
    """v2 Phase 0. Each case is the real repo whose evidence forced the rule."""

    def test_default_build_is_kept(self):
        rec = validate_target("make -j$(nproc)", None)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "already_default_build"

    def test_command_with_own_fallback_is_kept(self, tmp_path):
        # pg_ivm: `ninja <artifact> || ninja` already recovers by itself — v1 threw the
        # whole command away, including its fallback, and regressed the repo
        rec = validate_target("ninja libpg_ivm.a || ninja", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "command_falls_back_to_default_build"

    def test_unrecognised_command_is_kept(self, tmp_path):
        rec = validate_target("/bin/true", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "no_recognised_build_command"

    def test_subdir_invocation_is_replaced_even_when_declared(self, tmp_path):
        # gensio: `libgensioglib.la` IS declared in glib/Makefile.am, but building it
        # via `-C glib` never builds its parent lib/. Declaredness does not save it.
        _write(tmp_path, "glib/Makefile.am", "lib_LTLIBRARIES = libgensioglib.la\n")
        rec = validate_target("make -j$(nproc) -C glib libgensioglib.la", tmp_path)
        assert rec.action == "validate_replace_target"
        assert rec.reason == "subdir_invocation_bypasses_root_build_graph"

    def test_declared_project_target_is_kept(self, tmp_path):
        # onomondo-uicc: declared in a nested, non-vendored CMakeLists → v1 regressed it
        _write(tmp_path, "CMakeLists.txt", "project(softsim C)\nadd_subdirectory(src)\n")
        _write(tmp_path, "src/softsim/uicc/CMakeLists.txt",
               "add_library(uicc STATIC ${uicc_collection})\n")
        rec = validate_target("make -j$(nproc) uicc", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "declared_project_target"
        assert rec.artifact.endswith("CMakeLists.txt")

    def test_vendored_declaration_is_replaced(self, tmp_path):
        # astera: `glfw` is a valid declared CMake target — of a bundled dependency
        _write(tmp_path, "CMakeLists.txt",
               "project(astera VERSION 0.0.1 LANGUAGES C)\n"
               "add_library(${PROJECT_NAME} STATIC)\n")
        _write(tmp_path, "dep/glfw/src/CMakeLists.txt", "add_library(glfw ${glfw_SOURCES})\n")
        rec = validate_target("make -j$(nproc) glfw", tmp_path)
        assert rec.action == "validate_replace_target"
        assert rec.reason == "declared_in_vendored_subtree"

    def test_project_name_variable_is_resolved(self, tmp_path):
        # the same astera tree: its own target is declared as ${PROJECT_NAME}, so a
        # literal-text validator would not see it at all
        _write(tmp_path, "CMakeLists.txt",
               "project(astera VERSION 0.0.1 LANGUAGES C)\n"
               "add_library(${PROJECT_NAME} STATIC)\n")
        rec = validate_target("make -j$(nproc) astera", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "declared_project_target"

    def test_undeclared_target_is_replaced(self, tmp_path):
        # tiny-AES-c: the onboarder's normalised `tiny_AES_c` is not the declared
        # `tiny-AES-c`. No -/_ normalisation: the mismatch is a real build failure.
        _write(tmp_path, "CMakeLists.txt",
               "project(tiny-AES-c C)\nadd_library(${PROJECT_NAME})\n")
        rec = validate_target("make -j$(nproc) tiny_AES_c", tmp_path)
        assert rec.action == "validate_replace_target"
        assert rec.reason == "undeclared_target"

    def test_commented_declaration_does_not_count(self, tmp_path):
        # astera's CMakeLists carries a commented-out add_library on the line above
        _write(tmp_path, "CMakeLists.txt",
               "project(astera C)\n#add_library(ghost STATIC)\n")
        rec = validate_target("make -j$(nproc) ghost", tmp_path)
        assert rec.action == "validate_replace_target"
        assert rec.reason == "undeclared_target"

    def test_autotools_artifact_target_is_kept(self, tmp_path):
        # libxml2: the configured target is the artifact name itself
        _write(tmp_path, "Makefile.am", "lib_LTLIBRARIES = libxml2.la\n")
        rec = validate_target("make -j$(nproc) libxml2.la", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "declared_project_target"

    def test_library_artifact_does_not_match_a_program(self, tmp_path):
        # gifsicle: the config names `libgifsicle.la`, the project declares the PROGRAM
        # `gifsicle`. Matching them would validate a library that does not exist —
        # exactly the false-KEEP the validity predicate must not produce.
        _write(tmp_path, "src/Makefile.am", "bin_PROGRAMS = gifsicle\n")
        rec = validate_target("make -j$(nproc) libgifsicle.la", tmp_path)
        assert rec.action == "validate_replace_target"
        assert rec.reason == "undeclared_target"

    def test_library_artifact_matches_its_logical_library_target(self, tmp_path):
        # the legitimate half of the same rule: add_library(foo) produces libfoo.a
        _write(tmp_path, "CMakeLists.txt", "project(p C)\nadd_library(foo STATIC)\n")
        rec = validate_target("make -j$(nproc) libfoo.a", tmp_path)
        assert rec.action == "validate_keep_target"
        assert rec.reason == "declared_project_target"

    def test_project_declaration_wins_over_vendored_namesake(self, tmp_path):
        _write(tmp_path, "CMakeLists.txt", "project(p C)\nadd_library(zlib STATIC)\n")
        _write(tmp_path, "third_party/zlib/CMakeLists.txt", "add_library(zlib STATIC)\n")
        rec = validate_target("make -j$(nproc) zlib", tmp_path)
        assert rec.action == "validate_keep_target"
        assert "third_party" not in rec.artifact

    def test_missing_source_root_is_reported_not_guessed(self, tmp_path):
        rec = validate_target("make -j$(nproc) foo", tmp_path / "nope")
        assert rec.action == "validate_replace_target"
        assert rec.reason == "source_root_unavailable_for_validation"
