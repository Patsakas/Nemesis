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
    target_is_specific,
)


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
