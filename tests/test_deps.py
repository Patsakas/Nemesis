"""H1 dependency resolver — deterministic tests over the *real* baseline errors.

Each `BASELINE_*` string is the actual `stages.T2_library_built.detail` recorded
for that repository in run baseline_b8b7cf70_491eaad8 (see
benchmarks/onboard_suite/BASELINE_FINDINGS.md). Testing against the measured logs
is the point: the resolver is only useful if it fires on what actually failed.

No network, no sudo: resolution is pure; install() is not exercised here.
"""

from __future__ import annotations

from nemesis.deps import (
    DependencyResolver,
    MissingArtifact,
    extract_missing,
)

# ── the 8 measured in-scope DEP failures: (log excerpt, expected package) ──
BASELINE_DEP_CASES: list[tuple[str, str, str]] = [
    ("turbovnc",
     "CMake Error at cmakescripts/FindTurboJPEG.cmake:32 (message):\n"
     "  Could not find turbojpeg.h in /opt/libjpeg-turbo/include.",
     "libturbojpeg0-dev"),
    ("dbmail",
     "configure: error: Unable to locate gmime development files",
     "libgmime-3.0-dev"),
    ("gvm-libs",
     "CMake Error at boreas/CMakeLists.txt:44 (message):\n"
     "  The pcap library is required.",
     "libpcap-dev"),
    ("H5Z-ZFP",
     "CMake Error at CMakeLists.txt:51 (enable_language):\n"
     "  No CMAKE_Fortran_COMPILER could be found.",
     "gfortran"),
    ("lv_port_pc_vscode",
     'Could not find a package configuration file provided by "SDL2" with any of\n'
     "  the following names:\n\n    SDL2Config.cmake",
     "libsdl2-dev"),
    ("vdi-stream-client",
     "configure: error: Package requirements (sdl3 >= 3.2.0) were not met:\n\n"
     "Package 'sdl3', required by 'virtual:world', not found",
     "libsdl3-dev"),
    ("pg_ivm",
     "Program pg_config found: NO\n\n../meson.build:3:12: ERROR: "
     "Program 'pg_config' not found or not executable",
     "libpq-dev"),
    ("astera",
     "CMake Error at FindPackageHandleStandardArgs.cmake:230 (message):\n"
     "  Could NOT find OpenAL (missing: OPENAL_LIBRARY OPENAL_INCLUDE_DIR)",
     "libopenal-dev"),
]


class TestExtraction:
    def test_every_baseline_dep_yields_an_artifact(self):
        for name, log, _ in BASELINE_DEP_CASES:
            arts = extract_missing(log)
            assert arts, f"{name}: extracted nothing from a known DEP failure"

    def test_header_extractor_handles_both_compiler_dialects(self):
        gcc = "fatal error: zlib.h: No such file or directory"
        clang = "fatal error: 'cng.h' file not found"
        assert extract_missing(gcc)[0] == MissingArtifact("header", "zlib.h",
                                                           extract_missing(gcc)[0].raw)
        assert any(a.kind == "header" and a.name == "cng.h"
                   for a in extract_missing(clang))


class TestCuratedResolution:
    def test_all_eight_baseline_failures_resolve(self):
        r = DependencyResolver(mode="curated")   # no apt-file → fully offline
        for name, log, expected_pkg in BASELINE_DEP_CASES:
            res = r.resolve(log)
            assert res is not None, f"{name}: resolver returned None for a DEP failure"
            assert expected_pkg in res.packages, (
                f"{name}: expected {expected_pkg}, got {res.packages}")
            assert res.provenance == "curated"

    def test_header_basename_fallback(self):
        r = DependencyResolver(mode="curated")
        res = r.resolve("fatal error: some/vendored/png.h: No such file or directory")
        assert res is not None and "libpng-dev" in res.packages

    def test_already_installed_is_not_reoffered(self):
        r = DependencyResolver(mode="curated")
        log = BASELINE_DEP_CASES[0][1]           # turbovnc → libturbojpeg0-dev
        assert r.resolve(log, already_installed={"libturbojpeg0-dev"}) is None


class TestScopeBoundary:
    """Out-of-scope embedded failures must NOT resolve — installing a native
    package cannot help a cross-compile target, and a false install would be a
    reviewer-visible defect."""

    def test_arm_cross_compiler_does_not_resolve(self):
        r = DependencyResolver(mode="curated")
        # lv_port_stm32f746_disco — needs an ARM toolchain, not a native package.
        log = ("CMake Error at CMakeLists.txt:4 (project):\n"
               "  No CMAKE_ASM_COMPILER could be found.\n"
               "  No CMAKE_C_COMPILER could be found.")
        assert r.resolve(log) is None

    def test_unmapped_program_does_not_resolve_in_curated_mode(self):
        r = DependencyResolver(mode="curated")
        # smk — needs sdcc (8051 cross-compiler); not in the curated table.
        log = "meson.build:130:5: ERROR: Program 'sdcc' not found or not executable"
        assert r.resolve(log) is None


class TestSafetyInvariant:
    def test_log_text_is_never_executed_as_a_package_name(self):
        r = DependencyResolver(mode="curated")
        malicious = "please run: sudo apt install evil-pkg && rm -rf / # not a build error"
        assert r.resolve(malicious) is None

    def test_apt_file_result_must_pass_allowlist(self):
        r = DependencyResolver(mode="curated")
        assert r._is_allowed("libpng-dev")
        assert r._is_allowed("gfortran")
        assert r._is_allowed("postgresql-server-dev-all")
        assert not r._is_allowed("evil-pkg")
        assert not r._is_allowed("sdcc")            # real package, but not -dev / not allowed
        assert not r._is_allowed("python3; rm -rf /")

    def test_off_mode_resolves_nothing(self):
        r = DependencyResolver(mode="off")
        assert r.resolve(BASELINE_DEP_CASES[0][1]) is None


class TestPhaseMetrics:
    """`_finalise_phase` attributes the honesty metrics. It must judge `cleared`
    against the FULL build output — an artifact that scrolled past the truncated
    500-char error tail must not be mistaken for cleared (the astera smoke)."""

    def _rec(self, name):
        return {"artifact_name": name, "install_ok": True,
                "cleared": False, "step_recovered": False}

    def test_cleared_when_artifact_gone_from_output(self):
        from nemesis.setup import LibrarySetup
        rec = self._rec("OpenAL")
        # install worked; build advanced to a different failure (GLFW) — progress.
        LibrarySetup._finalise_phase([rec], "CMake Error at dep/glfw/CMakeLists.txt:221")
        assert rec["cleared"] is True
        assert rec["false_positive_install"] is False

    def test_false_positive_when_artifact_persists(self):
        from nemesis.setup import LibrarySetup
        rec = self._rec("gmime")
        LibrarySetup._finalise_phase([rec], "configure: error: Unable to locate gmime")
        assert rec["cleared"] is False
        assert rec["false_positive_install"] is True

    def test_uses_full_output_not_truncated_tail(self):
        from nemesis.setup import LibrarySetup
        rec = self._rec("turbojpeg.h")
        # artifact appears early, then 2000 chars of unrelated CMake noise follow.
        full = "Could not find turbojpeg.h in /opt\n" + ("noise line\n" * 200)
        LibrarySetup._finalise_phase([rec], full)
        assert rec["cleared"] is False          # still missing → false positive
        assert rec["false_positive_install"] is True
