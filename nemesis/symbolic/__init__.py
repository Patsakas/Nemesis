"""
NEMESIS Stage 3 — Symbolic (Z3 verification + patch application).

Verifies that proposed patches create satisfiable paths,
applies patches to source, and triggers instrumented builds.

v0.2.0 — Added harness compilation with libarchive linking.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.library_resolver import LibraryResolution, LibraryResolver
from nemesis.logging import get_logger
from nemesis.models import (
    AnalysisContext,
    HarnessSpec,
    PatchProposal,
    VerificationResult,
)
from nemesis.recon.predicate_synthesis import (
    canary_filter_predicates,
    inject_predicates,
    load_canary_seeds,
    synthesize_predicates,
)
from nemesis.recon.validation_gates import (
    extract_validation_gates,
    inject_setter_calls,
)


# Fix 135: sanitizer-flag resolution for the AFL harness compile.
#
# Until Fix 135, every harness was compiled with hardcoded
#   "-fsanitize=address,undefined -fno-omit-frame-pointer"
# without `-fno-sanitize-recover=undefined`. UBSan diagnostics (signed-integer
# overflow, shift overflow, pointer-overflow, …) only LOGGED a message and let
# the program keep running, so AFL never saw a crash even though the library
# build itself used `-fno-sanitize-recover=all`. The harness was effectively
# blind to entire bug classes.
#
# The profile is read from `target.sanitizer_profile` in the YAML.
def _resolve_sanitizer_flags(config) -> str:
    """Return the `-fsanitize=…` flag set for the AFL harness compile.

    Profiles
    --------
    asan_only         : ASAN only. Legacy / debugging.
    asan_ubsan        : ASAN + UBSan, with recover-off on UBSan so any
                        undefined-behaviour check actually crashes AFL's
                        child instead of just printing. Recommended default.
    asan_ubsan_strict : asan_ubsan plus `integer` and `implicit-conversion`
                        groups — catches unsigned overflow and lossy implicit
                        casts. Higher false-positive rate; only use on
                        libraries known to be careful with arithmetic
                        (compression, parsers).
    msan              : Fix 149: MemorySanitizer ONLY (no ASAN — mutually
                        exclusive runtimes). Catches use-of-uninitialized-value
                        reads that ASAN/UBSan are blind to. Requires
                        `target.msan_supported: True` AND every linked dep
                        compiled with `-fsanitize=memory`; on a vanilla distro
                        you will get thousands of false positives from libc.
                        Track origins level 2 helps triage at runtime cost.
    tsan              : Fix 150: ThreadSanitizer ONLY (mutually exclusive with
                        ASAN/MSAN). Catches data races (CWE-362) on shared state
                        when paired with a `threaded_oracle: true` pinned_func
                        that drives the target from multiple threads. Requires
                        `target.tsan_supported: True`; the library must document
                        thread-safe APIs or you'll see noise from sequential globals.
    """
    profile = (getattr(config.target, "sanitizer_profile", "") or "asan_ubsan").strip()
    base = "-fno-omit-frame-pointer"
    # `-fno-sanitize=function` is a near-universal cure for fuzz harnesses
    # that use callback APIs (TIFFClientOpen, png_set_read_fn, ...). The
    # `function` check (part of UBSan-undefined) flags any function-pointer
    # cast where the call signature doesn't match exactly — and LLM-generated
    # harnesses regularly produce tiny mismatches like `unsigned long` vs
    # `uint64_t` (same width, different type) in callback typedefs. The
    # resulting `runtime error: call to function ... through pointer to
    # incorrect function type` masquerades as a real bug at every fuzz
    # invocation. Turning the check off keeps every other UBSan diagnostic
    # in place — including the divide-by-zero and integer-overflow checks
    # that found CVE-2018-13785.
    fn_check_off = "-fno-sanitize=function"
    # Drop the UBSan `alignment` check on UBSan profiles: a misaligned load/store
    # is UB but rarely the real vulnerability (packed-buffer parsers do it
    # deliberately), and with -fno-sanitize-recover it ABORTS before ASAN can
    # report the out-of-bounds access the misaligned pointer sits on — masking
    # OOB read/write bugs and mis-classifying them as generic CWE-758 instead of
    # CWE-125/787. Measured on rpng: alignment-on hid an OOB read as UB.
    align_off = "-fno-sanitize=alignment"
    if profile == "asan_only":
        return f"-fsanitize=address {base}"
    if profile == "asan_ubsan_strict":
        return (
            "-fsanitize=address,undefined,integer,implicit-conversion "
            f"-fno-sanitize-recover=undefined,integer,implicit-conversion "
            f"{fn_check_off} {align_off} {base}"
        )
    # Fix 149: MSan profile — gated by msan_supported flag because uninstrumented
    # deps (libc, libstdc++, third-party libs not built with -fsanitize=memory)
    # produce thousands of false positives from "uninitialized value" on every
    # external call. The gate forces the user to confirm they've rebuilt the
    # dependency chain. `track-origins=2` makes the report actionable (shows
    # WHERE the uninit value was allocated) at ~1.5x runtime cost.
    if profile == "msan":
        if not getattr(config.target, "msan_supported", False):
            raise ValueError(
                "sanitizer_profile='msan' requires target.msan_supported=True. "
                "MSan needs every linked dependency built with -fsanitize=memory; "
                "without that, uninstrumented libc/libstdc++ produce a false-positive "
                "flood. Set msan_supported: true in the target YAML once you've "
                "rebuilt deps (or confirmed the library is self-contained)."
            )
        return (
            f"-fsanitize=memory -fsanitize-memory-track-origins=2 "
            f"-fno-sanitize-recover=memory {fn_check_off} {base}"
        )
    # Fix 150: TSan profile — gated by tsan_supported flag because TSan reports
    # races on every unsynchronised access. Single-threaded libs that just use
    # globals will spew noise. The harness must also be threaded
    # (`threaded_oracle: true` on the pinned_func) for TSan to find anything;
    # _resolve_sanitizer_flags can't enforce that here, so the validation gate
    # in recon/validation_gates handles the cross-check.
    if profile == "tsan":
        if not getattr(config.target, "tsan_supported", False):
            raise ValueError(
                "sanitizer_profile='tsan' requires target.tsan_supported=True. "
                "TSan reports races on any unsynchronised access — single-threaded "
                "libs with globals will produce noise. Set tsan_supported: true only "
                "when the library documents thread-safe APIs and deps that share "
                "state across threads are also TSan-instrumented."
            )
        return (
            f"-fsanitize=thread -fno-sanitize-recover=thread {fn_check_off} {base}"
        )
    # default + explicit "asan_ubsan"
    return (
        f"-fsanitize=address,undefined -fno-sanitize-recover=undefined "
        f"{fn_check_off} {align_off} {base}"
    )


# AFL stub header — replaces persistent-mode macros with stdin equivalents
# so harnesses compiled with plain clang can process crash inputs without AFL.
_AFL_STUB_HEADER = """\
/* AFL stub — replaces persistent-mode macros for standalone crash reproduction */
#include <stdio.h>
#include <stdint.h>
static uint8_t __afl_stub_buf[1 << 20];
static int     __afl_stub_len = 0;
static int     __afl_stub_called = 0;
#define __AFL_FUZZ_INIT()
#define __AFL_INIT()
#define __AFL_LOOP(n) (__afl_stub_called++ == 0 ? \
    (__afl_stub_len = (int)fread(__afl_stub_buf, 1, sizeof(__afl_stub_buf), stdin), 1) : 0)
#define __AFL_FUZZ_TESTCASE_LEN  __afl_stub_len
#define __AFL_FUZZ_TESTCASE_BUF  __afl_stub_buf
#define __AFL_COVERAGE()
#define __AFL_COVERAGE_ON()
#define __AFL_COVERAGE_OFF()
"""


def _cmake_cache_compiler_matches(cmake_cache: Path, configure_cmd: str, log) -> bool:
    """True if CMakeCache.txt was configured with the C compiler the configure
    command requests. Guards against reusing a stale cache from a different
    (e.g. non-instrumented) compiler, which would silently yield an
    uninstrumented library. Returns True (trust cache) only on a confirmed
    basename match; returns False whenever the compilers differ or can't be read.
    """
    m = (re.search(r"-DCMAKE_C_COMPILER=(\S+)", configure_cmd)
         or re.search(r"\bCC=(\S+)", configure_cmd))
    if not m:
        return True  # configure doesn't pin a compiler → nothing to validate
    expected = Path(m.group(1).strip('"\'')).name
    try:
        for line in cmake_cache.read_text(errors="replace").splitlines():
            if line.startswith("CMAKE_C_COMPILER:"):
                actual = Path(line.split("=", 1)[1].strip()).name
                if actual != expected:
                    log.warning("build.cmake_cache.compiler_mismatch",
                                expected=expected, actual=actual)
                return actual == expected
    except OSError:
        return False
    return False  # no compiler line found → don't trust the cache


class SymbolicStage:
    """Stage 3 orchestrator."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("symbolic")
        self.verifier = Z3Verifier(config)
        self.applicator = PatchApplicator(config)
        self.builder = InstrumentedBuilder(config)
        self._neural: object | None = None  # Injected by pipeline for LLM harness repair

    @staticmethod
    def _resolve_link_libs(libs: str, build_dir: Path) -> str:
        """Fix 113: Resolve relative -L paths in link_libs to absolute paths.

        Config link_libs uses -L. which only works when subprocess cwd=build_dir.
        For coverage/debug/ubsan builds where subprocess runs without cwd set,
        -L. resolves to Python's CWD (wrong). Replace with -L{build_dir}.
        Also handles -L../ and other relative paths.
        """
        import re as _re
        if not libs:
            return libs
        # Replace -L. (exact, not -L..) with -L{build_dir}
        libs = _re.sub(r'-L\.(?![./\w])', f'-L{build_dir}', libs)
        # Replace -L../ with absolute resolved path relative to build_dir
        def _resolve_rel(m):
            rel = m.group(1)
            resolved = (build_dir / rel).resolve()
            return f'-L{resolved}'
        libs = _re.sub(r'-L(\.\.[^\ ]*)', _resolve_rel, libs)
        return libs

    def set_neural(self, neural_stage: object) -> None:
        """Inject neural stage so symbolic can call repair_harness() on compile failure."""
        self._neural = neural_stage

    def verify(
        self,
        patch: PatchProposal,
        context: AnalysisContext,
    ) -> VerificationResult:
        """Verify that the patch creates a satisfiable path."""
        return self.verifier.verify(patch, context)

    def build_unpatched_library(self) -> bool:
        """
        Build the ASAN debug library from the CLEAN source (source_root).

        Called ONCE at startup. source_root is NEVER patched, so no git stash needed.
        The resulting libarchive.a lives in debug_build_dir and is reused for all
        per-target unpatched harness compilations.

        Returns True on success.
        """
        debug_build_dir = Path(self.config.target.debug_build_dir)
        debug_configure = self.config.target.build.debug_configure
        debug_make = self.config.target.build.debug_make

        if not debug_configure:
            self.log.warning("unpatched.no_debug_configure — skipping unpatched verification")
            return False

        debug_build_dir.mkdir(parents=True, exist_ok=True)
        # cmake .. points to source_root (parent of debug_build_dir) — always clean
        full_cmd = (
            f"cd {debug_build_dir} && "
            f"{debug_configure.strip()} && "
            f"{debug_make.strip()}"
        )
        self.log.info("unpatched.build_library.start", build_dir=str(debug_build_dir))
        build_result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True,
            timeout=600, cwd=str(debug_build_dir),
        )
        if build_result.returncode != 0:
            self.log.error("unpatched.build_library.failed", stderr=build_result.stderr[-300:])
            return False

        lib = self.builder._find_library(debug_build_dir, self.config.target.library_name)
        if not lib:
            self.log.error("unpatched.library_not_found", name=self.config.target.library_name)
            return False

        self.log.info("unpatched.build_library.done", lib=lib)
        return True

    def build_unpatched_debug(self, harness: HarnessSpec | None) -> bool:
        """
        Compile the harness against the pre-built unpatched ASAN library.

        The unpatched library MUST already be built via build_unpatched_library()
        (called once at startup). source_root is NEVER patched in the two-repo
        architecture, so no git stash is needed.

        Returns True if the debug harness binary was compiled successfully.
        """
        source_root = Path(self.config.target.source_root)
        debug_build_dir = Path(self.config.target.debug_build_dir)

        if not harness or not harness.c_code:
            self.log.warning("unpatched.no_harness")
            return False

        # Find the pre-built unpatched library (built once at startup)
        lib_name = self.config.target.library_name
        libarchive_a = self.builder._find_library(debug_build_dir, lib_name)
        if not libarchive_a:
            self.log.error(
                "unpatched.library_not_found",
                hint="call build_unpatched_library() first",
                name=lib_name,
            )
            return False

        # Compile harness against unpatched library
        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        debug_bin = debug_build_dir / "fuzz_nemesis_debug"
        harness_src = debug_build_dir / "fuzz_nemesis_debug.c"

        fixed_code = self.builder._fix_harness_includes(harness.c_code)
        harness_src.write_text(_AFL_STUB_HEADER + fixed_code)

        libs = self._resolve_link_libs(self.config.target.link_libs or "", debug_build_dir)
        asan_flags = _resolve_sanitizer_flags(self.config)  # Fix 135
        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable"
        )
        # Also include build_dir's include subdir for cmake-generated headers
        # (e.g. tiffconf.h in libtiff/build_debug/libtiff, config.h in libarchive)
        build_include = debug_build_dir / include_subdir if include_subdir else debug_build_dir
        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        # Fix 89: always add bare build_dir for cmake-generated headers
        if debug_build_dir != include_path and debug_build_dir != build_include:
            include_flags += f" -I{debug_build_dir}"
        # Fix 90: include NEMESIS templates dir so harnesses can #include "fuzz_data_provider.h"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"
        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re_dbg
            for m in _re_dbg.finditer(r"-I(\S+)", harness.compile_flags):
                ipath = m.group(0)  # -I/path
                if ipath not in include_flags:
                    include_flags += f" {ipath}"
        compile_cmd = (
            f"clang {include_flags} -g -O1 {asan_flags} {warn_flags} "
            f"-o {debug_bin} {harness_src} "
            f"{libarchive_a} {libs} 2>&1"
        )
        compile_result = subprocess.run(
            compile_cmd, shell=True, capture_output=True,
            text=True, timeout=120,
        )
        if compile_result.returncode == 0 and debug_bin.exists():
            self.log.info("unpatched.harness_built", binary=str(debug_bin))
            return True
        else:
            self.log.error(
                "unpatched.harness_compile_failed",
                stdout=compile_result.stdout[-300:],
            )
            return False

    def build_ubsan_library(self) -> bool:
        """Build the UBSan-only library from the CLEAN source (source_root).

        Similar to build_unpatched_library() but uses ubsan_configure/ubsan_make.
        Only builds if ubsan_configure is non-empty.
        Returns True on success.
        """
        ubsan_build_dir = Path(self.config.target.ubsan_build_dir)
        ubsan_configure = self.config.target.build.ubsan_configure
        ubsan_make = (
            self.config.target.build.ubsan_make
            or self.config.target.build.debug_make
        )

        # Fix 126: Path("") → str() = "." (truthy); check raw config value instead
        if not ubsan_configure or not self.config.target.ubsan_build_dir:
            self.log.info("ubsan.no_config — skipping UBSan build")
            return False

        ubsan_build_dir.mkdir(parents=True, exist_ok=True)
        full_cmd = (
            f"cd {ubsan_build_dir} && "
            f"{ubsan_configure.strip()} && "
            f"{ubsan_make.strip()}"
        )
        self.log.info("ubsan.build_library.start", build_dir=str(ubsan_build_dir))
        build_result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True,
            timeout=600, cwd=str(ubsan_build_dir),
        )
        if build_result.returncode != 0:
            self.log.error("ubsan.build_library.failed", stderr=build_result.stderr[-300:])
            return False

        lib = self.builder._find_library(ubsan_build_dir, self.config.target.library_name)
        if not lib:
            self.log.error("ubsan.library_not_found", name=self.config.target.library_name)
            return False

        self.log.info("ubsan.build_library.done", lib=lib)
        return True

    def build_ubsan_debug(self, harness: HarnessSpec | None) -> bool:
        """Compile the harness against the pre-built UBSan library.

        Similar to build_unpatched_debug() but uses UBSan flags instead of ASAN.
        Returns True if the UBSan harness binary was compiled successfully.
        """
        source_root = Path(self.config.target.source_root)
        ubsan_build_dir = Path(self.config.target.ubsan_build_dir)

        if not harness or not harness.c_code:
            self.log.warning("ubsan.no_harness")
            return False

        # Fix 126: Path("") → str() = "." (truthy); check raw config value
        if not self.config.target.ubsan_build_dir:
            return False

        lib_name = self.config.target.library_name
        lib_a = self.builder._find_library(ubsan_build_dir, lib_name)
        if not lib_a:
            self.log.error("ubsan.library_not_found", hint="call build_ubsan_library() first")
            return False

        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        ubsan_bin = ubsan_build_dir / "fuzz_nemesis_ubsan"
        harness_src = ubsan_build_dir / "fuzz_nemesis_ubsan.c"

        fixed_code = self.builder._fix_harness_includes(harness.c_code)
        harness_src.write_text(_AFL_STUB_HEADER + fixed_code)

        libs = self._resolve_link_libs(self.config.target.link_libs or "", ubsan_build_dir)
        ubsan_flags = "-fsanitize=undefined,pointer-overflow -fno-sanitize-recover=all -fno-omit-frame-pointer"
        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable"
        )
        build_include = ubsan_build_dir / include_subdir if include_subdir else ubsan_build_dir
        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        if ubsan_build_dir != include_path and ubsan_build_dir != build_include:
            include_flags += f" -I{ubsan_build_dir}"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"
        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133b
            for m in _re133b.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        compile_cmd = (
            f"clang {include_flags} -g -O1 {ubsan_flags} {warn_flags} "
            f"-o {ubsan_bin} {harness_src} "
            f"{lib_a} {libs} 2>&1"
        )
        compile_result = subprocess.run(
            compile_cmd, shell=True, capture_output=True,
            text=True, timeout=120,
        )
        if compile_result.returncode == 0 and ubsan_bin.exists():
            self.log.info("ubsan.harness_built", binary=str(ubsan_bin))
            return True
        else:
            self.log.error("ubsan.harness_compile_failed", stdout=compile_result.stdout[-300:])
            return False

    def build_coverage_library(self) -> bool:
        """Build the LLVM source-coverage library from the CLEAN source (source_root).

        Similar to build_ubsan_library() but uses coverage_configure/coverage_make.
        Produces a library instrumented with -fprofile-instr-generate -fcoverage-mapping
        for use with llvm-profdata/llvm-cov.
        Only builds if coverage_configure is non-empty.
        Returns True on success.
        """
        cov_configure = self.config.target.build.coverage_configure
        cov_make = (
            self.config.target.build.coverage_make
            or self.config.target.build.debug_make
        )

        # `Path("")` is `Path(".")`, so an unset coverage_build_dir used to pass
        # the emptiness check and cmake ran against whatever the cwd happened to
        # be — failing with "does not contain CMakeLists.txt" and leaving
        # line_cov unmeasured. Test the configured value, not the Path.
        raw_build_dir = str(self.config.target.coverage_build_dir or "").strip()
        if not cov_configure or raw_build_dir in ("", "."):
            self.log.info("coverage.not_configured",
                          note="set target.coverage_build_dir + build.coverage_configure "
                               "to measure line coverage")
            return False

        cov_build_dir = Path(raw_build_dir)

        cov_build_dir.mkdir(parents=True, exist_ok=True)
        full_cmd = (
            f"cd {cov_build_dir} && "
            f"{cov_configure.strip()} && "
            f"{cov_make.strip()}"
        )
        self.log.info("coverage.build_library.start", build_dir=str(cov_build_dir))
        build_result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True,
            timeout=600, cwd=str(cov_build_dir),
        )
        if build_result.returncode != 0:
            self.log.error("coverage.build_library.failed", stderr=build_result.stderr[-300:])
            return False

        lib = self.builder._find_library(cov_build_dir, self.config.target.library_name)
        if not lib:
            self.log.error("coverage.library_not_found", name=self.config.target.library_name)
            return False

        self.log.info("coverage.build_library.done", lib=lib)
        return True

    def build_coverage_harness(self, harness: HarnessSpec | None) -> bool:
        """Compile the harness against the coverage-instrumented library.

        Uses clang with -fprofile-instr-generate -fcoverage-mapping (NO sanitizers,
        which are incompatible with profiling). Prepends AFL stub header to replace
        AFL macros with stdin equivalents.

        Returns True if the coverage harness binary was compiled successfully.
        """
        source_root = Path(self.config.target.source_root)
        cov_build_dir = Path(self.config.target.coverage_build_dir)

        if not harness or not harness.c_code:
            self.log.warning("coverage.no_harness")
            return False

        if not str(cov_build_dir):
            return False

        lib_name = self.config.target.library_name
        lib_a = self.builder._find_library(cov_build_dir, lib_name)
        if not lib_a:
            self.log.error(
                "coverage.library_not_found",
                hint="call build_coverage_library() first",
            )
            return False

        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        cov_bin = cov_build_dir / "fuzz_nemesis_coverage"
        harness_src = cov_build_dir / "fuzz_nemesis_coverage.c"

        fixed_code = self.builder._fix_harness_includes(harness.c_code)
        harness_src.write_text(_AFL_STUB_HEADER + fixed_code)

        libs = self._resolve_link_libs(self.config.target.link_libs or "", cov_build_dir)
        cov_flags = "-fprofile-instr-generate -fcoverage-mapping"
        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable"
        )
        build_include = cov_build_dir / include_subdir if include_subdir else cov_build_dir
        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        if cov_build_dir != include_path and cov_build_dir != build_include:
            include_flags += f" -I{cov_build_dir}"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"
        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133c
            for m in _re133c.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        compile_cmd = (
            f"clang {include_flags} -g -O1 {cov_flags} {warn_flags} "
            f"-o {cov_bin} {harness_src} "
            f"{lib_a} {libs} 2>&1"
        )
        compile_result = subprocess.run(
            compile_cmd, shell=True, capture_output=True,
            text=True, timeout=120,
        )
        if compile_result.returncode == 0 and cov_bin.exists():
            self.log.info("coverage.harness_built", binary=str(cov_bin))
            return True
        else:
            self.log.error(
                "coverage.harness_compile_failed",
                stdout=compile_result.stdout[-300:],
            )
            return False

    def measure_function_source_coverage(
        self,
        harness: HarnessSpec,
        target_func: str,
        corpus_files: list[Path],
        n_samples: int = 20,
    ) -> float:
        """Measure real source-line coverage of target_func using LLVM source coverage.

        Steps:
        1. Build coverage harness if not already built
        2. Run N corpus files through it, each generating a .profraw file
        3. llvm-profdata merge → merged.profdata
        4. llvm-cov export --format=json → extract line coverage %

        Returns: 0.0-100.0 (percentage of source lines covered in target_func)
                 -1.0 if measurement failed
        """
        import json as _json
        import os as _os

        cov_build_dir = Path(self.config.target.coverage_build_dir)
        if not str(cov_build_dir) or not cov_build_dir.exists():
            return -1.0

        cov_bin = cov_build_dir / "fuzz_nemesis_coverage"
        # Fix 107: Always rebuild coverage harness for the current target.
        # Previously only rebuilt if binary was missing, so switching targets
        # (e.g. htmlReadMemory → xmlReadMemory) reused the stale binary → 0%.
        if not self.build_coverage_harness(harness):
            return -1.0

        # Clean old profraw files
        for old_prof in cov_build_dir.glob("*.profraw"):
            old_prof.unlink(missing_ok=True)

        # Run corpus files through the coverage binary
        env = {**_os.environ, "LLVM_PROFILE_FILE": str(cov_build_dir / "corpus_%p_%m.profraw")}
        samples = corpus_files[:n_samples]
        runs_ok = 0
        for corpus_file in samples:
            try:
                with open(corpus_file, "rb") as f:
                    subprocess.run(
                        [str(cov_bin)],
                        stdin=f,
                        timeout=5,
                        env=env,
                        capture_output=True,
                    )
                runs_ok += 1
            except (subprocess.TimeoutExpired, OSError):
                continue

        if runs_ok == 0:
            self.log.warning("source_coverage.no_successful_runs", func=target_func)
            return -1.0

        # Merge profraw files
        profraw_files = list(cov_build_dir.glob("*.profraw"))
        if not profraw_files:
            self.log.warning("source_coverage.no_profraw_files", func=target_func)
            return -1.0

        merged_prof = cov_build_dir / "merged.profdata"
        try:
            merge_result = subprocess.run(
                ["llvm-profdata", "merge", "-sparse"]
                + [str(f) for f in profraw_files]
                + ["-o", str(merged_prof)],
                capture_output=True, text=True, timeout=60,
            )
            if merge_result.returncode != 0:
                self.log.warning(
                    "source_coverage.merge_failed",
                    stderr=merge_result.stderr[-200:],
                )
                return -1.0
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.log.warning("source_coverage.merge_error", error=str(exc))
            return -1.0

        # Fix 106: Use `llvm-cov report -show-functions` to measure LINE coverage,
        # matching the same metric OSS-Fuzz Introspector uses (lines_hit / total_lines).
        # Previously used `llvm-cov export` JSON regions which measured region coverage —
        # a different metric that is not comparable with OSS-Fuzz numbers.
        #
        # First, find the source file for the target function via `llvm-cov export`.
        source_file = None
        try:
            export_result = subprocess.run(
                ["llvm-cov", "export", str(cov_bin), f"-instr-profile={merged_prof}"],
                capture_output=True, text=True, timeout=120,
            )
            if export_result.returncode == 0:
                cov_data = _json.loads(export_result.stdout)
                for func_entry in cov_data.get("data", [{}])[0].get("functions", []):
                    fname = func_entry.get("name", "")
                    if fname == target_func or fname.endswith(f":{target_func}"):
                        filenames = func_entry.get("filenames", [])
                        if filenames:
                            source_file = filenames[0]
                        break
        except Exception:
            pass

        if not source_file:
            self.log.warning("source_coverage.source_file_not_found", func=target_func)
            for f in profraw_files:
                f.unlink(missing_ok=True)
            return -1.0

        # Run llvm-cov report with -show-functions to get line coverage %.
        # Output format (columns): Regions Miss Cover% Lines Miss Cover% Branches Miss Cover%
        try:
            import re as _re
            report_result = subprocess.run(
                [
                    "llvm-cov", "report", str(cov_bin),
                    f"-instr-profile={merged_prof}",
                    "-show-functions", source_file,
                ],
                capture_output=True, text=True, timeout=120,
            )
            if report_result.returncode != 0:
                self.log.warning(
                    "source_coverage.report_failed",
                    stderr=report_result.stderr[-200:],
                )
                for f in profraw_files:
                    f.unlink(missing_ok=True)
                return -1.0

            # Parse: "funcName  R Rmiss R%  L Lmiss L%  B Bmiss B%"
            #
            # Static functions (and other internal-linkage symbols) are
            # disambiguated by llvm-cov with a "<sourcefile>:" prefix:
            #   tif_dirread.c:TIFFFetchNormalTag   416  309  25.72%  701  511  27.10% ...
            # External-linkage functions appear bare:
            #   png_check_chunk_length             18    4  77.78%   28    7  75.00% ...
            # The previous parser only matched the bare form and silently
            # returned -1 (→ "line_cov=n/a") for every static target.
            for line in report_result.stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("-") or stripped.startswith("Name"):
                    continue
                # Strip the "<sourcefile>:" prefix if present so we can match
                # the bare function name regardless of linkage.
                if ":" in stripped.split()[0]:
                    matched_name = stripped.split(":", 1)[1]
                else:
                    matched_name = stripped
                if not (matched_name.startswith(target_func + " ")
                        or matched_name.startswith(target_func + "\t")):
                    continue
                # Extract all numeric values: R Rmiss R% L Lmiss L% B Bmiss B%
                nums = _re.findall(r"[\d.]+", matched_name[len(target_func):])
                # nums: [reg_total, reg_miss, reg_pct, line_total, line_miss, line_pct,
                #        branch_total, branch_miss, branch_pct]
                if len(nums) >= 6:
                    reg_total, reg_miss = int(nums[0]), int(nums[1])
                    line_total, line_miss = int(nums[3]), int(nums[4])
                    line_pct = float(nums[5])
                    branch_total = int(nums[6]) if len(nums) >= 9 else 0
                    branch_miss = int(nums[7]) if len(nums) >= 9 else 0
                    branch_pct = float(nums[8]) if len(nums) >= 9 else 0.0
                    self.log.info(
                        "source_coverage.measured",
                        func=target_func,
                        line_cov=f"{line_total - line_miss}/{line_total} ({line_pct}%)",
                        region_cov=f"{reg_total - reg_miss}/{reg_total} ({float(nums[2])}%)",
                        branch_cov=f"{branch_total - branch_miss}/{branch_total} ({branch_pct}%)",
                        corpus_samples=len(samples),
                        runs_ok=runs_ok,
                    )
                    for f in profraw_files:
                        f.unlink(missing_ok=True)
                    return line_pct

            self.log.debug(
                "source_coverage.function_not_found",
                func=target_func,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError) as exc:
            self.log.debug("source_coverage.report_error", error=str(exc))

        # Clean up profraw files
        for f in profraw_files:
            f.unlink(missing_ok=True)
        return -1.0

    def build_harness_only(self, harness: HarnessSpec | None) -> bool:
        """Compile the harness without applying any patch.

        Used when has_blocker=False (force_no_blocker=True): no patch needed,
        but the AFL-instrumented library must still be built first if missing
        (rsync --delete wipes build_fuzz before each target).
        """
        build_dir = Path(self.config.target.build_dir)
        work_root = Path(self.config.target.effective_work_root)

        if not harness or not harness.c_code:
            self.log.error("build.no_harness")
            return False

        # Build the AFL-instrumented library if not already present
        if not self.builder._find_library(build_dir, self.config.target.library_name):
            self.log.info("build.library_missing_rebuilding")
            if not self.builder.build_library(work_root, build_dir):
                self.log.error("build.library_failed")
                return False

        return self._try_build_harness_with_llm_repair(
            harness, build_dir, is_static=harness.is_static,
            indirect_reach=harness.indirect_reach,
            direct_internal=getattr(harness, 'direct_internal', False),  # Fix 123
        )

    @staticmethod
    def _auto_fix_compile_errors(src_file: Path, stderr: str, log) -> bool:
        """
        Auto-fix common compile errors from LLM-generated patches.

        Handles:
        1. -Wunused-variable / -Wunused-but-set-variable: inject (void)var;
        2. -Wunused-parameter: inject (void)param;
        3. -Wuninitialized: add = NULL/0 to declaration
        4. -Wimplicit-int (undeclared var): extract decl from #if 0 blocks

        Returns True if any fixes were applied.
        """
        import re as _re

        content = src_file.read_text()
        lines = content.splitlines(keepends=True)
        changed = False

        # ---- 1. Unused variables: inject (void)var; ----
        var_pattern = r":(\d+):\d+: error: (?:unused variable|variable) '(\w+)'(?: set but not used)?"
        param_pattern = r":(\d+):\d+: error: unused parameter '(\w+)'"
        var_matches = _re.findall(var_pattern, stderr)
        param_matches = _re.findall(param_pattern, stderr)

        if var_matches or param_matches:
            var_insertions = []
            seen = set()
            for line_str, var_name in var_matches:
                key = (int(line_str), var_name)
                if key not in seen:
                    seen.add(key)
                    var_insertions.append(key)

            param_names = []
            param_line = 0
            for line_str, param_name in param_matches:
                pline = int(line_str)
                if param_name not in param_names:
                    param_names.append(param_name)
                    if pline > param_line:
                        param_line = pline

            param_insert_line = 0
            if param_names and param_line > 0:
                for i in range(param_line - 1, min(param_line + 10, len(lines))):
                    if "{" in lines[i]:
                        param_insert_line = i + 1
                        break

            var_insertions.sort(reverse=True)
            for line_num, var_name in var_insertions:
                if 0 < line_num <= len(lines):
                    decl_line = lines[line_num - 1]
                    indent = len(decl_line) - len(decl_line.lstrip())
                    void_line = " " * indent + f"(void){var_name};\n"
                    lines.insert(line_num, void_line)
                    if param_insert_line >= line_num:
                        param_insert_line += 1
                    changed = True

            if param_names and param_insert_line > 0:
                if param_insert_line < len(lines):
                    next_line = lines[param_insert_line]
                    indent = len(next_line) - len(next_line.lstrip())
                    if indent == 0:
                        indent = 8
                else:
                    indent = 8
                void_lines = "".join(
                    " " * indent + f"(void){p};\n" for p in param_names
                )
                lines.insert(param_insert_line, void_lines)
                changed = True

        # ---- 2. Uninitialized variables: add = NULL/0 to declaration ----
        # error: variable 'p' is uninitialized when used here [-Werror,-Wuninitialized]
        uninit_pattern = r":(\d+):\d+: error: variable '(\w+)' is uninitialized"
        uninit_matches = _re.findall(uninit_pattern, stderr)
        for _use_line_str, var_name in uninit_matches:
            use_line = int(_use_line_str)
            # Search backwards from usage for declaration of this variable
            for i in range(min(use_line - 1, len(lines) - 1), max(use_line - 200, -1), -1):
                ln = lines[i]
                # Match: "type *var;" or "type var;" or "type *var," etc.
                decl_match = _re.search(
                    r'(\b(?:const\s+)?(?:unsigned\s+)?(?:char|int|long|size_t|ssize_t|__LA_\w+|uint\d+_t|int\d+_t|void)\s*\**\s*)(\b'
                    + _re.escape(var_name)
                    + r'\b)\s*([;,])',
                    ln,
                )
                if decl_match and '#if 0' not in ln and '/* NEMESIS' not in ln:
                    # Add initializer based on whether it's a pointer
                    prefix = decl_match.group(1)
                    is_ptr = '*' in prefix
                    init_val = "NULL" if is_ptr else "0"
                    old_decl = decl_match.group(0)
                    new_decl = old_decl.replace(
                        var_name + decl_match.group(3),
                        var_name + " = " + init_val + decl_match.group(3),
                    )
                    lines[i] = ln.replace(old_decl, new_decl, 1)
                    changed = True
                    break

        # ---- 3. Undeclared variables (implicit-int): find type & add declaration ----
        # error: type specifier missing, defaults to 'int' at line N
        # with expression like: "p = func_call(...);"
        implicit_pattern = r":(\d+):\d+: error: type specifier missing, defaults to 'int'"
        implicit_matches = _re.findall(implicit_pattern, stderr)
        if implicit_matches:
            # Build a map of all variable declarations in the file (including #if 0 blocks)
            # Note: \s*\b handles both "char *p" and "char * p" (asterisk adjacent or not)
            type_re = r'\b((?:const\s+)?(?:unsigned\s+)?(?:char|int|long|size_t|ssize_t|__LA_\w+|uint\d+_t|int\d+_t|void)\s*\**)\s*\b(\w+)\s*[;=,]'
            all_decls = {}  # var_name → type_str
            for ln in lines:
                for type_str, vname in _re.findall(type_re, ln):
                    if vname not in all_decls:
                        all_decls[vname] = type_str.strip()

            # Process implicit-int errors in reverse order (bottom-up for insertions)
            inserted = set()
            for use_line_str in sorted(implicit_matches, reverse=True):
                use_line = int(use_line_str)
                if 0 < use_line <= len(lines):
                    usage_ln = lines[use_line - 1]
                    assign_m = _re.match(r'\s+(\w+)\s*=', usage_ln)
                    if assign_m:
                        var_name = assign_m.group(1)
                        if var_name in inserted:
                            continue
                        # Check if already declared in nearby lines (avoid redefinition)
                        already_declared = False
                        for j in range(max(0, use_line - 10), min(len(lines), use_line + 2)):
                            if _re.search(r'\b(?:const\s+)?(?:unsigned\s+)?(?:char|int|long|size_t|ssize_t|void|__LA_\w+|uint\d+_t|int\d+_t)\s*\**\s*\b' + _re.escape(var_name) + r'\b\s*[=;,]', lines[j]):
                                already_declared = True
                                break
                        if already_declared:
                            continue
                        # Try to find type from existing declarations
                        type_str = all_decls.get(var_name)
                        if not type_str:
                            # Guess type from RHS context
                            rhs = usage_ln.split('=', 1)[1].strip() if '=' in usage_ln else ''
                            if 'read_ahead' in rhs or 'strdup' in rhs or 'malloc' in rhs:
                                type_str = "const char *"
                            elif 'strlen' in rhs or 'sizeof' in rhs:
                                type_str = "size_t"
                            else:
                                type_str = "int"
                        is_ptr = '*' in type_str
                        init_val = "NULL" if is_ptr else "0"
                        indent = len(usage_ln) - len(usage_ln.lstrip())
                        decl_line = " " * indent + f"{type_str} {var_name} = {init_val};\n"
                        lines.insert(use_line - 1, decl_line)
                        inserted.add(var_name)
                        changed = True

        # ---- 4. Extra tokens on preprocessor directives ----
        # error: extra tokens at end of #endif directive [-Werror,-Wextra-tokens]
        extra_tokens_pattern = r":(\d+):\d+: error: extra tokens at end of #(\w+) directive"
        extra_tokens_matches = _re.findall(extra_tokens_pattern, stderr)
        for line_str, directive in extra_tokens_matches:
            line_num = int(line_str)
            if 0 < line_num <= len(lines):
                ln = lines[line_num - 1]
                # Strip everything after #directive (keep just "#endif\n" or "#if 0\n")
                cleaned = _re.sub(r'(#' + directive + r')\b.*', r'\1', ln.rstrip()) + '\n'
                if cleaned != ln:
                    lines[line_num - 1] = cleaned
                    changed = True

        # ---- 5. Non-void function missing return ----
        # error: non-void function does not return a value in all control paths
        return_pattern = r":(\d+):\d+: error: non-void function does not return a value"
        return_matches = _re.findall(return_pattern, stderr)
        if return_matches:
            # Find the closing brace of the function and insert return 0; before it
            last_error_line = max(int(ln) for ln in return_matches)
            if 0 < last_error_line <= len(lines):
                # Search forward from error line for the function's closing }
                for i in range(last_error_line - 1, min(last_error_line + 5, len(lines))):
                    if lines[i].strip() == '}':
                        indent = len(lines[i]) - len(lines[i].lstrip()) + 4
                        lines.insert(i, " " * indent + "return 0;\n")
                        changed = True
                        break

        if changed:
            src_file.write_text("".join(lines))
            # Summarize what was fixed
            fixed = []
            if var_matches:
                fixed.extend(v for _, v in var_matches)
            if param_matches:
                fixed.extend(p for _, p in param_matches)
            if uninit_matches:
                fixed.extend(f"{v}=init" for _, v in uninit_matches)
            if implicit_matches:
                fixed.append(f"implicit_int×{len(implicit_matches)}")
            if extra_tokens_matches:
                fixed.append(f"extra_tokens×{len(extra_tokens_matches)}")
            if return_matches:
                fixed.append(f"return_added×{len(return_matches)}")
            log.info("patch.auto_fix_compile_errors", count=len(fixed), fixes=fixed)
        return changed

    @staticmethod
    def _preflight_harness(
        harness_code: str,
        target_func: str,
        is_static: bool = False,
        indirect_reach: bool = False,
        direct_internal: bool = False,  # Fix 123
        target_declaration: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Pre-flight check on harness source (~1s) before starting cmake/make (~60s).

        Catches the most common LLM harness mistakes without a full build:
        1. Missing AFL++ persistent-mode macros
        2. Target function not called in harness
        3. Unbalanced braces (syntax error indicator)
        4. No main() function

        Fix A: fdp_consume_ calls are whitelisted (valid FuzzedDataProvider usage).
        Fix B: Non-fatal warning logged when no precondition guard is present.
        Fix 119: indirect_reach=True skips target-func-name check (function is reached
                 via public API with specific parameters, not called directly).
        Fix 123: direct_internal=True MUST call the target directly — do NOT skip check.

        Returns (passed, list_of_failure_reasons).
        """
        reasons = []
        warnings = []

        # 1. AFL++ persistent mode macros required
        if "__AFL_LOOP" not in harness_code:
            reasons.append("missing __AFL_LOOP — harness is not in persistent mode")
        if "__AFL_FUZZ_TESTCASE_BUF" not in harness_code:
            reasons.append("missing __AFL_FUZZ_TESTCASE_BUF — input buffer not referenced")

        # 2. Harness actually calls the target function.
        # Fix A: fdp_consume_* calls are valid FDP usage — do NOT treat as missing symbol.
        # Fix 91: Upgraded from WARNING to FAILURE — triggers LLM repair which has a
        # much better chance of adding the target function call.  The profiling stage
        # (gdb breakpoint) remains the ultimate check, but this gives repair one shot.
        # Fix 95: Static functions CANNOT be called directly — they must be reached
        # indirectly via public API.  Skip this check for static targets.
        # Fix 119: Skip when indirect_reach=True — function is reached via public API
        # with specific parameter values (e.g. quality=1 reaches compress_fragment).
        # Fix 123: direct_internal MUST call function directly; indirect_reach skips only
        # when NOT direct_internal (direct_internal overrides indirect_reach skip).
        skip_name_check = is_static or (indirect_reach and not direct_internal)
        if target_func and target_func not in harness_code and not skip_name_check:
            reasons.append(f"target function '{target_func}' not called in harness")

        # 3. Balanced braces (simple count — catches truncated LLM outputs)
        open_count = harness_code.count("{")
        close_count = harness_code.count("}")
        if abs(open_count - close_count) > 1:
            reasons.append(
                f"unbalanced braces: {open_count} '{{' vs {close_count} '}}'"
            )

        # 4. main() function present
        if "main(" not in harness_code:
            reasons.append("no main() function found in harness")

        # 5. Fix 104: Detect pipe() without fork/thread — deadlock for large inputs.
        if "pipe(" in harness_code and "fork(" not in harness_code and "pthread_" not in harness_code:
            reasons.append(
                "pipe() used without fork/thread — will deadlock for inputs > 64KB. "
                "Use tmpfile() + fileno() or memory-based API instead"
            )

        # Fix B: Non-fatal warning if no precondition guard (continue; inside loop body)
        # Pattern: __AFL_LOOP body with no `continue` statement = no early pruning
        has_loop = "__AFL_LOOP" in harness_code
        has_continue = "continue;" in harness_code
        if has_loop and not has_continue:
            warnings.append(
                "no precondition guard (continue;) in AFL loop — "
                "consider adding if (len < MIN_SIZE) continue; for BEACON-style pruning"
            )
        # These are only warnings — do NOT add to reasons (non-fatal)
        _ = warnings  # stored for potential future structured logging

        # Variadic arity: a callee reads one argument per format directive, so
        # passing fewer is undefined behaviour in the harness and every crash it
        # yields is a false positive. The pipeline shipped exactly that for
        # minmea_scan; see nemesis/symbolic/variadic_arity.py. Fatal, because a
        # rejected harness gets regenerated while an accepted one silently
        # poisons the whole run.
        if target_declaration and target_func:
            from nemesis.symbolic import variadic_arity as _va
            if _va.target_is_variadic(target_declaration):
                findings = _va.check(harness_code, target_func)
                if findings:
                    reasons.extend(str(f) for f in findings)
                    reasons.append(_va.REGENERATION_HINT)

        return len(reasons) == 0, reasons

    def _target_declaration(self, func: str) -> str | None:
        """The target's declaration, resolved by the builder.

        Delegates rather than keeping a second copy: two implementations of
        "where does this thing live" is exactly what cost a whole libnmea
        campaign when the library resolvers diverged.
        """
        return self.builder.target_declaration(func)

    def _auto_resolve_compile_errors(
        self, harness: HarnessSpec, compile_errors: str,
    ) -> bool:
        """Fix 133: Auto-resolve undeclared identifiers and missing headers.

        Generic for any library.  Searches source-tree headers to find:
        1. Which header declares an undeclared function / type / macro
        2. Where a missing header file actually lives (basename search)

        Modifies ``harness.c_code`` (adds/fixes ``#include``) and
        ``harness.compile_flags`` (adds ``-I`` dirs) **in-place**.

        Returns True if any fixes were applied.
        """
        import re as _re133

        source_root = Path(self.config.target.source_root)
        if not source_root.is_dir():
            return False

        # ── Parse error messages ────────────────────────────────────
        _undecl_pats = [
            r"implicit declaration of function '(\w+)'",
            r"call to undeclared function '(\w+)'",
            r"use of undeclared identifier '(\w+)'",
            r"unknown type name '(\w+)'",
            r"incomplete definition of type 'struct (\w+)'",
        ]
        undeclared: set[str] = set()
        for pat in _undecl_pats:
            undeclared.update(_re133.findall(pat, compile_errors))

        # Filter AFL macros and stdint types (not resolvable from source tree)
        _SKIP = {
            "__AFL_FUZZ_TESTCASE_BUF", "__AFL_FUZZ_TESTCASE_LEN",
            "__AFL_LOOP", "__AFL_INIT", "__AFL_FUZZ_INIT",
            "__AFL_COVERAGE", "__AFL_COVERAGE_ON", "__AFL_COVERAGE_OFF",
            "__AFL_HAVE_MANUAL_CONTROL",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t",
            "int8_t", "int16_t", "int32_t", "int64_t",
            "size_t", "ssize_t", "NULL", "bool", "true", "false",
        }
        undeclared -= _SKIP

        _missing_pats = [
            r"'([^']+\.h)' file not found",
            r"fatal error:\s*([^\s:]+\.h):\s*No such file",
        ]
        missing_headers: set[str] = set()
        for pat in _missing_pats:
            missing_headers.update(_re133.findall(pat, compile_errors))

        if not undeclared and not missing_headers:
            return False

        self.log.info(
            "harness.auto_resolve.start",
            undeclared=sorted(undeclared)[:10],
            missing_headers=sorted(missing_headers)[:5],
            fix="Fix 133",
        )

        # ── Index all .h files in source tree ───────────────────────
        all_headers = list(source_root.rglob("*.h"))
        if len(all_headers) > 500:
            # Limit to internal_include_dirs + include_subdir to stay fast
            priority_dirs: list[Path] = []
            for idir in self.config.target.internal_include_dirs:
                p = source_root / idir
                if p.is_dir():
                    priority_dirs.append(p)
            incl_sub = self.config.target.include_subdir
            if incl_sub:
                p = source_root / incl_sub
                if p.is_dir():
                    priority_dirs.append(p)
            subset: list[Path] = []
            for pd in priority_dirs:
                subset.extend(pd.rglob("*.h"))
            all_headers = subset[:500]

        # Lazy header-content cache
        _hcache: dict[Path, str] = {}

        def _read_h(h: Path) -> str:
            if h not in _hcache:
                try:
                    _hcache[h] = h.read_text(errors="ignore")
                except OSError:
                    _hcache[h] = ""
            return _hcache[h]

        changed = False
        new_includes: list[str] = []
        extra_dirs: set[Path] = set()

        # Dirs already covered by -I flags
        known_dirs: set[Path] = {source_root}
        incl_sub = self.config.target.include_subdir or self.config.target.source_subdir
        if incl_sub:
            known_dirs.add(source_root / incl_sub)
        # Ungated to match the -I emission above: these directories are now
        # always passed to the compiler, so treating them as uncovered here
        # would make this pass re-resolve headers that already compile.
        for idir in self.config.target.internal_include_dirs:
            known_dirs.add(source_root / idir)
        if harness.compile_flags:
            for m in _re133.finditer(r"-I(\S+)", harness.compile_flags):
                known_dirs.add(Path(m.group(1)))

        # ── Resolve missing headers (exact basename match) ──────────
        resolved_missing: set[str] = set()
        for missing in sorted(missing_headers):
            basename = Path(missing).name
            candidates = [h for h in all_headers if h.name == basename]
            if candidates:
                # Prefer candidate inside internal_include_dirs
                best = candidates[0]
                for c in candidates:
                    for idir in self.config.target.internal_include_dirs:
                        if str(source_root / idir) in str(c.parent):
                            best = c
                            break

                parent = best.parent
                for variant in [f'#include "{missing}"', f"#include <{missing}>"]:
                    if variant in harness.c_code:
                        harness.c_code = harness.c_code.replace(
                            variant, f'#include "{basename}"', 1,
                        )
                        changed = True

                if parent not in known_dirs:
                    extra_dirs.add(parent)
                    known_dirs.add(parent)
                resolved_missing.add(missing)
                self.log.info(
                    "harness.auto_resolve.fixed_path",
                    missing=missing,
                    found=str(best.relative_to(source_root)),
                )
            else:
                # No match — comment out the broken #include so the compiler
                # can continue past the fatal error.  The undeclared-identifier
                # resolution below will add the correct header instead.
                for variant in [f'#include "{missing}"', f"#include <{missing}>"]:
                    if variant in harness.c_code:
                        harness.c_code = harness.c_code.replace(
                            variant,
                            f"/* Fix 133: removed — {basename} not found */",
                            1,
                        )
                        changed = True
                        self.log.info(
                            "harness.auto_resolve.removed_broken",
                            missing=missing,
                        )

        # ── Resolve undeclared identifiers ──────────────────────────
        for name in sorted(undeclared):
            best_header: Path | None = None
            best_score = 0

            for hfile in all_headers:
                content = _read_h(hfile)
                if not content:
                    continue

                score = 0
                esc = _re133.escape(name)
                # Function / macro-like declaration (strongest)
                if _re133.search(rf"\b{esc}\s*\(", content) or _re133.search(rf"#define\s+{esc}\b", content):
                    score = 3
                # typedef / struct / enum containing the name
                elif _re133.search(
                    rf"(?:typedef|struct|enum)\s+[^;]*\b{esc}\b", content,
                ) or _re133.search(rf"extern\b[^;]*\b{esc}\b", content):
                    score = 2
                else:
                    continue

                # Bonus: header in an internal_include_dir
                for idir in self.config.target.internal_include_dirs:
                    if str(source_root / idir) in str(hfile.parent):
                        score += 1
                        break

                if score > best_score:
                    best_score = score
                    best_header = hfile

            if best_header:
                hname = best_header.name
                directive = f'#include "{hname}"'
                if directive not in harness.c_code:
                    new_includes.append(directive)

                parent = best_header.parent
                if parent not in known_dirs:
                    extra_dirs.add(parent)
                    known_dirs.add(parent)

                self.log.info(
                    "harness.auto_resolve.found_decl",
                    identifier=name,
                    header=str(best_header.relative_to(source_root)),
                )

        # ── Apply new #include directives ───────────────────────────
        if new_includes:
            # De-duplicate
            new_includes = list(dict.fromkeys(new_includes))
            lines = harness.c_code.splitlines(keepends=True)
            last_inc = -1
            for i, line in enumerate(lines):
                if line.strip().startswith("#include"):
                    last_inc = i
            block = "\n".join(new_includes) + "\n"
            if last_inc >= 0:
                lines.insert(last_inc + 1, block)
            else:
                lines.insert(0, block)
            harness.c_code = "".join(lines)
            changed = True

        # ── Apply extra -I dirs via compile_flags ───────────────────
        if extra_dirs:
            flags = harness.compile_flags or "-g -O0"
            for d in sorted(extra_dirs):
                flag = f"-I{d}"
                if flag not in flags:
                    flags += f" {flag}"
            harness.compile_flags = flags
            changed = True

        if changed:
            self.log.info(
                "harness.auto_resolve.applied",
                includes_added=len(new_includes),
                dirs_added=len(extra_dirs),
                fix="Fix 133",
            )

        return changed

    def _required_direct_call_func(self) -> str:
        """Return the func_name that must be called directly when auto_expose
        is set, or empty string if no auto_expose pin exists.

        Compatibility shim — kept so log lines that reference the primary
        auto-expose'd target still resolve. Validation logic has moved to
        `_required_direct_call_funcs` (plural), which accepts any one of
        the exposed functions being called.
        """
        funcs = self._required_direct_call_funcs()
        return funcs[0] if funcs else ""

    def _required_direct_call_funcs(self) -> list[str]:
        """All function names that have auto_expose=true. Validation passes
        when ANY one of them is called from the harness.
        """
        try:
            pins = self.config.target.pinned_funcs or []
        except AttributeError:
            return []
        return [
            getattr(p, "func_name", "")
            for p in pins
            if getattr(p, "auto_expose", False)
            and getattr(p, "func_name", "")
        ]

    def _public_api_priority_funcs(self) -> list[str]:
        """Names of the highest-priority public-API entry points for the
        target library, used by the ordering gate to verify the harness
        calls one of them BEFORE the auto_expose'd function.

        Derived from `recon_scoring.bonus_func_patterns` — any function
        with a score >= 10 is treated as a primary entry point.
        """
        try:
            patterns = self.config.recon_scoring.bonus_func_patterns or {}
        except AttributeError:
            return []
        return [name for name, score in patterns.items() if score >= 10]

    def _validate_auto_expose_harness(
        self, c_code: str,
    ) -> tuple[bool, str]:
        """Combined gate for hybrid Strategy A+B harnesses.

        Validation passes when AT LEAST ONE of the auto_expose'd
        functions is called AND the chosen call comes after a
        public-API entry-point call (so internal state is populated
        when the exposed function runs).

        With multiple auto_expose pins (e.g. build_node + build_model),
        the architect is encouraged to pick the SIMPLEST callable
        — usually the non-recursive caller — and only that call is
        required. Architects often pick the gateway that takes only
        the opaque parser/codec; we accept that.

        Returns (True, "") on success, or (False, error_message) on
        failure.
        """
        required_any = self._required_direct_call_funcs()
        if not required_any:
            return True, ""  # auto_expose not in use; no constraints
        called = [n for n in required_any if self._harness_calls(c_code, n)]
        if not called:
            primary = required_any[0]
            alternatives = ", ".join(required_any[1:]) or "—"
            return False, (
                f"REJECTED — harness compiles but does NOT call any of "
                f"the visibility-patched functions ({', '.join(required_any)}).\n"
                f"\n"
                f"At least ONE of these must appear as a function call "
                f"inside the __AFL_LOOP body. PREFERRED: call the "
                f"simplest one — the function whose argument list is "
                f"only the opaque parser/codec object (no internal "
                f"struct fields). For example, if `{primary}` is the "
                f"deep-recursive helper but a non-recursive caller "
                f"({alternatives}) is also exposed and only takes the "
                f"parser, call THAT — it will trigger the recursion "
                f"path through the library's own glue code without "
                f"requiring you to construct any internal struct.\n"
                f"\n"
                f"Order inside __AFL_LOOP:\n"
                f"  1. Construct parser/codec\n"
                f"  2. Feed AFL input through the public API "
                f"(XML_Parse / png_read_info / ...)\n"
                f"  3. THEN call ONE of the exposed functions\n"
                f"  4. Cleanup\n"
                f"\n"
                f"Do NOT delete the call again to fix subsequent "
                f"compile errors — fix the underlying type/include "
                f"error instead."
            )
        # At least one exposed function is called. Pick the FIRST one
        # found (in source order) and ensure it comes after the
        # public API call.
        api_candidates = self._public_api_priority_funcs()
        if not api_candidates:
            return True, ""  # no candidates configured; accept presence alone
        api_off = self._public_api_call_offset(c_code, api_candidates)
        if api_off < 0:
            return False, (
                f"REJECTED — harness must FIRST feed the AFL input "
                f"through the public API (e.g. one of: "
                f"{', '.join(api_candidates[:5])}). The exposed "
                f"functions ({', '.join(called)}) read internal state "
                f"that is only populated by the public-API call. Add "
                f"the public-API call BEFORE the exposed function call."
            )
        # Find the earliest exposed-function call site
        earliest_call = -1
        earliest_name = ""
        for fname in called:
            off = self._direct_call_offset(c_code, fname)
            if off >= 0 and (earliest_call < 0 or off < earliest_call):
                earliest_call = off
                earliest_name = fname
        if earliest_call < 0:
            return False, "internal error: exposed call gone after presence check"
        if earliest_call < api_off:
            return False, (
                f"REJECTED — `{earliest_name}(...)` is called BEFORE "
                f"the public-API entry point. The exposed function "
                f"reads internal state built by the public API; "
                f"calling it first means it reads zero-initialised "
                f"state and does no useful work.\n"
                f"\n"
                f"REQUIRED ORDER inside __AFL_LOOP:\n"
                f"  1. Construct the parser/codec\n"
                f"  2. Call ONE of {api_candidates[:5]} on the AFL "
                f"input — this populates internal state\n"
                f"  3. THEN call `{earliest_name}(...)` on the "
                f"populated state\n"
                f"  4. Cleanup\n"
                f"\n"
                f"Move the call to `{earliest_name}(...)` AFTER the "
                f"public-API call. Re-emit the COMPLETE C source."
            )
        return True, ""

    @staticmethod
    def _public_api_call_offset(c_code: str, candidates: list[str]) -> int:
        """Find the lowest character offset of any public-API call site
        among `candidates`. -1 if none found.

        Used by the ordering gate to ensure the visibility-patched call
        comes AFTER the public-API call that populates internal state.
        """
        if not c_code or not candidates:
            return -1
        best = -1
        for c in candidates:
            for m in re.finditer(
                r"(?:^|[^\w])" + re.escape(c) + r"\s*\(",
                c_code,
                re.MULTILINE,
            ):
                if best == -1 or m.start() < best:
                    best = m.start()
        return best

    @staticmethod
    def _direct_call_offset(c_code: str, func_name: str) -> int:
        """Find the lowest character offset of a CALL to `func_name`
        that is NOT a forward declaration. -1 if none."""
        clean = re.sub(r"/\*.*?\*/", " ", c_code, flags=re.DOTALL)
        clean = re.sub(r"//[^\n]*", " ", clean)
        for m in re.finditer(
            r"(?:^|[^\w])" + re.escape(func_name) + r"\s*\(",
            clean,
            re.MULTILINE,
        ):
            line_start = clean.rfind("\n", 0, m.start()) + 1
            tail_end = clean.find(";", m.end())
            if tail_end < 0:
                return m.start()
            stmt = clean[line_start : tail_end + 1].strip()
            decl_prefixes = (
                "extern ", "static ", "void ", "int ", "char ", "long ",
                "short ", "unsigned ", "signed ", "const ", "struct ",
                "union ", "enum ",
            )
            looks_like_decl = (
                any(stmt.startswith(p) for p in decl_prefixes)
                and "{" not in stmt
                and not stmt.startswith(func_name + "(")
            )
            if not looks_like_decl:
                return m.start()
        return -1

    @staticmethod
    def _harness_calls(c_code: str, func_name: str) -> bool:
        """True iff the harness C source contains a CALL to `func_name`
        (not just a forward declaration or a comment)."""
        if not func_name or not c_code:
            return False
        # Strip C/C++ comments so a `// build_node(...)` mention doesn't count
        clean = re.sub(r"/\*.*?\*/", " ", c_code, flags=re.DOTALL)
        clean = re.sub(r"//[^\n]*", " ", clean)
        # A forward declaration ends with `;` immediately after the `)`. A
        # call has the result either statement-context or assigned. The
        # simplest discriminator: at least one occurrence of `name(` that
        # is NOT immediately followed (after balanced parens) by a `;`
        # marking it as a declaration. Approximation: count occurrences
        # whose enclosing line starts with an identifier or `=` (call
        # context) vs. starts with a type-like keyword (decl context).
        call_re = re.compile(
            r"(?:^|[^\w])" + re.escape(func_name) + r"\s*\(",
            re.MULTILINE,
        )
        for m in call_re.finditer(clean):
            line_start = clean.rfind("\n", 0, m.start()) + 1
            # Forward decl heuristic: starts with a return-type token
            # (uppercase/lowercase identifier + maybe `*` or `void`) and
            # ends in `;`. We look at the WHOLE statement: from line
            # start to next `;` after the call's closing paren.
            tail_end = clean.find(";", m.end())
            if tail_end < 0:
                # No semicolon → definitely not a forward decl. Treat as call.
                return True
            stmt = clean[line_start : tail_end + 1]
            stmt_stripped = stmt.strip()
            # Heuristic decl prefixes
            decl_prefixes = (
                "extern ", "static ", "void ", "int ", "char ", "long ",
                "short ", "unsigned ", "signed ", "const ", "struct ",
                "union ", "enum ",
            )
            looks_like_decl = (
                any(stmt_stripped.startswith(p) for p in decl_prefixes)
                and "{" not in stmt_stripped  # decls don't have a body here
                and not stmt_stripped.startswith(func_name + "(")
            )
            if not looks_like_decl:
                return True
        return False

    def _try_build_harness_with_llm_repair(
        self,
        harness: HarnessSpec,
        build_dir: Path,
        is_static: bool = False,
        indirect_reach: bool = False,
        direct_internal: bool = False,  # Fix 123
    ) -> bool:
        """Compile harness with LLM repair on failure.

        Flow:
        1. Pre-flight check (~1s) — catches missing AFL macros, unbalanced braces, etc.
        2. If pre-flight fails: call LLM repair once, then re-check.
        3. Attempt compile. On failure: call LLM repair up to 2 more times.

        Fix 119: indirect_reach=True passes through to _preflight_harness to skip
        the target-func-name check when the function is reached via parameter control.
        Fix 123: direct_internal=True passes through so preflight enforces direct call.

        Returns True if the harness binary was successfully built.
        """
        # ── 1. Pre-flight ────────────────────────────────────────
        target_decl = self._target_declaration(harness.target_func or "")
        ok, reasons = self._preflight_harness(
            harness.c_code, harness.target_func or "",
            is_static=is_static, indirect_reach=indirect_reach,
            direct_internal=direct_internal,
            target_declaration=target_decl,
        )
        # Outcome record. Without it the run keeps only the harness that
        # eventually passed, and six months later there is no trace of why the
        # first one was rejected — which is the interesting half. Distinguishes
        # first-pass soundness from soundness-after-repair, because only the
        # first measures the generator and only the second measures the product.
        from nemesis.symbolic.variadic_arity import target_is_variadic
        self._last_validation = {
            "target": harness.target_func or "",
            "variadic": bool(target_decl and target_is_variadic(target_decl)),
            "declaration": target_decl,
            "first_pass_passed": ok,
            "first_pass_reasons": list(reasons),
            "repair_attempted": False,
            "repair_produced_code": False,
            "final_passed": ok,
            "outcome": "first_pass_ok" if ok else "pending",
        }
        if not ok:
            self.log.warning(
                "harness.preflight_failed",
                func=harness.target_func,
                reasons=reasons,
            )
            self._last_validation["repair_attempted"] = True
            if self._neural is not None:
                repaired = self._neural.repair_harness(  # type: ignore[union-attr]
                    harness.c_code,
                    "\n".join(reasons),
                    harness.target_func or "",
                )
                if repaired:
                    harness.c_code = repaired
                    self._last_validation["repair_produced_code"] = True
                    self.log.info("harness.preflight_llm_repair_applied", func=harness.target_func)
                    # Re-check after repair
                    ok2, reasons2 = self._preflight_harness(
                        harness.c_code, harness.target_func or "",
                        is_static=is_static, indirect_reach=indirect_reach,
                        direct_internal=direct_internal,
                        target_declaration=target_decl,
                    )
                    self._last_validation.update(
                        final_passed=ok2,
                        final_reasons=list(reasons2),
                        outcome="repair_ok" if ok2 else "repair_failed",
                    )
                    if not ok2:
                        self.log.warning(
                            "harness.preflight_still_failed", func=harness.target_func, reasons=reasons2
                        )
                        # Continue anyway — compile will give better errors
                else:
                    self._last_validation["outcome"] = "repair_empty"
                    self.log.warning("harness.preflight_llm_repair_empty", func=harness.target_func)
                    self.log.info("harness.validation", **self._last_validation)
                    return False
            else:
                self._last_validation["outcome"] = "no_repair_available"
                self.log.info("harness.validation", **self._last_validation)
                return False

        self.log.info("harness.validation", **self._last_validation)

        # ── 2. First compile attempt ─────────────────────────────
        if self.builder.build_harness(harness, build_dir):
            # Fix 145+146: validation gate for hybrid Strategy A+B —
            # checks both presence AND ordering of the exposed-function
            # call relative to public-API calls.
            ok, err = self._validate_auto_expose_harness(harness.c_code)
            if not ok:
                self.log.warning(
                    "harness.auto_expose_invalid",
                    func=self._required_direct_call_func(),
                    reason=err.split("\n", 1)[0][:120],
                    stage="first_compile",
                )
                self.builder._last_harness_compile_errors = err
                # Fall through to repair loop below
            else:
                # Fix C: compile CMPLOG binary (non-blocking — failure doesn't abort pipeline)
                cmplog_path = self.builder.compile_harness_cmplog(harness, build_dir)
                if cmplog_path:
                    harness.cmplog_binary = cmplog_path
                return True

        # ── 2b. Fix 133: Auto-resolve before LLM repair ──────────
        # Parse compile errors for undeclared identifiers and missing
        # headers, search the source tree for the correct declarations,
        # and auto-add #include + -I flags.  Up to 2 passes (second
        # pass catches errors uncovered after removing broken includes).
        compile_errors = self.builder._last_harness_compile_errors
        for _ar_pass in range(2):
            if not self._auto_resolve_compile_errors(harness, compile_errors):
                break  # nothing fixable
            if self.builder.build_harness(harness, build_dir):
                # Fix 145+146: validation gate (same logic as above).
                ok, err = self._validate_auto_expose_harness(harness.c_code)
                if not ok:
                    self.log.warning(
                        "harness.auto_expose_invalid",
                        func=self._required_direct_call_func(),
                        reason=err.split("\n", 1)[0][:120],
                        stage="auto_resolve",
                    )
                    self.builder._last_harness_compile_errors = err
                else:
                    self.log.info(
                        "harness.auto_resolve.compile_success",
                        func=harness.target_func,
                        pass_num=_ar_pass + 1,
                        fix="Fix 133",
                    )
                    cmplog_path = self.builder.compile_harness_cmplog(harness, build_dir)
                    if cmplog_path:
                        harness.cmplog_binary = cmplog_path
                    return True
            compile_errors = self.builder._last_harness_compile_errors

        # ── 3. LLM repair loop (up to 2 retries) ─────────────────
        if self._neural is None:
            return False

        compile_errors = self.builder._last_harness_compile_errors
        # Fix 145 part 2: bumped from 2 to 4 retries because the validation
        # gate (direct_call_missing) may consume one or two attempts before
        # the LLM accepts the constraint and stops deleting the direct call.
        max_repair_attempts = 4 if self._required_direct_call_func() else 2
        for attempt in range(max_repair_attempts):
            self.log.info(
                "harness.llm_repair_attempt",
                func=harness.target_func,
                attempt=attempt + 1,
                errors_preview=compile_errors[:200],
            )
            repaired = self._neural.repair_harness(  # type: ignore[union-attr]
                harness.c_code,
                compile_errors,
                harness.target_func or "",
            )
            if not repaired:
                self.log.warning("harness.llm_repair_no_output", attempt=attempt + 1)
                break
            harness.c_code = repaired
            if self.builder.build_harness(harness, build_dir):
                # Fix 145+146: combined validation gate — checks call
                # presence AND ordering. The error message returned by
                # _validate_auto_expose_harness is detailed enough to
                # guide the repair LLM through both failure modes.
                ok, err = self._validate_auto_expose_harness(harness.c_code)
                if not ok:
                    self.log.warning(
                        "harness.auto_expose_invalid",
                        func=self._required_direct_call_func(),
                        reason=err.split("\n", 1)[0][:120],
                        stage="llm_repair",
                        attempt=attempt + 1,
                    )
                    compile_errors = err
                    self.builder._last_harness_compile_errors = compile_errors
                    continue  # next repair attempt
                self.log.info(
                    "harness.llm_repair_success",
                    func=harness.target_func,
                    attempt=attempt + 1,
                )
                # Fix C: CMPLOG binary after repair success
                cmplog_path = self.builder.compile_harness_cmplog(harness, build_dir)
                if cmplog_path:
                    harness.cmplog_binary = cmplog_path
                return True
            compile_errors = self.builder._last_harness_compile_errors

        self.log.error(
            "harness.llm_repair_exhausted",
            func=harness.target_func,
            last_errors=compile_errors[:300],
        )
        return False

    def profile_harness_variant(
        self,
        harness: HarnessSpec,
        build_dir: Path,
        timeout_sec: int = 120,
    ) -> tuple[bool, float, int]:
        """Fix D: Delegate to InstrumentedBuilder.profile_harness_variant()."""
        return self.builder.profile_harness_variant(harness, build_dir, timeout_sec)

    def collect_gcov_around_function(
        self,
        harness: HarnessSpec,
        target_func: str,
        corpus_files: list[Path],
        n_samples: int = 5,
    ) -> str:
        """Delegate to InstrumentedBuilder.collect_gcov_around_function()."""
        build_dir = Path(self.config.target.build_dir)
        return self.builder.collect_gcov_around_function(
            harness, build_dir, target_func, corpus_files, n_samples,
        )

    def apply_and_build(
        self,
        patch: PatchProposal,
        harness: HarnessSpec | None,
    ) -> bool:
        """Apply patch, write harness, and build instrumented binary."""
        # Patches always go into work_root (the patched copy) — NEVER source_root
        work_root = Path(self.config.target.effective_work_root)
        build_dir = Path(self.config.target.build_dir)

        # Auto-convert known-bad patch patterns to safe #if 0 wrapping
        self.applicator.sanitize_patch(patch)

        # Apply source patch (skip if no patch provided)
        patch_applied = False
        if patch.file_path:
            if self.applicator.apply(patch, work_root):
                patch_applied = True
                # Quick syntax check (~1s) before the full cmake build (~60s).
                # Retry up to 3 times with auto-fix for compile errors.
                syntax_ok = self.builder.syntax_check(patch.file_path, work_root, build_dir)
                if not syntax_ok:
                    src_file = work_root / patch.file_path
                    prev_stderr = ""
                    for attempt in range(3):
                        cur_stderr = self.builder._last_syntax_stderr
                        # Early exit: if stderr is identical to previous attempt, auto-fix is stuck
                        if cur_stderr and cur_stderr == prev_stderr:
                            self.log.warning(
                                "patch.auto_fix_stuck",
                                attempt=attempt + 1,
                                reason="stderr unchanged between retries",
                            )
                            break
                        prev_stderr = cur_stderr
                        if self._auto_fix_compile_errors(
                            src_file, cur_stderr, self.log
                        ):
                            if self.builder.syntax_check(patch.file_path, work_root, build_dir):
                                self.log.info("patch.auto_fix_success", attempts=attempt + 1)
                                syntax_ok = True
                                break
                        else:
                            break  # no more fixable errors
                if not syntax_ok and patch_applied:
                    self.log.warning(
                        "patch.syntax_failed_after_autofix — rolling back"
                    )
                    self.applicator.rollback(work_root)
                    patch_applied = False
            else:
                self.log.warning("patch.apply_failed — continuing with unpatched source")

        # Build libarchive with AFL++ instrumentation (cmake .. → work_root)
        lib_ok = self.builder.build_library(work_root, build_dir)
        if not lib_ok and patch_applied:
            # Patch caused build failure — rollback and retry without patch.
            # An unpatched AFL run is still better than no AFL run at all.
            self.log.warning("build.patched_failed — rolling back, retrying unpatched")
            self.applicator.rollback(work_root)
            patch_applied = False
            lib_ok = self.builder.build_library(work_root, build_dir)
        if not lib_ok:
            self.log.error("build.library_failed")
            return False

        # Write and compile the harness (with LLM repair on failure)
        if harness and harness.c_code:
            harness_ok = self._try_build_harness_with_llm_repair(
                harness, build_dir, is_static=harness.is_static,
                indirect_reach=harness.indirect_reach,
                direct_internal=getattr(harness, 'direct_internal', False),  # Fix 123
            )
            if not harness_ok:
                self.log.error("build.harness_failed")
                return False
        else:
            self.log.error("build.no_harness")
            return False

        return True


class Z3Verifier:
    """
    Uses Z3 to verify path satisfiability.

    Two modes:
    1. AST-level: fast, handles compile-time guards (#ifdef)
    2. angr-based: slow, handles runtime constraints (future)
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("symbolic.z3")

    def verify(
        self,
        patch: PatchProposal,
        context: AnalysisContext,
    ) -> VerificationResult:
        """
        Verify that patching creates a satisfiable path to the target.

        Strategy:
        1. Extract constraints from blockers in the call chain
        2. Encode as Z3 formulas
        3. Check SAT under the patched condition
        """
        import time
        start = time.monotonic()

        try:
            from z3 import Bool, Solver

            s = Solver()
            s.set("timeout", self.config.symbolic.timeout_seconds * 1000)

            constraints_added = 0

            # Encode each blocker as a Z3 constraint
            for blocker in context.call_chain.blockers:
                if blocker.blocker_type.value == "macro":
                    macro_var = Bool(f"macro_{blocker.condition[:30]}")

                    if self._patch_bypasses_blocker(patch, blocker):
                        s.add(macro_var == True)
                        self.log.debug("constraint.bypassed", blocker=blocker.condition)
                    else:
                        s.add(macro_var == False)
                    constraints_added += 1

                elif blocker.blocker_type.value == "format_requirement":
                    format_var = Bool(f"format_{blocker.condition[:30]}")
                    s.add(format_var == True)
                    constraints_added += 1

            reachable = Bool("target_reachable")
            s.add(reachable == True)

            result = s.check()
            solve_time = (time.monotonic() - start) * 1000

            if str(result) == "sat":
                model_dict = {}
                m = s.model()
                for d in m.decls():
                    model_dict[d.name()] = str(m[d])

                self.log.info(
                    "verify.sat",
                    constraints=constraints_added,
                    solve_ms=round(solve_time, 1),
                )
                return VerificationResult(
                    is_satisfiable=True,
                    model=model_dict,
                    solve_time_ms=solve_time,
                    constraints_count=constraints_added,
                )
            else:
                self.log.warning("verify.unsat", constraints=constraints_added)
                return VerificationResult(
                    is_satisfiable=False,
                    unsat_core=["Could not satisfy path constraints"],
                    solve_time_ms=solve_time,
                    constraints_count=constraints_added,
                )

        except ImportError:
            self.log.warning("z3.not_installed, assuming SAT")
            return VerificationResult(
                is_satisfiable=True,
                model={"note": "Z3 not available, assumed SAT"},
                solve_time_ms=0,
            )

    def _patch_bypasses_blocker(self, patch: PatchProposal, blocker) -> bool:
        """Check if a patch bypasses a given blocker."""
        if blocker.condition in patch.original:
            return True
        if "/* NEMESIS" in patch.replacement or "#if 0" in patch.replacement:
            return True
        if patch.patch_type == "blocker_bypass":
            return True
        return False


class PatchApplicator:
    """Applies source patches safely with rollback support."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("symbolic.patch")
        self._backups: dict[str, str] = {}

    def sanitize_patch(self, patch: PatchProposal) -> None:
        """
        Template-based patching for blocker_bypass patches.

        For ALL blocker_bypass patches: ignore LLM replacement entirely,
        wrap original code in C block comments /* ... */.

        Block comments avoid preprocessor parsing issues that #if 0 causes
        (e.g. "token is not a valid binary operator" when struct declarations
        appear on the same line as #if 0).

        Downstream _auto_fix_compile_errors handles unused vars etc.
        """
        orig = patch.original or ""
        if not orig:
            return

        if patch.patch_type == "blocker_bypass":
            # Escape any existing */ inside the block to prevent nested comment breakage
            escaped = orig.replace("*/", "* /")
            safe_repl = f"/* NEMESIS: blocker bypass\n{escaped}\n*/"
            self.log.info(
                "patch.template_bypass",
                original_len=len(orig),
                llm_replacement_discarded=bool(patch.replacement),
            )
            patch.replacement = safe_repl

    def apply(self, patch: PatchProposal, source_root: Path) -> bool:
        """
        Apply a patch to the source tree.
        Creates a backup of the original file for rollback.
        """
        target_file = source_root / patch.file_path
        if not target_file.exists():
            self.log.error("file.not_found", path=str(target_file))
            return False

        content = target_file.read_text()

        # Try exact match first; fall back to whitespace-normalized fuzzy match.
        # LLM often generates the right code but with different indentation/spacing.
        actual_original = patch.original
        if patch.original and patch.original not in content:
            fuzzy = self._fuzzy_find_original(content, patch.original, patch.line)
            if fuzzy:
                self.log.info(
                    "patch.fuzzy_matched",
                    file=patch.file_path,
                    line=patch.line,
                    llm_len=len(patch.original),
                    actual_len=len(fuzzy),
                )
                actual_original = fuzzy
            else:
                self.log.error(
                    "patch.mismatch",
                    file=patch.file_path,
                    line=patch.line,
                )
                return False

        # Reject patches that are known to cause compile failures
        if self._patch_is_dangerous(patch):
            return False

        # Backup
        self._backups[str(target_file)] = content

        # Apply
        if actual_original:
            new_content = content.replace(actual_original, patch.replacement, 1)
        else:
            lines = content.splitlines(keepends=True)
            if 0 < patch.line <= len(lines):
                lines.insert(patch.line - 1, patch.replacement + "\n")
                new_content = "".join(lines)
            else:
                self.log.error("patch.line_out_of_range", line=patch.line)
                return False

        target_file.write_text(new_content)
        self.log.info("patch.applied", file=patch.file_path, line=patch.line)
        return True

    def _patch_is_dangerous(self, patch: PatchProposal) -> bool:
        """
        Reject patches with patterns known to cause -Werror compile failures.

        Returns True (dangerous = reject) if the patch matches any bad pattern.
        """
        repl = patch.replacement or ""
        orig = patch.original or ""

        # `if (0 && expr)` disables the expression → variables inside become unused
        if "if (0 &&" in repl:
            self.log.warning(
                "patch.rejected_dangerous",
                reason="if (0 &&) disables expression — makes variables unused",
                replacement=repl[:80],
            )
            return True

        # Inline preprocessor directives inside C code (e.g. `} else #if 0`)
        if "#if" in repl and ("} else" in repl or "else {" in repl):
            self.log.warning(
                "patch.rejected_dangerous",
                reason="preprocessor directive inside else branch — invalid C syntax",
                replacement=repl[:80],
            )
            return True

        # `#if 0 && (expr)` or `#if 0 && expr` — LLM puts C code into the preprocessor
        # condition instead of wrapping it. Results in syntax errors below the directive.
        import re as _re
        if _re.search(r"#if\s+0\s+&&", repl):
            self.log.warning(
                "patch.rejected_dangerous",
                reason="#if 0 && ... mixes preprocessor and C code — syntax error",
                replacement=repl[:80],
            )
            return True

        # Disabling memory allocation NULL checks — harness will crash before target
        if ("NULL ==" in orig or "== NULL" in orig) and (
            "if (0" in repl or "if (1 &&" in repl
        ):
            self.log.warning(
                "patch.rejected_dangerous",
                reason="disabling NULL check on allocation — harness will crash",
                replacement=repl[:80],
            )
            return True

        return False

    def _fuzzy_find_original(
        self, content: str, target: str, hint_line: int
    ) -> str | None:
        """
        Find the exact text in content that corresponds to target after
        whitespace normalization.  The LLM often generates the right code
        but with different indentation or collapsed/expanded spaces.

        Returns the EXACT substring from content (preserving its whitespace)
        so that content.replace(result, replacement, 1) works correctly.
        Returns None if no match is found.
        """
        import re as _re

        def _norm(s: str) -> str:
            """Collapse all whitespace runs to a single space and strip."""
            return _re.sub(r"\s+", " ", s).strip()

        norm_target = _norm(target)
        target_source_lines = [l.strip() for l in target.splitlines() if l.strip()]
        n = len(target_source_lines)

        content_lines = content.splitlines(keepends=True)
        total = len(content_lines)

        # Search in a ±40-line window around the hinted line (1-indexed)
        lo = max(0, hint_line - 40)
        hi = min(total, hint_line + 40)

        if n == 1:
            # Single-line: compare normalized line text
            for i in range(lo, hi):
                if _norm(content_lines[i]) == norm_target:
                    return content_lines[i].rstrip("\n")
        else:
            # Multi-line: check consecutive window of n lines
            norm_target_lines = [_norm(l) for l in target_source_lines]
            for i in range(lo, min(hi, total - n + 1)):
                window_norm = [_norm(content_lines[i + j]) for j in range(n)]
                if window_norm == norm_target_lines:
                    return "".join(content_lines[i : i + n]).rstrip("\n")

        return None

    def rollback(self, source_root: Path) -> None:
        """Restore all patched files from backups."""
        for path_str, content in self._backups.items():
            Path(path_str).write_text(content)
            self.log.info("patch.rolled_back", file=path_str)
        self._backups.clear()


class InstrumentedBuilder:
    """Builds the target with AFL++ instrumentation + ASan."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("symbolic.builder")
        self._last_syntax_stderr = ""  # captured for auto-fix analysis
        self._last_harness_compile_errors = ""  # captured for LLM repair (Fix A)

    def configure_fuzz_build_dir(self) -> bool:
        """
        Run cmake configure-only (no make) in build_fuzz to pre-generate flags.make.

        Called once at startup so that syntax_check() has flags.make available
        for the very first target (before any full build has run).
        Safe to call even if build_dir already has a valid cmake cache.
        """
        build_dir = Path(self.config.target.build_dir)
        configure_cmd = self.config.target.build.configure
        if not configure_cmd:
            return False
        build_dir.mkdir(parents=True, exist_ok=True)
        # Check if flags.make already exists — skip if so
        if list(build_dir.glob("**/flags.make")):
            self.log.debug("configure_fuzz.already_done")
            return True
        full_cmd = f"cd {build_dir} && {configure_cmd.strip()}"
        self.log.info("configure_fuzz.start", build_dir=str(build_dir))
        try:
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                self.log.info("configure_fuzz.done")
                return True
            else:
                self.log.warning(
                    "configure_fuzz.failed",
                    stderr=result.stderr[-200:] if result.stderr else "",
                )
                return False
        except subprocess.TimeoutExpired:
            self.log.warning("configure_fuzz.timeout")
            return False

    def syntax_check(
        self, rel_file_path: str, work_root: Path, build_dir: Path
    ) -> bool:
        """
        Quick single-file syntax/type check using cmake's stored compile flags.

        Reads C_FLAGS, C_DEFINES, C_INCLUDES from the cmake-generated flags.make
        for the patched file and runs `afl-clang-fast -fsyntax-only`.
        Takes ~1s vs ~60s for a full cmake build.

        Returns True if the file compiles cleanly, False on any error.
        Falls back to True (skip check) if flags.make cannot be found — the
        full cmake build will catch errors anyway.
        """
        import re as _re

        src_file = work_root / rel_file_path
        if not src_file.exists():
            return True  # nothing to check

        # Locate the cmake flags.make for this source file.
        # Convention: build_dir/{subdir}/CMakeFiles/{target}.dir/flags.make
        flags_candidates = list(build_dir.glob("**/flags.make"))
        if not flags_candidates:
            self.log.debug("syntax_check.no_flags_make")
            return True  # can't check → optimistically pass

        flags_file = flags_candidates[0]
        try:
            flags_text = flags_file.read_text()
        except OSError:
            return True

        def _extract(key: str) -> str:
            m = _re.search(rf"^{key}\s*=\s*(.+)$", flags_text, _re.MULTILINE)
            return m.group(1).strip() if m else ""

        c_flags = _extract("C_FLAGS")
        c_defines = _extract("C_DEFINES")
        c_includes = _extract("C_INCLUDES")

        # Fix 117: Filter unresolved cmake variables (${...}) that appear as literal
        # text when flags.make uses generator expressions or unsubstituted vars.
        # Without this, clang gets "no such file or directory: 'C_INCLUDES'" errors.
        def _strip_cmake_vars(s: str) -> str:
            return _re.sub(r'\$\{[^}]*\}', '', s)
        c_flags = _strip_cmake_vars(c_flags)
        c_defines = _strip_cmake_vars(c_defines)
        c_includes = _strip_cmake_vars(c_includes)

        # Keep -Werror so syntax_check catches the same warnings as cmake build.
        # Previously used -Wno-error, but this let patches through that caused
        # -Wunused-variable / -Wuninitialized warnings → -Werror build failure.
        cmd = (
            f"afl-clang-fast -fsyntax-only {c_flags} "
            f"{c_defines} {c_includes} {src_file}"
        )
        self.log.info("syntax_check.start", file=rel_file_path)
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(build_dir),
            )
            self._last_syntax_stderr = result.stderr or ""
            if result.returncode == 0:
                self.log.info("syntax_check.ok", file=rel_file_path)
                return True
            else:
                self.log.warning(
                    "syntax_check.failed",
                    file=rel_file_path,
                    stderr=result.stderr[:300],
                )
                return False
        except subprocess.TimeoutExpired:
            self.log.warning("syntax_check.timeout", file=rel_file_path)
            self._last_syntax_stderr = ""
            return True  # timeout → optimistically pass

    def build_library(self, source_root: Path, build_dir: Path) -> bool:
        """
        Build the target library with AFL++ instrumentation.
        Runs cmake + make in build_dir.

        If CMakeCache.txt already exists (from configure_fuzz_build_dir or a
        previous target), skips the expensive reconfigure (~45s) and only runs
        make (~15s incremental recompile).
        """
        build_dir.mkdir(parents=True, exist_ok=True)

        configure_cmd = self.config.target.build.configure
        make_cmd = self.config.target.build.make

        if not configure_cmd:
            self.log.warning("build.no_configure_command")
            return False

        cmake_cache = build_dir / "CMakeCache.txt"
        # Only trust an existing cache if it was configured with the SAME C
        # compiler the configure command requests. A stale cache from a plain
        # `clang` (or a different target) would skip reconfigure and silently
        # produce an UNINSTRUMENTED library → 0% AFL coverage with no error.
        use_incremental = cmake_cache.exists() and _cmake_cache_compiler_matches(
            cmake_cache, configure_cmd, self.log
        )
        if use_incremental:
            # Incremental build — cmake cache valid, just recompile changed files.
            # rsync + touch in _sync_work_repo() ensures source timestamps > .o timestamps
            # for all files, so make recompiles everything that changed.
            full_cmd = f"cd {build_dir} && {make_cmd.strip()}"
            self.log.info("build.library.start", build_dir=str(build_dir), incremental=True)
        else:
            if cmake_cache.exists():
                try:
                    cmake_cache.unlink()
                    self.log.warning(
                        "build.cmake_cache.stale_cleared", build_dir=str(build_dir),
                        reason="compiler mismatch — forcing clean reconfigure to keep instrumentation",
                    )
                except OSError:
                    pass
            full_cmd = f"cd {build_dir} && {configure_cmd.strip()} && {make_cmd.strip()}"
            self.log.info("build.library.start", build_dir=str(build_dir))

        try:
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(build_dir),
            )

            if result.returncode == 0:
                self.log.info("build.library.success")
                return True
            else:
                self.log.error(
                    "build.library.failed",
                    returncode=result.returncode,
                    stderr=result.stderr[-500:] if result.stderr else "",
                )
                return False

        except subprocess.TimeoutExpired:
            self.log.error("build.library.timeout")
            return False

    def build_seed_producer(self, producer_src: Path, out_bin: Path) -> bool:
        """Compile a round-trip *seed producer* program linking the target lib.

        Unlike `build_harness`, the producer is a plain `main()` executable that
        drives the library's WRITE/ENCODE API to emit valid seeds — so it is
        compiled with vanilla `clang`/`clang++` (NO afl instrumentation, NO
        sanitizers: we want fast, clean seed generation, not crash detection).
        It reuses the exact include-path and library-archive resolution that
        `build_harness` uses, so it links against whatever the target already
        built. Returns True iff `out_bin` was produced. Never raises.
        """
        try:
            build_dir = Path(self.config.target.build_dir)
            # Ensure the library exists (same guard as build_harness_only).
            lib_a = self._find_library(build_dir, self.config.target.library_name)
            if not lib_a:
                self.log.warning("roundtrip.build.library_not_found",
                                 name=self.config.target.library_name)
                lib_a = ""

            source_root = Path(self.config.target.source_root)
            include_subdir = (self.config.target.include_subdir
                              or self.config.target.source_subdir)
            include_path = source_root / include_subdir if include_subdir else source_root
            build_include = build_dir / include_subdir if include_subdir else build_dir

            include_flags = f"-I{include_path}"
            if build_include.exists() and build_include != include_path:
                include_flags += f" -I{build_include}"
            if build_dir != include_path and build_dir != build_include:
                include_flags += f" -I{build_dir}"

            # C++ projects need the C++ compiler to parse their public headers.
            is_cpp = bool(getattr(self.config.target, "is_cpp", False))
            try:
                src_text = producer_src.read_text(errors="replace")
            except OSError:
                src_text = ""
            if any(tok in src_text for tok in ("std::", "namespace ", "#include <string>")):
                is_cpp = True
            compiler = "clang++" if is_cpp else "clang"

            link_libs = self._resolve_link_libs(
                self.config.target.link_libs or "", build_dir)

            if lib_a:
                cmd = (f"{compiler} -g -O1 {include_flags} "
                       f"-o {out_bin} {producer_src} {lib_a} {link_libs} 2>&1")
            else:
                cmd = (f"{compiler} -g -O1 {include_flags} "
                       f"-o {out_bin} {producer_src} {link_libs} 2>&1")

            self.log.info("roundtrip.build.start", cmd=cmd[:160])
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=120, cwd=str(build_dir),
            )
            if result.returncode == 0 and Path(out_bin).exists():
                self.log.info("roundtrip.build.success", binary=str(out_bin))
                return True
            self.log.warning("roundtrip.build.failed",
                             stderr=(result.stdout or result.stderr or "")[-400:])
            return False
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
            self.log.warning("roundtrip.build.error", error=str(exc))
            return False

    def target_declaration(self, func: str) -> str | None:
        """The target's C declaration from the source tree, or None.

        Used to answer "is this function variadic?". Headers are read first and
        the result is cached: the scan is a handful of file reads, but it runs
        on every harness revision and every variant.
        """
        if not func:
            return None
        cache = getattr(self, "_decl_cache", None)
        if cache is None:
            cache = self._decl_cache = {}
        if func in cache:
            return cache[func]

        from nemesis.symbolic.variadic_arity import find_declaration
        source_root = Path(self.config.target.source_root)
        sources: dict[str, str] = {}
        try:
            for pattern in ("**/*.h", "**/*.c"):
                for path in source_root.glob(pattern):
                    if any(p in {".git", "build", "test", "tests"} for p in path.parts):
                        continue
                    try:
                        sources[str(path)] = path.read_text(errors="replace")
                    except OSError:
                        continue
                    if len(sources) > 400:      # bound the scan on large trees
                        break
        except OSError:
            pass
        cache[func] = find_declaration(sources, func) if sources else None
        return cache[func]

    def _variadic_arity_ok(self, harness: HarnessSpec) -> bool:
        """False when the harness calls a variadic target with too few args."""
        func = harness.target_func or ""
        decl = self.target_declaration(func)
        if not decl:
            return True

        from nemesis.symbolic import variadic_arity as _va
        if not _va.target_is_variadic(decl):
            return True

        findings = _va.check(harness.c_code, func)
        if not findings:
            return True

        self.log.error(
            "harness.variadic_arity_rejected",
            func=func,
            declaration=decl,
            findings=[str(f) for f in findings],
            impact=("the callee reads one argument per format directive; passing "
                    "fewer is undefined behaviour in the harness, so any crash it "
                    "produces is a false positive. Refusing to build."),
        )
        return False

    def build_harness(self, harness: HarnessSpec, build_dir: Path) -> bool:
        """
        Compile the fuzzing harness and link it with libarchive.

        The harness is compiled with afl-clang-fast and linked against
        the instrumented libarchive.a + system deps.
        """
        harness_src = build_dir / "fuzz_nemesis.c"
        harness_bin = build_dir / "fuzz_nemesis"

        # Variadic arity, checked here rather than only in the repair wrapper:
        # this is the one function every path reaches. The harness-variant path
        # calls it directly, so a gate placed upstream let unsound variants
        # compile and be profiled as if they were fine. An unsound harness must
        # not become a binary — every crash it could produce is a false
        # positive. See nemesis/symbolic/variadic_arity.py.
        if not self._variadic_arity_ok(harness):
            return False

        # Write harness source with auto-injected includes
        harness_src.parent.mkdir(parents=True, exist_ok=True)
        fixed_code = self._fix_harness_includes(harness.c_code)

        # Auto-inject limit-relaxation setter calls. The architect ignores
        # textual hints in the prompt when they conflict with the per-target
        # harness_template C skeleton; deterministic source rewriting is the
        # only reliable path for getting these calls in.
        from nemesis.feature_flags import is_enabled as _fflag
        if _fflag("validation_gates"):
            try:
                cached = getattr(self, "_vg_cache", None)
                source_root = Path(self.config.target.source_root)
                if cached is None or cached[0] != source_root:
                    gates = extract_validation_gates(source_root)
                    self._vg_cache = (source_root, gates)
                else:
                    gates = cached[1]
                if gates:
                    rewritten = inject_setter_calls(fixed_code, gates)
                    if rewritten != fixed_code:
                        self.log.info(
                            "harness.validation_gates_injected",
                            added_chars=len(rewritten) - len(fixed_code),
                        )
                        fixed_code = rewritten
            except Exception as exc:
                self.log.warning("harness.validation_gates_inject_failed", error=str(exc))
        else:
            self.log.info("harness.validation_gates_disabled")

        # Tier 1 #2 (2026-05-07): Locus-style progress-predicate injection.
        # Synthesise 3-5 boolean expressions that act as on-path waypoints to
        # the target bug, then inject them as `if (!(cond)) continue;` gates
        # before the first call to the target function. Each predicate
        # creates a distinct AFL coverage edge so seeds making genuine
        # structural progress are scored higher than off-path noise.
        # Best-effort: failure here writes the harness without gates.
        if not _fflag("predicates"):
            self.log.info("harness.progress_predicates_disabled")
        try:
            target_func = getattr(harness, "target_func", "") or "" if _fflag("predicates") else ""
            if target_func:
                from nemesis.neural import LLMClient
                from nemesis.recon import cve_context as _cc
                from nemesis.recon.format_specs import get_format_spec

                # config/targets/ is a sibling of nemesis/, so resolve from
                # this file's location two levels up — same convention used
                # by mutator_synthesis for scaffold lookup.
                nemesis_root = Path(__file__).resolve().parent.parent.parent
                targets_dir = nemesis_root / "config" / "targets"
                lib_name = self.config.target.name or ""

                cve_records = _cc.get_or_fetch(
                    library_name=lib_name,
                    targets_dir=targets_dir,
                    max_cves=3,
                    log=self.log,
                ) if lib_name else []

                format_spec = get_format_spec(lib_name, targets_dir=targets_dir) if lib_name else ""

                # Lazy LLMClient — InstrumentedBuilder is constructed with
                # only `config`, so we instantiate a client here on demand.
                # The shared sha256 LLM cache deduplicates calls across
                # client instances, so the cost is just constructor overhead.
                _llm_client = LLMClient(self.config)

                preds = synthesize_predicates(
                    library_name=lib_name,
                    target_func=target_func,
                    harness_source=fixed_code,
                    cve_records=cve_records,
                    format_spec=format_spec,
                    client=_llm_client,
                    log=self.log,
                )
                # Fix C (2026-05-07): canary-validate the predicate set
                # against real sample seeds before injecting. Drops any
                # predicate that rejects >99% of seeds — those almost
                # always indicate the LLM modeled the wrong format
                # (e.g. lz4 frame vs lz4 block, off-by-N header offset).
                if preds:
                    # Bugfix 2026-05-08: paths from YAML use $HOME / $VAR
                    # syntax. `expanduser` only handles `~`, NOT `$HOME` —
                    # earlier version returned $HOME/Nemesis/... unchanged
                    # which never existed → 0 canary seeds → no-op filter.
                    import os as _os  # noqa: PLC0415 (module keeps os imports local)

                    def _expand(p: str) -> Path:
                        return Path(_os.path.expandvars(_os.path.expanduser(p))).resolve()

                    canary_dirs: list[Path] = []
                    seeds_cfg = getattr(self.config.target, "seeds", None)
                    oss_corpus = getattr(seeds_cfg, "oss_fuzz_corpus", "") if seeds_cfg else ""
                    if oss_corpus:
                        canary_dirs.append(_expand(oss_corpus))
                    fmt_paths = getattr(seeds_cfg, "formats", {}) if seeds_cfg else {}
                    if isinstance(fmt_paths, dict):
                        for fp in fmt_paths.values():
                            if fp:
                                canary_dirs.append(_expand(str(fp)))
                    # Walk nemesis_root/seeds and add ONLY subdirs that
                    # plausibly contain seeds for THIS library — matched
                    # by name substring against the library name, the
                    # `lib`-stripped name, or any `magic_bytes` format key.
                    # Without this filter, mixing formats (e.g. lz4
                    # predicates tested against png seeds) catastrophically
                    # drops good predicates.
                    nemesis_seeds_root = nemesis_root / "seeds"
                    if nemesis_seeds_root.is_dir():
                        lib_lower = lib_name.lower()
                        bare = lib_lower.removeprefix("lib") if lib_lower.startswith("lib") else lib_lower
                        match_keys: set[str] = {lib_lower, bare}
                        magic = getattr(self.config.target, "magic_bytes", {}) or {}
                        if isinstance(magic, dict):
                            match_keys.update(k.lower() for k in magic)
                        for sub in nemesis_seeds_root.iterdir():
                            if not sub.is_dir():
                                continue
                            sub_lower = sub.name.lower()
                            if any(k and k in sub_lower for k in match_keys):
                                canary_dirs.append(sub)
                    canary_seeds = load_canary_seeds(canary_dirs, max_seeds=50, log=self.log)
                    # Always invoke the canary filter — when no real seeds
                    # are available it falls back to its built-in 200
                    # random byte sequences which catch logical
                    # contradictions between predicates (the lz4 case
                    # where one gate required `nibble == 15` and another
                    # `nibble != 15` — no input could satisfy both).
                    before = len(preds)
                    preds = canary_filter_predicates(
                        preds, canary_seeds,
                        min_pass_rate=0.01, log=self.log,
                    )
                    if len(preds) < before:
                        self.log.warning(
                            "harness.predicates_canary_pruned",
                            before=before, after=len(preds),
                        )
                if preds:
                    rewritten = inject_predicates(fixed_code, preds, target_func, log=self.log)
                    if rewritten != fixed_code:
                        self.log.info(
                            "harness.progress_predicates_injected",
                            count=len(preds),
                            names=[p.name for p in preds],
                            added_chars=len(rewritten) - len(fixed_code),
                        )
                        fixed_code = rewritten
        except Exception as exc:
            self.log.warning("harness.progress_predicates_inject_failed", error=str(exc))

        harness_src.write_text(fixed_code)
        self.log.info("harness.written", path=str(harness_src))

        # Find the target library in the build tree
        lib_name = self.config.target.library_name
        libarchive_a = self._find_library(build_dir, lib_name)
        if not libarchive_a:
            self.log.warning(
                "build.library_not_found", name=lib_name,
            )
            libarchive_a = ""

        # Determine include path
        source_root = Path(self.config.target.source_root)
        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root

        # Build the compile command
        # Extra flags from harness spec or defaults
        extra_flags = harness.compile_flags or "-g -O0"

        # Defense against LLM hallucination: strip `-l<projname>` and `-l<libbasename>` tokens.
        # Onboarders sometimes propagate `-ltiff` / `-larchive` etc. into compile_flags, but
        # the build wrapper already links the static archive directly. The shared variant
        # (lib<name>.so) often is not installed, causing the linker to fail.
        try:
            import re as _re_strip
            lib_name_full = self.config.target.library_name or ""
            # library_name may be "libtiff/libtiff.a" or "libtiff.a" — extract bare name
            base = Path(lib_name_full).name
            if base.startswith("lib") and base.endswith(".a"):
                proj_lib = base[3:-2]  # libtiff.a → tiff
                if proj_lib:
                    pattern = r"\s-l" + _re_strip.escape(proj_lib) + r"(?=\s|$)"
                    cleaned = _re_strip.sub(pattern, "", " " + extra_flags).strip()
                    if cleaned != extra_flags.strip():
                        self.log.info(
                            "harness.compile_flags.stripped_proj_lib",
                            removed=f"-l{proj_lib}",
                            note="LLM added redundant -l<projlib>; build wrapper already links static archive",
                        )
                        extra_flags = cleaned
        except Exception as _exc:
            self.log.debug("harness.compile_flags.strip_skipped", error=str(_exc))

        # Always add ASan + fuzzer flags
        asan_flags = _resolve_sanitizer_flags(self.config)  # Fix 135

        # Also include build_dir's include subdir for cmake-generated headers
        # (e.g. tiffconf.h in libtiff, config.h in libarchive)
        build_include = build_dir / include_subdir if include_subdir else build_dir
        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        # Fix 89: always add bare build_dir for cmake-generated headers that live
        # directly under build_dir (e.g. libxml2: build_fuzz/libxml/xmlversion.h)
        if build_dir != include_path and build_dir != build_include:
            include_flags += f" -I{build_dir}"

        # Fix A: include NEMESIS templates dir so harnesses can #include "fuzz_data_provider.h"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"

        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133d
            for m in _re133d.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        # Fix 148: auto-add -pthread when the harness uses pthread_* (small-
        # stack worker pattern for deep_recursion targets). Without this the
        # linker emits "undefined reference to pthread_create" and the
        # repair LLM may strip the worker thread to "fix" the error,
        # defeating the purpose. Cheap to always check; harmless if added
        # to a non-pthread harness.
        try:
            harness_src_text = Path(harness_src).read_text(errors="replace")
        except (OSError, NameError):
            harness_src_text = harness.c_code or ""
        if "pthread_" in harness_src_text and "-pthread" not in extra_flags:
            extra_flags = (extra_flags + " -pthread").strip()
            self.log.info(
                "harness.compile_flags.pthread_added",
                note="harness uses pthread_*; -pthread linker flag injected",
            )

        # Fix 155: detect C++ harness and switch to afl-clang-fast++. The C
        # compiler rejects `-std=c++17` outright ("invalid argument not
        # allowed with 'C'"), and even without that flag many flatbuffers /
        # RE2 / abseil headers fail with `extern "C++"` linkage errors when
        # parsed as C. Triggers: any `c++` token in extra_flags, OR C++ syntax
        # in the harness source (`std::`, `namespace `, `extern "C"`, `<string>`).
        is_cpp_harness = (
            "c++" in extra_flags.lower()
            or "std::" in harness_src_text
            or "namespace " in harness_src_text
            or 'extern "C"' in harness_src_text
            or "#include <string>" in harness_src_text
            or "#include <vector>" in harness_src_text
        )
        compiler = "afl-clang-fast++" if is_cpp_harness else "afl-clang-fast"
        if is_cpp_harness:
            self.log.info(
                "harness.compile.cpp_detected",
                compiler=compiler,
                note="harness contains C++ markers — switching to afl-clang-fast++",
            )

        if libarchive_a:
            # Link with real library
            compile_cmd = (
                f"{compiler} "
                f"{include_flags} "
                f"{extra_flags} {asan_flags} "
                f"-o {harness_bin} {harness_src} "
                f"{libarchive_a} "
                f"{self.config.target.link_libs} "
                f"2>&1"
            )
        else:
            # Standalone compile (no libarchive linking)
            compile_cmd = (
                f"{compiler} "
                f"{extra_flags} {asan_flags} "
                f"-o {harness_bin} {harness_src} "
                f"2>&1"
            )

        self.log.info("harness.compile.start", cmd=compile_cmd[:120])

        try:
            result = subprocess.run(
                compile_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(build_dir),
            )

            if result.returncode == 0 and harness_bin.exists():
                self._last_harness_compile_errors = ""
                self.log.info("harness.compile.success", binary=str(harness_bin))
                return True
            else:
                # Capture combined compile output for LLM repair (Fix A)
                self._last_harness_compile_errors = (
                    (result.stdout or "") + "\n" + (result.stderr or "")
                ).strip()
                # If linking fails due to missing libs, try minimal linking
                self.log.warning(
                    "harness.compile.failed",
                    returncode=result.returncode,
                    stderr=result.stderr[-500:] if result.stderr else "",
                    stdout=result.stdout[-500:] if result.stdout else "",
                )
                fallback_ok = self._fallback_compile(
                    harness_src, harness_bin, libarchive_a, include_flags, extra_flags
                )
                if fallback_ok:
                    self._last_harness_compile_errors = ""
                return fallback_ok

        except subprocess.TimeoutExpired:
            self.log.error("harness.compile.timeout")
            return False

    def compile_harness_cmplog(
        self, harness: HarnessSpec, build_dir: Path
    ) -> str | None:
        """Fix C: Compile a CMPLOG-instrumented binary for AFL++ RedQueen.

        AFL++ CMPLOG requires a SEPARATE binary compiled with AFL_LLVM_CMPLOG=1.
        Without this, the -c flag to afl-fuzz is ignored and RedQueen is inactive.

        The CMPLOG binary is identical to the main binary except for the extra
        AFL instrumentation. It is passed to AFL main via -c {cmplog_binary}.

        Returns the path to the cmplog binary, or None on failure.
        """
        harness_src = build_dir / "fuzz_nemesis.c"
        cmplog_bin = build_dir / "fuzz_nemesis_cmplog"

        if not harness_src.exists():
            self.log.warning("cmplog.no_source", hint="build_harness() must run first")
            return None

        lib_name = self.config.target.library_name
        libarchive_a = self._find_library(build_dir, lib_name)
        if not libarchive_a:
            libarchive_a = ""

        source_root = Path(self.config.target.source_root)
        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        build_include = build_dir / include_subdir if include_subdir else build_dir

        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        # Fix 89: always add bare build_dir for cmake-generated headers
        if build_dir != include_path and build_dir != build_include:
            include_flags += f" -I{build_dir}"

        # Fix A: include templates dir
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"

        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133e
            for m in _re133e.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        extra_flags = harness.compile_flags or "-g -O0"
        asan_flags = _resolve_sanitizer_flags(self.config)  # Fix 135

        # Fix 155: same C++ detection as the main harness compile.
        try:
            _hsrc_text = Path(harness_src).read_text(errors="replace")
        except (OSError, NameError):
            _hsrc_text = ""
        is_cpp_harness = (
            "c++" in extra_flags.lower()
            or "std::" in _hsrc_text
            or "namespace " in _hsrc_text
            or 'extern "C"' in _hsrc_text
            or "#include <string>" in _hsrc_text
            or "#include <vector>" in _hsrc_text
        )
        cmplog_compiler = "afl-clang-fast++" if is_cpp_harness else "afl-clang-fast"

        if libarchive_a:
            compile_cmd = (
                f"AFL_LLVM_CMPLOG=1 {cmplog_compiler} "
                f"{include_flags} "
                f"{extra_flags} {asan_flags} "
                f"-o {cmplog_bin} {harness_src} "
                f"{libarchive_a} "
                f"{self.config.target.link_libs} "
                f"2>&1"
            )
        else:
            compile_cmd = (
                f"AFL_LLVM_CMPLOG=1 {cmplog_compiler} "
                f"{extra_flags} {asan_flags} "
                f"-o {cmplog_bin} {harness_src} "
                f"2>&1"
            )

        self.log.info("cmplog.compile.start", binary=str(cmplog_bin))
        try:
            result = subprocess.run(
                compile_cmd, shell=True, capture_output=True,
                text=True, timeout=120, cwd=str(build_dir),
            )
            if result.returncode == 0 and cmplog_bin.exists():
                self.log.info("cmplog.compile.success", binary=str(cmplog_bin))
                return str(cmplog_bin)
            else:
                self.log.warning(
                    "cmplog.compile.failed",
                    returncode=result.returncode,
                    stderr=(result.stderr or "")[-300:],
                )
                return None
        except subprocess.TimeoutExpired:
            self.log.warning("cmplog.compile.timeout")
            return None

    def _build_profile_debug_binary(
        self, harness: HarnessSpec, build_dir: Path,
    ) -> Path | None:
        """Build a non-AFL debug binary for gdb breakpoint checking.

        Compiles the harness with plain clang + ASAN (no AFL instrumentation)
        so we can run it under gdb with stdin redirection. Returns the binary
        path on success, None on failure.
        """
        debug_bin = build_dir / "fuzz_nemesis_profile"
        harness_src = build_dir / "fuzz_nemesis_profile.c"

        fixed_code = self._fix_harness_includes(harness.c_code)
        harness_src.write_text(_AFL_STUB_HEADER + fixed_code)

        lib_name = self.config.target.library_name
        lib_a = self._find_library(build_dir, lib_name) or ""

        source_root = Path(self.config.target.source_root)
        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        build_include = build_dir / include_subdir if include_subdir else build_dir

        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        if build_dir != include_path and build_dir != build_include:
            include_flags += f" -I{build_dir}"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"

        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133f
            for m in _re133f.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        link_libs = self.config.target.link_libs
        compile_cmd = (
            f"clang {include_flags} -g -O1 -fsanitize=address "
            f"-o {debug_bin} {harness_src} "
            f"{lib_a} {link_libs} 2>&1"
        )

        try:
            result = subprocess.run(
                compile_cmd, shell=True, capture_output=True,
                text=True, timeout=60, cwd=str(build_dir),
            )
            if result.returncode == 0 and debug_bin.exists():
                self.log.debug("profile_debug.built", binary=str(debug_bin))
                return debug_bin
        except (subprocess.TimeoutExpired, OSError):
            pass

        self.log.debug("profile_debug.build_failed")
        return None

    def _quick_function_reach_check(
        self, binary: Path, func_name: str, queue_dir: Path,
    ) -> bool:
        """Sample up to 3 smallest queue files with gdb breakpoint to check function reach.

        Returns True if any queue file triggers a breakpoint on func_name.
        Total overhead: ≤15s (5s per file).
        """
        import os as _os

        if not binary.exists() or not queue_dir.exists():
            return False

        queue_files = [
            f for f in sorted(queue_dir.iterdir())
            if f.is_file() and f.stat().st_size > 0 and not f.name.startswith(".")
        ]
        if not queue_files:
            return False

        # Fix 100: take 3 LARGEST files — smallest (1-8 bytes) lack format
        # magic bytes and never trigger deep parsing → function_reached=False.
        samples = sorted(queue_files, key=lambda f: f.stat().st_size, reverse=True)[:3]
        asan_env = {**_os.environ, "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:halt_on_error=0"}

        for corpus_file in samples:
            try:
                gdb_result = subprocess.run(
                    [
                        "gdb", "-batch",
                        "-ex", f"break {func_name}",
                        "-ex", f"run < {corpus_file}",
                        "-ex", "info breakpoints",
                        str(binary),
                    ],
                    capture_output=True, text=True, timeout=5, env=asan_env,
                )
                out = gdb_result.stdout + gdb_result.stderr
                if (
                    f"Breakpoint 1, {func_name}" in out
                    or "breakpoint already hit" in out
                ):
                    self.log.info(
                        "variant.reach_check.hit",
                        func=func_name,
                        file=corpus_file.name,
                    )
                    return True
            except (OSError, subprocess.TimeoutExpired):
                pass

        self.log.debug("variant.reach_check.miss", func=func_name, samples=len(samples))
        return False

    # ── gcov coverage for refinement prompt (Feature B) ───

    def build_gcov_binary(self, harness: HarnessSpec, build_dir: Path) -> Path | None:
        """Build a coverage-instrumented binary for gcov line-level analysis.

        Compiles harness with --coverage (no ASAN — incompatible with gcov).
        Returns binary path on success, None on failure.
        """
        gcov_bin = build_dir / "fuzz_nemesis_gcov"
        harness_src = build_dir / "fuzz_nemesis_gcov.c"

        if not harness or not harness.c_code:
            return None

        fixed_code = self._fix_harness_includes(harness.c_code)
        harness_src.write_text(_AFL_STUB_HEADER + fixed_code)

        lib_name = self.config.target.library_name
        lib_a = self._find_library(build_dir, lib_name) or ""

        source_root = Path(self.config.target.source_root)
        include_subdir = self.config.target.include_subdir or self.config.target.source_subdir
        include_path = source_root / include_subdir if include_subdir else source_root
        build_include = build_dir / include_subdir if include_subdir else build_dir

        include_flags = f"-I{include_path}"
        if build_include.exists() and build_include != include_path:
            include_flags += f" -I{build_include}"
        if build_dir != include_path and build_dir != build_include:
            include_flags += f" -I{build_dir}"
        templates_dir = Path(__file__).parent.parent / "templates"
        if templates_dir.exists():
            include_flags += f" -I{templates_dir}"
        # Fix 123 / Fix 157: internal include dirs. No longer gated on
        # `direct_internal` — that flag marks a deliberate pin from the
        # dashboard, but a generated harness reaches into internal headers
        # whenever the public API alone cannot exercise the target, which is
        # the common case. Gating on the pin meant the ordinary path compiled
        # without them and died on the first internal header (bcg729: "cng.h"
        # not found, reproduced across two runs). Appended after include_subdir
        # so the public directory still wins on a basename clash.
        for idir in self.config.target.internal_include_dirs:
            ipath = source_root / idir
            if ipath.is_dir() and f"-I{ipath}" not in include_flags:
                include_flags += f" -I{ipath}"
        # Fix 133: propagate extra -I flags from auto-resolve (compile_flags)
        if harness.compile_flags:
            import re as _re133g
            for m in _re133g.finditer(r"-I(\S+)", harness.compile_flags):
                if m.group(0) not in include_flags:
                    include_flags += f" {m.group(0)}"

        link_libs = self.config.target.link_libs or ""
        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable"
        )
        compile_cmd = (
            f"clang {include_flags} -g -O0 --coverage {warn_flags} "
            f"-o {gcov_bin} {harness_src} "
            f"{lib_a} {link_libs} -lgcov 2>&1"
        )

        try:
            result = subprocess.run(
                compile_cmd, shell=True, capture_output=True,
                text=True, timeout=60, cwd=str(build_dir),
            )
            if result.returncode == 0 and gcov_bin.exists():
                self.log.info("gcov.binary_built", binary=str(gcov_bin))
                return gcov_bin
        except (subprocess.TimeoutExpired, OSError):
            pass

        self.log.debug("gcov.build_failed", stderr=result.stdout[-200:] if result else "")
        return None

    def collect_gcov_around_function(
        self,
        harness: HarnessSpec,
        build_dir: Path,
        target_func: str,
        corpus_files: list[Path],
        n_samples: int = 5,
    ) -> str:
        """Run corpus through gcov binary and return annotated lines around target function.

        Returns formatted gcov output like:
            12:  345:  static int parse_header(const char *buf, size_t len) {
             -:  346:      /* validate magic */
            12:  347:      if (memcmp(buf, "MSCF", 4) != 0)
            12:  348:          return -1;
         #####:  349:      int num_folders = le16(buf + 26);

        Lines marked ##### were NEVER executed across all corpus samples.
        """
        gcov_bin = build_dir / "fuzz_nemesis_gcov"
        harness_src = build_dir / "fuzz_nemesis_gcov.c"

        # Build gcov binary if not already present
        if not gcov_bin.exists():
            gcov_bin = self.build_gcov_binary(harness, build_dir)
            if not gcov_bin:
                return ""

        if not harness_src.exists():
            return ""

        import os as _os
        env = _os.environ.copy()
        # Set GCOV_PREFIX to build_dir so .gcda files land there
        env["GCOV_PREFIX"] = str(build_dir)
        env["GCOV_PREFIX_STRIP"] = "100"  # strip all path components
        # Disable ASAN (gcov binary has no ASAN, but env may have leftover vars)
        env.pop("ASAN_OPTIONS", None)

        # Clean any stale .gcda files
        for gcda in build_dir.glob("*.gcda"):
            try:
                gcda.unlink()
            except OSError:
                pass

        # Run N corpus files through gcov binary
        samples = sorted(corpus_files, key=lambda f: f.stat().st_size)[:n_samples]
        for corpus_file in samples:
            try:
                with open(corpus_file, "rb") as fin:
                    subprocess.run(
                        [str(gcov_bin)],
                        stdin=fin,
                        capture_output=True,
                        timeout=5,
                        env=env,
                        cwd=str(build_dir),
                    )
            except (subprocess.TimeoutExpired, OSError):
                pass

        # Run gcov / llvm-cov gcov to produce annotated source
        gcov_output = ""
        try:
            # Try llvm-cov gcov first (LLVM toolchain), then plain gcov
            for gcov_cmd in [["llvm-cov", "gcov"], ["gcov"]]:
                try:
                    r = subprocess.run(
                        gcov_cmd + [str(harness_src)],
                        capture_output=True, text=True, timeout=10,
                        cwd=str(build_dir),
                    )
                    if r.returncode == 0:
                        break
                except FileNotFoundError:
                    continue

            # Find the generated .gcov file
            gcov_file = build_dir / (harness_src.name + ".gcov")
            if not gcov_file.exists():
                # Some gcov versions use different naming
                candidates = list(build_dir.glob("*.gcov"))
                if candidates:
                    gcov_file = candidates[0]

            if gcov_file.exists():
                gcov_output = gcov_file.read_text(errors="replace")
        except (subprocess.TimeoutExpired, OSError):
            pass

        if not gcov_output:
            self.log.debug("gcov.no_output", func=target_func)
            return ""

        # Extract lines around the target function (±50 lines from function start)
        return self._extract_gcov_around_function(gcov_output, target_func)

    @staticmethod
    def _extract_gcov_around_function(
        gcov_text: str, func_name: str, context_lines: int = 50,
    ) -> str:
        """Extract annotated gcov lines around a function definition.

        Looks for the function name in the gcov output, then extracts
        context_lines before and after. Returns the annotated block.
        """
        lines = gcov_text.splitlines()
        func_line_idx = None

        for i, line in enumerate(lines):
            # gcov format: "    COUNT:  LINENO:  SOURCE"
            # The source part may contain the function name
            parts = line.split(":", 2)
            if len(parts) >= 3 and func_name in parts[2]:
                # Check it looks like a function definition (has opening paren)
                src = parts[2]
                if "(" in src or "{" in src:
                    func_line_idx = i
                    break

        if func_line_idx is None:
            # Function not found in gcov output — return first 80 lines as fallback
            if len(lines) > 80:
                return "\n".join(lines[:80]) + "\n... (truncated)"
            return gcov_text

        start = max(0, func_line_idx - 5)
        end = min(len(lines), func_line_idx + context_lines)
        return "\n".join(lines[start:end])

    def profile_harness_variant(
        self,
        harness: HarnessSpec,
        build_dir: Path,
        timeout_sec: int = 120,
    ) -> tuple[bool, float, int]:
        """Fix D: Build a harness variant and profile it for 2 min with AFL++.

        Returns (compiled, function_coverage_pct, corpus_paths).
        Used by the multi-variant selection to pick the best harness.

        - compiled: whether the binary was built successfully
        - function_coverage_pct: 100.0 if function reached, 0.0 if not, -1.0 if not measurable
        - corpus_paths: AFL corpus_count after timeout_sec
        """
        import tempfile as _tempfile

        # Build the variant
        compiled = self.build_harness(harness, build_dir)
        if not compiled:
            return False, -1.0, 0

        binary = build_dir / "fuzz_nemesis"
        if not binary.exists():
            return False, -1.0, 0

        # Quick AFL profiling run
        with _tempfile.TemporaryDirectory(prefix="nemesis_variant_") as tmpdir:
            tmp_findings = Path(tmpdir) / "findings"
            tmp_findings.mkdir()

            # Seed priority: per-target seeds → minset corpus → all_formats → zero fallback
            slug = harness.target_func or "variant"
            work_dir = Path(self.config.engine.work_dir)
            lib_name = self.config.target.library_name
            candidate_dirs = [
                work_dir / "fuzzing" / "seeds" / slug,
                work_dir / "seeds_minset" / lib_name,
            ]
            # Also check project seeds/all_formats (relative to nemesis package)
            _pkg_root = Path(__file__).parent.parent
            candidate_dirs.append(_pkg_root / "seeds" / "all_formats")

            seeds_dir = None
            for _cd in candidate_dirs:
                if _cd.exists() and any(_cd.iterdir()):
                    seeds_dir = _cd
                    break

            if seeds_dir is None:
                seeds_dir = Path(tmpdir) / "seeds"
                seeds_dir.mkdir(exist_ok=True)
                (seeds_dir / "seed").write_bytes(b"\x00" * 64)

            import os as _os
            env = _os.environ.copy()
            env.update({
                "AFL_NO_UI": "1",
                "AFL_SKIP_CPUFREQ": "1",
                "AFL_NO_AFFINITY": "1",
                "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0",
            })

            cmd = [
                "afl-fuzz",
                "-M", "main",
                "-i", str(seeds_dir),
                "-o", str(tmp_findings),
                "-t", "5000",
                "-V", str(timeout_sec),
                "--", str(binary),
            ]

            self.log.info(
                "variant.profile.start",
                func=harness.target_func,
                timeout_sec=timeout_sec,
            )

            try:
                proc = subprocess.Popen(
                    cmd, env=env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                proc.wait(timeout=timeout_sec + 30)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
            except FileNotFoundError:
                self.log.warning("variant.profile.afl_not_found")
                return compiled, -1.0, 0

            # Parse AFL stats
            corpus_paths = 0
            stats_file = tmp_findings / "main" / "fuzzer_stats"
            if stats_file.exists():
                for line in stats_file.read_text().splitlines():
                    if "corpus_count" in line or "paths_total" in line:
                        try:
                            corpus_paths = int(line.split(":", 1)[1].strip())
                        except (ValueError, IndexError):
                            pass

            # Feature A: Quick function reach check via gdb breakpoint
            function_reached = False
            debug_bin = self._build_profile_debug_binary(harness, build_dir)
            if debug_bin:
                queue_dir = tmp_findings / "main" / "queue"
                function_reached = self._quick_function_reach_check(
                    debug_bin, harness.target_func, queue_dir,
                )

            # Fix 116: Bitmap-based reach fallback — if GDB says not reached but
            # AFL achieved significant bitmap coverage, the function IS being exercised.
            # GDB breakpoints fail for inlined/complex/renamed functions. 3% bitmap
            # threshold means the harness is doing meaningful work beyond just exiting.
            bitmap_pct = 0.0
            if stats_file.exists():
                for line in stats_file.read_text().splitlines():
                    if "bitmap_cvg" in line:
                        try:
                            bitmap_pct = float(line.split(":", 1)[1].strip().rstrip("%"))
                        except (ValueError, IndexError):
                            pass
            if not function_reached and bitmap_pct > 3.0:
                self.log.info(
                    "variant.profile.bitmap_reach_override",
                    func=harness.target_func,
                    bitmap_pct=bitmap_pct,
                    reason="GDB breakpoint missed but bitmap indicates code reached",
                )
                function_reached = True

        coverage_pct = 100.0 if function_reached else 0.0

        self.log.info(
            "variant.profile.done",
            func=harness.target_func,
            corpus_paths=corpus_paths,
            function_reached=function_reached,
        )
        return compiled, coverage_pct, corpus_paths

    def _fix_harness_includes(self, code: str) -> str:
        """
        Auto-inject missing standard includes, library includes, and fix known
        wrong API calls / syntax in LLM-generated harness code.
        """
        import re as _re_inc

        required_includes = [
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdint.h>",
            "#include <unistd.h>",
        ]
        header_block = ""
        for inc in required_includes:
            if inc not in code:
                header_block += inc + "\n"
                self.log.debug("harness.auto_include", include=inc)

        # Fix 89: Force-inject ALL library-specific includes from config.
        # The LLM often omits required headers (e.g., HTMLparser.h for htmlReadMemory),
        # causing "undeclared function" errors.  Extra unused includes are harmless.
        for inc in self.config.target.harness_includes:
            directive_angle = f"#include <{inc}>"
            directive_quote = f'#include "{inc}"'
            if directive_angle not in code and directive_quote not in code:
                header_block += directive_angle + "\n"

        if header_block:
            code = header_block + code
            self.log.info("harness.includes_injected", count=header_block.count("#include"))

        # Inject conditional includes: if a token appears in code and the include is missing, add it.
        cond_includes = ""
        for token, include_line in self.config.target.harness_conditional_includes.items():
            if token in code and include_line not in code:
                cond_includes += include_line + "\n"
                self.log.info("harness.conditional_include_injected", token=token, include=include_line)
        if cond_includes:
            code = cond_includes + code

        # Fix 105: Unescape double-escaped string literals from LLM JSON output.
        # When the LLM double-escapes quotes in JSON, the parsed c_code contains
        # literal \" (backslash+quote) where string delimiters should be, causing:
        #   error: expected expression
        #   32 | const char *s = \"hello\";
        # Also fixes \' → ' (same issue with single quotes in XML content).
        # Detect: \" at string-delimiter positions (after = , ( or before ; , ) ).
        if '\\"' in code:
            if _re_inc.search(r'[=,(]\s*\\"', code) or _re_inc.search(r'\\"\s*[;,)]', code):
                code = code.replace('\\"', '"')
                self.log.info("harness.escaped_strings_fixed", fix="Fix 105")
        if "\\'" in code:
            if _re_inc.search(r"[=,(]\s*\\'", code) or _re_inc.search(r"\\'\s*[;,)]", code):
                code = code.replace("\\'", "'")

        # Fix 131: Strip wrong prefixed internal include paths.
        # LLM writes `#include "c/enc/hash.h"` or `#include "../c/enc/hash.h"` but
        # with `-I{source_root}/c/enc`, only `#include "hash.h"` works.
        # Strip any path prefix that matches an internal_include_dir.
        internal_dirs = self.config.target.internal_include_dirs
        if internal_dirs:
            def _strip_internal_prefix(m: _re_inc.Match) -> str:
                inc_path = m.group(1)
                # Remove leading ../ sequences
                stripped = _re_inc.sub(r'^(?:\.\./)+', '', inc_path)
                # Check if path starts with any internal_include_dir prefix
                for idir in internal_dirs:
                    prefix = idir.rstrip("/") + "/"
                    if stripped.startswith(prefix):
                        return f'#include "{stripped[len(prefix):]}"'
                return m.group(0)  # no match, keep original
            new_code = _re_inc.sub(
                r'#include\s+"([^"]+)"',
                _strip_internal_prefix,
                code,
            )
            if new_code != code:
                code = new_code
                self.log.info("harness.internal_include_path_fixed", fix="Fix 131")

        # Fix 90 (extended 2026-05-05): Auto-fix __AFL_LOOP syntax variants.
        # LLM emits any of:
        #   (a) __AFL_LOOP(N) {            ← needs `while ( … )` wrapper
        #   (b) __AFL_LOOP(N)              ← bare on its own line, body on next line
        #   (c) __AFL_LOOP(N);             ← treated as statement, no body iteration
        # Correct form is always: `while (__AFL_LOOP(N)) { … }`.
        if "__AFL_LOOP" in code:
            fixed_lines = []
            for line in code.splitlines(keepends=True):
                if "__AFL_LOOP" in line and "while" not in line and "//" not in line.split("__AFL_LOOP")[0]:
                    # Form (a): __AFL_LOOP(N) {  →  while (__AFL_LOOP(N)) {
                    line = _re_inc.sub(
                        r'__AFL_LOOP\s*\((\d+)\)\s*\{',
                        r'while (__AFL_LOOP(\1)) {',
                        line,
                    )
                    # Form (c): __AFL_LOOP(N);  →  while (__AFL_LOOP(N))  (let next stmt be body)
                    # Form (b): __AFL_LOOP(N) at end of line  → same
                    line = _re_inc.sub(
                        r'__AFL_LOOP\s*\((\d+)\)\s*;?\s*$',
                        r'while (__AFL_LOOP(\1))',
                        line,
                    )
                fixed_lines.append(line)
            new_code = "".join(fixed_lines)
            if new_code != code:
                code = new_code
                self.log.info("harness.afl_loop_syntax_fixed")

        # Fix 138 (2026-05-05): __AFL_FUZZ_TESTCASE_BUF / _LEN are MACROS that expand
        # to expressions — they are NOT assignable l-values. LLM occasionally writes
        # `__AFL_FUZZ_TESTCASE_BUF = malloc(...)` or `... = fuzz_buf;` thinking these
        # are regular pointer variables. Compiler errors with "expression is not
        # assignable". Strip such assignments — AFL manages the buffer itself.
        _afl_assign_pattern = _re_inc.compile(
            r'^\s*__AFL_FUZZ_TESTCASE_(BUF|LEN)\s*=\s*[^;]+;\s*$',
            _re_inc.MULTILINE,
        )
        new_code = _afl_assign_pattern.sub(
            r'/* removed: __AFL_FUZZ_TESTCASE_\1 is a macro, not assignable */',
            code,
        )
        if new_code != code:
            code = new_code
            self.log.info("harness.afl_macro_assignment_stripped", fix="Fix 138")

        # Fix 139 (2026-05-05): Auto-rewrite "raw AFL buf to parser" pattern to use a
        # tightly-sized heap copy so ASAN redzones surround the input. Without this
        # fix, heap-buffer-over-read CVEs (e.g. cJSON CVE-2023-53154, libxml2
        # buffer-over-read class) NEVER trigger under AFL because the AFL input
        # lives in a 1 MB+ static/shared buffer — semantic over-reads land in
        # valid memory and ASAN sees nothing. The transformation wraps any
        # statement of the form
        #     [type name =] Func((cast)__AFL_FUZZ_TESTCASE_BUF, ..., __AFL_FUZZ_TESTCASE_LEN, ...);
        # with a malloc/memcpy/free block where the macro references are replaced
        # by `_nfx_buf` / `_nfx_len` (a tightly-sized heap copy with redzones).
        # This is the single highest-impact change for finding parser CVEs.
        if "__AFL_FUZZ_TESTCASE_BUF" in code and "__AFL_FUZZ_TESTCASE_LEN" in code:
            # Match a single statement of the form:
            #   <type or auto> name = Func(<cast>__AFL_FUZZ_TESTCASE_BUF, ..., <cast>__AFL_FUZZ_TESTCASE_LEN);
            # OR a bare expression statement:
            #   Func(<cast>__AFL_FUZZ_TESTCASE_BUF, ..., <cast>__AFL_FUZZ_TESTCASE_LEN);
            # The pattern below intentionally keeps the entire match (statement)
            # so we can substitute. Multi-line aware because cJSON's call spans
            # several lines.
            # The middle/trailing arg classes intentionally exclude `;`, `{`,
            # and `}` so the lazy match can't slurp across statement
            # boundaries. Without the brace exclusion the regex would
            # eat past an `if (Parser(BUF, LEN, ...)) { other = OtherCall(BUF, LEN); }`
            # construct and substitute over both calls + the brace block,
            # producing invalid C (declarations injected into the if-condition).
            stmt_pattern = _re_inc.compile(
                r'((?:[A-Za-z_][A-Za-z0-9_ \t\*]*\s*=\s*)?'   # optional `Type *name = `
                r'[A-Za-z_][A-Za-z0-9_]*\s*\(\s*'              # FuncName(
                r'(?:\([^){}]*\)\s*)?'                          # optional cast
                r'__AFL_FUZZ_TESTCASE_BUF\s*,'
                r'[^;{}]*?'                                     # middle args (no ; { })
                r'(?:\([^){}]*\)\s*)?'                          # optional cast
                r'__AFL_FUZZ_TESTCASE_LEN'
                r'[^;{}]*?'                                     # trailing args (no ; { })
                r'\)\s*;)',
                _re_inc.DOTALL,
            )

            def _wrap_with_heap_copy(m):
                stmt = m.group(1)
                # Replace the macros with our heap-copy variables in the statement.
                replaced = stmt.replace("__AFL_FUZZ_TESTCASE_BUF", "_nfx_buf")
                replaced = replaced.replace("__AFL_FUZZ_TESTCASE_LEN", "_nfx_len")
                # Inject as inline preamble + free, NOT wrapped in a new block —
                # variables declared in the parser call (e.g. `cJSON *json = …`)
                # remain visible to subsequent code in the same scope. Each AFL_LOOP
                # iteration enters a fresh scope so re-declaration of _nfx_buf /
                # _nfx_len is fine.
                return (
                    "/* Fix 139 heap-copy: ASAN redzones catch parser over-reads */\n"
                    "        size_t _nfx_len = (size_t)__AFL_FUZZ_TESTCASE_LEN;\n"
                    "        uint8_t *_nfx_buf = (uint8_t *)malloc(_nfx_len ? _nfx_len : 1);\n"
                    "        if (_nfx_buf && _nfx_len) memcpy(_nfx_buf, __AFL_FUZZ_TESTCASE_BUF, _nfx_len);\n"
                    "        " + replaced + "\n"
                    "        free(_nfx_buf);"
                )

            new_code = stmt_pattern.sub(_wrap_with_heap_copy, code)
            if new_code != code:
                code = new_code
                self.log.info(
                    "harness.heap_copy_injected",
                    fix="Fix 139",
                    note="parser call now uses tightly-sized heap copy → ASAN catches over-reads",
                )

        # Fix 106: Auto-inject __AFL_FUZZ_INIT() when missing.
        # LLM frequently uses __AFL_FUZZ_TESTCASE_BUF / __AFL_FUZZ_TESTCASE_LEN
        # but forgets __AFL_FUZZ_INIT() which declares the shared-memory variables.
        # Without it: "use of undeclared identifier '__afl_fuzz_ptr'" (5+ failures per scan).
        # __AFL_FUZZ_INIT() must be at global scope (before main).
        uses_fuzz_buf = "__AFL_FUZZ_TESTCASE_BUF" in code or "__AFL_FUZZ_TESTCASE_LEN" in code
        if uses_fuzz_buf and "__AFL_FUZZ_INIT" not in code and "int main" in code:
            code = code.replace("int main", "__AFL_FUZZ_INIT();\n\nint main", 1)
            self.log.info("harness.afl_fuzz_init_injected", fix="Fix 106")

        # Fix known wrong API function names from config (LLM hallucinations)
        for wrong, correct in self.config.target.api_func_fixes.items():
            if wrong in code:
                code = code.replace(wrong, correct)
                self.log.info("harness.func_fixed", wrong=wrong, correct=correct)

        # Inject harness_helpers — static C helper definitions required by the harness.
        # If the helper function name appears in code but no definition exists, inject it.
        # A "definition" is detected by looking for `func_name (` preceded by a return type
        # on the same line (i.e., not just a plain call like `foo(...)`).
        import re as _re2
        for func_name, definition in self.config.target.harness_helpers.items():
            if func_name not in code:
                continue
            # A definition has the pattern: [type keywords] func_name(  on one line
            # (e.g.  "static void xmlSilenceErrors("  or  "void xmlSilenceErrors(")
            has_definition = bool(_re2.search(
                r'(?:static\s+|extern\s+)?\w[\w\s\*]*\b' + _re2.escape(func_name) + r'\s*\(',
                code.split(func_name + '(')[0],  # only check text BEFORE the first occurrence
            )) if code.count(func_name + '(') > 1 else False
            # Simpler fallback: if the function name appears before 'int main', it's defined
            if not has_definition:
                pre_main = code.split('int main')[0] if 'int main' in code else ''
                has_definition = func_name + '(' in pre_main
            if not has_definition and 'int main' in code:
                code = code.replace('int main', definition + '\n\nint main', 1)
                self.log.info("harness.helper_injected", helper=func_name)

        # Fix C++ FuzzedDataProvider method calls → C fdp_* equivalents.
        # The LLM sometimes generates C++ syntax even for C harnesses:
        #   provider.ConsumeInteger()  / provider.GetInt()
        #   provider.ConsumeRemainingBytesAsString()  / provider.GetString()
        # These are C++ and won't compile with clang in C mode.
        import re as _re
        # Fix 131: Match ANY variable name (provider|fdp|fuzz_provider|etc) not just 'provider'.
        # Also handle template arguments <T> and non-numeric args in InRange calls.
        _VAR = r'\w+'  # any C variable name
        _fdp_method_fixes = [
            # ConsumeIntegralInRange<T>(min, max) / ConsumeIntegerInRange<T>(min, max)
            # Handles: template args, variable args (not just digits)
            (r'(' + _VAR + r')\s*\.\s*Consume(?:Integral|Integer)InRange\s*(?:<[^>]*>)?\s*\([^)]*\)',
             'fdp_consume_u32(&fdp)'),
            # ConsumeIntegral<T>() / ConsumeInteger<T>()
            (r'(' + _VAR + r')\s*\.\s*Consume(?:Integral|Integer)\s*(?:<[^>]*>)?\s*\(\s*\)',
             'fdp_consume_u32(&fdp)'),
            # GetInt() / ConsumeInt() / ConsumeInteger()
            (r'(' + _VAR + r')\s*\.\s*(?:Get|Consume)Int(?:eger)?\s*\(\s*\)',
             'fdp_consume_u32(&fdp)'),
            # ConsumeBool()
            (r'(' + _VAR + r')\s*\.\s*ConsumeBool\s*\(\s*\)',
             '(fdp_consume_u8(&fdp) & 1)'),
            # ConsumeRemainingBytes / ConsumeRemainingBytesAsString / GetString
            (r'(' + _VAR + r')\s*\.\s*(?:ConsumeRemainingBytes(?:AsString|AsVector(?:<[^>]*>)?)?|GetString)\s*\(\s*\)',
             '(const char *)fdp_consume_bytes(&fdp, fdp_remaining(&fdp))'),
            # ConsumeBytes<N>() / ConsumeBytes(n)
            (r'(' + _VAR + r')\s*\.\s*ConsumeBytes\s*(?:<[^>]*>)?\s*\(\s*([^)]*)\)',
             r'fdp_consume_bytes(&fdp, \2)'),
            # ConsumeRandomLengthString() / ConsumeRandomLengthString(max)
            (r'(' + _VAR + r')\s*\.\s*ConsumeRandomLengthString\s*\([^)]*\)',
             '(const char *)fdp_consume_bytes(&fdp, fdp_remaining(&fdp))'),
            # remaining_bytes() / .size() chained — just use len
            (r'(' + _VAR + r')\s*\.\s*remaining_bytes\s*\(\s*\)',
             '((size_t)(len))'),
        ]
        for pattern, replacement in _fdp_method_fixes:
            new_code = _re.sub(pattern, replacement, code)
            if new_code != code:
                self.log.info("harness.fdp_method_fixed", pattern=pattern[:40])
                code = new_code

        # Fix 121: Detect and remove C++ syntax in C harness before compile.
        # Common LLM mistakes: C++ constructor syntax, new/delete, std::, namespace::.
        # These waste a compile→repair cycle; auto-fix here saves iteration time.
        _cpp_fixes_applied = False

        # C++ constructor: `ClassName varName(args);` → comment or remove
        # Pattern: identifier followed by identifier followed by (args) at statement level
        # We specifically target FuzzedDataProvider / FuzzDataProvider C++ usage
        cpp_ctor_pattern = r'\b(Fuzz(?:ed)?DataProvider)\s+(\w+)\s*\(\s*([^)]*)\)\s*;'
        if _re.search(cpp_ctor_pattern, code):
            # Replace with C-style FDP initialization
            code = _re.sub(
                cpp_ctor_pattern,
                r'FuzzDataProvider \2; fdp_init(&\2, \3);',
                code,
            )
            _cpp_fixes_applied = True

        # `new Type(...)` → `malloc(sizeof(Type))` or just remove
        if ' new ' in code:
            code = _re.sub(r'\bnew\s+(\w+)\s*\(\s*\)', r'((\1 *)malloc(sizeof(\1)))', code)
            code = _re.sub(r'\bnew\s+(\w+)\s*\[([^\]]+)\]', r'((\1 *)malloc(sizeof(\1) * (\2)))', code)
            _cpp_fixes_applied = True

        # `delete ptr` / `delete[] ptr` → `free(ptr)`
        if 'delete' in code:
            code = _re.sub(r'\bdelete\s*\[\]\s*(\w+)', r'free(\1)', code)
            code = _re.sub(r'\bdelete\s+(\w+)', r'free(\1)', code)
            _cpp_fixes_applied = True

        # `std::` prefix → remove (harness uses C equivalents)
        if 'std::' in code:
            code = code.replace('std::vector', '/* removed std::vector */')
            code = code.replace('std::string', 'const char *')
            code = code.replace('std::', '')
            _cpp_fixes_applied = True

        if _cpp_fixes_applied:
            self.log.info("harness.cpp_syntax_fixed", fix="Fix 121")

        return code

    def _find_library(self, build_dir: Path, name: str) -> str:
        """Path to the built library as a string, or "" if not found.

        Thin wrapper over the shared LibraryResolver so this stage and the
        fuzzing stage can never disagree about where a library lives — they did
        once, and the probe build failed while the harness compile succeeded,
        which silently disabled every per-input coverage consumer for a whole
        campaign. Returns a bare string because callers test truthiness; use
        `resolve_library()` when the provenance matters.
        """
        return str(self.resolve_library(build_dir, name).path or "")

    def resolve_library(self, build_dir: Path, name: str) -> LibraryResolution:
        """Locate the built library, keeping how it was found."""
        return LibraryResolver(
            source_subdir=self.config.target.source_subdir, log=self.log,
        ).resolve(build_dir, name)

    def _fallback_compile(
        self,
        harness_src: Path,
        harness_bin: Path,
        libarchive_a: str,
        include_path: Path,
        extra_flags: str,
    ) -> bool:
        """
        Fallback compilation with minimal linking.
        Tries progressively simpler link commands.
        """
        asan_flags = "-fsanitize=address -fno-omit-frame-pointer"

        # Fix 89: use same include_flags as main compile (include_path may be a
        # string with multiple -I flags when passed from the caller)
        inc = str(include_path)
        inc_flags = inc if inc.startswith("-I") else f"-I{inc}"

        # Fix 155: same C++ detection as the primary compile.
        try:
            _hsrc_text = Path(harness_src).read_text(errors="replace")
        except (OSError, NameError):
            _hsrc_text = ""
        is_cpp = (
            "c++" in extra_flags.lower()
            or "std::" in _hsrc_text
            or "namespace " in _hsrc_text
            or 'extern "C"' in _hsrc_text
            or "#include <string>" in _hsrc_text
            or "#include <vector>" in _hsrc_text
        )
        compiler = "afl-clang-fast++" if is_cpp else "afl-clang-fast"

        # Attempt 1: Link with library + minimal deps only
        minimal_libs = self.config.target.link_libs or ""
        if libarchive_a:
            cmd = (
                f"{compiler} {inc_flags} {extra_flags} {asan_flags} "
                f"-o {harness_bin} {harness_src} {libarchive_a} {minimal_libs} 2>&1"
            )
            self.log.info("harness.compile.fallback_1", cmd=cmd[:120])
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0 and harness_bin.exists():
                    self.log.info("harness.compile.fallback_1.success")
                    return True
            except subprocess.TimeoutExpired:
                pass

        # Attempt 2: Standalone compile (no libarchive linking at all)
        cmd = (
            f"{compiler} {extra_flags} {asan_flags} "
            f"-o {harness_bin} {harness_src} 2>&1"
        )
        self.log.info("harness.compile.fallback_2_standalone")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and harness_bin.exists():
                self.log.info("harness.compile.fallback_2.success")
                return True
        except subprocess.TimeoutExpired:
            pass

        self.log.error("harness.compile.all_attempts_failed")
        return False

    # Keep backward compatibility with old method name
    def build(self, source_root: Path, build_dir: Path) -> bool:
        """Legacy method — calls build_library."""
        return self.build_library(source_root, build_dir)
