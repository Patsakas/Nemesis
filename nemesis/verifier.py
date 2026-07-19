"""
NEMESIS Offline Crash Verifier

Determines whether crashes found with LLM patches applied also reproduce
on the unpatched (original) source — distinguishing real CVE candidates
from patch-induced false positives.

Two scenarios:
  Scenario 1 (FALSE POSITIVE):  crash only with patch  → patch_induced=True
  Scenario 2 (TRUE POSITIVE):   crash also without patch → patch_induced=False → CVE candidate

Usage:
  nemesis verify-crashes --target libarchive
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import CoverageTarget, HarnessSpec


class OfflineCrashVerifier:
    """
    Runs unpatched verification on all existing crash files.

    Build flow (one-time):
      1. Locate pre-built unpatched libarchive.a in debug_build_dir
         (built at pipeline startup by SymbolicStage.build_unpatched_library)
      2. No git stash needed — source_root is NEVER patched (two-repo architecture)

    Per-target flow:
      4. Re-run Stage 2 (LLM cache hit, $0) → get harness
      5. Compile harness against unpatched libarchive as fuzz_nemesis_debug
      6. Run each crash file through fuzz_nemesis_debug
      7. Report: REAL BUG (reproduces) or patch-induced (does not)
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("verifier")
        self.source_root = Path(config.target.source_root)
        self.debug_build_dir = Path(config.target.debug_build_dir)
        self.findings_base = Path(config.engine.work_dir) / "fuzzing" / "findings"
        self._unpatched_lib: Optional[str] = None  # path to unpatched libarchive.a

    # ── Public API ────────────────────────────────────────────

    def run(self, targets: list[CoverageTarget]) -> list[VerificationResult]:
        """
        Verify all crash files for targets that have existing findings.

        Returns list of VerificationResult, one per target with crashes.
        """
        # Filter to targets that actually have crashes
        targets_with_crashes = [
            t for t in targets
            if self._crash_files(t.func_name)
        ]

        if not targets_with_crashes:
            self.log.info("verify.no_crashes_found")
            return []

        self.log.info(
            "verify.start",
            targets=len(targets_with_crashes),
            funcs=[t.func_name for t in targets_with_crashes],
        )

        # Build unpatched libarchive ONCE for all targets
        if not self._build_unpatched_library():
            self.log.error("verify.unpatched_build_failed — cannot verify any crashes")
            return []

        results: list[VerificationResult] = []
        for target in targets_with_crashes:
            result = self._verify_target(target)
            results.append(result)
            self._print_result(result)

        return results

    # ── Unpatched library build (once) ────────────────────────

    def _build_unpatched_library(self) -> bool:
        """
        Use the pre-built unpatched debug library from debug_build_dir.

        In the two-repo architecture, source_root is NEVER patched and the debug
        library is built once at pipeline startup (via SymbolicStage.build_unpatched_library).
        This method just locates the already-built libarchive.a — no git stash needed.
        """
        lib = self._find_library(self.config.target.library_name)
        if lib:
            self._unpatched_lib = lib
            self.log.info("verify.unpatched_lib.found", lib=lib)
            return True

        # Library not pre-built — build it now (fallback for standalone verify-crashes invocation)
        debug_configure = self.config.target.build.debug_configure
        debug_make = self.config.target.build.debug_make

        if not debug_configure:
            self.log.error("verify.no_debug_configure")
            return False

        self.debug_build_dir.mkdir(parents=True, exist_ok=True)
        full_cmd = (
            f"cd {self.debug_build_dir} && "
            f"{debug_configure.strip()} && "
            f"{debug_make.strip()}"
        )
        self.log.info("verify.build_unpatched.start")
        r = subprocess.run(
            full_cmd, shell=True, capture_output=True,
            text=True, timeout=600, cwd=str(self.debug_build_dir),
        )
        if r.returncode != 0:
            self.log.error("verify.build_failed", stderr=r.stderr[-400:])
            return False

        lib = self._find_library(self.config.target.library_name)
        if not lib:
            self.log.error("verify.library_not_found", name=self.config.target.library_name)
            return False

        self._unpatched_lib = lib
        self.log.info("verify.build_unpatched.done", lib=lib)
        return True

    # ── Per-target verification ───────────────────────────────

    def _verify_target(self, target: CoverageTarget) -> "VerificationResult":
        """Verify crashes for one target function."""
        crash_files = self._crash_files(target.func_name)
        result = VerificationResult(func_name=target.func_name, crash_files=crash_files)

        # Re-run Stage 2 (from LLM cache) to get harness code
        harness = self._get_harness(target)
        if harness is None:
            self.log.warning("verify.harness_unavailable", func=target.func_name)
            result.error = "Could not retrieve harness from LLM cache"
            return result

        # Compile harness against unpatched libarchive
        debug_bin = self._compile_debug_harness(harness, target.func_name)
        if debug_bin is None:
            result.error = "Harness compile failed against unpatched library"
            return result

        result.debug_binary = str(debug_bin)

        # Test each crash file
        for crash_file in crash_files:
            crashes = self._test_crash(debug_bin, crash_file)
            result.per_crash[crash_file.name] = crashes
            if crashes:
                result.real_crashes.append(crash_file.name)
            else:
                result.patch_induced.append(crash_file.name)

        return result

    def _get_harness(self, target: CoverageTarget) -> Optional[HarnessSpec]:
        """Re-run Stage 2 for this target (LLM cache hit → free)."""
        try:
            from nemesis.recon import ReconStage
            from nemesis.neural import NeuralStage
            from nemesis.models import AnalysisContext

            recon = ReconStage(self.config)
            neural = NeuralStage(self.config)

            context = recon.extract_context(target)
            analysis = neural.analyze(context)
            harness = neural.generate_harness(analysis, context)

            if harness and harness.c_code:
                return harness

        except Exception as e:
            self.log.warning("verify.harness_fetch_failed", func=target.func_name, error=str(e))

        return None

    # AFL stub header — replaces AFL persistent-mode macros with stdin equivalents
    # so harnesses compiled with plain clang can still process crash inputs.
    AFL_STUB_HEADER = """\
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

    def _compile_debug_harness(
        self, harness: HarnessSpec, func_name: str
    ) -> Optional[Path]:
        """Compile harness against unpatched libarchive.a using clang+ASAN.

        Prepends an AFL stub header so AFL persistent-mode macros work with
        plain clang (reads from stdin instead of shared memory).
        """
        from nemesis.symbolic import SymbolicStage

        builder = SymbolicStage(self.config).builder
        fixed_code = builder._fix_harness_includes(harness.c_code)
        # Prepend AFL stubs before any other code
        full_code = self.AFL_STUB_HEADER + fixed_code

        harness_src = self.debug_build_dir / f"fuzz_verify_{func_name}.c"
        debug_bin = self.debug_build_dir / f"fuzz_verify_{func_name}"
        harness_src.write_text(full_code)

        # Config-driven include dirs + link libs (was hardcoded to libarchive).
        inc_dirs: list[Path] = [self.source_root]
        for sub in (self.config.target.include_subdir,
                    self.config.target.source_subdir,
                    "include", "libarchive"):
            if sub:
                d = self.source_root / sub
                if d.is_dir():
                    inc_dirs.append(d)
        include_flags = " ".join(f"-I{d}" for d in dict.fromkeys(inc_dirs))
        libs = self.config.target.link_libs or ""
        # -O0 (was -O1): -O1 dead-store/load elimination can hide the very
        # UAF/over-read/uninit bug we're verifying, flipping a REAL CVE to
        # "patch-induced". -fno-sanitize-recover=undefined makes UBSan-class
        # crashes actually abort here too (parity with the AFL harness build).
        asan_flags = (
            "-fsanitize=address,undefined -fno-sanitize-recover=undefined "
            "-fno-omit-frame-pointer"
        )
        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable"
        )

        cmd = (
            f"clang {include_flags} -g -O0 {asan_flags} {warn_flags} "
            f"-o {debug_bin} {harness_src} "
            f"{self._unpatched_lib} {libs} 2>&1"
        )
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and debug_bin.exists():
            self.log.info("verify.harness_compiled", func=func_name, binary=str(debug_bin))
            return debug_bin
        else:
            self.log.error("verify.compile_failed", func=func_name, output=r.stdout[-300:])
            return None

    def _test_crash(self, debug_bin: Path, crash_file: Path) -> bool:
        """Run crash file through unpatched binary. Returns True if it crashes."""
        asan_env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"}
        try:
            with open(crash_file, "rb") as f:
                r = subprocess.run(
                    [str(debug_bin)], stdin=f,
                    capture_output=True, timeout=15, env=asan_env,
                )
            return r.returncode != 0
        except subprocess.TimeoutExpired:
            return True  # hang = crash
        except (OSError, FileNotFoundError):
            return False

    # ── Helpers ───────────────────────────────────────────────

    def _crash_files(self, func_name: str) -> list[Path]:
        """Return crash files for a target function."""
        target_dir = self.findings_base / func_name
        for subdir in ["main/crashes", "default/crashes"]:
            crashes_dir = target_dir / subdir
            if crashes_dir.exists():
                files = sorted(f for f in crashes_dir.glob("id:*") if f.is_file())
                if files:
                    return files
        return []

    def _find_library(self, name: str) -> str:
        """Search for the target's static library (config.target.library_name)
        in debug_build_dir, trying common layouts then a recursive find."""
        sub = self.config.target.source_subdir or ""
        for candidate in [
            self.debug_build_dir / sub / name if sub else self.debug_build_dir / name,
            self.debug_build_dir / "libarchive" / name,
            self.debug_build_dir / "lib" / name,
            self.debug_build_dir / name,
        ]:
            if candidate.exists():
                return str(candidate)
        try:
            r = subprocess.run(
                ["find", str(self.debug_build_dir), "-name", name, "-type", "f"],
                capture_output=True, text=True, timeout=10,
            )
            paths = r.stdout.strip().split("\n")
            if paths and paths[0]:
                return paths[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return ""

    def _print_result(self, result: "VerificationResult") -> None:
        real = len(result.real_crashes)
        induced = len(result.patch_induced)
        total = len(result.crash_files)
        status = "✅ REAL BUG" if real > 0 else "❌ patch-induced"
        self.log.info(
            "verify.result",
            func=result.func_name,
            total=total,
            real=real,
            patch_induced=induced,
            verdict=status,
            error=result.error or "",
        )


class VerificationResult:
    """Result of unpatched verification for one target."""

    def __init__(self, func_name: str, crash_files: list[Path]) -> None:
        self.func_name = func_name
        self.crash_files = crash_files
        self.debug_binary: str = ""
        self.per_crash: dict[str, bool] = {}   # filename → crashes_unpatched
        self.real_crashes: list[str] = []       # crash_induced=False
        self.patch_induced: list[str] = []      # crash_induced=True
        self.error: str = ""

    @property
    def verdict(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.real_crashes:
            return "REAL BUG — CVE candidate"
        return "patch-induced — false positive"
