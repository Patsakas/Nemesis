"""
NEMESIS library setup — auto-clone, prepare workspace, and verify builds.

Automates the manual steps of preparing a new library:
  1. Git clone → {name}_clean/ (pristine, never modified)
  2. Rsync → {name}_work/ (working copy for patching)
  3. Create build directories
  4. Run the fuzz build (afl-clang-fast) and verify output
  5. Run the debug build (clang + ASAN) and verify output

Usage:
    nemesis setup -t brotli           # setup from existing target YAML
    nemesis setup --url <git_url> -t libfoo  # clone + setup + onboard
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger


class LibrarySetup:
    """Handles cloning, building, and workspace preparation for a target library."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("setup")

    def clone(self, git_url: str, target_dir: Path) -> bool:
        """Git clone a repository to target_dir. Returns True on success."""
        if target_dir.exists() and list(target_dir.iterdir()):
            self.log.info("setup.clone_exists", path=str(target_dir))
            return True

        target_dir.parent.mkdir(parents=True, exist_ok=True)
        self.log.info("setup.cloning", url=git_url, dest=str(target_dir))
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", git_url, str(target_dir)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                self.log.error("setup.clone_failed", stderr=result.stderr[:500])
                return False
            self.log.info("setup.clone_ok", path=str(target_dir))
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.log.error("setup.clone_error", error=str(exc))
            return False

    def prepare_work_copy(self, source_root: Path, work_root: Path) -> bool:
        """Rsync source_root → work_root (creates the working copy)."""
        if source_root == work_root:
            self.log.warning("setup.same_root", path=str(source_root))
            return True

        work_root.mkdir(parents=True, exist_ok=True)
        self.log.info("setup.rsync", src=str(source_root), dest=str(work_root))
        try:
            result = subprocess.run(
                [
                    "rsync", "-a", "--delete",
                    f"{source_root}/", f"{work_root}/",
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                self.log.error("setup.rsync_failed", stderr=result.stderr[:500])
                return False
            self.log.info("setup.rsync_ok")
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.log.error("setup.rsync_error", error=str(exc))
            return False

    def create_build_dirs(self) -> list[Path]:
        """Create all build directories from config. Returns list of created dirs."""
        dirs = []
        for attr in ("build_dir", "debug_build_dir", "ubsan_build_dir", "coverage_build_dir"):
            build_dir = getattr(self.config.target, attr, None)
            if build_dir and str(build_dir) not in ("", "."):
                build_dir = Path(build_dir)
                build_dir.mkdir(parents=True, exist_ok=True)
                dirs.append(build_dir)
                self.log.debug("setup.mkdir", path=str(build_dir))
        return dirs

    def run_build(
        self,
        build_dir: Path,
        configure_cmd: str,
        make_cmd: str,
        label: str = "fuzz",
    ) -> tuple[bool, str]:
        """Run configure + make in build_dir. Returns (success, error_msg)."""
        if not configure_cmd:
            return False, f"No {label} configure command configured"

        build_dir.mkdir(parents=True, exist_ok=True)
        self.log.info(f"setup.build_{label}", build_dir=str(build_dir))

        # Configure
        try:
            result = subprocess.run(
                configure_cmd,
                shell=True, capture_output=True, text=True,
                timeout=180, cwd=str(build_dir),
                env={**os.environ, "AFL_NO_UI": "1"},
            )
            if result.returncode != 0:
                msg = result.stderr[-500:] if result.stderr else result.stdout[-500:]
                self.log.error(f"setup.configure_{label}_failed", error=msg)
                return False, f"Configure failed: {msg}"
        except subprocess.TimeoutExpired:
            return False, "Configure timed out after 180s"

        # Make
        try:
            result = subprocess.run(
                make_cmd,
                shell=True, capture_output=True, text=True,
                timeout=600, cwd=str(build_dir),
                env={**os.environ, "AFL_NO_UI": "1"},
            )
            if result.returncode != 0:
                msg = result.stderr[-500:] if result.stderr else result.stdout[-500:]
                self.log.error(f"setup.make_{label}_failed", error=msg)
                return False, f"Make failed: {msg}"
        except subprocess.TimeoutExpired:
            return False, "Make timed out after 600s"

        self.log.info(f"setup.build_{label}_ok")
        return True, ""

    def verify_library(self, build_dir: Path) -> Path | None:
        """Find the built .a or .so file in build_dir. Returns path or None."""
        lib_name = self.config.target.library_name
        # Search recursively in build_dir
        for ext in ("*.a", "*.so", "*.dylib"):
            for match in build_dir.rglob(ext):
                if lib_name == "lib*.a" or match.name == lib_name:
                    self.log.info("setup.library_found", path=str(match))
                    return match
                # Also match glob-style lib names
                if lib_name.startswith("lib") and match.name.startswith("lib"):
                    self.log.info("setup.library_found", path=str(match))
                    return match
        self.log.warning("setup.library_not_found", build_dir=str(build_dir), expected=lib_name)
        return None

    def full_setup(self, git_url: str = "") -> dict[str, bool | str]:
        """Run the complete setup pipeline. Returns status dict."""
        results: dict[str, bool | str] = {}
        source_root = Path(self.config.target.source_root)
        work_root = Path(self.config.target.effective_work_root)

        # Step 1: Clone if URL provided and source_root doesn't exist
        if git_url and not source_root.exists():
            results["clone"] = self.clone(git_url, source_root)
            if not results["clone"]:
                return results
        else:
            results["clone"] = "skipped" if source_root.exists() else "no_url"

        # Step 2: Prepare work copy
        results["work_copy"] = self.prepare_work_copy(source_root, work_root)

        # Step 3: Create build directories
        self.create_build_dirs()
        results["build_dirs"] = True

        # Step 4: Fuzz build (AFL)
        build_dir = Path(self.config.target.build_dir)
        ok, err = self.run_build(
            build_dir,
            self.config.target.build.configure,
            self.config.target.build.make,
            label="fuzz",
        )
        results["fuzz_build"] = ok
        if err:
            results["fuzz_build_error"] = err

        # Step 5: Verify fuzz library
        if ok:
            lib = self.verify_library(build_dir)
            results["fuzz_library"] = str(lib) if lib else "not_found"

        # Step 6: Debug build
        debug_dir = Path(self.config.target.debug_build_dir)
        if self.config.target.build.debug_configure:
            ok_dbg, err_dbg = self.run_build(
                debug_dir,
                self.config.target.build.debug_configure,
                self.config.target.build.debug_make or self.config.target.build.make,
                label="debug",
            )
            results["debug_build"] = ok_dbg
            if err_dbg:
                results["debug_build_error"] = err_dbg
        else:
            results["debug_build"] = "no_config"

        return results
