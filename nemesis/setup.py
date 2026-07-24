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
from nemesis.deps import DependencyResolver
from nemesis.logging import get_logger


class LibrarySetup:
    """Handles cloning, building, and workspace preparation for a target library."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("setup")
        # H1 dependency recovery state, shared across every build step in a run so
        # a package is installed at most once and the audit trail is one list.
        self._resolver: DependencyResolver | None = None
        self._installed: set[str] = set()
        self.dep_events: list[dict] = []

    def _get_resolver(self) -> DependencyResolver:
        if self._resolver is None:
            dep = self.config.dependencies
            self._resolver = DependencyResolver(
                mode=dep.resolver if dep.auto_install else "off",
                extra_allowlist=set(dep.extra_allowlist),
            )
        return self._resolver

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

    def _run_shell(
        self, cmd: str, build_dir: Path, timeout: int
    ) -> tuple[bool, str, str]:
        """Run one shell command in build_dir.

        Returns (ok, truncated_err, full_output). `full_output` is the whole
        stdout+stderr — the dependency resolver needs it, because the missing
        artifact is frequently outside the last 500 chars that get logged.
        """
        try:
            result = subprocess.run(
                cmd,
                shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=str(build_dir),
                env={**os.environ, "AFL_NO_UI": "1"},
            )
        except subprocess.TimeoutExpired:
            return False, f"timed out after {timeout}s", ""
        full = (result.stdout or "") + "\n" + (result.stderr or "")
        if result.returncode != 0:
            msg = result.stderr[-500:] if result.stderr else result.stdout[-500:]
            return False, msg, full
        return True, "", full

    def _run_phase(
        self, cmd: str, build_dir: Path, label: str, phase: str, timeout: int
    ) -> tuple[bool, str]:
        """Run one build phase (configure or make) with H1 dependency recovery:
        on failure, resolve the missing artifact to a package, install it, and
        retry — bounded by `dependencies.max_attempts`. When auto-install is off
        this is a single pass, identical to the pre-H1 behaviour."""
        resolver = self._get_resolver()
        dep = self.config.dependencies
        max_installs = dep.max_attempts if resolver.mode != "off" else 0
        installs_done = 0
        phase_records: list[dict] = []

        while True:
            ok, err, full = self._run_shell(cmd, build_dir, timeout)
            if ok:
                # Every install we made this phase let it progress to success.
                for rec in phase_records:
                    rec["cleared"] = True
                    rec["step_recovered"] = True
                return True, ""

            self.log.error(f"setup.{phase}_{label}_failed", error=err)

            if installs_done >= max_installs:
                self._finalise_phase(phase_records, full)
                return False, err

            resolution = resolver.resolve(full, self._installed)
            if resolution is None:
                # Nothing in the log maps to an allow-listed package — this is not
                # a recoverable dependency failure. Do not retry.
                if resolver.mode != "off":
                    self.log.info("setup.dep_unresolved", phase=phase, label=label)
                self._finalise_phase(phase_records, full)
                return False, err

            self.log.info(
                "setup.dep_resolution", phase=phase, label=label,
                artifact=f"{resolution.artifact.kind}:{resolution.artifact.name}",
                packages=resolution.packages, provenance=resolution.provenance,
                apt_file_db=resolution.apt_file_db,
            )
            install_ok = resolver.install(resolution.packages)
            rec = {
                "phase": phase, "label": label,
                "artifact_kind": resolution.artifact.kind,
                "artifact_name": resolution.artifact.name,
                "packages": resolution.packages,
                "provenance": resolution.provenance,
                "apt_file_db": resolution.apt_file_db,
                "install_ok": install_ok,
                "cleared": False,          # set at phase end / on recovery
                "step_recovered": False,
            }
            phase_records.append(rec)
            self.dep_events.append(rec)

            if not install_ok:
                self._finalise_phase(phase_records, full)
                return False, err
            self._installed.update(resolution.packages)
            installs_done += 1
            # loop: re-run the same phase now that the package is present

    @staticmethod
    def _finalise_phase(records: list[dict], final_output: str) -> None:
        """Attribute honesty metrics once a phase has failed for good. `cleared`
        means the artifact this install targeted no longer appears in the build
        output — i.e. the install worked and the build moved on to a *different*
        failure (progress). An install that did not even remove its own artifact
        is a false-positive install (installed, but useless). Checked against the
        FULL output, not the truncated error, so an artifact that scrolled out of
        the last 500 chars is not mistaken for cleared."""
        low = final_output.lower()
        for rec in records:
            rec["cleared"] = rec["artifact_name"].lower() not in low
            rec["false_positive_install"] = rec["install_ok"] and not rec["cleared"]

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

        ok, err = self._run_phase(configure_cmd, build_dir, label, "configure", 180)
        if not ok:
            return False, f"Configure failed: {err}"

        ok, err = self._run_phase(make_cmd, build_dir, label, "make", 600)
        if not ok:
            return False, f"Make failed: {err}"

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

        # H1: record the resolver configuration and the runner's actual install
        # capability up front, so a run's provenance is self-contained and a
        # degraded environment (no sudo / offline) is visible rather than inferred
        # from a wall of failed installs.
        dep = self.config.dependencies
        if dep.auto_install:
            from nemesis.deps import probe_capabilities
            self.log.info(
                "setup.dep_config",
                auto_install=dep.auto_install, resolver=dep.resolver,
                max_attempts=dep.max_attempts,
            )
            caps = probe_capabilities()
            self.log.info("setup.dep_capabilities", **caps)
            if not caps.get("sudo_noninteractive") or not caps.get("apt_available"):
                self.log.warning(
                    "setup.dep_capabilities_degraded",
                    hint="auto-deps requested but cannot install "
                         "(need apt-get + passwordless sudo); installs will fail",
                )

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

        # H1 metrics: distinguish real recovery from "installed packages, still
        # failed". Emitted as a structured event so the v0.2 analysis can parse it
        # straight out of the per-repo build log, no benchmark-code change needed.
        if self.dep_events:
            installed = sorted(self._installed)
            false_pos = [e for e in self.dep_events if e.get("false_positive_install")]
            cleared = [e for e in self.dep_events if e.get("cleared")]
            recovered = any(e.get("step_recovered") for e in self.dep_events)
            # "made progress" is the hypothesis-support signal: a build step either
            # recovered outright, or an installed dependency was cleared and the
            # build advanced to a *different* failure. Distinct from "reached T5".
            made_progress = recovered or bool(cleared)
            results["dep_installs"] = len(installed)
            results["dep_packages"] = ", ".join(installed)
            results["dep_artifacts_cleared"] = len(cleared)
            results["dep_false_positive_installs"] = len(false_pos)
            results["dep_made_progress"] = made_progress
            self.log.info(
                "setup.dep_summary",
                installed=installed,
                install_events=len(self.dep_events),
                artifacts_cleared=len(cleared),
                false_positive_installs=len(false_pos),
                any_step_recovered=recovered,
                made_progress=made_progress,
            )

        return results
