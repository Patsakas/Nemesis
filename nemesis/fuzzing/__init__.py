"""
NEMESIS Stage 4 — Fuzzing (AFL++ orchestration + crash triage).

Manages AFL++ execution, crash deduplication and classification,
and coverage delta analysis.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import (
    CWE,
    AFLStats,
    AppReproStatus,
    CoverageDelta,
    CoverageSnapshot,
    CrashReport,
    HarnessSpec,
    SanitizerClass,
    Severity,
)

# UBSan defaults to print-and-continue on diagnostics (halt_on_error=0). Triage
# replays an AFL crash input against an instrumented binary and decides the
# crash is real iff the process aborts. Without halt_on_error=1, UBSan-class
# bugs (integer overflow, divide-by-zero, etc.) print a "runtime error" line
# but the process continues and exits 0 — the triager then drops the crash as
# non-reproducible. Every triage env must include this.
_TRIAGE_UBSAN_OPTIONS = (
    "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
)


_INDEXED_CHAR_CMP = re.compile(r"(\w+)\s*\[\s*(\d+)\s*\]\s*==\s*'(.)'")


def _combine_adjacent_char_cmps(content: str, max_index: int = 32) -> set[str]:
    """Stitch adjacent indexed char comparisons into multi-byte magic tokens.

    Scans for patterns like `buf[0]=='G' && buf[1]=='I' && buf[2]=='F'` and
    returns the contiguous runs (``{"GIF"}``) so the AFL dictionary carries the
    full magic prefix, not just isolated single characters AFL cannot reassemble
    on its own. Only indices within ``max_index`` of the array base are
    considered (magic prefixes live at the very start of a buffer). Pure helper
    — extracted from `_generate_dictionary` so it can be unit-tested directly.
    """
    by_base: dict[str, dict[int, str]] = {}
    for m in _INDEXED_CHAR_CMP.finditer(content or ""):
        base, idx, ch = m.group(1), int(m.group(2)), m.group(3)
        if idx <= max_index:
            by_base.setdefault(base, {})[idx] = ch
    tokens: set[str] = set()
    for idx_map in by_base.values():
        run = ""
        for i in range(0, max(idx_map) + 1):
            if i in idx_map:
                run += idx_map[i]
            else:
                if len(run) >= 2:
                    tokens.add(run)
                run = ""
        if len(run) >= 2:
            tokens.add(run)
    return tokens


class FuzzingStage:
    """Stage 4 orchestrator."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("fuzzing")
        self.orchestrator = AFLOrchestrator(config)
        self.triager = CrashTriager(config)
        self.coverage = CoverageAnalyzer(config)
        self._last_error_log = ""

    def run(
        self,
        harness: HarnessSpec,
        target_name: str = "",
        target_file_path: str = "",
    ) -> tuple[AFLStats, list[CrashReport]]:
        """Run AFL++ and return stats + crash reports."""
        stats = self.orchestrator.run(harness, target_name=target_name, target_file_path=target_file_path)
        # Point triager and coverage analyzer at per-target findings dir (run-scoped)
        findings_base = self.orchestrator.workspace / "findings" / self.orchestrator.run_id if self.orchestrator.run_id else self.orchestrator.workspace / "findings"
        findings_dir = findings_base / (target_name or "default")
        main_dir = findings_dir / "main"
        self.triager.crashes_dir = (main_dir if main_dir.exists() else findings_dir / "default") / "crashes"
        self.triager.asan_log_dir = getattr(self.orchestrator, "asan_log_dir", None)
        self.coverage._findings_dir = findings_dir
        crashes = self.triager.triage_all()
        # Collect unique hangs (potential DoS) alongside crashes
        hangs = self.triager.triage_hangs()
        if hangs:
            self.log.info("triage.hangs_found", count=len(hangs))
        # Fix 136: post-fuzz LeakSanitizer pass (CWE-401) — opt-in via target.leak_detection.
        # Fix 137: pass func_name so triage_leaks can rebuild the saved reference
        # harness and filter out LLM-induced harness FPs.
        leaks: list[CrashReport] = []
        if getattr(self.config.target, "leak_detection", False):
            sample = getattr(self.config.target, "leak_detection_sample_size", 30)
            leaks = self.triager.triage_leaks(sample_size=sample, func_name=target_name)
            if leaks:
                self.log.info("triage.leaks_found", count=len(leaks))
        return stats, crashes + hangs + leaks

    def measure_coverage(self) -> CoverageDelta:
        """Measure coverage delta from the fuzzing run."""
        return self.coverage.measure()

    def get_error_log(self) -> str:
        """Get the error log from the last run."""
        return self._last_error_log

    def ensure_seeds(
        self,
        harness: HarnessSpec,
        target_file_path: str = "",
    ) -> Path:
        """Compatibility wrapper for seed prepopulation in pipeline paths."""
        return self.orchestrator.ensure_seeds(harness, target_file_path)

    def sweep_corpus_ubsan(
        self,
        ubsan_binary: Path,
        target_name: str = "",
        max_files: int = 500,
    ) -> list[CrashReport]:
        """Post-fuzz UBSan corpus sweep: run AFL queue through UBSan binary.

        Catches undefined behavior (integer overflow, shift-out-of-range,
        pointer-overflow) that ASAN+AFL may miss because UB doesn't always
        cause a memory safety violation.

        Args:
            ubsan_binary: Path to the UBSan-instrumented harness binary.
            target_name: Target function slug (for finding the AFL queue).
            max_files: Max corpus files to test (sample if larger).

        Returns:
            List of CrashReport for any UBSan violations found.
        """
        if not ubsan_binary.exists():
            self.log.warning("ubsan_sweep.binary_missing", path=str(ubsan_binary))
            return []

        slug = target_name or "default"
        # Locate AFL queue directory
        findings_base = (
            self.orchestrator.workspace / "findings" / self.orchestrator.run_id
            if self.orchestrator.run_id
            else self.orchestrator.workspace / "findings"
        )
        queue_dir = findings_base / slug / "main" / "queue"
        if not queue_dir.exists():
            # Fallback: try "current" symlink
            queue_dir = self.orchestrator.workspace / "findings" / "current" / slug / "main" / "queue"
        if not queue_dir.exists():
            self.log.info("ubsan_sweep.no_queue", slug=slug)
            return []

        queue_files = sorted(
            f for f in queue_dir.iterdir()
            if f.is_file() and f.stat().st_size > 0 and not f.name.startswith(".")
        )
        if not queue_files:
            self.log.info("ubsan_sweep.empty_queue", slug=slug)
            return []

        # Sample if corpus too large
        import random
        if len(queue_files) > max_files:
            queue_files = random.sample(queue_files, max_files)

        self.log.info(
            "ubsan_sweep.start",
            slug=slug,
            corpus_size=len(queue_files),
            binary=str(ubsan_binary),
        )

        ubsan_pattern = re.compile(r"runtime error:\s*(.+)")
        reports: list[CrashReport] = []
        seen_errors: set[str] = set()  # deduplicate by error message

        env = os.environ.copy()
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
        # Disable ASAN if the binary also has it (we only care about UBSan here)
        env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1"

        for corpus_file in queue_files:
            try:
                with open(corpus_file, "rb") as f:
                    input_data = f.read()
                proc = subprocess.run(
                    [str(ubsan_binary)],
                    input=input_data,
                    capture_output=True,
                    timeout=10,
                    env=env,
                )
                stderr_text = proc.stderr.decode("utf-8", errors="replace")

                # Check for UBSan runtime errors
                matches = ubsan_pattern.findall(stderr_text)
                for error_msg in matches:
                    # Deduplicate by error message prefix (first 80 chars)
                    dedup_key = error_msg[:80]
                    if dedup_key in seen_errors:
                        continue
                    seen_errors.add(dedup_key)

                    # Extract location from stderr (file:line:col pattern)
                    loc_match = re.search(r"(\S+:\d+:\d+):", stderr_text)
                    location = loc_match.group(1) if loc_match else "unknown"

                    # Extract stack trace lines
                    stack_lines = [
                        line.strip()
                        for line in stderr_text.split("\n")
                        if line.strip().startswith("#")
                    ]

                    report = CrashReport(
                        input_file=str(corpus_file),
                        crash_location=location,
                        stack_trace=stack_lines[:20],
                        cwe=CWE.UNDEFINED_BEHAVIOR,
                        severity=Severity.MEDIUM,
                        asan_output=stderr_text[:2000],
                        detected_by=SanitizerClass.UBSAN,
                        patch_induced=False,
                    )
                    reports.append(report)
                    self.log.info(
                        "ubsan_sweep.violation",
                        file=corpus_file.name,
                        error=error_msg[:100],
                        location=location,
                    )

            except subprocess.TimeoutExpired:
                continue
            except Exception as exc:
                self.log.debug("ubsan_sweep.file_error", file=str(corpus_file), error=str(exc))
                continue

        self.log.info(
            "ubsan_sweep.done",
            slug=slug,
            tested=len(queue_files),
            violations=len(reports),
        )
        return reports


class AFLOrchestrator:
    """
    Manages AFL++ fuzzing sessions.

    Supports multi-instance fuzzing with different strategies.
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("fuzzing.afl")
        self.workspace = Path(config.engine.work_dir) / "fuzzing"
        self.workspace.mkdir(parents=True, exist_ok=True)
        # Set by pipeline before first run — scopes findings to this run
        self.run_id: str = ""

    def ensure_seeds(
        self,
        harness: HarnessSpec,
        target_file_path: str = "",
    ) -> Path:
        """Ensure format-specific seeds exist for a target (idempotent).

        Called by the pipeline before profiling so gdb has real format data
        instead of the 64-null-byte fallback.  Returns the seeds directory.
        """
        slug = harness.target_func or "default"
        seeds_dir = self.workspace / "seeds" / slug
        seeds_dir.mkdir(parents=True, exist_ok=True)

        # Skip if seeds already populated (e.g. re-run or Stage 4 already ran)
        existing = [f for f in seeds_dir.iterdir() if f.is_file() and f.stat().st_size > 0]
        if existing:
            return seeds_dir

        self._generate_seeds(harness, seeds_dir, target_file_path)
        return seeds_dir

    def run(
        self,
        harness: HarnessSpec,
        target_name: str = "",
        target_file_path: str = "",
    ) -> AFLStats:
        """
        Launch AFL++ against the harness binary.

        Spawns one main instance (-M main) and N-1 slave instances (-S slave_N)
        in parallel, waits for timeout, then terminates all.

        target_file_path: relative source path of the target function
          (e.g. "libarchive/archive_read_support_format_7zip.c").
          Used as primary seed selection key — more reliable than input_format.
        """
        self._crash_logged = False  # Fix 126: reset per-run
        slug = target_name or "default"
        seeds_dir = self.workspace / "seeds" / slug
        # Scope findings to run_id so each scan preserves its crash files
        findings_base = self.workspace / "findings" / self.run_id if self.run_id else self.workspace / "findings"
        findings_dir = findings_base / slug
        seeds_dir.mkdir(parents=True, exist_ok=True)
        findings_dir.mkdir(parents=True, exist_ok=True)

        # Fix: AFL_AUTORESUME + changed binary → rc=1 early exit.
        # Delete AFL runner metadata files (target_hash, fuzz_bitmap, fuzzer_stats,
        # cmdline, queue/) so AFL treats this as a fresh start.
        # Crash files (crashes/, hangs/) are preserved — already triaged or needed later.
        import shutil as _shutil
        for _afl_dir in [findings_dir / "main"] + [findings_dir / f"slave_{i}" for i in range(1, 8)]:
            if _afl_dir.exists():
                for _stale in ("target_hash", "fuzz_bitmap", "fuzzer_stats", "cmdline", ".cur_input"):
                    (_afl_dir / _stale).unlink(missing_ok=True)
                _queue = _afl_dir / "queue"
                if _queue.exists():
                    _shutil.rmtree(_queue, ignore_errors=True)

        # Generate seeds — file_path takes priority over input_format
        self._generate_seeds(harness, seeds_dir, target_file_path)

        from nemesis.feature_flags import is_enabled as _fflag

        # Tier 2 #3 (2026-05-07): SeedMind-style LLM-driven seedgen.
        # Asks the architect LLM for a Python generator script, runs it
        # ~200× with varying rng_seeds, and appends unique outputs to the
        # AFL `-i` directory. Augments the static seed harvesting above
        # rather than replacing it: the existing _minimize_seeds /
        # _prevalidate_seeds stages drop crashers and duplicates, so the
        # generator does not need to be perfect — only diverse.
        if _fflag("seedgen"):
            try:
                from nemesis.neural import LLMClient
                from nemesis.recon import cve_context as _cc
                from nemesis.recon import seedgen as _sg
                from nemesis.recon.format_specs import get_format_spec

                nemesis_root = Path(__file__).resolve().parents[2]
                targets_dir = nemesis_root / "config" / "targets"
                lib_name = self.config.target.name or ""
                target_func = getattr(harness, "target_func", "") or ""

                cve_records = _cc.get_or_fetch(
                    library_name=lib_name,
                    targets_dir=targets_dir,
                    max_cves=3,
                    log=self.log,
                ) if lib_name else []
                format_spec = get_format_spec(lib_name, targets_dir=targets_dir) if lib_name else ""

                _llm = LLMClient(self.config)
                script = _sg.synthesize_generator_script(
                    library_name=lib_name,
                    target_func=target_func,
                    harness_source=getattr(harness, "c_code", "") or "",
                    cve_records=cve_records,
                    format_spec=format_spec,
                    client=_llm,
                    log=self.log,
                )
                if script:
                    n_unique = _sg.produce_seeds(
                        script_source=script,
                        out_dir=seeds_dir,
                        n_seeds=200,
                        log=self.log,
                    )
                    self.log.info("seedgen.appended_to_corpus",
                                  unique=n_unique, seeds_dir=str(seeds_dir))
                else:
                    # Robustness fallback (#6): the freeform script was rejected
                    # or smoke-failed. Ask for a declarative JSON field spec
                    # instead — there is no LLM-authored code to crash, so the
                    # produce wave can't be wasted on a runtime error.
                    from nemesis.recon import fieldspec_seedgen as _fs

                    # Prefer a MEASURED spec over a recalled one. Probing the
                    # instrumented binary tells us which bytes actually steer
                    # the program, which beats asking the model to remember a
                    # format it may never have seen. Needs a seed to probe and
                    # an instrumented binary; falls back to the LLM whenever
                    # either is missing or nothing measurable comes back.
                    spec = self._measured_fieldspec(seeds_dir)
                    if spec is None:
                        spec = _fs.synthesize_fieldspec(
                            library_name=lib_name,
                            target_func=target_func,
                            format_spec=format_spec,
                            cve_records=cve_records,
                            client=_llm,
                            log=self.log,
                        )
                    if spec:
                        n_fs = _fs.produce_seeds_from_spec(
                            spec, seeds_dir, n_seeds=200, log=self.log,
                        )
                        self.log.info("fieldspec.appended_to_corpus",
                                      unique=n_fs, seeds_dir=str(seeds_dir))
            except Exception as exc:
                self.log.warning("seedgen.failed", error=str(exc))
        else:
            self.log.info("seedgen.disabled")

        # Minimize seed corpus: keep only seeds that produce unique coverage
        seeds_dir = self._minimize_seeds(seeds_dir, Path(self.config.target.build_dir) / "fuzz_nemesis")

        # Fix 107: Pre-validate seeds — remove seeds that crash the binary.
        # Prevents AFL early-exit (all-seeds-crash) which wastes 60s+ on warmup.
        surviving = self._prevalidate_seeds(
            Path(self.config.target.build_dir) / "fuzz_nemesis", seeds_dir,
        )
        if surviving == 0:
            self.log.warning("seeds.all_crash", fix="Fix 107", seeds_dir=str(seeds_dir))
            return self._parse_stats(findings_dir)

        # Generate AFL dictionary from source file magic bytes/tokens + LLM entries
        dict_file = self._generate_dictionary(
            target_file_path, self.workspace / "dict" / slug, harness.dictionary_entries,
        )

        binary = Path(self.config.target.build_dir) / "fuzz_nemesis"
        # Snapshot binary into the per-target findings dir BEFORE AFL launches.
        # Feedback-loop refinement recompiles fuzz_nemesis between iterations,
        # clobbering the binary that produced this run's crashes. Without a
        # snapshot, afl-cmin's reproducibility check at triage time runs against
        # a different binary and silently drops every crash as non-reproducible.
        # The snapshot is the authoritative binary for verifying THIS run's crashes.
        try:
            snapshot = findings_dir / "binary_snapshot"
            cmplog_snapshot = findings_dir / "binary_cmplog_snapshot"
            debug_snapshot = findings_dir / "binary_debug_snapshot"
            if binary.exists():
                _shutil.copy2(binary, snapshot)
                snapshot.chmod(0o755)
            cmplog_bin = Path(self.config.target.build_dir) / "fuzz_nemesis_cmplog"
            if cmplog_bin.exists():
                _shutil.copy2(cmplog_bin, cmplog_snapshot)
                cmplog_snapshot.chmod(0o755)
            debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
            if debug_bin.exists():
                _shutil.copy2(debug_bin, debug_snapshot)
                debug_snapshot.chmod(0o755)
            self.log.info(
                "afl.binary_snapshot",
                snapshot=str(snapshot),
                size=snapshot.stat().st_size if snapshot.exists() else 0,
                debug_size=debug_snapshot.stat().st_size if debug_snapshot.exists() else 0,
            )
        except Exception as _exc:
            self.log.warning("afl.binary_snapshot_failed", error=str(_exc))
        timeout_s = int(self.config.fuzzing.timeout_hours * 3600)
        n_instances = max(1, self.config.fuzzing.instances)

        # AFL++ 4.x requires symbolize=0 — it aborts if symbolize=1 is set.
        # log_path still works with symbolize=0 (writes raw ASAN report without symbols).
        # Symbolization happens later in triage when we run the debug binary standalone.
        asan_log_dir = self.workspace / "asan_logs" / slug
        asan_log_dir.mkdir(parents=True, exist_ok=True)
        self.asan_log_dir = asan_log_dir  # exposed for CrashTriager

        env = os.environ.copy()
        env.update(self.config.fuzzing.afl_env)
        asan_opts = (
            "abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1"
            f":log_path={asan_log_dir}/crash"
        )
        if getattr(self, "_asan_disable_suar", False):
            asan_opts += ":detect_stack_use_after_return=0"
        env["ASAN_OPTIONS"] = asan_opts
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_NO_AFFINITY"] = "1"

        # Custom mutator: compile and load if configured. If no mutator is
        # configured but the target has structured magic_bytes, ask the
        # architect LLM to synthesise an adapter from the scaffold + the
        # PNG reference. Closes the "narrow byte-pattern trigger" gap that
        # blocked libwebp / lz4 / similar benchmarks.
        from nemesis.feature_flags import is_enabled as _fflag
        mutator_source = self.config.fuzzing.custom_mutator_source
        if (not mutator_source and getattr(self.config.target, "magic_bytes", None)
                and _fflag("mutator_synthesis")):
            try:
                # Use the same LLM client as the rest of the pipeline.
                from nemesis.neural import LLMClient
                from nemesis.recon.mutator_synthesis import (
                    synthesize_and_compile_adapter,
                )
                _llm = LLMClient(self.config)
                nemesis_root = Path(__file__).resolve().parents[2]
                synth_path = synthesize_and_compile_adapter(
                    self.config, _llm, self.log, nemesis_root,
                )
                if synth_path is not None:
                    mutator_source = str(synth_path)
                    self.log.info(
                        "afl.custom_mutator_synthesized",
                        source=str(synth_path),
                    )
            except Exception as exc:
                self.log.warning("afl.custom_mutator_synth_error", error=str(exc))

        if mutator_source:
            mutator_path = Path(os.path.expandvars(os.path.expanduser(mutator_source)))
            if mutator_path.exists():
                mutator_so = self.workspace / "mutator" / f"{mutator_path.stem}.so"
                mutator_so.parent.mkdir(parents=True, exist_ok=True)
                # Plain clang, NOT afl-clang-fast: the mutator .so is loaded by
                # afl-fuzz itself, not the target. Instrumenting it leaves
                # dangling references to __afl_area_ptr that abort AFL at
                # load_custom_mutator() (afl-fuzz-mutators.c).
                compile_cmd = [
                    "clang", "-shared", "-fPIC", "-O2",
                    "-o", str(mutator_so), str(mutator_path),
                ]
                try:
                    compile_result = subprocess.run(
                        compile_cmd, capture_output=True, text=True, timeout=30,
                    )
                    if compile_result.returncode == 0:
                        env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(mutator_so)
                        env["AFL_CUSTOM_MUTATOR_ONLY"] = "0"  # combine with havoc
                        self.log.info(
                            "afl.custom_mutator_loaded",
                            source=str(mutator_path),
                            so=str(mutator_so),
                        )
                    else:
                        self.log.warning(
                            "afl.custom_mutator_compile_failed",
                            stderr=compile_result.stderr[-300:],
                        )
                except Exception as exc:
                    self.log.warning("afl.custom_mutator_error", error=str(exc))
            else:
                self.log.warning("afl.custom_mutator_not_found", path=str(mutator_path))

        self.log.info(
            "afl.launch",
            binary=str(binary),
            seeds=str(seeds_dir),
            timeout_h=self.config.fuzzing.timeout_hours,
            instances=n_instances,
        )

        procs: list[subprocess.Popen] = []

        def _make_cmd(role: str, instance_id: int = 0) -> list[str]:
            flag = "-M" if role == "main" else "-S"
            cmd = [
                "afl-fuzz",
                flag, role,
                "-i", str(seeds_dir),
                "-o", str(findings_dir),
                "-t", "10000",  # 10s per-input timeout (CAB + ASan overhead)
                "-V", str(timeout_s),
            ]
            # Fix C: CMPLOG — use separate CMPLOG binary if available (RedQueen auto-solving).
            # Without -c {cmplog_binary}, -l 2 is a no-op.
            if role == "main":
                cmplog_bin = getattr(harness, "cmplog_binary", None)
                if cmplog_bin and Path(cmplog_bin).exists():
                    cmd.extend(["-c", cmplog_bin])
                    self.log.info("afl.cmplog_active", binary=cmplog_bin)
                else:
                    # Fallback: -l 2 without explicit CMPLOG binary (may still work on some builds)
                    cmd.extend(["-l", "2"])
            # MOpt: genetic mutation scheduling on even-numbered secondaries
            if role != "main" and instance_id % 2 == 0:
                cmd.extend(["-L", "0"])
            if dict_file:
                cmd.extend(["-x", str(dict_file)])
            cmd.extend(["--", str(binary)])
            return cmd

        import resource as _resource

        def _afl_preexec():
            """Apply resource limits to each AFL child process.

            RLIMIT_AS  — 4 GB virtual address space (prevents runaway memory).
            RLIMIT_NPROC — 512 child processes max (protects against fork bombs).
            RLIMIT_CPU is intentionally NOT set here — AFL run duration is managed
            by the polling loop below (hard kill after timeout).
            """
            try:
                # NOTE: Do NOT set RLIMIT_AS with ASAN — ASAN needs ~20TB virtual
                # address space for shadow memory. 4GB limit kills the fork server
                # with signal 6 (SIGABRT). AFL++ handles memory limits internally.
                _resource.setrlimit(
                    _resource.RLIMIT_NPROC, (512, 512)
                )
            except (OSError, ValueError):
                pass  # WSL / container environments may not support all limits

        # Capture AFL stderr to log files for debugging early exits
        afl_log_dir = findings_dir / "afl_logs"
        afl_log_dir.mkdir(parents=True, exist_ok=True)

        try:
            main_stderr = open(afl_log_dir / "main.log", "w")
            procs.append(subprocess.Popen(
                _make_cmd("main", 0), env=env,
                stdout=subprocess.DEVNULL, stderr=main_stderr,
                preexec_fn=_afl_preexec,
            ))
        except FileNotFoundError:
            self.log.error("afl.not_found — is afl-fuzz installed?")
            return self._parse_stats(findings_dir)

        slave_logs = []
        for i in range(1, n_instances):
            try:
                slog = open(afl_log_dir / f"slave_{i}.log", "w")
                slave_logs.append(slog)
                procs.append(subprocess.Popen(
                    _make_cmd(f"slave_{i}", i), env=env,
                    stdout=subprocess.DEVNULL, stderr=slog,
                    preexec_fn=_afl_preexec,
                ))
            except FileNotFoundError:
                break

        # Poll AFL stats for early-exit conditions instead of blind wait.
        # Check every 30s after initial 60s warmup:
        #   - map_density < 0.5% → harness is broken, stop early
        #   - unique_crashes > 0  → found a bug, stop early
        import time
        warmup_s = 60
        poll_interval_s = 30
        deadline = time.monotonic() + timeout_s + 60  # hard deadline

        try:
            procs[0].wait(timeout=warmup_s)
            # AFL exited within warmup — log stderr for debugging
            rc = procs[0].returncode
            main_stderr.close()
            afl_err = ""
            try:
                afl_err = (afl_log_dir / "main.log").read_text()[-500:]
            except Exception:
                pass
            if rc != 0 or not (findings_dir / "main" / "fuzzer_stats").exists():
                self.log.warning(
                    "afl.early_exit_warmup",
                    returncode=rc,
                    stderr_tail=afl_err.strip(),
                )
        except subprocess.TimeoutExpired:
            # Main still running after warmup — start polling
            while time.monotonic() < deadline:
                # Check if main already exited
                if procs[0].poll() is not None:
                    break

                stats = self._parse_stats(findings_dir)
                if stats.map_density_pct > 0:
                    # Skip the low-coverage early-exit when the harness has
                    # progress predicates injected — by design those gate
                    # most seeds at the top of __AFL_LOOP, so bitmap stays
                    # low for the first minute while AFL learns to satisfy
                    # them. The "harness is broken" interpretation that
                    # justifies an exit at 0.5% only applies to vanilla
                    # harnesses without predicate gating.
                    has_predicates = False
                    try:
                        harness_src_path = (
                            Path(self.config.target.build_dir)
                            / "fuzz_nemesis.c"
                        )
                        txt = harness_src_path.read_text(errors="replace")
                        has_predicates = "/* nemesis: progress predicates" in txt
                    except OSError:
                        pass
                    if (not has_predicates) and stats.map_density_pct < 0.5:
                        self.log.info(
                            "afl.early_exit",
                            reason="low_coverage",
                            map_density=stats.map_density_pct,
                            elapsed_s=stats.duration_seconds,
                        )
                        break
                    if has_predicates and stats.map_density_pct < 0.5:
                        self.log.info(
                            "afl.early_exit_skipped_predicates",
                            map_density=stats.map_density_pct,
                            note="predicates gate bitmap by design",
                        )
                    # Fix 126: don't exit immediately on first crash — continue
                    # fuzzing to find additional distinct bugs. Only log once.
                    if stats.unique_crashes > 0 and not getattr(self, "_crash_logged", False):
                        self.log.info(
                            "afl.crash_found_continuing",
                            crashes=stats.unique_crashes,
                            elapsed_s=stats.duration_seconds,
                            hint="continuing fuzzing for remaining budget",
                        )
                        self._crash_logged = True

                try:
                    procs[0].wait(timeout=poll_interval_s)
                    break  # exited normally
                except subprocess.TimeoutExpired:
                    continue

        # Terminate any remaining instances
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

        # Close log file handles
        try:
            main_stderr.close()
        except Exception:
            pass
        for slog in slave_logs:
            try:
                slog.close()
            except Exception:
                pass

        self.log.info("afl.complete", instances=len(procs))
        return self._parse_stats(findings_dir)

    def _try_capture_seed_crash(
        self,
        binary: Path,
        seeds_dir: Path,
        findings_dir: Path,
        asan_log_dir: Path,
        env: dict,
        timeout_s: int,
    ) -> None:
        """When AFL exits immediately (all seeds crash), run AFL in crash exploration mode.

        Uses `afl-fuzz -C` which is specifically designed for inputs that all crash,
        allowing AFL to fuzz for variations of the crash.
        Alternatively copies seed files to the crashes dir for triage.
        """
        import shutil as _shutil

        seed_files = [f for f in seeds_dir.iterdir() if f.is_file()]
        if not seed_files or not binary.exists():
            return

        # Copy seeds to crashes dir so triage runs on them
        crashes_dir = findings_dir / "main" / "crashes"
        crashes_dir.mkdir(parents=True, exist_ok=True)

        # Write a dummy fuzzer_stats so _parse_stats picks up unique_crashes
        stats_dir = findings_dir / "main"
        stats_dir.mkdir(parents=True, exist_ok=True)

        for i, seed in enumerate(seed_files[:5]):
            dest = crashes_dir / f"id:{i:06d},seed_crash,orig:{seed.name}"
            _shutil.copy2(seed, dest)

        # Write fuzzer_stats with crashes count so pipeline sees crashes
        (stats_dir / "fuzzer_stats").write_text(
            f"unique_crashes       : {min(len(seed_files), 5)}\n"
            f"saved_crashes        : {min(len(seed_files), 5)}\n"
            f"corpus_count         : 0\n"
            f"execs_per_sec        : 0.00\n"
            f"bitmap_cvg           : 0%\n"
            f"stability            : 0.00%\n"
            f"run_time             : 0\n"
            f"fuzzer_pid           : 99999999\n"
        )

        self.log.info(
            "afl.seed_crash_captured",
            seeds_copied=min(len(seed_files), 5),
            crashes_dir=str(crashes_dir),
        )

    def _prevalidate_seeds(self, binary: Path, seeds_dir: Path) -> int:
        """Test each seed against the harness binary, remove seeds that crash.

        Fix 107: When ALL seeds crash the ASAN-instrumented binary, AFL exits
        immediately (rc=1) wasting 60s+ on warmup.  Pre-validating seeds avoids
        this and produces a clear diagnostic.

        Seeds are run standalone (not under AFL): __AFL_LOOP returns 1 once then
        0, so exactly one iteration per run.  __AFL_FUZZ_TESTCASE_BUF falls back
        to reading from stdin when not under AFL.

        Returns count of surviving (non-crashing) seeds.
        """
        seed_files = [
            f for f in seeds_dir.iterdir()
            if f.is_file() and f.stat().st_size > 0 and not f.name.startswith(".")
        ]
        if not seed_files or not binary.exists():
            return len(seed_files)

        env = os.environ.copy()
        # Match AFL's ASAN config so crash behavior is identical, but capture stderr
        # (NOT redirected to log_path) so we can read the sanitizer report directly.
        env["ASAN_OPTIONS"] = (
            "abort_on_error=1:detect_leaks=0:symbolize=1:allocator_may_return_null=1"
        )

        # Sanitizer markers — if any of these appear in stderr, the crash is a REAL
        # bug detected by ASAN/UBSan/LSan, not a harness issue. Such seeds must be
        # preserved: AFL will replay them on first iteration and surface the bug
        # immediately. Removing them (the original Fix 107 behavior) silently
        # discards confirmed bug triggers — exactly the wrong outcome for backtests.
        _SANITIZER_MARKERS = (
            "AddressSanitizer:",
            "ERROR: AddressSanitizer",
            "UndefinedBehaviorSanitizer:",
            "runtime error:",
            "LeakSanitizer:",
            "ThreadSanitizer:",
        )

        removed = 0
        kept_with_bug = 0
        suar_count = 0  # stack-use-after-return false-positive (setjmp+ASAN interaction)
        for seed in seed_files:
            try:
                with open(seed, "rb") as f:
                    result = subprocess.run(
                        [str(binary)],
                        stdin=f,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        env=env,
                    )
                if result.returncode < 0:
                    stderr_text = (
                        result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
                    )
                    if any(m in stderr_text for m in _SANITIZER_MARKERS):
                        # Real sanitizer-detected bug — keep this seed; AFL will
                        # replay it and the triager will produce a finding.
                        kept_with_bug += 1
                        if "stack-use-after-return" in stderr_text:
                            suar_count += 1
                        first_line = next(
                            (ln for ln in stderr_text.splitlines() if "Sanitizer" in ln or "runtime error" in ln),
                            "",
                        )[:140]
                        self.log.info(
                            "seeds.prevalidated.crash_kept",
                            seed=seed.name,
                            sanitizer_marker=first_line,
                        )
                    else:
                        # Crash with no sanitizer report (likely harness bug or OOM)
                        seed.unlink()
                        removed += 1
            except subprocess.TimeoutExpired:
                pass  # timeout = not a crash, keep seed
            except Exception:
                pass  # can't test = keep seed

        surviving = len(seed_files) - removed
        # SUAR-storm auto-detection: if a majority of prevalidated crashes are
        # stack-use-after-return, treat as setjmp+ASAN false-positive class
        # (libpng's png_jmpbuf path is the canonical example). Persisting fake
        # stack frames across AFL persistent-loop iterations makes setjmp/longjmp
        # land on freed fake frames; ASAN flags every seed and AFL aborts at
        # calibration. Disabling the fake-stack mechanism for the AFL run keeps
        # the rest of ASAN's heap/global checks intact.
        self._asan_disable_suar = (
            kept_with_bug >= 3 and suar_count >= max(3, kept_with_bug // 2)
        )
        if self._asan_disable_suar:
            self.log.info(
                "seeds.prevalidated.suar_storm_detected",
                suar_seeds=suar_count,
                total_kept=kept_with_bug,
                action="adding detect_stack_use_after_return=0 to AFL ASAN_OPTIONS",
            )
        if removed > 0 or kept_with_bug > 0:
            self.log.info(
                "seeds.prevalidated",
                removed=removed,
                kept_with_bug=kept_with_bug,
                surviving=surviving,
                fix="Fix 107 (relaxed 2026-05-05)",
            )
        return surviving

    def _seeds_from_file_path(self, file_path: str, func_name: str = "") -> list[Path]:
        """
        Map source file path + function name deterministically to seed directories.

        Uses the filename (e.g. archive_read_support_format_7zip.c) AND the
        function name (e.g. pax_attribute) as seed selectors.  This avoids
        fragile LLM text matching (e.g. "7-Zip" vs "7zip" vs "seven zip").

        Fix 115: Detects encoder/producer role from file path (enc/ subdir) or
        function name (encode/compress/write). When detected, uses encoder_formats
        seeds (plaintext) instead of decoder formats (compressed).

        Returns [] if no match, in which case the caller falls back to
        input_format matching.
        """
        if not file_path:
            return []

        fname = Path(file_path).stem.lower()  # archive_read_support_format_7zip
        s = self.config.seeds

        # Build search tokens: filename stem + function name (if provided)
        search_tokens = [fname]
        if func_name:
            search_tokens.append(func_name.lower())

        # Fix 115: Detect encoder/producer role — check if file is in an encoder subdir
        # or if function name contains encoder-related keywords
        is_encoder = False
        path_parts = Path(file_path).parts
        encoder_subdirs = s.encoder_subdirs if s.encoder_subdirs else [
            "enc", "encode", "compress", "write", "output"
        ]
        for part in path_parts:
            if part.lower() in encoder_subdirs:
                is_encoder = True
                break
        if not is_encoder and func_name:
            fn_lower = func_name.lower()
            if any(kw in fn_lower for kw in ("encode", "compress", "write", "emit", "store")):
                is_encoder = True

        # Fix 115: If encoder role detected and encoder_formats configured, use those
        if is_encoder and s.encoder_formats:
            for fmt_key, seed_path in s.encoder_formats.items():
                if not seed_path:
                    continue
                for token in search_tokens:
                    if fmt_key in token:
                        return [Path(seed_path)]
            # Fallback: use first encoder_formats entry (generic plaintext seeds)
            first_path = next((v for v in s.encoder_formats.values() if v), None)
            if first_path:
                return [Path(first_path)]

        # Use config.seeds.formats dict if available (generic path)
        if s.formats:
            # Phase 1: direct format key match in any token
            for fmt_key, seed_path in s.formats.items():
                if not seed_path:
                    continue
                for token in search_tokens:
                    if fmt_key in token:
                        return [Path(seed_path)]
            # Phase 2: prefix match on filename
            for fmt_key, seed_path in s.formats.items():
                if not seed_path:
                    continue
                if fname.startswith(fmt_key):
                    return [Path(seed_path)]
                fname_prefix = fname.split("_")[0] if "_" in fname else fname
                if len(fname_prefix) >= 3 and fmt_key.startswith(fname_prefix):
                    return [Path(seed_path)]
            # Phase 3: aliases from config + built-in defaults
            builtin_aliases = {
                "7zip": "sevenzip", "iso9660": "iso", "rar": "rar5",
            }
            alias_map = {**builtin_aliases, **s.format_aliases}
            for alias, canonical in alias_map.items():
                if canonical not in s.formats or not s.formats[canonical]:
                    continue
                for token in search_tokens:
                    if alias in token:
                        return [Path(s.formats[canonical])]
            return []

        # Legacy per-field mapping (backward compat)
        mapping: list[tuple[str, str]] = [
            ("format_7zip",    s.sevenzip),
            ("format_lha",     s.lha),
            ("format_cab",     s.cab),
            ("format_rar5",    s.rar5),
            ("format_rar",     s.rar5),   # RAR5 seeds work for both
            ("format_xar",     s.xar),
            ("format_zip",     s.zip),
            ("format_iso9660", s.iso),
            ("filter_uu",      s.uu),
        ]

        for pattern, seed_path in mapping:
            if pattern in fname and seed_path:
                return [Path(seed_path)]

        return []  # no specific match → fall through

    def _generate_seeds(
        self,
        harness: HarnessSpec,
        seeds_dir: Path,
        file_path: str = "",
    ) -> None:
        """Generate seed files from harness spec and configured seed directories.

        Seed selection priority:
        1. file_path-based lookup (deterministic, derived from source filename)
        2. input_format text matching (fallback, fragile but covers edge cases)
        3. Default: pax + all_formats
        """
        import shutil

        seed_dirs_to_copy: list[Path] = []

        # Priority 0: OSS-Fuzz corpus — valid inputs that already pass format checks
        _corpus_cfg = self.config.seeds.oss_fuzz_corpus
        if _corpus_cfg:
            _corpus_dir = Path(_corpus_cfg)

            # Option A: Use pre-computed library-level minset when available (Rebert 2014).
            # afl-cmin reduces the corpus to the minimal set of inputs that together
            # achieve the same edge coverage as the full corpus — quality over quantity.
            # Built lazily on first run and cached; falls back to raw corpus if unavailable.
            _binary = Path(self.config.target.build_dir) / "fuzz_nemesis"
            _minset_dir = (
                self._ensure_corpus_minset(_corpus_dir, _binary)
                if _corpus_dir.exists()
                else None
            )

            # Determine candidate pool: minset (preferred) or raw corpus (fallback)
            if _minset_dir and _minset_dir.exists():
                candidate_pool = [f for f in _minset_dir.iterdir() if f.is_file()]
                pool_label = "minset"
            elif _corpus_dir.exists():
                candidate_pool = [
                    f for f in _corpus_dir.iterdir()
                    if f.is_file() and f.stat().st_size > 0
                ]
                pool_label = "corpus"
            else:
                candidate_pool = []
                pool_label = "none"

            if candidate_pool:
                # Option B: Size-STRATIFIED sampling. Taking the smallest N (the
                # old behaviour, justified by faster AFL calibration) seeded the
                # fuzzer with degenerate/header-only inputs: measured on wavpack,
                # the smallest-50 corpus seeds left the decoder (unpack.c /
                # read_words.c / decorr_utils.c) near 0% line coverage, while a
                # size-diverse small+large sample of the SAME corpus reached
                # ~67%. Sample evenly across the size-sorted pool so AFL starts
                # from seeds that already exercise the deep decode paths (where
                # the bugs are) and mutates from there. 80 (was 50) keeps
                # calibration cheap while widening structural coverage.
                _pool_sorted = sorted(candidate_pool, key=lambda f: f.stat().st_size)
                _k = min(len(_pool_sorted), 80)
                _stride = len(_pool_sorted) / _k if _k else 1
                sample = [_pool_sorted[int(i * _stride)] for i in range(_k)]
                copied = 0
                for seed_file in sample:
                    dest = seeds_dir / f"corpus_{seed_file.name}"
                    try:
                        shutil.copy2(seed_file, dest)
                        copied += 1
                    except OSError:
                        pass
                if copied:
                    self.log.info(
                        "seeds.oss_fuzz_corpus",
                        source=pool_label,
                        pool_size=len(candidate_pool),
                        sampled=copied,
                    )

        # Feature C: LLM-generated targeted seeds (structure-aware)
        slug = harness.target_func or ""
        targeted_dir = (
            Path(self.config.engine.work_dir) / "fuzzing" / "seeds" / slug / "targeted"
        )
        if targeted_dir.exists():
            targeted_files = sorted(targeted_dir.glob("*"))
            if targeted_files:
                copied = 0
                for seed_file in targeted_files:
                    if not seed_file.is_file():
                        continue
                    dest = seeds_dir / f"targeted_{seed_file.name}"
                    try:
                        shutil.copy2(seed_file, dest)
                        copied += 1
                    except OSError:
                        pass
                if copied:
                    self.log.info("seeds.targeted_added", count=copied)

        # Priority 1: deterministic file_path + func_name lookup
        file_path_seeds = self._seeds_from_file_path(file_path, func_name=harness.target_func)
        if file_path_seeds:
            seed_dirs_to_copy = file_path_seeds
            self.log.debug(
                "seeds.from_file_path",
                file_path=file_path,
                dirs=[str(p) for p in seed_dirs_to_copy],
            )
        else:
            # Priority 2: input_format text matching (normalize to remove hyphens/spaces)
            fmt = harness.input_format.lower().replace("-", "").replace(" ", "")

            if "acl" in fmt or fmt.startswith("text"):
                if self.config.seeds.acl_text:
                    seed_dirs_to_copy.append(Path(self.config.seeds.acl_text))
            elif "uu" in fmt or "uuencode" in fmt or "uudecode" in fmt:
                if self.config.seeds.uu:
                    seed_dirs_to_copy.append(Path(self.config.seeds.uu))
            elif "cab" in fmt or "cabinet" in fmt or "mscf" in fmt:
                if self.config.seeds.cab:
                    seed_dirs_to_copy.append(Path(self.config.seeds.cab))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "rar5" in fmt or ("rar" in fmt and "5" in fmt):
                if self.config.seeds.rar5:
                    seed_dirs_to_copy.append(Path(self.config.seeds.rar5))
            elif "rar" in fmt:
                if self.config.seeds.rar5:
                    seed_dirs_to_copy.append(Path(self.config.seeds.rar5))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "7z" in fmt or "7zip" in fmt or "sevenzip" in fmt:
                if self.config.seeds.sevenzip:
                    seed_dirs_to_copy.append(Path(self.config.seeds.sevenzip))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "lha" in fmt or "lzh" in fmt:
                if self.config.seeds.lha:
                    seed_dirs_to_copy.append(Path(self.config.seeds.lha))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "xar" in fmt:
                if self.config.seeds.xar:
                    seed_dirs_to_copy.append(Path(self.config.seeds.xar))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "zip" in fmt:
                if self.config.seeds.zip:
                    seed_dirs_to_copy.append(Path(self.config.seeds.zip))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            elif "iso" in fmt or "zisofs" in fmt or "iso9660" in fmt:
                if self.config.seeds.iso:
                    seed_dirs_to_copy.append(Path(self.config.seeds.iso))
                elif self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))
            else:
                # Priority 3: default
                if self.config.seeds.pax:
                    seed_dirs_to_copy.append(Path(self.config.seeds.pax))
                if self.config.seeds.all_formats:
                    seed_dirs_to_copy.append(Path(self.config.seeds.all_formats))

        for src_dir in seed_dirs_to_copy:
            if not src_dir.exists():
                continue
            copied = 0
            for seed_file in sorted(src_dir.iterdir()):
                if not seed_file.is_file():
                    continue
                dest = seeds_dir / f"prebuilt_{src_dir.name}_{seed_file.name}"
                try:
                    shutil.copy2(seed_file, dest)
                    copied += 1
                    if copied >= 30:  # cap per directory to avoid slow calibration
                        break
                except OSError:
                    pass
            if copied:
                self.log.info("seeds.copied", src=str(src_dir), count=copied)

        # Fix 122: Target-aware seed synthesis from harness input_spec
        if harness.input_spec is not None:
            from nemesis.fuzzing.seed_synthesizer import SeedSynthesizer
            synth_count = SeedSynthesizer.generate(harness.input_spec, seeds_dir)
            if synth_count:
                self.log.info("seeds.synthesized", func=harness.target_func, count=synth_count)

        # 2. Run LLM-provided seed generation commands
        # Fix 126 (relaxed 2026-05-05): allow common seed-engineering tools.
        # Original strict allowlist (echo/printf/dd/python/head/tr) blocked many
        # legitimate LLM-generated synthesis commands like:
        #   for i in $(seq 1 5); do cp tmpl.tif seed_$i.tif; done
        #   convert -size 1x1 xc:white seed.tif
        # Strategy: broader allowlist + denylist on dangerous patterns.
        # Sandbox: cwd=seeds_dir + 30s timeout still apply.
        _ALLOWED_SEED_CMDS = {
            "echo", "printf", "dd", "python3", "python", "head", "tail", "tr",
            "cp", "mv", "ln", "cat", "tee", "mkdir", "touch",
            "convert", "magick", "ffmpeg", "xxd", "base64",
            "seq", "find", "for", "do", "done", "if", "then", "fi", "elif",
            "while", "until", "case", "esac", "bash", "sh",
        }
        # Fix 146: tightened from bare `/root` to ` /root` (with leading
        # space) so XML closing tags `</root>` and similar literal text
        # inside seed payloads no longer trigger the filter. The intent
        # was always to block path arguments to commands; a path argument
        # is preceded by whitespace or a `=`. Same fix for `/home`.
        _DANGEROUS_SUBSTRINGS = (
            " rm ", "\trm ", "\trm\t", "rm -rf", "rm -f /",
            " wget ", " curl ", " nc ", " ncat ",
            " chmod ", " chown ", " sudo ",
            " eval ", " source ",
            "/etc/", "/var/", "/usr/", "/sys/", "/proc/",
            " /root", "=/root",
            " /home", "=/home", " > /", " >> /",
            "shutdown", "reboot", "kill -9", "pkill",
            "$(rm", "`rm", "$(curl", "`curl", "$(wget", "`wget",
        )
        for cmd in harness.seed_commands:
            if cmd.startswith("#"):
                continue
            _tokens = cmd.split()
            _first = _tokens[0] if _tokens else ""
            _base = _first.rsplit("/", 1)[-1]
            if _base not in _ALLOWED_SEED_CMDS:
                self.log.warning("seed.command_blocked", cmd=cmd[:80],
                                 reason=f"'{_base}' not in allowed list")
                continue
            cmd_padded = " " + cmd + " "
            hit = next((p for p in _DANGEROUS_SUBSTRINGS if p in cmd_padded), None)
            if hit:
                self.log.warning("seed.command_blocked", cmd=cmd[:80],
                                 reason=f"dangerous substring: {hit!r}")
                continue
            self.log.debug("seed.generate", cmd=cmd)
            try:
                subprocess.run(
                    cmd, shell=True, capture_output=True,
                    timeout=30, cwd=str(seeds_dir),
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # 3. Minimal fallback if still empty
        if not list(seeds_dir.iterdir()):
            (seeds_dir / "minimal").write_bytes(b"\x00" * 64)
            self.log.warning("seeds.fallback_minimal")

    def _measured_fieldspec(self, seeds_dir: Path) -> dict | None:
        """Derive a fieldspec by probing the instrumented binary, or None.

        Returns None — meaning "fall back to the LLM-synthesised spec" — when
        the feature is off, there is no instrumented binary, there is no seed
        to probe, or probing found nothing measurable. Never raises: this is an
        optimisation over the LLM path, and a failure here must not cost the
        run its seeds.

        The seed chosen is the smallest available. Probing costs one execution
        per byte per probe value, and a small seed that still covers the parser
        yields the same field layout as a large one for a fraction of the work.
        """
        from nemesis.feature_flags import is_enabled as _fflag
        if not _fflag("byte_influence"):
            self.log.info("byte_influence.disabled")
            return None

        # A PROBE binary, not the fuzzing one. The fuzzing harness is AFL++
        # persistent mode with shared-memory test cases and receives no input
        # at all when run outside afl-fuzz, so every probe would return an
        # identical map (measured on cJSON: flat 9 edges for everything).
        # See nemesis/recon/probe_build.py.
        build_dir = Path(self.config.target.build_dir)
        harness_src = build_dir / "fuzz_nemesis.c"
        if not harness_src.exists():
            self.log.debug("byte_influence.no_harness_source", path=str(harness_src))
            return None

        source_root = Path(self.config.target.source_root)
        include_subdir = (
            self.config.target.include_subdir or self.config.target.source_subdir
        )
        includes = [str(source_root)]
        if include_subdir:
            includes.append(str(source_root / include_subdir))

        lib_name = self.config.target.library_name
        library = build_dir / lib_name if lib_name else None

        try:
            from nemesis.recon.probe_build import build_probe_binary
            binary = build_probe_binary(
                harness_source_path=harness_src,
                library_archive=library,
                out_dir=Path(self.workspace) / "probe",
                include_dirs=includes,
                link_libs=self.config.target.link_libs or "",
            )
        except Exception as exc:
            self.log.warning("byte_influence.probe_build_error", error=str(exc))
            return None
        if binary is None:
            return None

        try:
            candidates = [f for f in seeds_dir.iterdir()
                          if f.is_file() and f.stat().st_size > 0]
        except OSError:
            return None
        if not candidates:
            self.log.debug("byte_influence.no_seeds", dir=str(seeds_dir))
            return None
        seed_file = min(candidates, key=lambda f: f.stat().st_size)

        try:
            from nemesis.recon.byte_influence import infer_fieldspec
            spec = infer_fieldspec(
                binary=binary,
                seed=seed_file.read_bytes(),
                work_dir=Path(self.workspace) / "byte_influence",
            )
        except Exception as exc:
            self.log.warning("byte_influence.failed", error=str(exc))
            return None

        if spec:
            self.log.info(
                "byte_influence.measured_spec",
                seed=seed_file.name, fields=len(spec.get("fields", [])),
            )
        return spec

    def _minimize_seeds(self, seeds_dir: Path, binary: Path) -> Path:
        """Run afl-cmin on seed corpus BEFORE fuzzing to remove redundant inputs.

        Keeps only seeds that produce unique coverage paths — dramatically
        reduces AFL calibration time when using large corpora (e.g. OSS-Fuzz 29K+).

        Returns the minimized directory, or the original if afl-cmin unavailable.
        """
        seed_files = [f for f in seeds_dir.iterdir() if f.is_file()]
        if len(seed_files) <= 10 or not binary.exists():
            return seeds_dir  # not worth minimizing small sets

        minimized_dir = seeds_dir.parent / f"{seeds_dir.name}_cmin"
        minimized_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [
                    "afl-cmin",
                    "-i", str(seeds_dir),
                    "-o", str(minimized_dir),
                    "-t", "5000",  # 5s per-input timeout
                    "--", str(binary),
                ],
                capture_output=True, text=True, timeout=120,
                env={
                    **os.environ,
                    "AFL_NO_UI": "1",
                    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1",
                },
            )
            if result.returncode == 0:
                minimized = [f for f in minimized_dir.iterdir() if f.is_file()]
                if minimized:
                    self.log.info(
                        "seeds.cmin_complete",
                        before=len(seed_files),
                        after=len(minimized),
                    )
                    return minimized_dir
                else:
                    self.log.warning("seeds.cmin_empty_result")
            else:
                self.log.debug("seeds.cmin_failed", stderr=result.stderr[:200])
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log.debug("seeds.cmin_unavailable")

        return seeds_dir  # fallback to original

    def _ensure_corpus_minset(self, corpus_dir: Path, binary: Path) -> Path | None:
        """Build (once) or load cached library-level corpus minset.

        Runs afl-cmin against the instrumented binary to reduce the full
        OSS-Fuzz corpus to the minimal set that achieves the same edge coverage.
        Per Rebert 2014: quality beats quantity — 1% more coverage correlates
        with 0.92% more bugs found in a campaign.

        Result cached at workspace/seeds_minset/{library_name}/.
        Cache is invalidated when the corpus file-count or total size changes.

        Returns the minset directory path, or None if unavailable/failed.
        """
        import shutil
        import tempfile

        library_name = self.config.target.name
        minset_dir = self.workspace / "seeds_minset" / library_name
        fp_file = minset_dir.parent / f"{library_name}.fingerprint"

        # Fingerprint: file count + total byte size (fast; avoids hashing 29K files)
        all_files = [f for f in corpus_dir.iterdir() if f.is_file() and f.stat().st_size > 0]
        if not all_files:
            return None
        total_size = sum(f.stat().st_size for f in all_files)
        fp_hash = f"{len(all_files)}:{total_size}"

        # Return cached minset if fingerprint matches
        if fp_file.exists() and minset_dir.exists():
            if fp_file.read_text().strip() == fp_hash:
                existing = [f for f in minset_dir.iterdir() if f.is_file()]
                if existing:
                    self.log.debug(
                        "seeds.minset_cached",
                        library=library_name,
                        size=len(existing),
                    )
                    return minset_dir

        if not binary.exists():
            return None

        # Pre-select inputs for afl-cmin. Two hard-won constraints:
        #
        #  (1) SIZE DIVERSITY, not smallest-first. Taking the smallest N (the old
        #      behaviour) biased the seed set toward degenerate/header-only
        #      inputs. Measured on wavpack: the decoder (unpack.c/read_words.c)
        #      stayed at 0% line coverage with smallest-N seeds, but replaying
        #      the LARGEST corpus files alone hit read_words.c 89% / unpack.c 32%
        #      — the valid, decodable streams are the larger files. So sample
        #      EVENLY across the size-sorted corpus to span small→large.
        #  (2) Bounded total count (1200) and per-file size (2 MiB) so cmin
        #      finishes in budget — 2000 inputs (or multi-MB files) routinely
        #      overran the 300 s budget on slow harnesses (~11-28 execs/s). The
        #      timeout path below salvages a still-diverse set if it overruns.
        _MAX_SEED_BYTES = 2 * 1024 * 1024
        sized = sorted(
            (f for f in all_files if f.stat().st_size <= _MAX_SEED_BYTES),
            key=lambda f: f.stat().st_size,
        )
        if len(sized) > 1200:
            # Evenly-spaced stride across the size-sorted list → small AND large.
            _step = len(sized) / 1200.0
            cmin_input = [sized[int(i * _step)] for i in range(1200)]
        else:
            cmin_input = sized

        self.log.info(
            "seeds.minset_building",
            library=library_name,
            corpus_size=len(all_files),
            cmin_input=len(cmin_input),
        )

        with tempfile.TemporaryDirectory(prefix="nemesis_cmin_") as tmp_in:
            tmp_path = Path(tmp_in)
            for i, f in enumerate(cmin_input):
                try:
                    shutil.copy2(f, tmp_path / f"{i:06d}_{f.name[:40]}")
                except OSError:
                    pass

            if minset_dir.exists():
                shutil.rmtree(minset_dir, ignore_errors=True)
            minset_dir.mkdir(parents=True, exist_ok=True)

            _env = os.environ.copy()
            _env.update({
                "AFL_NO_UI": "1",
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1",
            })

            try:
                result = subprocess.run(
                    [
                        "afl-cmin",
                        "-i", str(tmp_path),
                        "-o", str(minset_dir),
                        "-t", "5000",   # 5 s per-input timeout
                        "--", str(binary),
                    ],
                    capture_output=True, text=True, timeout=300, env=_env,
                )
                minset_files = [f for f in minset_dir.iterdir() if f.is_file()]
                if result.returncode == 0 and minset_files:
                    fp_file.write_text(fp_hash)
                    reduction_pct = (1 - len(minset_files) / len(cmin_input)) * 100
                    self.log.info(
                        "seeds.minset_ready",
                        library=library_name,
                        input_size=len(cmin_input),
                        minset_size=len(minset_files),
                        reduction=f"{reduction_pct:.1f}%",
                    )
                    return minset_dir
                else:
                    self.log.warning(
                        "seeds.minset_build_failed",
                        returncode=result.returncode,
                        stderr=result.stderr[:300],
                    )
                    shutil.rmtree(minset_dir, ignore_errors=True)
            except subprocess.TimeoutExpired:
                # cmin couldn't finish in budget (slow harness). Don't discard
                # everything and fall back to a tiny 50-seed random sample —
                # salvage a bounded, size-ranked slice of the candidate pool so
                # the fuzzer still launches with a diverse, fast-executing seed
                # set. Cache the salvage (write the fingerprint): on a harness
                # this slow, full cmin will time out every time, and the same
                # corpus gets minimized twice per run (profiling seed-prep AND
                # main-fuzz seed-prep) — without caching that is two ~5-min
                # timeouts per run. Caching reuses the salvaged set for the rest
                # of the run (and future runs until the corpus fingerprint
                # changes, which also re-enables a fresh full attempt).
                self.log.warning("seeds.minset_timeout", library=library_name)
                shutil.rmtree(minset_dir, ignore_errors=True)
                minset_dir.mkdir(parents=True, exist_ok=True)
                # Stride across cmin_input (which is size-ordered) so the salvage
                # keeps the large, decoder-covering inputs — NOT cmin_input[:512],
                # which would be the smaller half and leave the decoder at 0%.
                _n = min(len(cmin_input), 512)
                if _n > 0:
                    _s = len(cmin_input) / float(_n)
                    salvage = [cmin_input[int(i * _s)] for i in range(_n)]
                else:
                    salvage = []
                saved = 0
                for i, f in enumerate(salvage):
                    try:
                        shutil.copy2(f, minset_dir / f"{i:06d}_{f.name[:40]}")
                        saved += 1
                    except OSError:
                        pass
                if saved:
                    fp_file.write_text(fp_hash)
                    self.log.warning(
                        "seeds.minset_timeout_salvaged",
                        library=library_name,
                        salvaged=saved,
                    )
                    return minset_dir
                shutil.rmtree(minset_dir, ignore_errors=True)
            except FileNotFoundError:
                self.log.debug("seeds.minset_no_afl_cmin")

        return None

    def _parse_stats(self, findings_dir: Path) -> AFLStats:
        """Parse AFL++ fuzzer_stats file (main instance, fallback to default)."""
        stats_file = findings_dir / "main" / "fuzzer_stats"
        if not stats_file.exists():
            stats_file = findings_dir / "default" / "fuzzer_stats"
        stats = AFLStats()

        if not stats_file.exists():
            return stats

        try:
            content = stats_file.read_text()
            for line in content.splitlines():
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip()

                if key == "execs_per_sec":
                    stats.exec_per_sec = float(val)
                elif key in ("paths_total", "corpus_count"):  # AFL++ 4.x uses corpus_count
                    stats.total_paths = int(val)
                elif key == "saved_crashes":
                    stats.unique_crashes = int(val)
                elif key == "saved_hangs":
                    stats.unique_hangs = int(val)
                elif key == "run_time":
                    stats.duration_seconds = int(val)
                elif key == "bitmap_cvg":
                    stats.map_density_pct = float(val.rstrip("%"))
                elif key == "stability":
                    stats.stability_pct = float(val.rstrip("%"))
        except (ValueError, OSError) as e:
            self.log.warning("stats.parse_error", error=str(e))

        return stats

    def _generate_dictionary(
        self,
        file_path: str,
        dict_dir: Path,
        llm_entries: list[str] | None = None,
    ) -> Path | None:
        """Extract magic bytes and format tokens from source code for AFL dictionary.

        Scans the target source file for string literals used in memcmp, strcmp,
        and magic byte comparisons. Also includes LLM-provided dictionary entries.
        Returns path to dictionary file, or None.
        """
        if not file_path and not llm_entries:
            return None

        # Ablation gate (seed pipeline #4): disabling dict_extract runs AFL with
        # NO dictionary, so the contribution of the auto-extracted tokens to
        # time-to-bug can be measured against a no-dictionary baseline. Default
        # is enabled, so production behaviour is unchanged.
        from nemesis.feature_flags import is_enabled as _fflag
        if not _fflag("dict_extract"):
            self.log.info("dict.disabled")
            return None

        tokens: set[str] = set()

        # Add LLM-provided dictionary entries (magic bytes, key strings)
        if llm_entries:
            tokens.update(llm_entries)

        # Resolve source file from clean source root
        source_root = Path(self.config.target.source_root)
        src_file = source_root / file_path if file_path else None
        content = ""
        if src_file and src_file.exists():
            try:
                content = src_file.read_text(errors="replace")
            except OSError:
                pass

        # Extract string literals from memcmp/strcmp/strncmp calls
        # e.g. memcmp(p, "MSCF", 4) → "MSCF"
        for m in re.finditer(r'(?:memcmp|strcmp|strncmp)\s*\([^,]+,\s*"([^"]+)"', content):
            tokens.add(m.group(1))

        # Extract string literals compared with ==
        # e.g. if (p[0] == 'P' && p[1] == 'K')  — captured as individual chars
        for m in re.finditer(r'==\s*\'(.)\'', content):
            tokens.add(m.group(1))

        # Combine ADJACENT indexed char comparisons into a multi-byte token.
        # e.g. `buf[0]=='G' && buf[1]=='I' && buf[2]=='F'` → "GIF". Many image/
        # container formats (GIF, BM, Ogg "OggS", ELF) are recognised this way
        # rather than via memcmp, and AFL cannot synthesise the full magic from
        # the individual single-char dictionary tokens alone — it needs the
        # contiguous string.
        tokens.update(_combine_adjacent_char_cmps(content))

        # Extract hex byte patterns used in comparisons
        # e.g. p[0] == 0x37 && p[1] == 0x7A → "7z"
        for m in re.finditer(r'==\s*0x([0-9a-fA-F]{2})', content):
            byte_val = int(m.group(1), 16)
            if 0x20 <= byte_val <= 0x7e:  # printable ASCII
                tokens.add(chr(byte_val))

        # Extract string constants assigned to variables
        # e.g. const char magic[] = "7z\xBC\xAF\x27\x1C"
        for m in re.finditer(r'(?:magic|signature|header)\w*\s*(?:\[\])?\s*=\s*"([^"]+)"', content, re.I):
            tokens.add(m.group(1))

        # Auto-extract integer constants from public headers as LE byte sequences.
        # Many binary formats (TIFF tags, PNG chunk IDs, XML node types, ELF section
        # types, ...) are uint16/uint32 values defined as `#define NAME 0xXXXX`. AFL
        # cannot synthesize these via byte-level mutation in a 15-min budget — but
        # given them as dictionary entries, it inserts them into mutations directly,
        # dramatically accelerating discovery of structural bugs.
        try:
            src_root = Path(self.config.target.source_root)
            inc_sub = self.config.target.include_subdir or ""
            inc_dir = src_root / inc_sub if inc_sub else src_root
            # Scan ALL public headers in the include dir (not just harness_includes),
            # because constants like TIFF tag IDs live in tiff.h while the harness
            # only includes tiffio.h (which transitively includes tiff.h). Limited
            # to top-level *.h to avoid pulling in private/internal headers (which
            # tend to be in subdirs like internal/ or have *iop.h / *priv.h names).
            header_files: list[Path] = []
            if inc_dir.is_dir():
                for h in sorted(inc_dir.glob("*.h")):
                    name = h.name.lower()
                    if any(skip in name for skip in ("iop.h", "priv.h", "internal.h", "_p.h")):
                        continue
                    header_files.append(h)
            scanned = 0
            extracted = 0
            for hdr in header_files[:20]:  # cap at 20 headers — enough for any lib
                try:
                    hdr_text = hdr.read_text(errors="replace")
                except OSError:
                    continue
                scanned += 1
                for m in re.finditer(
                    r"^#define\s+([A-Z][A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|\d+)\b",
                    hdr_text,
                    re.MULTILINE,
                ):
                    raw = m.group(2)
                    try:
                        val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
                    except ValueError:
                        continue
                    if val == 0 or val > 0xFFFFFFFF:
                        continue
                    if val <= 0xFFFF:
                        tokens.add(val.to_bytes(2, "little").decode("latin-1"))
                    else:
                        tokens.add(val.to_bytes(4, "little").decode("latin-1"))
                    extracted += 1
            if scanned:
                self.log.debug(
                    "dict.header_scan",
                    headers_scanned=scanned,
                    constants_extracted=extracted,
                )
        except Exception as _exc:
            self.log.debug("dict.header_scan_failed", error=str(_exc))

        # Magic bytes from config (target-specific) or built-in fallback
        basename = Path(file_path).stem.lower() if file_path else ""
        magic_bytes = self.config.target.magic_bytes
        if not magic_bytes:
            # Built-in fallback for backward compat
            magic_bytes = {
                "format_zip": ["PK\x03\x04", "PK\x05\x06"],
                "format_cab": ["MSCF"],
                "format_rar": ["Rar!\x1a\x07\x00"],
                "format_rar5": ["Rar!\x1a\x07\x01\x00"],
                "format_7zip": ["7z\xbc\xaf\x27\x1c"],
                "format_xar": ["xar!"],
                "format_cpio": ["070701", "070702"],
                "format_lha": ["-lh0-", "-lh5-", "-lzs-", "-lz4-"],
                "format_warc": ["WARC/"],
            }
        for pattern, magics in magic_bytes.items():
            if pattern in basename:
                tokens.update(magics)

        if not tokens:
            return None

        dict_dir.mkdir(parents=True, exist_ok=True)
        dict_file = dict_dir / "nemesis.dict"

        lines = []
        for i, token in enumerate(sorted(tokens)):
            # AFL dictionary format: keyword="bytes"
            escaped = ""
            for ch in token:
                if 0x20 <= ord(ch) <= 0x7e and ch != '"' and ch != '\\':
                    escaped += ch
                else:
                    escaped += f"\\x{ord(ch):02x}"
            lines.append(f'token_{i}="{escaped}"')

        dict_file.write_text("\n".join(lines) + "\n")
        self.log.info("dict.generated", tokens=len(tokens), path=str(dict_file))
        return dict_file


class CrashTriager:
    """
    Processes AFL++ crashes: dedup, minimize, classify, reproduce.
    """

    # ASan error type → CWE mapping
    # NOTE: Order matters — more specific patterns must come BEFORE generic ones.
    ASAN_CWE_MAP: dict[str, CWE] = {
        # UBSan — undefined behavior (checked FIRST for specificity)
        "applying non-zero offset to null pointer": CWE.UNDEFINED_BEHAVIOR,
        "applying non-zero offset": CWE.UNDEFINED_BEHAVIOR,
        "pointer index expression": CWE.UNDEFINED_BEHAVIOR,
        "shift exponent": CWE.UNDEFINED_BEHAVIOR,
        "load of misaligned address": CWE.UNDEFINED_BEHAVIOR,
        # ASan — memory corruption (HIGH)
        "heap-buffer-overflow": CWE.HEAP_OVERFLOW,
        "global-buffer-overflow": CWE.HEAP_OVERFLOW,
        "container-overflow": CWE.HEAP_OVERFLOW,
        "heap-buffer-underflow": CWE.BUFFER_UNDERWRITE,
        "stack-buffer-overflow": CWE.STACK_OVERFLOW,
        "stack-buffer-underflow": CWE.BUFFER_UNDERWRITE,
        "heap-use-after-free": CWE.USE_AFTER_FREE,
        "stack-use-after-return": CWE.USE_AFTER_FREE,
        "stack-use-after-scope": CWE.STACK_USE_AFTER_SCOPE,
        "use-after-poison": CWE.USE_AFTER_FREE,
        "out-of-bounds-write": CWE.OUT_OF_BOUNDS_WRITE,
        "double-free": CWE.DOUBLE_FREE,
        "attempting free on address which was not malloc": CWE.DOUBLE_FREE,
        # ASan — memory reads (MEDIUM)
        "out-of-bounds-read": CWE.OUT_OF_BOUNDS_READ,
        "SEGV on unknown address": CWE.NULL_DEREF,
        "null pointer": CWE.NULL_DEREF,
        # ASan — resource exhaustion (MEDIUM)
        "allocation-size-too-big": CWE.RESOURCE_CONSUMPTION,
        "requested allocation size": CWE.RESOURCE_CONSUMPTION,
        "negative-size-param": CWE.RESOURCE_CONSUMPTION,
        # UBSan patterns
        "signed integer overflow": CWE.INTEGER_OVERFLOW,
        "unsigned integer overflow": CWE.INTEGER_OVERFLOW,
        "integer overflow": CWE.INTEGER_OVERFLOW,
        "division by zero": CWE.DIVIDE_BY_ZERO,
        "runtime error: division": CWE.DIVIDE_BY_ZERO,
        # MSan
        "use-of-uninitialized-value": CWE.UNINITIALIZED_VALUE,
        "uninitialized value": CWE.UNINITIALIZED_VALUE,
        # TSan (Fix 150) — ThreadSanitizer reports for data races and lock-order issues
        "data race": CWE.RACE_CONDITION,
        "data race on": CWE.RACE_CONDITION,
        "lock-order-inversion": CWE.RACE_CONDITION,
        "thread leak": CWE.RACE_CONDITION,
        "double lock of a mutex": CWE.RACE_CONDITION,
        "unlock of an unlocked mutex": CWE.RACE_CONDITION,
        # Format string
        "format string": CWE.FORMAT_STRING,
    }

    # CWE → Severity mapping
    CWE_SEVERITY: dict[CWE, Severity] = {
        CWE.HEAP_OVERFLOW: Severity.HIGH,
        CWE.STACK_OVERFLOW: Severity.HIGH,
        CWE.USE_AFTER_FREE: Severity.HIGH,
        CWE.OUT_OF_BOUNDS_WRITE: Severity.HIGH,
        CWE.DOUBLE_FREE: Severity.HIGH,
        CWE.BUFFER_UNDERWRITE: Severity.HIGH,
        CWE.STACK_USE_AFTER_SCOPE: Severity.HIGH,
        CWE.FORMAT_STRING: Severity.HIGH,
        CWE.NULL_DEREF: Severity.MEDIUM,
        CWE.INTEGER_OVERFLOW: Severity.MEDIUM,
        CWE.OUT_OF_BOUNDS_READ: Severity.MEDIUM,
        CWE.RESOURCE_CONSUMPTION: Severity.MEDIUM,
        CWE.UNINITIALIZED_VALUE: Severity.MEDIUM,
        CWE.DIVIDE_BY_ZERO: Severity.MEDIUM,
        CWE.UNDEFINED_BEHAVIOR: Severity.MEDIUM,
        CWE.RACE_CONDITION: Severity.MEDIUM,  # Fix 150: TSan-detected data race
        CWE.MEMORY_LEAK: Severity.LOW,
    }

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("fuzzing.triager")
        self.crashes_dir = Path(config.engine.work_dir) / "fuzzing" / "findings" / "default" / "crashes"
        # Set by SymbolicStage after build_unpatched_debug() succeeds
        self.unpatched_binary: Path | None = None
        # Set by FuzzingStage.run() to the per-target asan_logs dir (Fix 85)
        self.asan_log_dir: Path | None = None
        # Multi-build verification binaries (set by pipeline/symbolic stage)
        self.ubsan_binary: Path | None = None   # UBSan debug binary
        self.clean_binary: Path | None = None    # No-sanitizer binary (repro_binary)

    def triage_all(self) -> list[CrashReport]:
        """Process all crash files in the findings directory.

        AFL_AUTORESUME archives old crashes into crashes.<timestamp>/ dirs
        and creates a fresh crashes/ dir.  We collect from ALL of them.
        """
        reports = []

        if not self.crashes_dir.exists():
            return reports

        # Collect crashes from crashes/ AND any crashes.<timestamp>/ dirs
        # created by AFL_AUTORESUME — for EVERY AFL instance, not just main.
        # AFL secondaries (-S slave_N) write to their own findings/slave_N/crashes;
        # scanning only findings/main/crashes silently dropped bugs found solely by
        # a secondary (which run different schedules and often find unique crashes).
        parent = self.crashes_dir.parent          # findings/<instance>  (usually main)
        findings_root = parent.parent             # findings/
        all_crash_dirs = [self.crashes_dir]

        instance_dirs = [parent]
        if findings_root.is_dir():
            for inst in sorted(findings_root.iterdir()):
                if not inst.is_dir() or inst == parent:
                    continue
                if inst.name == "main" or inst.name.startswith(("slave_", "secondary")):
                    instance_dirs.append(inst)

        for inst in instance_dirs:
            cdir = inst / "crashes"
            if cdir.is_dir() and cdir != self.crashes_dir:
                all_crash_dirs.append(cdir)
            # archived crashes.<timestamp>/ dirs within this instance
            for d in inst.iterdir():
                if d.is_dir() and d.name.startswith("crashes."):
                    all_crash_dirs.append(d)

        # Optional: run afl-cmin to reduce crash corpus before triaging (main only)
        effective_dir = self._run_afl_cmin(self.crashes_dir)

        crash_files = sorted(effective_dir.glob("id:*"))
        # Also gather from archived + secondary-instance crash dirs
        for d in all_crash_dirs:
            if d != self.crashes_dir:
                crash_files.extend(sorted(d.glob("id:*")))
        self.log.info("triage.start", crash_count=len(crash_files),
                      instances=len(instance_dirs), crash_dirs=len(all_crash_dirs))

        # Reproduce-on-latest-upstream: resolved once per run (read-only git),
        # stamped onto every finding so "reproduces now" can be qualified against
        # the upstream tip.
        upstream = None
        if getattr(self.config.target, "upstream_check", False) and crash_files:
            upstream = self._resolve_upstream_status()

        seen_keys: set[str] = set()

        for crash_file in crash_files:
            if crash_file.name == "README.txt":
                continue

            report = self._analyze_crash(crash_file)
            if report is None:
                continue

            # Dedup key = signal (from filename) + top-3 stack frame hash.
            # Using signal prevents over-deduplication across different bug classes
            # (e.g. SIGSEGV vs SIGABRT) even when stack hashes collide.
            sig = self._extract_signal(crash_file.name)
            dedup_key = f"{sig}:{self._hash_trace(report.stack_trace[:3])}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Gate: verify crash reproduces in a single-shot (non-persistent)
            # run of the debug binary.  AFL persistent mode can generate
            # spurious signals (SIGPIPE sig:13, SIGILL sig:04) due to
            # state accumulation across thousands of loop iterations — these
            # never reproduce standalone and must be discarded.
            if not self._verify_crash_standalone(crash_file):
                self.log.info(
                    "triage.crash_false_positive",
                    file=crash_file.name,
                    signal=sig,
                    reason="does not reproduce outside AFL persistent mode",
                )
                continue

            # Try to reproduce in the application binary
            report.app_repro = self._app_repro_status(crash_file)

            # Unpatched verification: does this crash exist WITHOUT the LLM patch?
            if self.unpatched_binary and self.unpatched_binary.exists():
                crashes_unpatched = self._verify_unpatched(crash_file)
                report.patch_induced = not crashes_unpatched
                self.log.info(
                    "triage.unpatched_verification",
                    file=crash_file.name,
                    crashes_unpatched=crashes_unpatched,
                    patch_induced=report.patch_induced,
                    verdict="REAL BUG" if not report.patch_induced else "patch-induced",
                )

            if upstream is not None:
                report.upstream_status = upstream.status
                report.upstream_detail = upstream.detail

            reports.append(report)
            self.log.info(
                "triage.crash",
                file=crash_file.name,
                location=report.crash_location,
                cwe=report.cwe.value,
                severity=report.severity.value,
                reproduces=report.reproduces_in_app,
                app_repro=report.app_repro.value,
            )

            # Delta-debug the confirmed crash to a minimal same-site reproducer
            # (populates report.minimized_input). Best-effort — never lose a
            # finding to a minimization error.
            if getattr(self.config.target, "minimize_crashes", False):
                try:
                    self.minimize_crash(crash_file, report)
                except Exception as exc:
                    self.log.warning(
                        "triage.minimize_failed", file=crash_file.name, error=str(exc)
                    )

        self.log.info("triage.complete", unique_crashes=len(reports))
        return reports

    def triage_hangs(self) -> list[CrashReport]:
        """Collect unique hangs from AFL hangs/ directory.

        Hangs = inputs that exceed AFL timeout (default 1s).
        Classified as CWE-400 (Uncontrolled Resource Consumption) / DoS.

        Each candidate is verified with a single-shot (non-persistent) run of
        the debug binary to filter out AFL persistent-mode false positives.
        Only inputs that actually hang standalone are reported.
        """
        hangs_dir = self.crashes_dir.parent / "hangs"
        if not hangs_dir.exists():
            return []

        hang_files = sorted(hangs_dir.glob("id:*"))
        if not hang_files:
            return []

        self.log.info("triage.hangs_start", hang_count=len(hang_files))
        reports: list[CrashReport] = []
        seen_keys: set[str] = set()

        for hang_file in hang_files:
            if hang_file.name == "README.txt":
                continue

            # Dedup by MD5 of first 256 bytes (same input = same hang)
            try:
                content = hang_file.read_bytes()
                import hashlib as _hashlib
                dedup_key = _hashlib.md5(content[:256]).hexdigest()
            except OSError:
                continue
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Verify hang reproduces outside AFL persistent mode.
            # AFL persistent mode accumulates state across iterations, causing
            # spurious timeouts that don't reproduce in a single-shot run.
            if not self._verify_hang_standalone(hang_file):
                self.log.info(
                    "triage.hang_false_positive",
                    file=hang_file.name,
                    reason="does not hang outside AFL persistent mode",
                )
                continue

            report = CrashReport(
                input_file=str(hang_file),
                crash_location="hang (timeout)",
                stack_trace=[],
                cwe=CWE.RESOURCE_CONSUMPTION,
                severity=Severity.MEDIUM,
                patch_induced=False,
                asan_output=(
                    "AFL++ detected an input that causes the target to hang "
                    "(exceed timeout). Potential denial-of-service via "
                    "algorithmic complexity or infinite loop."
                ),
            )

            # Fix 104: Verify hang reproduces in the real application binary.
            # If the app binary (xmllint, bsdtar) does NOT hang, the hang is
            # likely a harness I/O bug (e.g. pipe() deadlock), not a library bug.
            # Only drop the hang when it was actually TESTED and failed to
            # reproduce (NOT_REPRODUCED). NOT_TESTABLE (fuzz-target-only libs with
            # no app wrapper) can't disprove the hang, so keep it.
            report.app_repro = self._app_repro_status(Path(report.input_file))
            if report.app_repro == AppReproStatus.NOT_REPRODUCED:
                self.log.info(
                    "triage.hang_harness_only",
                    file=hang_file.name,
                    reason="hang does not reproduce in application binary — likely harness I/O bug",
                )
                continue  # Skip: harness-induced hang, not a library bug

            reports.append(report)
            self.log.info("triage.hang_confirmed", file=hang_file.name)

        self.log.info("triage.hangs_complete", unique_hangs=len(reports))
        return reports

    def triage_leaks(
        self,
        sample_size: int = 30,
        func_name: str | None = None,
    ) -> list[CrashReport]:
        """Fix 136: post-fuzz leak detection (CWE-401).

        LSan can't run during AFL persistent mode — there is no clean exit on
        which to enumerate live allocations. Instead, after AFL completes we
        sample inputs from the AFL queue and replay them against the
        single-shot debug binary with ``ASAN_OPTIONS=detect_leaks=1``. Any
        ``LeakSanitizer:`` report on stderr becomes a CWE-401 finding.

        Sampled inputs (not crashes) are intentional — leaks usually surface
        on benign inputs that happen to take a path that forgets a free.

        Fix 137 — reference-harness verification: when a saved reference
        harness exists at ``config/targets/<target>/harnesses/<func>.c`` (the
        high-coverage version Nemesis already validated on a prior run), each
        raw leak finding is replayed against a fresh build of that harness.
        Reports that don't reproduce there are dropped as harness-induced
        FPs (the LLM had an early-return cleanup bug on this run, not a real
        library leak). Falls back to current behaviour when no saved harness
        is available.
        """
        if self.unpatched_binary is None or not self.unpatched_binary.exists():
            self.log.info("triage.leak_skipped", reason="no unpatched_binary available")
            return []

        # AFL stores interesting inputs that exercised new paths in queue/.
        queue_dir = self.crashes_dir.parent / "queue"
        if not queue_dir.exists():
            # AFL_AUTORESUME may have moved it under main/queue or default/queue
            for cand in (self.crashes_dir.parent / "main" / "queue",
                         self.crashes_dir.parent / "default" / "queue"):
                if cand.exists():
                    queue_dir = cand
                    break
        if not queue_dir.exists():
            self.log.info("triage.leak_skipped", reason="no AFL queue dir found")
            return []

        queue_files = sorted(queue_dir.glob("id:*"))
        if not queue_files:
            return []
        if sample_size > 0 and len(queue_files) > sample_size:
            # Evenly-spaced sample across the queue — favours diverse paths
            # over the front of the queue (which is dominated by initial seeds).
            step = len(queue_files) / sample_size
            queue_files = [queue_files[int(i * step)] for i in range(sample_size)]

        self.log.info("triage.leak_start", samples=len(queue_files))
        reports: list[CrashReport] = []
        seen_keys: set[str] = set()

        # exitcode=23 is the LSan default — keeps it distinct from ASAN's 1.
        # abort_on_error=0: we want LSan to print its report on clean exit, not
        # SIGABRT before the leak summary.
        env = {
            **os.environ,
            "ASAN_OPTIONS": (
                "detect_leaks=1:abort_on_error=0:exitcode=23:"
                "allocator_may_return_null=1:print_summary=1:symbolize=1"
            ),
            "LSAN_OPTIONS": "report_objects=1:print_suppressions=0",
        }

        for q_file in queue_files:
            try:
                with open(q_file, "rb") as inp:
                    result = subprocess.run(
                        [str(self.unpatched_binary)],
                        stdin=inp,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=15,
                        env=env,
                    )
            except subprocess.TimeoutExpired:
                continue
            except Exception as exc:  # noqa: BLE001 — best-effort triage
                self.log.debug("triage.leak_run_error", file=q_file.name, error=str(exc))
                continue

            stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
            if "LeakSanitizer" not in stderr_text or "leak" not in stderr_text.lower():
                continue

            stack = self._extract_lsan_stack(stderr_text)
            dedup_key = self._hash_trace(stack[:3]) if stack else q_file.name
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            crash_loc = stack[0] if stack else "leak (unknown frame)"
            # Persist forensic artefacts next to the AFL findings dir so leaks
            # remain inspectable after the debug binary gets rebuilt for the
            # next target. Three files per leak: full LSan stderr, harness
            # source snapshot, and a tiny manifest.json.
            try:
                leaks_dir = self.crashes_dir.parent / "leaks"
                leaks_dir.mkdir(parents=True, exist_ok=True)
                stem = q_file.name.replace(":", "_").replace(",", "_")[:80]
                lsan_path = leaks_dir / f"{stem}.lsan.log"
                lsan_path.write_text(stderr_text, encoding="utf-8")
                # Snapshot the harness source that produced this leak (current
                # build_dir/fuzz_nemesis.c) — gets overwritten by the next target.
                harness_src = Path(self.config.target.build_dir) / "fuzz_nemesis.c"
                if harness_src.exists():
                    (leaks_dir / f"{stem}.harness.c").write_text(
                        harness_src.read_text(encoding="utf-8", errors="replace"),
                        encoding="utf-8",
                    )
                manifest = {
                    "input": str(q_file),
                    "binary_at_capture": str(self.unpatched_binary),
                    "crash_location": crash_loc,
                    "stack_trace": stack,
                    "lsan_log": str(lsan_path),
                    "harness_snapshot": str(leaks_dir / f"{stem}.harness.c"),
                    "asan_options": env.get("ASAN_OPTIONS", ""),
                    "lsan_options": env.get("LSAN_OPTIONS", ""),
                }
                import json as _json
                (leaks_dir / f"{stem}.manifest.json").write_text(
                    _json.dumps(manifest, indent=2), encoding="utf-8"
                )
                self.log.info("triage.leak_artifacts_saved", dir=str(leaks_dir), stem=stem)
            except Exception as exc:  # noqa: BLE001 — persistence is best-effort
                self.log.debug("triage.leak_persist_failed", error=str(exc))

            reports.append(CrashReport(
                input_file=str(q_file),
                crash_location=crash_loc,
                stack_trace=stack,
                cwe=CWE.MEMORY_LEAK,
                severity=Severity.LOW,
                detected_by=SanitizerClass.ASAN,
                asan_output=stderr_text[:4096],
                patch_induced=False,
            ))
            self.log.info(
                "triage.leak_found",
                file=q_file.name,
                location=crash_loc,
                returncode=result.returncode,
            )

        # Fix 137: reference-harness verification. Drop any leak that doesn't
        # reproduce against the saved high-coverage harness — those are LLM
        # harness bugs (e.g. an early `continue` that skipped DestroyInstance),
        # not real library leaks.
        if reports:
            # Auto-derive func_name from crashes_dir if caller didn't provide.
            if not func_name:
                try:
                    p = self.crashes_dir.parent
                    if p.name == "main":
                        p = p.parent
                    func_name = p.name
                except Exception:
                    func_name = None
            if func_name:
                ref_bin = self._build_reference_harness(func_name)
                if ref_bin is not None:
                    verified: list[CrashReport] = []
                    for r in reports:
                        input_path = Path(r.input_file)
                        if not input_path.exists():
                            verified.append(r)  # can't verify → keep
                            continue
                        try:
                            with open(input_path, "rb") as inp:
                                ref_result = subprocess.run(
                                    [str(ref_bin)],
                                    stdin=inp,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE,
                                    timeout=15,
                                    env=env,
                                )
                            ref_stderr = (ref_result.stderr or b"").decode("utf-8", errors="replace")
                            if "LeakSanitizer" in ref_stderr:
                                verified.append(r)
                                self.log.info(
                                    "triage.leak_verified_real",
                                    file=input_path.name,
                                    func=func_name,
                                )
                            else:
                                self.log.info(
                                    "triage.leak_filtered_fp",
                                    file=input_path.name,
                                    func=func_name,
                                    reason="reference harness did not reproduce leak",
                                )
                        except subprocess.TimeoutExpired:
                            verified.append(r)  # ambiguous, keep
                        except Exception as exc:  # noqa: BLE001
                            self.log.debug("triage.leak_verify_error", error=str(exc))
                            verified.append(r)
                    if len(verified) != len(reports):
                        self.log.info(
                            "triage.leak_verification_summary",
                            kept=len(verified),
                            dropped=len(reports) - len(verified),
                            func=func_name,
                        )
                    reports = verified
                else:
                    self.log.debug(
                        "triage.leak_ref_unavailable",
                        func=func_name,
                        hint="no saved harness — first-run leak findings registered as-is",
                    )

        self.log.info("triage.leaks_complete", unique_leaks=len(reports))
        return reports

    def _build_reference_harness(self, func_name: str) -> Path | None:
        """Fix 137: compile the saved reference harness for ``func_name``.

        The reference harness lives at
        ``<repo_root>/config/targets/<target>/harnesses/<func>.c``. Nemesis
        only writes it when a previous run achieved high source-line
        coverage, so it represents a known-good version of the harness with
        proper cleanup paths. Used by ``triage_leaks`` to filter out
        harness-induced LSan reports.

        Returns the compiled binary path, or ``None`` when:
          - No saved harness exists yet (first run for this target).
          - The compile fails (config drift, missing headers, etc).
          - The unpatched debug library hasn't been built (no link target).

        On any failure the caller falls back to registering leaks as-is.
        """
        target_name = self.config.target.name
        if not target_name or not func_name:
            return None
        # nemesis/fuzzing/__init__.py → repo root is two parents up
        repo_root = Path(__file__).parent.parent.parent
        saved = repo_root / "config" / "targets" / target_name / "harnesses" / f"{func_name}.c"
        if not saved.exists():
            return None

        # Mirror of _AFL_STUB_HEADER in nemesis/symbolic/__init__.py — keeps
        # this module independent of the symbolic stage at import time.
        afl_stub = (
            "#include <stdio.h>\n"
            "#include <stdint.h>\n"
            "static uint8_t __afl_stub_buf[1 << 20];\n"
            "static int     __afl_stub_len = 0;\n"
            "static int     __afl_stub_called = 0;\n"
            "#define __AFL_FUZZ_INIT()\n"
            "#define __AFL_INIT()\n"
            "#define __AFL_LOOP(n) (__afl_stub_called++ == 0 ? \\\n"
            "    (__afl_stub_len = (int)fread(__afl_stub_buf, 1, sizeof(__afl_stub_buf), stdin), 1) : 0)\n"
            "#define __AFL_FUZZ_TESTCASE_LEN  __afl_stub_len\n"
            "#define __AFL_FUZZ_TESTCASE_BUF  __afl_stub_buf\n"
        )

        out_dir = self.crashes_dir.parent / "leaks"
        out_dir.mkdir(parents=True, exist_ok=True)
        src_path = out_dir / "reference_harness.c"
        try:
            src_path.write_text(afl_stub + saved.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            self.log.debug("triage.leak_ref_write_failed", error=str(exc))
            return None

        bin_path = out_dir / "reference_harness"

        source_root = Path(self.config.target.source_root)
        include_subdir = (
            self.config.target.include_subdir or self.config.target.source_subdir
        )
        include_path = source_root / include_subdir if include_subdir else source_root

        debug_dir = Path(self.config.target.debug_build_dir)
        link_libs = self.config.target.link_libs or ""
        # Resolve "-L." against debug_dir so the linker finds the right .a archives
        # regardless of subprocess cwd.
        link_libs = link_libs.replace("-L.", f"-L{debug_dir}")

        warn_flags = (
            "-Wno-deprecated-declarations -Wno-unused-variable "
            "-Wno-unused-parameter -Wno-uninitialized "
            "-Wno-format-security -Wno-unused-const-variable -Wno-implicit-function-declaration"
        )
        cmd = (
            f"clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer "
            f"{warn_flags} "
            f"-I{include_path} "
            f"{src_path} "
            f"{link_libs} "
            f"-o {bin_path} 2>&1"
        )
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60,
                cwd=str(debug_dir),
            )
        except Exception as exc:  # noqa: BLE001
            self.log.debug("triage.leak_ref_build_error", error=str(exc))
            return None

        if result.returncode != 0 or not bin_path.exists():
            self.log.debug(
                "triage.leak_ref_build_failed",
                stdout=(result.stdout or "")[-300:],
            )
            return None

        self.log.info("triage.leak_ref_built", binary=str(bin_path), func=func_name)
        return bin_path

    @staticmethod
    def _extract_lsan_stack(stderr_text: str) -> list[str]:
        """Pull the first leak's stack frames from a LeakSanitizer report."""
        frames: list[str] = []
        in_leak = False
        for line in stderr_text.splitlines():
            if "Direct leak of" in line or "Indirect leak of" in line:
                if frames:
                    break  # only first leak
                in_leak = True
                continue
            if in_leak:
                m = re.match(r"\s*#\d+\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(.+?)(?:\s+\(|$)", line)
                if m:
                    frames.append(m.group(1).strip())
                elif frames and not line.strip():
                    break
        return frames

    def _verify_hang_standalone(self, hang_file: Path, timeout_s: int = 15) -> bool:
        """Verify a hang reproduces outside AFL persistent mode.

        Runs the non-persistent debug binary with the hang input. If it
        completes within timeout_s seconds it is an AFL persistent-mode
        artifact (false positive). If it actually times out, it is a real hang.

        Returns True if the hang is confirmed real, False otherwise.
        """
        if self.unpatched_binary is None or not self.unpatched_binary.exists():
            # No debug binary available — skip verification, trust AFL result.
            self.log.warning(
                "triage.hang_verify_skipped",
                reason="no unpatched_binary available",
            )
            return True

        import subprocess as _subprocess

        try:
            with open(hang_file, "rb") as inp:
                # Fix 126: abort_on_error=1 so ASAN crash != false hang
                _subprocess.run(
                    [str(self.unpatched_binary)],
                    stdin=inp,
                    stdout=_subprocess.DEVNULL,
                    stderr=_subprocess.DEVNULL,
                    timeout=timeout_s,
                    env={
                        **os.environ,
                        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
                        "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
                    },
                )
            # Completed within timeout → not a real hang
            return False
        except _subprocess.TimeoutExpired:
            # Actual hang confirmed
            return True
        except Exception as exc:
            self.log.warning("triage.hang_verify_error", error=str(exc))
            return True  # uncertain — include to avoid missing real bugs

    # Return codes that indicate a child-process signal rather than a memory bug.
    # 128+N = process killed by signal N (shell convention).
    # Negative values = Python's returncode for signal-killed processes.
    _CHILD_SIGNAL_RETURNCODES: frozenset[int] = frozenset(
        {
            141, -13,  # SIGPIPE  (13) — broken pipe, spawned child exited
            132,  -4,  # SIGILL   ( 4) — illegal instruction, persistent-mode state
            135,  -7,  # SIGBUS   ( 7) — bus error, misaligned after state corruption
        }
    )

    def _verify_crash_standalone(self, crash_file: Path, timeout_s: int = 15) -> bool:
        """Verify a crash reproduces outside AFL persistent mode.

        AFL persistent mode (``__AFL_LOOP``) accumulates parser state across
        thousands of iterations, causing spurious signals that never reproduce
        in a single-shot run:
          - sig:13 (SIGPIPE)  — AFL pipe broken after many iterations
          - sig:04 (SIGILL)   — illegal instruction from corrupted state
          - sig:07 (SIGBUS)   — misaligned access after state corruption

        Runs the non-persistent debug binary with the crash input (stdin).
        Any non-zero exit code (ASAN abort, SIGSEGV, SIGABRT, …) confirms
        the crash is real.  Exit 0 = AFL persistent-mode artifact → discard.
        SIGPIPE/SIGILL/SIGBUS exit codes are also treated as artifacts.

        Falls back to True (include) when no debug binary is available,
        EXCEPT for sig:13 and sig:04 which are never real memory-safety bugs.
        """
        # Fast-path: SIGPIPE is always an AFL persistent-mode artifact.
        #
        # SIGILL (sig:04) used to be on this fast-discard list under the same
        # rationale, but `-fno-sanitize-recover=undefined` makes UBSan emit
        # `__builtin_trap()` (= SIGILL) for every halt-on-error diagnostic.
        # Discarding sig:04 unconditionally was throwing away every real
        # UBSan-detected bug (integer overflow, divide-by-zero, ...). We now
        # let SIGILL fall through to standalone verification — if it does not
        # reproduce, it gets filtered there.
        sig = self._extract_signal(crash_file.name)
        # Fix 132: compare as int to handle zero-padded signals (e.g. "04" vs "4")
        try:
            sig_int = int(sig)
        except ValueError:
            sig_int = -1
        if sig_int == 13:
            self.log.info(
                "triage.crash_signal_artifact",
                file=crash_file.name,
                signal=sig,
                reason="SIGPIPE is always an AFL persistent-mode artifact",
            )
            return False

        if self.unpatched_binary is None or not self.unpatched_binary.exists():
            self.log.warning(
                "triage.crash_verify_skipped",
                file=crash_file.name,
                reason="no unpatched_binary available",
            )
            return True

        # Try the debug binary first (richer ASAN/UBSan diagnostics, symbolised
        # stack traces). Fall back to the AFL build's binary_snapshot if the
        # debug binary returns clean — sometimes the debug build's `-O1`
        # optimisation elides the buggy code path that the AFL build
        # (compiled with default -O) preserves. We saw this on
        # libtiff CVE-2022-3970: AFL caught a heap-buffer-overflow in
        # TIFFReadRGBATileExt that the -O1 debug build silently optimised
        # away.
        afl_snapshot_binary = (
            crash_file.parent.parent.parent / "binary_snapshot"
        )
        candidate_binaries = [self.unpatched_binary]
        if afl_snapshot_binary.exists() and afl_snapshot_binary != self.unpatched_binary:
            candidate_binaries.append(afl_snapshot_binary)

        try:
            for binary in candidate_binaries:
                with open(crash_file, "rb") as inp:
                    result = subprocess.run(
                        [str(binary)],
                        stdin=inp,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=timeout_s,
                        env={
                            **os.environ,
                            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
                            "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
                        },
                    )
                stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
                has_sanitizer_report = (
                    "AddressSanitizer" in stderr_text
                    or "LeakSanitizer" in stderr_text
                    or "UndefinedBehaviorSanitizer" in stderr_text
                    or "ERROR: " in stderr_text
                )
                if has_sanitizer_report:
                    self.log.info(
                        "triage.crash_sanitizer_confirmed",
                        file=crash_file.name,
                        returncode=result.returncode,
                        binary_used=binary.name,
                    )
                    return True
                if (
                    result.returncode in self._CHILD_SIGNAL_RETURNCODES
                    and binary == candidate_binaries[-1]
                ):
                    # Last binary returned a child-signal artifact and no
                    # earlier binary confirmed — drop the crash.
                    self.log.info(
                        "triage.crash_signal_skip",
                        file=crash_file.name,
                        returncode=result.returncode,
                        reason="SIGPIPE/SIGILL/SIGBUS from spawned subprocess",
                    )
                    return False
                if result.returncode != 0:
                    return True  # real crash (ASAN, SIGABRT/6, SIGSEGV/11, …)
                # rc == 0 on this binary; try next candidate (-O1 elision case)
            return False  # all candidates returned 0 cleanly = false positive
        except subprocess.TimeoutExpired:
            return True  # actual hang = real bug
        except Exception as exc:
            self.log.warning("triage.crash_verify_error", error=str(exc))
            return True  # uncertain — include to avoid missing real bugs

    def _run_input(self, data: bytes, timeout_s: int = 10) -> tuple[int, str]:
        """Run the single-shot debug binary on raw bytes via stdin.

        Returns (returncode, stderr_text). Used by crash minimization to fingerprint
        each candidate. Mirrors the env of _verify_crash_standalone (symbolized so
        the fault frame is recoverable).
        """
        if self.unpatched_binary is None:
            raise RuntimeError("no debug binary available for minimization")
        result = subprocess.run(
            [str(self.unpatched_binary)],
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            env={
                **os.environ,
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=1",
                "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
            },
        )
        return result.returncode, (result.stderr or b"").decode("utf-8", errors="replace")

    @classmethod
    def _crash_signature(cls, returncode: int, stderr: str) -> tuple[str, str] | None:
        """Fingerprint a crash by (sanitizer error class, first app fault frame).

        Returns None when the input did NOT crash (clean exit 0). The fault frame is
        reduced to ``basename:line`` so path prefixes don't perturb equality. Used to
        keep delta-debugging anchored to the SAME bug (no crash-drift to another site).
        """
        if returncode == 0:
            return None
        m = re.search(
            r"(?:AddressSanitizer|MemorySanitizer|ThreadSanitizer|"
            r"UndefinedBehaviorSanitizer):?\s*([A-Za-z0-9_-]+)",
            stderr,
        )
        if not m:
            m = re.search(r"runtime error:\s*(.{0,40})", stderr)
        err_class = m.group(1).strip() if m else f"signal:{returncode}"
        frames = cls._parse_asan_stack(stderr)
        top = cls._first_app_frame(frames) if frames else ""
        top = top.split("/")[-1] if top else ""
        return (err_class, top)

    @staticmethod
    def _ddmin(
        data: bytes,
        still_crashes: Callable[[bytes], bool],
        deadline: float = 0.0,
    ) -> bytes:
        """Greedy delta-debug: delete byte blocks while ``still_crashes`` holds.

        Block size halves from len//2 down to 1, so it removes big chunks first then
        trims byte-by-byte. Stops early (returns best-so-far) once ``deadline``
        (a time.monotonic() value; 0 disables) is passed. Pure and side-effect free
        so it is unit-testable with a synthetic predicate.
        """
        n = max(1, len(data) // 2)
        while n >= 1:
            i = 0
            changed = False
            while i < len(data):
                if deadline and time.monotonic() > deadline:
                    return data
                candidate = data[:i] + data[i + n:]
                if candidate and still_crashes(candidate):
                    data = candidate
                    changed = True
                else:
                    i += n
            if not changed:
                n //= 2
        return data

    def minimize_crash(self, crash_file: Path, report: CrashReport) -> Path | None:
        """Delta-debug ``crash_file`` to a minimal same-site reproducer.

        Saves the reduced input under ``<findings>/minimized/`` and records its path
        on ``report.minimized_input``. Best-effort and bounded: no-op when disabled,
        when no debug binary is set, when the input exceeds ``minimize_max_bytes``, or
        when it does not reproduce single-shot. Never raises — a minimization failure
        must not drop a real finding.
        """
        tgt = self.config.target
        if not getattr(tgt, "minimize_crashes", False):
            return None
        if self.unpatched_binary is None or not self.unpatched_binary.exists():
            return None
        try:
            data = crash_file.read_bytes()
        except OSError:
            return None
        max_bytes = getattr(tgt, "minimize_max_bytes", 65536)
        if len(data) > max_bytes:
            self.log.info(
                "triage.minimize_skip",
                file=crash_file.name,
                size=len(data),
                reason=f"input exceeds minimize_max_bytes ({max_bytes})",
            )
            return None
        try:
            rc, err = self._run_input(data)
        except Exception as exc:
            self.log.warning("triage.minimize_run_error", error=str(exc))
            return None
        target_sig = self._crash_signature(rc, err)
        if target_sig is None:
            return None  # does not reproduce single-shot — nothing to anchor on

        def still(candidate: bytes) -> bool:
            try:
                c_rc, c_err = self._run_input(candidate)
            except Exception:
                return False
            return self._crash_signature(c_rc, c_err) == target_sig

        budget = getattr(tgt, "minimize_timeout_s", 60)
        deadline = time.monotonic() + budget if budget else 0.0
        mini = self._ddmin(data, still, deadline)

        out_dir = self.crashes_dir.parent / "minimized"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{crash_file.name}.min"
        out_path.write_bytes(mini)
        report.minimized_input = str(out_path)
        self.log.info(
            "triage.minimized",
            file=crash_file.name,
            orig_bytes=len(data),
            min_bytes=len(mini),
            site=str(target_sig),
        )
        return out_path

    def _resolve_upstream_status(self):
        """Check whether source_root is at the latest upstream tip (read-only git).

        Lazy-imports nemesis.upstream to keep triager import light. Logs at WARNING
        when the checkout is behind (finding may already be fixed upstream), INFO
        otherwise. Returns an UpstreamStatus (status "unknown" on any failure).
        """
        from nemesis.upstream import check_upstream_freshness

        src = self.config.target.source_root
        branch = getattr(self.config.target, "upstream_branch", "")
        us = check_upstream_freshness(src, branch)
        log_fn = self.log.warning if us.status == "behind" else self.log.info
        log_fn(
            "triage.upstream_check",
            status=us.status,
            ref=us.upstream_ref,
            current=us.current_commit,
            upstream=us.upstream_commit,
            detail=us.detail,
        )
        return us

    def _extract_signal(self, filename: str) -> str:
        """Extract signal number from AFL++ crash filename (sig:NN)."""
        m = re.search(r"sig:(\d+)", filename)
        return m.group(1) if m else "00"

    def _run_afl_cmin(self, crashes_dir: Path) -> Path:
        """
        Run afl-cmin to reduce the crash corpus to a minimal representative set.

        Returns the minimized directory path, or the original if afl-cmin is
        unavailable or the crash set is too small to be worth minimizing.
        """
        crash_files = list(crashes_dir.glob("id:*"))
        if len(crash_files) <= 5:
            return crashes_dir  # not worth minimizing small sets

        # Prefer the per-AFL-run binary snapshot (saved by AFLOrchestrator before
        # launch). Without it we'd verify against a freshly-refined harness that
        # never produced these crashes — afl-cmin would drop everything as
        # non-reproducible. crashes_dir parent layout: <findings_dir>/<main|slave_N>/crashes
        snapshot = crashes_dir.parent.parent / "binary_snapshot"
        if snapshot.exists():
            binary = snapshot
            self.log.debug("cmin.using_snapshot", path=str(snapshot))
        else:
            binary = Path(self.config.target.build_dir) / "fuzz_nemesis"
            if not binary.exists():
                return crashes_dir

        minimized_dir = crashes_dir.parent / "crashes_cmin"
        minimized_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [
                    "afl-cmin",
                    "-i", str(crashes_dir),
                    "-o", str(minimized_dir),
                    "--", str(binary),
                ],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "AFL_NO_UI": "1"},
            )
            if result.returncode == 0:
                minimized = list(minimized_dir.glob("*"))
                self.log.info(
                    "cmin.complete",
                    before=len(crash_files),
                    after=len(minimized),
                )
                # afl-cmin sometimes drops everything because afl-showmap can't
                # reproduce ASAN heap-overflow crashes single-shot — the bug
                # depends on heap layout that varies across runs. In that case
                # fall back to the original crashes_dir so the triager (which
                # has its own AFL-snapshot fallback in `_verify_crash_standalone`)
                # gets the chance to verify each crash against the binary that
                # actually produced it. The README.txt that afl-cmin always
                # emits is filtered separately.
                real_minimized = [
                    p for p in minimized if p.name != "README.txt"
                ]
                if len(real_minimized) == 0 and len(crash_files) > 0:
                    self.log.warning(
                        "cmin.empty_result_falling_back_to_raw",
                        before=len(crash_files),
                        note=(
                            "afl-cmin found 0 reproducible single-shot crashes. "
                            "Falling back to the raw crashes/ dir so the triager's "
                            "AFL-snapshot-fallback verifier gets a chance to confirm "
                            "the crashes (typical for ASAN heap-layout-dependent bugs)."
                        ),
                    )
                    return crashes_dir
                return minimized_dir
            else:
                self.log.warning(
                    "cmin.failed",
                    returncode=result.returncode,
                    stderr=(result.stderr or "")[:300],
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log.debug("cmin.unavailable")

        return crashes_dir

    def _analyze_crash(self, crash_file: Path) -> CrashReport | None:
        """Analyze a single crash file: ASAN run for CWE classification, GDB for backtrace.

        GDB intercepts SIGSEGV before ASAN can print its diagnostic, so we run
        the binary standalone first (stdin) to get the ASAN output for CWE
        classification, then run GDB separately for the symbolic backtrace.
        """
        # Fix 82: prefer standalone debug binary (no AFL macros, reads from stdin)
        # over AFL-instrumented binary where __AFL_FUZZ_TESTCASE_BUF may be NULL standalone.
        # Per-AFL-run snapshot wins over current binary (debug or fuzz) because the
        # current one may have been recompiled by feedback refinement after the
        # crash was recorded — see _run_afl_cmin for the full rationale.
        # crash_file path: <findings_dir>/<main|slave_N>/crashes/id:...
        # findings_dir: crash_file.parent.parent.parent
        findings_dir = crash_file.parent.parent.parent
        debug_snapshot = findings_dir / "binary_debug_snapshot"
        afl_snapshot = findings_dir / "binary_snapshot"
        debug_binary = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
        afl_binary = Path(self.config.target.build_dir) / "fuzz_nemesis"
        if debug_snapshot.exists():
            binary = debug_snapshot
        elif debug_binary.exists():
            binary = debug_binary
        elif afl_snapshot.exists():
            binary = afl_snapshot
        else:
            binary = afl_binary
        asan_env = {
            **os.environ,
            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
            "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
        }

        try:
            # Step 1: standalone ASAN run for CWE classification
            with open(crash_file, "rb") as crash_input:
                asan_result = subprocess.run(
                    [str(binary)],
                    stdin=crash_input,
                    capture_output=True,
                    timeout=30,
                    env=asan_env,
                )
            asan_output = (asan_result.stdout + asan_result.stderr).decode("utf-8", errors="replace")

            # Fallback 1: ASAN log files written by AFL during the fuzzing run
            # (Fix 85 — persistent-mode crashes may not reproduce standalone).
            if "AddressSanitizer" not in asan_output and "ERROR:" not in asan_output:
                log_content = self._read_asan_log()
                if log_content:
                    self.log.debug("analyze.asan_log_fallback", file=crash_file.name)
                    asan_output = log_content

            # Fallback 2: verbose ASAN re-run (print_stacktrace=1) — extracts
            # richer output for crashes that need a second pass to show full report.
            if "AddressSanitizer" not in asan_output and "ERROR:" not in asan_output:
                verbose_env = {
                    **os.environ,
                    "ASAN_OPTIONS": (
                        "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1"
                        ":print_stacktrace=1:symbolize=1"
                        ":handle_abort=1:handle_segv=1"
                    ),
                    "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
                }
                try:
                    with open(crash_file, "rb") as crash_input:
                        verbose_result = subprocess.run(
                            [str(binary)],
                            stdin=crash_input,
                            capture_output=True,
                            timeout=30,
                            env=verbose_env,
                        )
                    verbose_out = (verbose_result.stdout + verbose_result.stderr).decode(
                        "utf-8", errors="replace"
                    )
                    if "AddressSanitizer" in verbose_out or "ERROR:" in verbose_out:
                        self.log.debug("analyze.verbose_asan_fallback", file=crash_file.name)
                        asan_output = verbose_out
                except (subprocess.TimeoutExpired, OSError):
                    pass

            # Step 2: GDB run for symbolic backtrace
            gdb_result = subprocess.run(
                [
                    "gdb", "-batch",
                    "-ex", f"run < {crash_file}",
                    "-ex", "bt",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=asan_env,
            )
            gdb_output = gdb_result.stdout + gdb_result.stderr

            gdb_stack = self._parse_backtrace(gdb_output)
            # Prefer the ASAN/UBSan report's OWN stack: it points straight at the
            # faulting line, whereas the GDB backtrace tops out at the abort()
            # machinery (__pthread_kill) the sanitizer invokes after reporting —
            # which is what made crash_location show "__pthread_kill" instead of
            # the real rpng.h:1639 heap-overflow site.
            asan_stack = self._parse_asan_stack(asan_output)
            if asan_stack:
                stack_trace = asan_stack
                crash_location = self._first_app_frame(asan_stack)
            else:
                stack_trace = gdb_stack
                crash_location = self._first_app_frame(gdb_stack)
            cwe = self._classify_cwe(asan_output + " " + gdb_output)

            # Fallback 3: signal-based CWE when both ASAN and GDB give nothing
            if cwe == CWE.UNKNOWN:
                sig = self._extract_signal(crash_file.name)
                cwe = self._classify_cwe_from_signal(sig)
                if cwe != CWE.UNKNOWN:
                    self.log.debug(
                        "analyze.signal_cwe_fallback",
                        file=crash_file.name,
                        signal=sig,
                        cwe=cwe.value,
                    )

            severity = self.CWE_SEVERITY.get(cwe, Severity.MEDIUM)

            # Classify which sanitizer detected the crash
            detected_by = self._classify_sanitizer(asan_output)

            report = CrashReport(
                input_file=str(crash_file),
                crash_location=crash_location,
                stack_trace=stack_trace,
                cwe=cwe,
                severity=severity,
                asan_output=asan_output[-1000:],
                detected_by=detected_by,
            )

            # Multi-build verification
            multi = self._verify_crash_multi_build(crash_file)
            report.reproduces_clean = multi["clean"]
            report.reproduces_asan = multi["asan"]
            report.reproduces_ubsan = multi["ubsan"]

            return report

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.log.warning("analyze.failed", file=crash_file.name, error=str(e))
            return None

    def _read_asan_log(self) -> str:
        """Read the most recent ASAN log file written during AFL fuzzing (Fix 85).

        AFL runs with __AFL_LOOP(), so the process doesn't exit between inputs.
        ASAN writes its error report to log_path.PID before calling abort().
        We read the most recently modified crash.* file from asan_log_dir.
        """
        if not self.asan_log_dir or not self.asan_log_dir.exists():
            return ""
        log_files = sorted(
            self.asan_log_dir.glob("crash.*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not log_files:
            return ""
        try:
            content = log_files[0].read_text(errors="replace")
            self.log.debug("asan_log.read", path=str(log_files[0]), size=len(content))
            return content
        except OSError:
            return ""

    def _parse_backtrace(self, output: str) -> list[str]:
        """Extract stack frames from GDB backtrace output."""
        frames = []
        for line in output.splitlines():
            # Match GDB frame format: #N 0xADDR in func_name at file:line
            m = re.match(r"#\d+\s+0x[\da-f]+\s+in\s+(\S+).*at\s+(\S+)", line)
            if m:
                frames.append(f"{m.group(1)} at {m.group(2)}")
            else:
                # Also match frames without address
                m = re.match(r"#\d+\s+(\S+)\s+\(.*\)\s+at\s+(\S+)", line)
                if m:
                    frames.append(f"{m.group(1)} at {m.group(2)}")
        return frames

    # Frames that are sanitizer/abort/libc machinery, NOT the bug site. When a
    # sanitizer aborts (abort_on_error=1) the GDB backtrace tops out at
    # __pthread_kill → abort → __asan_report; the real fault is several frames
    # down. crash_location must skip these.
    _MACHINERY_FRAME_RE = re.compile(
        r"(__pthread_kill|pthread_kill|__GI_raise|__GI_abort|\babort\b|\braise\b|"
        r"__libc_|^_start\b|_start at|__interceptor_|__asan|__ubsan|__msan|__tsan|"
        r"__sanitizer|AddressSanitizer|sanitizer_common|gsignal|raise\.c)",
        re.IGNORECASE,
    )

    @staticmethod
    def _parse_asan_stack(asan_output: str) -> list[str]:
        """Return the FIRST stack trace in an ASAN/UBSan report — the faulting
        location — as `func at file:line` frames. The first ``#N ... in`` block
        is the error stack; later blocks (allocated/freed by) are skipped.
        ASAN frame format: ``#0 0xADDR in func /path/file.c:line:col``.
        """
        frames: list[str] = []
        in_block = False
        for line in asan_output.splitlines():
            m = re.search(
                r"#\d+\s+0x[\da-fA-F]+\s+in\s+(\S+)\s+(\S+:\d+(?::\d+)?)",
                line,
            )
            if m:
                in_block = True
                frames.append(f"{m.group(1)} at {m.group(2)}")
            elif in_block:
                break  # first non-frame line ends the error stack
        return frames

    @classmethod
    def _first_app_frame(cls, frames: list[str]) -> str:
        """First frame that is real app/library code, skipping abort/sanitizer/
        libc machinery. Falls back to the top frame if all look like machinery."""
        for f in frames:
            if not cls._MACHINERY_FRAME_RE.search(f):
                return f
        return frames[0] if frames else "unknown"

    def _classify_cwe(self, output: str) -> CWE:
        """Classify crash CWE from ASan/UBSan/GDB output."""
        output_lower = output.lower()

        # Fix 140 (2026-05-05): When ASAN reports a buffer-overflow class crash,
        # the next line always specifies the operation type ("READ of size N" /
        # "WRITE of size N"). The MITRE CWE taxonomy distinguishes:
        #   READ past end of heap allocation  → CWE-125 (Out-of-bounds Read)
        #   WRITE past end of heap allocation → CWE-787 / CWE-122 (Heap Buffer Overflow)
        # The naive substring match maps everything to HEAP_OVERFLOW (CWE-122),
        # which is the parent category but loses the read/write specificity that
        # CVE records (e.g. CVE-2023-53154 → CWE-125) and triagers care about.
        _OVERFLOW_KEYWORDS = (
            "heap-buffer-overflow",
            "global-buffer-overflow",
            "container-overflow",
            "stack-buffer-overflow",
        )
        for kw in _OVERFLOW_KEYWORDS:
            if kw in output_lower:
                # Look for the operation line that ASAN prints right after the
                # error type. Format: "READ of size N at 0xADDR thread T0".
                if "read of size" in output_lower:
                    return CWE.OUT_OF_BOUNDS_READ
                if "write of size" in output_lower:
                    # Keep HEAP_OVERFLOW (CWE-122) for heap writes; for stack
                    # writes we still want STACK_OVERFLOW.
                    return (
                        CWE.STACK_OVERFLOW
                        if "stack-buffer-overflow" in output_lower
                        else CWE.HEAP_OVERFLOW
                    )
                # No explicit READ/WRITE marker — fall through to existing map.
                break

        for pattern, cwe in self.ASAN_CWE_MAP.items():
            if pattern.lower() in output_lower:
                return cwe

        # GDB / signal-based fallbacks when ASAN output is absent
        if "sigill" in output_lower or "illegal instruction" in output_lower:
            return CWE.NULL_DEREF
        if "sigsegv" in output_lower or "segmentation fault" in output_lower:
            return CWE.NULL_DEREF
        if "sigfpe" in output_lower or "floating point exception" in output_lower:
            return CWE.DIVIDE_BY_ZERO

        return CWE.UNKNOWN

    def _classify_cwe_from_signal(self, sig: str) -> CWE:
        """Last-resort CWE inference from AFL++ signal number alone.

        Used when both ASAN output and GDB output are empty/unavailable.
        Provides a best-effort classification rather than CWE-unknown.
        """
        _SIG_CWE: dict[str, CWE] = {
            "06": CWE.HEAP_OVERFLOW,       # SIGABRT — almost always ASAN abort
            "11": CWE.NULL_DEREF,           # SIGSEGV — null/invalid deref
            "08": CWE.DIVIDE_BY_ZERO,       # SIGFPE  — arithmetic error
            "07": CWE.NULL_DEREF,           # SIGBUS  — misaligned / invalid address
        }
        return _SIG_CWE.get(sig, CWE.UNKNOWN)

    def _classify_sanitizer(self, output: str) -> SanitizerClass:
        """Classify which sanitizer detected the crash from its output."""
        if "AddressSanitizer" in output:
            return SanitizerClass.ASAN
        if "runtime error:" in output:
            return SanitizerClass.UBSAN
        if "MemorySanitizer" in output or "use-of-uninitialized-value" in output:
            return SanitizerClass.MSAN
        # Fix 150: ThreadSanitizer for data races
        if "ThreadSanitizer" in output or "data race" in output.lower():
            return SanitizerClass.TSAN
        # Check for signal-based detection (no sanitizer output)
        if output.strip():
            return SanitizerClass.SIGNAL
        return SanitizerClass.UNKNOWN

    def _verify_crash_multi_build(self, crash_file: Path) -> dict[str, bool | None]:
        """Test crash against multiple build configurations.

        Returns {"clean": bool|None, "asan": bool|None, "ubsan": bool|None}.
        None = binary not available for that configuration.
        """
        results: dict[str, bool | None] = {
            "clean": None,
            "asan": None,
            "ubsan": None,
        }

        for key, binary in [
            ("clean", self.clean_binary),
            ("asan", self.unpatched_binary),
            ("ubsan", self.ubsan_binary),
        ]:
            if binary is None or not binary.exists():
                continue
            try:
                with open(crash_file, "rb") as inp:
                    # Fix 126: abort_on_error=1 for asan/ubsan builds
                    _abort_flag = "0" if key == "clean" else "1"
                    result = subprocess.run(
                        [str(binary)],
                        stdin=inp,
                        capture_output=True,
                        timeout=15,
                        env={
                            **os.environ,
                            "ASAN_OPTIONS": (
                                f"abort_on_error={_abort_flag}:detect_leaks=0"
                                ":allocator_may_return_null=1"
                            ),
                            "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
                        },
                    )
                stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
                has_sanitizer = (
                    "AddressSanitizer" in stderr_text
                    or "UndefinedBehaviorSanitizer" in stderr_text
                )
                # Fix 126: sanitizer output = real crash regardless of exit code
                if has_sanitizer:
                    results[key] = True
                elif result.returncode in self._CHILD_SIGNAL_RETURNCODES:
                    results[key] = False
                else:
                    results[key] = result.returncode != 0
            except subprocess.TimeoutExpired:
                results[key] = True  # hang = real issue
            except Exception:
                pass  # leave as None

        return results

    def _app_repro_status(self, crash_file: Path) -> AppReproStatus:
        """Replay the crash against the real application binary (e.g. bsdtar).

        Returns a three-state verdict instead of a bool so callers can tell an
        unverifiable crash apart from a disproven one:

        - CONFIRMED      — the app binary crashed on this input.
        - NOT_REPRODUCED — the app binary ran clean (artifact-suspect).
        - NOT_TESTABLE   — no repro_binary configured or the binary is missing.
        """
        if not self.config.target.repro_binary:
            return AppReproStatus.NOT_TESTABLE
        debug_dir = Path(self.config.target.debug_build_dir)
        repro_binary = debug_dir / self.config.target.repro_binary

        if not repro_binary.exists() or not repro_binary.is_file():
            self.log.debug("repro.binary_not_found", path=str(repro_binary))
            return AppReproStatus.NOT_TESTABLE

        repro_args = self.config.target.repro_args + [str(crash_file)]

        try:
            result = subprocess.run(
                [str(repro_binary)] + repro_args,
                capture_output=True,
                text=True,
                timeout=10,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=0:allocator_may_return_null=1",
                },
            )
            rc = result.returncode
            if rc == 0:
                return AppReproStatus.NOT_REPRODUCED  # clean exit — not a crash

            # SIGPIPE/SIGILL/SIGBUS from child process: not a memory-safety bug.
            if rc in self._CHILD_SIGNAL_RETURNCODES:
                return AppReproStatus.NOT_REPRODUCED

            # Distinguish real memory-safety crash from a plain format error:
            # - Signal-based exits (SIGABRT=134, SIGSEGV=139) are real crashes.
            # - ASAN/UBSan output in stderr is a real crash.
            # - Any other non-zero exit (e.g. bsdtar "unsupported format") is NOT.
            _CRASH_RC = {134, -6, 139, -11}  # SIGABRT, SIGSEGV
            asan_out = result.stderr + result.stdout
            has_asan = (
                "AddressSanitizer" in asan_out
                or "==ERROR==" in asan_out
                or "SUMMARY: Address" in asan_out
                or "runtime error:" in asan_out  # UBSan
            )
            if has_asan or rc in _CRASH_RC:
                return AppReproStatus.CONFIRMED
            return AppReproStatus.NOT_REPRODUCED

        except subprocess.TimeoutExpired:
            return AppReproStatus.CONFIRMED  # hang counts as reproduction
        except FileNotFoundError:
            return AppReproStatus.NOT_TESTABLE

    def _verify_unpatched(self, crash_file: Path) -> bool:
        """
        Run the crash input against the unpatched debug binary.

        Returns True if the binary crashes WITHOUT the LLM patch applied,
        meaning the bug is a pre-existing vulnerability in the original code
        (real CVE candidate, Scenario 2).

        Returns False if the crash does NOT reproduce without the patch,
        meaning the LLM patch itself introduced the bug (false positive,
        Scenario 1 — patch-induced).
        """
        if not self.unpatched_binary or not self.unpatched_binary.exists():
            return False

        asan_env = {
            **os.environ,
            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
            "UBSAN_OPTIONS": _TRIAGE_UBSAN_OPTIONS,
        }
        try:
            with open(crash_file, "rb") as f:
                result = subprocess.run(
                    [str(self.unpatched_binary)],
                    stdin=f,
                    capture_output=True,
                    timeout=15,
                    env=asan_env,
                )
            # Crashed if non-zero return code (signal or ASAN abort)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True  # hang = crash
        except (FileNotFoundError, OSError):
            return False

    def _hash_trace(self, trace: list[str]) -> str:
        """Hash top N stack frames for deduplication."""
        import hashlib
        content = "|".join(trace)
        return hashlib.md5(content.encode()).hexdigest()[:16]


class CoverageAnalyzer:
    """Tracks AFL++ bitmap coverage (edge-transition density).

    NOTE: bitmap_cvg measures the percentage of AFL's shared-memory bitmap that
    has been set. This is NOT source-line coverage — it is a proxy for how many
    unique edge transitions (basic-block pairs) the fuzzer has discovered across
    the ENTIRE instrumented binary. For function-level source coverage, use
    SymbolicStage.measure_function_source_coverage().
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("fuzzing.coverage")
        self._findings_dir = Path(config.engine.work_dir) / "fuzzing" / "findings"
        self._before_bitmap_cvg: float = 0.0

    def take_snapshot(self) -> CoverageSnapshot:
        """
        Capture baseline bitmap coverage before fuzzing.
        Called before AFL++ starts; stores value for later delta calculation.
        """
        cvg = self._read_bitmap_cvg()
        self._before_bitmap_cvg = cvg
        return CoverageSnapshot(
            line_coverage_pct=cvg,
            branch_coverage_pct=cvg,
            bitmap_coverage_pct=cvg,  # Fix 126: explicit bitmap field
        )

    def measure(self) -> CoverageDelta:
        """
        Measure coverage delta using AFL++ bitmap_cvg from fuzzer_stats.

        Falls back to plot_data trend if stats are unavailable.
        success=True when:
          - bitmap_cvg grew by at least coverage_threshold (default 5%)
          - OR coverage was still growing at end of run (not plateaued)
        """
        after_cvg = self._read_bitmap_cvg()
        before = CoverageSnapshot(
            line_coverage_pct=self._before_bitmap_cvg,
            branch_coverage_pct=self._before_bitmap_cvg,
            bitmap_coverage_pct=self._before_bitmap_cvg,
        )
        after = CoverageSnapshot(
            line_coverage_pct=after_cvg,
            branch_coverage_pct=after_cvg,
            bitmap_coverage_pct=after_cvg,
        )

        delta = after_cvg - self._before_bitmap_cvg
        threshold_pct = self.config.engine.coverage_threshold * 100  # 0.05 → 5%
        success = delta >= threshold_pct or self._is_coverage_growing()

        self.log.info(
            "bitmap_coverage.measured",
            bitmap_cvg_before=self._before_bitmap_cvg,
            bitmap_cvg_after=after_cvg,
            bitmap_cvg_delta=delta,
            growing=self._is_coverage_growing(),
            success=success,
        )

        return CoverageDelta(
            before=before,
            after=after,
            expanded_functions={"__afl_bitmap__": delta} if delta > 0 else {},
            total_expansion_pct=delta,
            success=success,
        )

    def _read_bitmap_cvg(self) -> float:
        """Read bitmap_cvg from AFL++ fuzzer_stats (main instance, fallback to default)."""
        stats_file = self._findings_dir / "main" / "fuzzer_stats"
        if not stats_file.exists():
            stats_file = self._findings_dir / "default" / "fuzzer_stats"
        if not stats_file.exists():
            return 0.0
        try:
            for line in stats_file.read_text().splitlines():
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                if key.strip() == "bitmap_cvg":
                    return float(val.strip().rstrip("%"))
        except (ValueError, OSError):
            pass
        return 0.0

    def _is_coverage_growing(self) -> bool:
        """
        Parse AFL++ plot_data to check if coverage was still expanding
        at the end of the run (i.e., not plateaued — more time would help).

        plot_data columns (AFL++ 4.x):
          unix_time, cycles_done, cur_item, corpus_count, pending_total,
          pending_favs, map_size, saved_crashes, saved_hangs, max_depth,
          execs_per_sec, total_execs, edges_found
        """
        plot_file = self._findings_dir / "main" / "plot_data"
        if not plot_file.exists():
            plot_file = self._findings_dir / "default" / "plot_data"
        if not plot_file.exists():
            return False
        try:
            lines = [
                ln for ln in plot_file.read_text().splitlines()
                if ln and not ln.startswith("#")
            ]
            if len(lines) < 4:
                return False

            def edges(line: str) -> float:
                parts = [p.strip().rstrip("%") for p in line.split(",")]
                return float(parts[12]) if len(parts) >= 13 else 0.0

            # Compare first quarter vs last quarter of the run
            quarter = max(1, len(lines) // 4)
            early = sum(edges(ln) for ln in lines[:quarter]) / quarter
            late = sum(edges(ln) for ln in lines[-quarter:]) / quarter
            return late > early
        except (ValueError, OSError, IndexError):
            return False
