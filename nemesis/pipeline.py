"""
NEMESIS pipeline orchestrator.

Wires all four stages together with the self-healing feedback loop.
Each stage is a pluggable module — swap implementations without
changing the orchestration logic.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import (
    AFLStats,
    AnalysisContext,
    CoverageDelta,
    CoverageSnapshot,
    CrashReport,
    CWE,
    FeedbackContext,
    HarnessExecutionDiagnostics,
    HarnessSpec,
    PipelineRun,
    PipelineStatus,
    Severity,
    TargetResult,
)


# Directory name segments that typically hold valid sample inputs in a source
# tree. Extension-based harvesting is restricted to these so we never drag in
# unrelated repo files (a stray config.json at the repo root is not a seed).
_TEST_DIR_SEGMENTS = frozenset({
    "test", "tests", "testsuite", "testdata", "test-data", "test_data",
    "sample", "samples", "example", "examples", "data", "fixtures",
    "corpus", "corpora", "regress", "regression", "cases",
})

# Library-name / format token → plausible file extensions for text and
# container formats whose magic bytes are absent or not at offset 0.
_FORMAT_EXT_HINTS = {
    "json": ("json",),
    "xml": ("xml", "xsd", "svg", "xhtml", "rss"),
    "yaml": ("yaml", "yml"),
    "toml": ("toml"),
    "html": ("html", "htm"),
    "csv": ("csv",),
    "ini": ("ini", "cfg"),
    "pdf": ("pdf",),
    "tiff": ("tif", "tiff"),
    "png": ("png",),
    "jpeg": ("jpg", "jpeg"),
    "gif": ("gif",),
    "webp": ("webp",),
    "wav": ("wav",),
    "flac": ("flac",),
    "lz4": ("lz4",),
    "zip": ("zip",),
}


def derive_seed_extensions(
    magic_keys,
    seed_extensions,
    library_name: str = "",
) -> set[str]:
    """Derive candidate file extensions (no dot, lowercase) for harvesting.

    Combines: explicit `target.seed_extensions` config, tokens stripped from
    `magic_bytes` format keys (``format_png`` → ``png``), the library name, and
    a small text/container-format hint map. Pure and side-effect-free so it can
    be unit-tested without a pipeline instance.
    """
    toks: set[str] = set()
    for e in seed_extensions or []:
        s = str(e).lower().lstrip(".")
        if s:
            toks.add(s)
    tokens_for_hints: set[str] = set()
    for key in (magic_keys or []):
        k = str(key).lower()
        for pre in ("format_", "format"):
            if k.startswith(pre):
                k = k[len(pre):]
                break
        if k:
            toks.add(k)
            tokens_for_hints.add(k)
    lib = (library_name or "").lower()
    if lib.startswith("lib"):
        lib = lib[3:]
    if lib:
        tokens_for_hints.add(lib)
    for tok in tokens_for_hints:
        for fmt, exts in _FORMAT_EXT_HINTS.items():
            if fmt in tok or tok in fmt:
                toks.update(exts)
    return {t for t in toks if t}


def is_under_test_dir(path_parts) -> bool:
    """True if any path segment names a test/sample/data directory."""
    return any(seg.lower() in _TEST_DIR_SEGMENTS for seg in path_parts)


def _classify_run_status(results, targets_processed: int, total_crashes: int):
    """Classify a completed run as SUCCESS or FAILED for the run-level gate.

    FAILED when no target was processable, or every non-skipped target FAILED
    and produced zero crashes. Otherwise SUCCESS. Returns (status, reasons).
    """
    non_skipped = [r for r in results if r.status != PipelineStatus.SKIPPED]
    all_failed = bool(non_skipped) and all(
        r.status == PipelineStatus.FAILED for r in non_skipped
    )
    if targets_processed == 0:
        return PipelineStatus.FAILED, ["no targets were processed"]
    if all_failed and total_crashes == 0:
        return PipelineStatus.FAILED, ["all processed targets failed"]
    return PipelineStatus.SUCCESS, []


class NemesisPipeline:
    """
    Main pipeline orchestrator.

    Stages:
        1. Recon   — identify low-coverage targets
        2. Neural  — LLM analysis, patch & harness generation
        3. Surgery — Z3 verification, patch application, build
        4. Fuzz    — AFL++ execution, crash triage, coverage analysis

    Feedback: Stage 4 failure → Stage 2 refinement (max N iterations)
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("pipeline")

        # Create workspace directory
        self.workspace = Path(config.engine.work_dir)
        self.workspace.mkdir(parents=True, exist_ok=True)

        # Cross-run library memory (lazy — only loaded when first used)
        self._library_memory: Optional["LibraryMemory"] = None  # type: ignore[type-arg]

        # Codebase oracle (RAG) — lazy, built once per run
        self._oracle = None

        # Two-Brain context builder — lazy, built once per run
        self._context_builder = None

        # Initialize stages lazily — they import heavy deps
        self._recon = None
        self._neural = None
        self._symbolic = None
        self._fuzzing = None

    @property
    def library_memory(self) -> "LibraryMemory":
        """Lazy-load cross-run library memory for the current target library."""
        if self._library_memory is None:
            from nemesis.library_memory import LibraryMemory
            self._library_memory = LibraryMemory(
                library_name=self.config.target.name,
                workspace_dir=self.config.engine.work_dir,
            )
        return self._library_memory

    @property
    def oracle(self):
        """Lazy-init codebase oracle (RAG) for the current target library."""
        if self._oracle is None:
            from nemesis.neural.oracle import CodebaseOracle
            self._oracle = CodebaseOracle(
                library_name=self.config.target.name,
                source_root=self.config.target.source_root,
                workspace_dir=self.config.engine.work_dir,
                nvidia_api_key=os.environ.get("NVIDIA_API_KEY", ""),
            )
        return self._oracle

    @property
    def context_builder(self):
        """Lazy-init budget-aware context builder for Two-Brain architecture."""
        if self._context_builder is None:
            from nemesis.neural.context_builder import ContextBuilder
            budget = 0
            ctx_window = 0
            max_out = 0
            if self.config.llm.architect:
                budget = self.config.llm.architect.context_budget_tokens
                ctx_window = self.config.llm.architect.context_window
                max_out = self.config.llm.architect.max_tokens
            self._context_builder = ContextBuilder(
                config=self.config,
                budget_tokens=budget,
                oracle=self._oracle,
                context_window=ctx_window,
                max_output_tokens=max_out,
            )
        return self._context_builder

    @property
    def recon(self):
        if self._recon is None:
            from nemesis.recon import ReconStage
            self._recon = ReconStage(self.config)
        return self._recon

    @property
    def neural(self):
        if self._neural is None:
            from nemesis.neural import NeuralStage
            self._neural = NeuralStage(self.config)
        return self._neural

    @property
    def symbolic(self):
        if self._symbolic is None:
            from nemesis.symbolic import SymbolicStage
            self._symbolic = SymbolicStage(self.config)
        # Wire neural stage for LLM harness repair (Fix A).
        # Neural is always initialized before symbolic in the pipeline flow
        # (neural generates harnesses before symbolic compiles them).
        if self._neural is not None and self._symbolic._neural is None:
            self._symbolic.set_neural(self._neural)
        return self._symbolic

    @property
    def fuzzing(self):
        if self._fuzzing is None:
            from nemesis.fuzzing import FuzzingStage
            self._fuzzing = FuzzingStage(self.config)
        return self._fuzzing

    def _harvest_seeds_from_source_tree(self, corpus_dir: Path) -> int:
        """Walk source_root looking for files whose first bytes match any of
        the target's magic_bytes. Most parser libraries ship a test/ or
        tests/ directory with dozens to hundreds of valid sample files —
        these are far better fuzz seeds than nothing, and they cost zero
        network/auth (the source is already cloned).

        Returns number of files harvested. Idempotent: only copies into an
        empty corpus_dir.
        """
        magic_bytes_map = self.config.target.magic_bytes or {}

        # Decode magic patterns into raw bytes once.
        raw_magics: list[bytes] = []
        for patterns in magic_bytes_map.values():
            for p in patterns:
                if isinstance(p, str):
                    try:
                        b = p.encode("latin-1").decode("unicode_escape").encode("latin-1")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        b = p.encode("latin-1", errors="ignore")
                    if b:
                        raw_magics.append(b)

        # #7: extension-based harvest for text/container formats whose magic is
        # absent or not at offset 0 (cJSON, libxml2, expat — magic_bytes empty,
        # so the magic path harvests nothing). Extension matches are restricted
        # to test/sample/data dirs to avoid dragging in unrelated repo files.
        ext_tokens = derive_seed_extensions(
            magic_bytes_map.keys(),
            getattr(self.config.target, "seed_extensions", None),
            self.config.target.name or "",
        )

        if not raw_magics and not ext_tokens:
            return 0

        source_root = Path(
            os.path.expandvars(os.path.expanduser(self.config.target.source_root))
        )
        if not source_root.exists():
            return 0

        # Heuristic skip-list: don't drag in build artefacts or VCS metadata,
        # but DO walk test/ tests/ testsuite/ samples/ — that's where the gold is.
        skip_segments = {
            "build", "build_fuzz", "build_debug", "build_ubsan",
            "build_coverage", ".git", ".github", "__pycache__", "node_modules",
        }

        max_seeds = 200          # cap so we don't flood AFL with thousands
        max_size = 64 * 1024     # 64 KB per seed (anything bigger is rare in test suites)
        magic_max_len = max((len(m) for m in raw_magics), default=0)

        corpus_dir.mkdir(parents=True, exist_ok=True)
        n_copied = 0
        for path in source_root.rglob("*"):
            if n_copied >= max_seeds:
                break
            if not path.is_file():
                continue
            if any(seg in skip_segments for seg in path.parts):
                continue
            try:
                size = path.stat().st_size
                if size == 0 or size > max_size:
                    continue
                matched = False
                if raw_magics:
                    with open(path, "rb") as f:
                        head = f.read(magic_max_len)
                    matched = any(head.startswith(m) for m in raw_magics)
                if not matched and ext_tokens:
                    suffix = path.suffix.lower().lstrip(".")
                    matched = (
                        suffix in ext_tokens and is_under_test_dir(path.parts)
                    )
                if not matched:
                    continue
                dest = corpus_dir / f"src_{n_copied:04d}_{path.name}"
                dest.write_bytes(path.read_bytes())
                n_copied += 1
            except OSError:
                continue

        if n_copied > 0:
            self.log.info(
                "corpus.harvested_from_source",
                count=n_copied,
                source_root=str(source_root),
                path=str(corpus_dir),
            )
        return n_copied

    def _ensure_oss_fuzz_corpus(self) -> None:
        """Download OSS-Fuzz corpus if configured but directory is empty/missing.

        Falls back to harvesting test-suite files from the cloned source tree
        when the GCS bucket returns 403 (the public buckets stopped allowing
        anonymous reads in 2023).
        """
        corpus_path = self.config.seeds.oss_fuzz_corpus
        if not corpus_path:
            return
        corpus_dir = Path(corpus_path)
        if corpus_dir.exists() and any(corpus_dir.iterdir()):
            return  # already have corpus

        project = self.config.target.oss_fuzz_project
        if not project:
            return

        self.log.info("corpus.downloading", project=project)

        # Build list of fuzzer names to try (config overrides, then common patterns)
        fuzzer_names = list(self.config.seeds.oss_fuzz_fuzzer_names)
        if not fuzzer_names:
            fuzzer_names = [f"{project}_fuzzer"]

        import urllib.request, urllib.error, zipfile, tempfile

        corpus_dir.mkdir(parents=True, exist_ok=True)

        for fuzzer_name in fuzzer_names:
            url = (
                f"https://storage.googleapis.com/{project}-backup"
                f".clusterfuzz-external.appspot.com/corpus/libFuzzer"
                f"/{fuzzer_name}/public.zip"
            )
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_path = tmp.name
                urllib.request.urlretrieve(url, tmp_path)
                with zipfile.ZipFile(tmp_path, "r") as z:
                    z.extractall(str(corpus_dir))
                count = len([f for f in corpus_dir.iterdir() if f.is_file()])
                self.log.info(
                    "corpus.downloaded",
                    fuzzer=fuzzer_name,
                    count=count,
                    path=str(corpus_dir),
                )
                os.unlink(tmp_path)
                return  # success — stop trying
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # OSS-Fuzz GCS buckets require Google auth since 2023.
                    # We fall back to harvesting test-suite files from the
                    # cloned source tree (see below). Log the manual gsutil
                    # command in case the user wants the full corpus.
                    self.log.warning(
                        "corpus.access_denied",
                        fuzzer=fuzzer_name,
                        hint=f"gsutil -m cp gs://{project}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/{fuzzer_name}/* {corpus_dir}/",
                    )
                    break  # 403 = auth issue, no point trying other fuzzers
                self.log.debug("corpus.fuzzer_attempt_failed", fuzzer=fuzzer_name, error=str(e))
            except Exception as e:
                self.log.debug(
                    "corpus.fuzzer_attempt_failed",
                    fuzzer=fuzzer_name,
                    error=str(e),
                )
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        # GCS path failed (403 or network error). Last-resort: walk the cloned
        # source tree and copy any file whose magic-byte prefix matches the
        # target's magic_bytes. test/ + tests/ + samples/ usually contain
        # dozens of valid format samples covering edge tag/chunk combinations
        # that random AFL byte-flips would never synthesise on their own.
        if not (corpus_dir.exists() and any(corpus_dir.iterdir())):
            self._harvest_seeds_from_source_tree(corpus_dir)

    def _sync_work_repo(self) -> bool:
        """
        rsync source_root → work_root to reset the working copy.

        Called once at startup (initial clone) and before each target (to roll
        back any LLM patches from the previous target without git stash).
        source_root is NEVER modified — only work_root is patched.
        """
        source_root = str(self.config.target.source_root)
        work_root = str(self.config.target.effective_work_root)

        if source_root == work_root:
            # Single-repo fallback — nothing to sync
            return True

        # Trailing slash on source: rsync copies *contents*, not the directory itself.
        # Exclude build dirs: build_fuzz (AFL instrumented), build/build_debug (cmake artifacts).
        # Without --exclude, rsync --delete wipes build_fuzz every target → cmake cache lost
        # → syntax_check has no flags.make → all bad patches pass → 60s wasted per build failure.
        cmd = [
            "rsync", "-a", "--delete",
            "--exclude", "build_fuzz",
            "--exclude", "build",
            "--exclude", "build_debug",
            source_root.rstrip("/") + "/",
            work_root + "/",
        ]
        self.log.info("sync.start", src=source_root, dst=work_root)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                # Touch all C source files to invalidate cmake's timestamp-based deps.
                # rsync -a preserves mtime from source_root, so after reset the source
                # files may be OLDER than .o files from the previous target's build.
                # Without touch, make skips recompilation → stale patched code stays.
                source_subdir = self.config.target.source_subdir
                if source_subdir:
                    lib_dir = Path(work_root) / source_subdir
                    if lib_dir.exists():
                        for c_file in lib_dir.glob("*.c"):
                            c_file.touch()
                else:
                    # No subdir — touch all C files in work_root
                    for c_file in Path(work_root).glob("*.c"):
                        c_file.touch()
                self.log.info("sync.done")
                return True
            else:
                self.log.error("sync.failed", stderr=r.stderr[:200])
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.log.error("sync.error", error=str(e))
            return False

    def _apply_visibility_patches(self, pins) -> None:
        """Strip `static` from pinned function definitions in `work_root`.

        The patch is intentionally minimal — visibility-only, no semantic
        change. `source_root` is never touched, so the debug binary used
        by `_verify_crash_standalone` is built from pristine source and
        every crash must reproduce there before being counted as a CVE
        rediscovery.
        """
        from nemesis.symbolic.visibility_patch import expose_static
        work_root = Path(self.config.target.effective_work_root)
        for pin in pins:
            file_rel = pin.file_path
            if not file_rel:
                self.log.warning(
                    "visibility_patch.skip_no_file_path",
                    func=pin.func_name,
                )
                continue
            target_file = work_root / file_rel
            if not target_file.exists():
                # If the YAML used `lib/xmlparse.c` but rsync put files
                # under a different layout, also try the bare basename.
                alt = work_root / Path(file_rel).name
                if alt.exists():
                    target_file = alt
                else:
                    self.log.warning(
                        "visibility_patch.file_missing",
                        func=pin.func_name,
                        path=str(target_file),
                    )
                    continue
            changed, msg = expose_static(target_file, pin.func_name)
            if changed:
                self.log.info(
                    "visibility_patch.applied",
                    func=pin.func_name,
                    file=str(target_file.relative_to(work_root)),
                    note="symbol now externally linkable; source_root untouched",
                )
            else:
                self.log.info(
                    "visibility_patch.noop",
                    func=pin.func_name,
                    reason=msg,
                )

    def execute(
        self,
        stage_list: list[int] | None = None,
        max_targets: int = 0,
        resume: bool = False,
    ) -> PipelineRun:
        """
        Execute the pipeline.

        Args:
            stage_list: Which stages to run (default: all)
            max_targets: Max number of targets to process (0 = all)
            resume: Skip already-processed targets; triage-only for targets with existing crashes

        Returns:
            PipelineRun with complete results
        """
        if stage_list is None:
            stage_list = [1, 2, 3, 4]

        run_id = uuid.uuid4().hex[:12]
        run = PipelineRun(run_id=run_id, target_name=self.config.target.name)
        self.log.info("execute.start", run_id=run_id, resume=resume)

        # Fix 151: cross-config oracle validation. Warns about combinations that
        # are individually valid but jointly waste a run (e.g. TSan profile with
        # no threaded_oracle pinned_func). Hard gates already live in
        # `_resolve_sanitizer_flags`; this only surfaces soft misconfigurations.
        from nemesis.recon.oracle_validation import validate_oracle_config
        for w in validate_oracle_config(self.config):
            self.log.warning(f"oracle.config.{w.key}",
                             message=w.message, suggestion=w.suggestion)

        # Scope AFL findings to this run so crash files are never overwritten
        self.fuzzing.orchestrator.run_id = run_id
        # Update `current` symlink so the Live dashboard always points to latest run
        findings_root = Path(self.config.engine.work_dir) / "fuzzing" / "findings"
        findings_root.mkdir(parents=True, exist_ok=True)
        current_link = findings_root / "current"
        run_findings = findings_root / run_id
        run_findings.mkdir(parents=True, exist_ok=True)
        if current_link.is_symlink() or current_link.exists():
            current_link.unlink()
        current_link.symlink_to(run_findings.resolve())

        # ── One-time setup: sync work repo + build unpatched debug library ──
        is_harness_strategy = self.config.fuzzing.strategy == "harness"
        # Fix 145: hybrid Strategy A+B. If any pinned function has
        # `auto_expose: true`, we sync source→work (even in Strategy A) and
        # apply a visibility-only patch to work_root before the fuzz build.
        # source_root stays pristine so debug binary verifies on clean source.
        auto_expose_pins = [
            p for p in (self.config.target.pinned_funcs or [])
            if getattr(p, "auto_expose", False)
        ]
        if not resume and 3 in stage_list:
            if is_harness_strategy:
                # Strategy A: build library once from clean source, never patch
                self.log.info("startup.strategy_a", msg="building unpatched library once")
                self.symbolic.build_unpatched_library()
                # Strategy A's fuzz build_dir lives under work_root, and the
                # out-of-tree ../configure resolves to work_root — so the work
                # copy must exist even though Strategy A never patches it.
                # Populate it unconditionally; previously this only ran for
                # auto_expose pins, leaving work_root empty on a plain harness
                # run against a fresh checkout (the fuzz library then never built).
                self._sync_work_repo()
                if auto_expose_pins:
                    # Hybrid: apply visibility patches to the work copy. The
                    # pristine source_root is untouched; _verify_crash_standalone
                    # later reproduces every crash on the unpatched debug binary.
                    self._apply_visibility_patches(auto_expose_pins)
                self.symbolic.builder.configure_fuzz_build_dir()
                # Build the AFL-instrumented fuzz library NOW, before harness
                # variant profiling. configure_fuzz_build_dir() only configures;
                # without the library present the first variant fails to link,
                # the lazy rebuild fires too late (after every variant is marked
                # none_compiled), and the target is skipped at 0 coverage.
                self.symbolic.builder.build_library(
                    Path(self.config.target.effective_work_root),
                    Path(self.config.target.build_dir),
                )
            else:
                self._sync_work_repo()
                self.log.info("startup.building_unpatched_library")
                self.symbolic.build_unpatched_library()
                if auto_expose_pins:
                    self._apply_visibility_patches(auto_expose_pins)
                self.symbolic.builder.configure_fuzz_build_dir()

        # ── Build codebase oracle (once per library, cached) ──
        if 2 in stage_list and os.environ.get("NVIDIA_API_KEY"):
            try:
                self.oracle.build()
                self.neural.set_oracle(self.oracle)
                self.log.info(
                    "oracle.ready",
                    library=self.config.target.name,
                    chunks=len(self.oracle._chunks),
                )
            except Exception as exc:
                self.log.warning("oracle.build_failed", error=str(exc))
                run.degraded_reasons.append(f"oracle build failed: {exc}")
                # Graceful degradation: continue without oracle

        # ── Wire context builder for Two-Brain architecture ──
        if 2 in stage_list and self.config.llm.architect:
            try:
                self.neural.set_context_builder(self.context_builder)
                self.log.info("context_builder.ready", library=self.config.target.name)
            except Exception as exc:
                self.log.warning("context_builder.failed", error=str(exc))
                run.degraded_reasons.append(f"context builder failed: {exc}")

        # ── Auto-download OSS-Fuzz corpus if not present ──
        self._ensure_oss_fuzz_corpus()

        # ── Pre-build library-level corpus minset (Rebert 2014, once per library) ──
        # Uses the instrumented binary if it already exists (e.g. from a previous run).
        # If the binary isn't built yet the call is a cheap no-op; the minset will be
        # built lazily during the first target's seed generation step instead.
        if 4 in stage_list and self.config.seeds.oss_fuzz_corpus:
            _unpatched_bin = Path(self.config.target.build_dir) / "fuzz_nemesis"
            if _unpatched_bin.exists():
                self.fuzzing.orchestrator._ensure_corpus_minset(
                    Path(self.config.seeds.oss_fuzz_corpus),
                    _unpatched_bin,
                )

        # ── Stage 1: Recon ──────────────────────────────────
        targets = []
        if 1 in stage_list:
            self.log.info("stage.start", stage=1, name="recon")
            targets = self.recon.run()
            # Filter out Introspector-derived targets that don't actually exist
            # in the local source. OSS-Fuzz Introspector indexes wrappers from
            # contrib/oss-fuzz/ (e.g. OSS_FUZZ_png_read_rows) which are absent
            # from the released source tree we are testing — they fail compile
            # or always report reaches_target=False, wasting an entire AFL slot.
            # Reuse the same source-existence check we use in _auto_discover_targets.
            try:
                src_root = Path(self.config.target.source_root)
                src_subdir = self.config.target.source_subdir or ""
                _filtered: list = []
                _dropped: list[str] = []
                for t in targets:
                    fpath = src_root / t.file_path
                    if not fpath.exists() and src_subdir:
                        fpath = src_root / src_subdir / t.file_path
                    if not fpath.exists():
                        # Cannot verify — keep (don't filter on read errors)
                        _filtered.append(t)
                        continue
                    try:
                        content = fpath.read_text(errors="replace")
                    except OSError:
                        _filtered.append(t)
                        continue
                    if f"{t.func_name}(" in content:
                        _filtered.append(t)
                    else:
                        _dropped.append(t.func_name)
                if _dropped:
                    self.log.info(
                        "recon.filtered_not_in_source",
                        dropped_count=len(_dropped),
                        dropped=_dropped[:10],
                        note="introspector wrappers / version-drift functions absent from local source",
                    )
                targets = _filtered
            except Exception as exc:
                self.log.debug("recon.source_filter_failed", error=str(exc))
            # Auto-discover overlooked 0%-coverage high-value targets
            if is_harness_strategy and self.config.engine.auto_discover_limit > 0:
                boosted = self._auto_discover_targets(targets, max_targets)
                if boosted:
                    boosted_names = {t.func_name for t in boosted}
                    # Fix 125: merge by priority_score (don't blindly prepend boosted)
                    targets = boosted + [t for t in targets if t.func_name not in boosted_names]
                    targets.sort(key=lambda t: t.priority_score, reverse=True)
            if max_targets > 0:
                targets = targets[:max_targets]
            self.log.info("stage.complete", stage=1, targets_found=len(targets))

        findings_base = Path(self.config.engine.work_dir) / "fuzzing" / "findings"

        # Fix 120: Dynamic time budget allocation.
        # If scan_budget_hours is set, divide evenly among targets with per_target_max_minutes cap.
        # If a target finishes early, its unused time is redistributed to remaining targets.
        _scan_budget_s = self.config.fuzzing.scan_budget_hours * 3600
        _per_target_cap_s = self.config.fuzzing.per_target_max_minutes * 60
        _budget_remaining_s = _scan_budget_s if _scan_budget_s > 0 else 0
        _n_remaining = len(targets)
        _scan_start = time.monotonic()

        # Fix 124: Load checkpoint for resume — skip targets already completed
        _checkpoint_run_id, _checkpoint_done = self._load_checkpoint(
            self.config.target.name,
        )
        if resume and _checkpoint_done:
            self.log.info(
                "checkpoint.loaded",
                completed=len(_checkpoint_done),
                run_id=_checkpoint_run_id,
            )
        _completed_funcs: list[str] = []

        # ── Process each target through stages 2-4 ─────────
        for target in targets:
            # Fix 124: skip targets already completed in checkpoint
            if resume and target.func_name in _checkpoint_done:
                self.log.info("checkpoint.skip", func=target.func_name)
                continue

            # Fix 120: compute dynamic timeout for this target
            # Fix 126: save/restore original to avoid shared config mutation
            _original_timeout_hours = self.config.fuzzing.timeout_hours
            if _budget_remaining_s > 0 and _n_remaining > 0:
                dynamic_timeout_s = _budget_remaining_s / _n_remaining
                if _per_target_cap_s > 0:
                    dynamic_timeout_s = min(dynamic_timeout_s, _per_target_cap_s)
                self.config.fuzzing.timeout_hours = dynamic_timeout_s / 3600
                self.log.info(
                    "budget.dynamic_timeout",
                    func=target.func_name,
                    timeout_min=round(dynamic_timeout_s / 60, 1),
                    remaining_budget_min=round(_budget_remaining_s / 60, 1),
                    targets_remaining=_n_remaining,
                )

            result = TargetResult(target=target, status=PipelineStatus.RUNNING)
            start = time.monotonic()

            # ── Resume logic ────────────────────────────────
            if resume:
                target_findings = findings_base / target.func_name
                if target_findings.exists():
                    crashes_dir = target_findings / "main" / "crashes"
                    if not crashes_dir.exists():
                        crashes_dir = target_findings / "default" / "crashes"
                    crash_files = (
                        [f for f in crashes_dir.glob("id:*") if f.is_file()]
                        if crashes_dir.exists()
                        else []
                    )
                    if crash_files:
                        self.log.info(
                            "target.resume_triage",
                            func=target.func_name,
                            crashes=len(crash_files),
                        )
                        try:
                            result = self._triage_existing(
                                target, result, stage_list, crashes_dir, target_findings
                            )
                        except Exception as e:
                            result.status = PipelineStatus.FAILED
                            self.log.error(
                                "target.triage_failed",
                                func=target.func_name,
                                error=str(e),
                                exc_info=True,
                            )
                    else:
                        self.log.info("target.skipped_resume", func=target.func_name)
                        result.status = PipelineStatus.SKIPPED
                    result.duration_seconds = time.monotonic() - start
                    run.results.append(result)
                    run.targets_processed += 1
                    if result.crashes:
                        run.targets_successful += 1
                        run.total_crashes += len(result.crashes)
                        run.total_cves += sum(
                            1 for c in result.crashes
                            if c.cwe != CWE.UNKNOWN and c.severity in (Severity.HIGH, Severity.MEDIUM)
                        )
                    run.total_llm_cost_usd += result.total_llm_cost_usd
                    continue

            self.log.info("target.start", func=target.func_name, file=target.file_path)

            # Reset work_root to clean state before each target (replaces git stash approach)
            # Strategy A: no rsync needed — library is never patched
            if not is_harness_strategy:
                self._sync_work_repo()

            try:
                result = self._process_target(target, result, stage_list)
            except Exception as e:
                result.status = PipelineStatus.FAILED
                self.log.error(
                    "target.failed",
                    func=target.func_name,
                    error=str(e),
                    exc_info=True,
                )

            result.duration_seconds = time.monotonic() - start
            run.results.append(result)
            run.targets_processed += 1

            # Fix 126: restore original timeout to avoid leaking into next target/deep phase
            self.config.fuzzing.timeout_hours = _original_timeout_hours

            # Fix 120: Update remaining budget after target completes
            if _budget_remaining_s > 0:
                elapsed_total = time.monotonic() - _scan_start
                _budget_remaining_s = max(0, _scan_budget_s - elapsed_total)
                _n_remaining -= 1
                if _budget_remaining_s <= 0 and _n_remaining > 0:
                    self.log.warning(
                        "budget.exhausted",
                        targets_remaining=_n_remaining,
                        elapsed_hours=round(elapsed_total / 3600, 2),
                    )
                    break  # Stop processing — budget exhausted

            if result.crashes:
                run.targets_successful += 1
                run.total_crashes += len(result.crashes)
                # CVE candidates: severity HIGH/MEDIUM + known CWE + NOT patch-induced
                # patch_induced=None means no patch was applied → always a real bug
                run.total_cves += sum(
                    1 for c in result.crashes
                    if c.cwe != CWE.UNKNOWN
                    and c.severity in (Severity.HIGH, Severity.MEDIUM)
                    and c.patch_induced is not True
                )

            run.total_llm_cost_usd += result.total_llm_cost_usd

            # Fix 124: Save checkpoint after each target
            _completed_funcs.append(target.func_name)
            self._save_checkpoint(run_id, _completed_funcs, self.config.target.name)

        run.finished_at = datetime.now()

        # ── Run-level success gate ──────────────────────────────
        # Previously execute() always returned a populated run that the CLI
        # treated as success — even when every target FAILED or no target was
        # processable. Classify the run so the CLI can exit non-zero.
        run.status, _gate_reasons = _classify_run_status(
            run.results, run.targets_processed, run.total_crashes
        )
        run.degraded_reasons.extend(_gate_reasons)
        if run.degraded_reasons:
            self.log.warning("run.degraded", status=run.status.value,
                             reasons=run.degraded_reasons)

        self._save_run(run)
        self._clear_checkpoint()  # Fix 124: clean up on successful completion
        return run

    def execute_deep(
        self,
        stage_list: list[int] | None = None,
        max_targets: int = 0,
        deep_top_n: int = 3,
        deep_timeout_hours: float = 4.0,
    ) -> PipelineRun:
        """
        Two-phase execution: scan → score → deep fuzz top-N.

        Phase 1 (scan): Run the full pipeline with short timeout (15 min/target).
        Phase 2 (deep): Score results, pick top-N targets, re-fuzz each for
                         deep_timeout_hours with full feedback iterations.

        Args:
            stage_list: Stages to run (default: all)
            max_targets: Max targets in scan phase (0 = all)
            deep_top_n: How many top targets to deep-fuzz (default 3)
            deep_timeout_hours: Per-target timeout for deep phase (default 4h)
        """
        # ── Phase 1: Scan ──
        self.log.info("deep.phase1_scan_start")
        # Save originals up-front; a try/finally guarantees they're restored even
        # if Phase 1 yields no targets (the early return below) or execute() raises.
        # Previously the early return leaked the 0.25h/1-iteration scan overrides
        # into the config for any later reuse (e.g. --auto-sanitizer passes).
        scan_timeout = self.config.fuzzing.timeout_hours
        scan_feedback = self.config.engine.max_feedback_iterations
        original_pinned = list(self.config.target.pinned_funcs)

        try:
            # Scan overrides
            self.config.fuzzing.timeout_hours = 0.25  # 15 min per target
            self.config.engine.max_feedback_iterations = 1

            scan_run = self.execute(
                stage_list=stage_list,
                max_targets=max_targets,
            )
            self.log.info(
                "deep.phase1_complete",
                targets=scan_run.targets_processed,
                crashes=scan_run.total_crashes,
            )

            # ── Score and rank targets ──
            scored = self._score_scan_results(scan_run)
            top_targets = scored[:deep_top_n]

            if not top_targets:
                self.log.warning("deep.no_targets_for_phase2")
                return scan_run  # finally restores config before returning

            self.log.info(
                "deep.phase2_targets",
                targets=[(name, f"{score:.1f}") for name, score in top_targets],
            )

            # ── Phase 2: Deep fuzz ──
            self.config.fuzzing.timeout_hours = deep_timeout_hours
            self.config.engine.max_feedback_iterations = scan_feedback

            # Rebuild targets list from scan results — only deep-fuzz the top-N
            deep_target_names = {name for name, _ in top_targets}

            # Pin the top-N targets so recon returns only them
            from nemesis.config import PinnedFunc
            self.config.target.pinned_funcs = []

            for result in scan_run.results:
                if result.target.func_name in deep_target_names:
                    self.config.target.pinned_funcs.append(PinnedFunc(
                        func_name=result.target.func_name,
                        file_path=result.target.file_path,
                        line=result.target.line,
                        has_memory_ops=result.target.has_memory_ops,
                        has_pointer_arith=result.target.has_pointer_arith,
                        force_no_blocker=result.target.force_no_blocker,
                    ))

            self.log.info("deep.phase2_start", timeout_h=deep_timeout_hours, targets=deep_top_n)

            # Reset recon cache so it picks up the new pinned_funcs
            self._recon = None

            deep_run = self.execute(
                stage_list=stage_list,
                max_targets=deep_top_n,
            )
        finally:
            # Always restore — even on the early return or an exception.
            self.config.target.pinned_funcs = original_pinned
            self.config.fuzzing.timeout_hours = scan_timeout
            self.config.engine.max_feedback_iterations = scan_feedback
            self._recon = None  # invalidate so next recon uses the restored pinned_funcs

        # ── Merge scan + deep WITHOUT double-counting the deep (top-N) targets ──
        # deep_run holds the top-N re-fuzzed with full budget; keep those and append
        # the scan results for every OTHER target, then recompute totals from the
        # union. The old code did `deep += scan`, counting the top-N twice.
        deep_names = {r.target.func_name for r in deep_run.results}
        combined = list(deep_run.results) + [
            r for r in scan_run.results if r.target.func_name not in deep_names
        ]
        deep_run.results = combined
        deep_run.targets_processed = len(combined)
        deep_run.targets_successful = sum(1 for r in combined if r.crashes)
        deep_run.total_crashes = sum(len(r.crashes) for r in combined)
        deep_run.total_cves = sum(
            1
            for r in combined
            for c in r.crashes
            if c.cwe != CWE.UNKNOWN
            and c.severity in (Severity.HIGH, Severity.MEDIUM)
            and c.patch_induced is not True
        )

        return deep_run

    def _score_scan_results(
        self, run: PipelineRun
    ) -> list[tuple[str, float]]:
        """
        Score targets after a scan phase for deep-fuzz prioritization.

        Scoring criteria (higher = more promising):
          +20  compile_time blocker + build success → CVE sweet spot
          +15  no blocker + build success → directly reachable
          +10  coverage still growing (more time would find more)
          +25  has crashes already → re-fuzz for confirmation
          -10  runtime blocker → seed/dict approach, less unique value
          -20  build failed → no point deep-fuzzing
          +N   map_density bonus (higher = more code reached)
        """
        scores: list[tuple[str, float]] = []

        for result in run.results:
            s = 0.0
            name = result.target.func_name

            # Build status — but don't penalize if fuzzer actually ran and got coverage
            has_afl_coverage = (
                result.afl_stats and result.afl_stats.map_density_pct > 0
            )
            if result.status == PipelineStatus.FAILED and not has_afl_coverage:
                s -= 20.0
            elif result.status == PipelineStatus.SKIPPED:
                s -= 15.0

            # Blocker classification
            if result.analysis:
                bc = result.analysis.blocker_class
                if bc == "compile_time" and result.status != PipelineStatus.FAILED:
                    s += 20.0
                elif not result.analysis.has_blocker and result.status != PipelineStatus.FAILED:
                    s += 15.0
                elif bc == "runtime" and not has_afl_coverage:
                    # Only penalize runtime blockers that got 0 coverage
                    # (if fuzzer reached code despite "runtime blocker", LLM misclassified)
                    s -= 10.0

            # Crashes → always deep-fuzz
            if result.crashes:
                s += 25.0

            # Coverage density
            if result.afl_stats and result.afl_stats.map_density_pct > 0:
                s += min(result.afl_stats.map_density_pct * 2, 15.0)
                # Stability bonus
                if result.afl_stats.stability_pct > 90:
                    s += 5.0

            # Exec speed — faster = more mutations explored per hour
            if result.afl_stats and result.afl_stats.exec_per_sec > 100:
                s += 5.0

            scores.append((name, s))

            self.log.info(
                "deep.score",
                func=name,
                score=round(s, 1),
                blocker_class=result.analysis.blocker_class if result.analysis else "?",
                status=result.status.value,
                crashes=len(result.crashes),
                map_density=result.afl_stats.map_density_pct if result.afl_stats else 0,
            )

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    # ── Auto-discovery of overlooked high-value targets ──────

    def _read_function_source(self, target) -> str:
        """Read ±50 lines around target function from source, capped at 3000 chars."""
        try:
            source_root = Path(self.config.target.source_root)
            fpath = source_root / target.file_path
            if not fpath.exists() and self.config.target.source_subdir:
                fpath = source_root / self.config.target.source_subdir / target.file_path
            if not fpath.exists():
                return ""
            lines = fpath.read_text(errors="replace").splitlines()
            center = max(0, target.line - 1)  # 0-indexed
            start = max(0, center - 50)
            end = min(len(lines), center + 50)
            snippet = "\n".join(lines[start:end])
            return snippet[:3000]
        except Exception:
            return ""

    def _auto_discover_targets(
        self,
        all_targets: list,
        max_targets: int,
    ) -> list:
        """Find overlooked 0%-coverage targets and boost those with non-trivial planner hints.

        Algorithm:
        1. Determine which targets would be selected without intervention (top max_targets).
        2. Filter 'overlooked': 0% coverage, not in would-select, priority > 5.0,
           and not cleanup/init functions.
        3. For top N candidates, call plan_harness(). If hint is non-empty, boost to 50.0.
        4. Return boosted targets only.
        """
        limit = self.config.engine.auto_discover_limit
        if limit <= 0:
            return []

        try:
            effective_max = max_targets if max_targets > 0 else len(all_targets)
            would_select = {t.func_name for t in all_targets[:effective_max]}

            # Cleanup/init/internal function name fragments to skip
            _skip_fragments = {"Free", "Init", "Clear", "Reset", "Destroy", "Internal"}

            # Fix 125: skip pinned targets — they already have config
            # (direct_internal, harness_hint, etc.) and don't need auto-discovery
            pinned_names = {
                t.func_name for t in all_targets
                if t.priority_score >= 100.0
                or getattr(t, "direct_internal", False)
            }

            overlooked = [
                t for t in all_targets
                if t.coverage_pct == 0.0
                and t.func_name not in would_select
                and t.func_name not in pinned_names  # Fix 125
                and t.priority_score > 5.0
                and not any(frag in t.func_name for frag in _skip_fragments)
            ]
            # Sort by priority_score descending — best candidates first
            overlooked.sort(key=lambda t: t.priority_score, reverse=True)

            if not overlooked:
                self.log.info("auto_discover.none_found")
                return []

            self.log.info(
                "auto_discover.overlooked_count",
                count=len(overlooked),
                top3=[t.func_name for t in overlooked[:3]],
            )

            boosted = []
            for t in overlooked[:limit]:
                source_snippet = self._read_function_source(t)
                # Defense against version drift: Introspector's all-functions list
                # comes from CURRENT upstream, not the source_root we are testing.
                # When we backtest an older version, Introspector may surface functions
                # that do not exist in the local source (e.g. TIFFOpenWExt added
                # post-libtiff-4.3.0). We must not promote those — the LLM will
                # cheerfully synthesize a harness against them and the linker will
                # fail with `undefined reference to <func>`.
                #
                # _read_function_source returns ±50 lines around `target.line`. If the
                # function does not exist at that line in our checkout, the snippet is
                # unrelated nearby code, not empty. So validate by checking that the
                # function name actually appears in the local file as a definition.
                _func_present = False
                try:
                    _src_root = Path(self.config.target.source_root)
                    _fpath = _src_root / t.file_path
                    if not _fpath.exists() and self.config.target.source_subdir:
                        _fpath = _src_root / self.config.target.source_subdir / t.file_path
                    if _fpath.exists():
                        _content = _fpath.read_text(errors="replace")
                        # Match definition-like occurrence: `func_name(` or `* func_name(`
                        # Cheap regex would be more precise, but substring is sufficient
                        # given the function name is library-prefixed (e.g. "TIFFOpenW").
                        _func_present = (f"{t.func_name}(" in _content)
                except Exception:
                    _func_present = True  # don't filter on read error — let it through
                if not _func_present:
                    self.log.info(
                        "auto_discover.skipped_not_in_source",
                        func=t.func_name,
                        file=str(t.file_path),
                        note="introspector listed function but it is absent from local source — likely version drift",
                    )
                    continue
                oracle_ctx = ""
                if self._oracle is not None and self._oracle.is_built():
                    oracle_ctx = self._oracle.query(t.func_name, k=5)
                hint, indirect_reach = self.neural.plan_harness(
                    target_func=t.func_name,
                    source_snippet=source_snippet,
                    oracle_context=oracle_ctx,
                )
                if hint:
                    t.harness_hint = hint
                    t.priority_score = 50.0
                    if indirect_reach:
                        t.force_no_blocker = True  # indirect targets skip patch generation
                    boosted.append(t)
                    self.log.info(
                        "auto_discover.promoted",
                        func=t.func_name,
                        hint_len=len(hint),
                        indirect_reach=indirect_reach,
                    )
                else:
                    self.log.info(
                        "auto_discover.skipped_no_hint",
                        func=t.func_name,
                    )

            return boosted
        except Exception as exc:
            self.log.warning("auto_discover.failed", error=str(exc))
            return []

    def _process_target(
        self,
        target,
        result: TargetResult,
        stage_list: list[int],
    ) -> TargetResult:
        """Process a single target through the pipeline stages."""
        is_harness = self.config.fuzzing.strategy == "harness"

        # ── Stage 1 continuation: extract context ───────────
        if 1 in stage_list:
            context = self.recon.extract_context(target)
        else:
            context = AnalysisContext(
                target=target,
                call_chain=target,  # placeholder
            )

        # ── Auto Harness Planner: generate per-target hint ──
        if (
            is_harness
            and 2 in stage_list
            and not target.harness_hint
        ):
            try:
                # Check library memory cache first
                cached_hint = self.library_memory.get_planner_hint(target.func_name)
                if cached_hint:
                    target.harness_hint = cached_hint
                    self.log.info(
                        "planner.hint_cached",
                        func=target.func_name,
                        hint_len=len(cached_hint),
                    )
                elif getattr(target, "indirect_reach", False):
                    # YAML pinned the function with indirect_reach=true. Skip the
                    # planner entirely: empirically, planners hallucinate direct-
                    # call recipes (root_table allocation, internal-header
                    # includes) that override the harness_template's "use the
                    # public API" guidance. Replace the planner hint with a
                    # canonical "use the primary decoder, do not call directly"
                    # fallback so the architect can't drift into an encoder path
                    # or a custom data-provider scheme.
                    target.harness_hint = (
                        f"INDIRECT-REACH pinned target: `{target.func_name}` lives in "
                        f"`{target.file_path}` and is INTERNAL — its parameters use "
                        "private types not declared in any public header. DO NOT "
                        "attempt to call it directly. DO NOT allocate Huffman/state "
                        "tables, reader contexts, or other internal structs in your "
                        "harness.\n\n"
                        "Instead: read the entire fuzz input as the format the library "
                        "primarily parses, and pass it to the library's PRIMARY READER "
                        "function (the one shown in the PROVEN WORKING TEMPLATE inside "
                        "the system prompt — e.g. WebPDecodeRGBA for libwebp, "
                        "png_read_info for libpng). The library will reach the target "
                        "function internally during normal parsing.\n\n"
                        "Include only public headers (the ones listed in <api_declarations>). "
                        "NEVER #include any internal `src/...` header. NEVER #include "
                        "`fuzz_data_provider.h` — that header does not exist; use AFL's "
                        "`__AFL_FUZZ_TESTCASE_BUF` / `__AFL_FUZZ_TESTCASE_LEN` directly."
                    )
                    self.log.info(
                        "planner.skipped_for_indirect_reach_pin",
                        func=target.func_name,
                        reason="canonical fallback hint installed; harness_template guides architect",
                    )
                else:
                    # Get source snippet for the planner
                    source_snippet = next(iter(context.source_snippets.values()), "")
                    # Get oracle context if available
                    oracle_ctx = ""
                    if self._oracle is not None and self._oracle.is_built():
                        oracle_ctx = self._oracle.query(target.func_name, k=5)
                    hint, indirect_reach = self.neural.plan_harness(
                        target_func=target.func_name,
                        source_snippet=source_snippet,
                        oracle_context=oracle_ctx,
                    )
                    if hint:
                        target.harness_hint = hint
                        if indirect_reach:
                            target.indirect_reach = True
                        self.log.info(
                            "planner.hint_set",
                            func=target.func_name,
                            hint_len=len(hint),
                            indirect_reach=indirect_reach,
                        )
            except Exception as e:
                self.log.warning(
                    "planner.failed",
                    func=target.func_name,
                    error=str(e),
                )

        # ── Stage 2: Neural analysis ────────────────────────
        if 2 in stage_list:
            self.log.info(
                "stage.start", stage=2, name="neural",
                func=target.func_name, strategy=self.config.fuzzing.strategy,
            )

            if is_harness:
                # Strategy A: harness-driven analysis (no blockers, no patches)
                analysis = self.neural.analyze_for_harness(context)
                result.analysis = analysis
                # Fix D: Multi-Variant Best-of-3 — generate 3 candidates, pick best.
                # Only if symbolic stage is available (needed for profiling).
                lib_mem_snippet = self.library_memory.build_prompt_snippet()
                harness = self._select_best_harness_variant(
                    analysis, context, lib_mem_snippet,
                )
                result.harness = harness
            else:
                # Strategy B (default): blocker analysis + optional patch
                analysis = self.neural.analyze(context)
                result.analysis = analysis

                self.log.info(
                    "blocker.assessed",
                    func=target.func_name,
                    has_blocker=analysis.has_blocker,
                    blocker_class=analysis.blocker_class,
                    description=analysis.blocker_description[:80] if analysis.blocker_description else "",
                )

                # Patch routing based on blocker classification:
                # - no blocker → skip patch, go straight to harness
                # - compile_time → patch (comment out preprocessor guard)
                # - runtime → skip patch, generate AFL dictionary instead
                skip_patch = not analysis.has_blocker or target.force_no_blocker
                if not skip_patch and analysis.blocker_class == "runtime":
                    self.log.info(
                        "patch.skipped_runtime_blocker",
                        func=target.func_name,
                        reason="runtime guards need seeds/dictionary, not patching",
                    )
                    skip_patch = True

                if skip_patch:
                    if target.force_no_blocker:
                        self.log.info("patch.skipped_forced", func=target.func_name)
                    elif not analysis.has_blocker:
                        self.log.info("patch.skipped_no_blocker", func=target.func_name)
                else:
                    patch = self.neural.generate_patch(analysis, context)
                    result.patch = patch

                lib_mem_snippet = self.library_memory.build_prompt_snippet()
                harness = self._select_best_harness_variant(
                    analysis, context, lib_mem_snippet,
                )
                result.harness = harness

            result.total_llm_cost_usd += self.neural.session_cost

        # ── Proactive caller escalation for static functions ──
        # Static functions cannot be called directly from a harness.
        # If the oracle is available, replace the harness NOW (before build)
        # with one targeting a public caller — avoids a wasted build+profile cycle.
        # Fix 123: skip for direct_internal targets — they call the function directly.
        if (
            is_harness
            and target.is_static
            and not getattr(target, "direct_internal", False)
            and result.harness
            and self._oracle is not None
            and self._oracle.is_built()
            and 2 in stage_list
        ):
            callers = self._oracle.find_callers(target.func_name, k=5)
            if callers:
                self.log.info(
                    "caller_escalation.proactive",
                    func=target.func_name,
                    callers=[c.name for c in callers[:3]],
                )
                escalated_harness = self.neural.generate_harness_via_caller(
                    target.func_name, callers, context,
                    previous_harness_code=result.harness.c_code if result.harness else "",
                )
                result.total_llm_cost_usd += self.neural.session_cost
                if escalated_harness and escalated_harness.c_code:
                    # Fix 101: keep original harness as fallback in case escalated one
                    # fails to compile (caller escalation LLM often uses non-standard AFL headers)
                    self._caller_escalation_original_harness = result.harness
                    self._propagate_target_flags(target, escalated_harness)  # Fix 127
                    result.harness = escalated_harness

        # ── Stage 3: Symbolic verification ──────────────────
        if 3 in stage_list:
            self.log.info("stage.start", stage=3, name="symbolic", func=target.func_name)

            # Fix 95: propagate is_static to harness so preflight skips direct-call check
            if result.harness and target.is_static:
                result.harness.is_static = True
            # Fix 114: propagate indirect_reach to harness so preflight accepts public API calls
            if result.harness and getattr(target, "indirect_reach", False):
                result.harness.indirect_reach = True
            # Fix 123: propagate direct_internal — harness calls function directly
            if result.harness and getattr(target, "direct_internal", False):
                result.harness.direct_internal = True

            if is_harness:
                # Strategy A: no patch, no Z3 — just build harness against unmodified library
                self.log.info("stage3.strategy_a_harness_only", func=target.func_name)
                build_ok = self.symbolic.build_harness_only(result.harness)
                # Fix 101: if escalated harness failed to compile, fallback to original
                if not build_ok and hasattr(self, "_caller_escalation_original_harness"):
                    original = self._caller_escalation_original_harness
                    if original and original.c_code:
                        self.log.warning(
                            "caller_escalation.compile_failed_fallback",
                            func=target.func_name,
                            hint="reverting to pre-escalation harness",
                        )
                        result.harness = original
                        self._propagate_target_flags(target, result.harness)  # Fix 127
                        build_ok = self.symbolic.build_harness_only(result.harness)
                    del self._caller_escalation_original_harness
                # Fix 82: build standalone runner (no AFL macros, ASAN only) for crash triage
                # Fix 88: set unpatched_binary so hang verification can filter
                # AFL persistent-mode false positives (even without patches)
                unpatched_ok = self.symbolic.build_unpatched_debug(result.harness)
                if unpatched_ok:
                    debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
                    self.fuzzing.triager.unpatched_binary = debug_bin
                    self.log.info("unpatched.debug_binary.ready", binary=str(debug_bin))
                else:
                    self.log.warning("unpatched.debug_binary.failed", func=target.func_name)
                    self.fuzzing.triager.unpatched_binary = None
            else:
                has_patch = result.patch and result.patch.file_path

                if has_patch:
                    # Full path: Z3 verify → apply patch → build library + harness
                    verification = self.symbolic.verify(result.patch, context)
                    result.verification = verification

                    if not verification.is_satisfiable:
                        self.log.warning(
                            "verification.unsat",
                            func=target.func_name,
                            unsat_core=verification.unsat_core,
                        )
                        result.status = PipelineStatus.SKIPPED
                        return result

                    build_ok = self.symbolic.apply_and_build(result.patch, result.harness)

                    # ── Stage 3.5: Unpatched verification binary ─────
                    # Build a clean ASAN binary (no AFL, no patch) so the triager can
                    # distinguish patch-induced crashes from real pre-existing bugs.
                    self.log.info("stage.start", stage="3.5", name="unpatched_build", func=target.func_name)
                    unpatched_ok = self.symbolic.build_unpatched_debug(result.harness)
                    if unpatched_ok:
                        debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
                        self.fuzzing.triager.unpatched_binary = debug_bin
                        self.log.info("unpatched.ready", binary=str(debug_bin))
                    else:
                        self.fuzzing.triager.unpatched_binary = None
                        self.log.warning("unpatched.unavailable", func=target.func_name)
                else:
                    # No-blocker path: no patch needed for the bug to surface,
                    # but the triager still needs the unpatched debug binary
                    # so it can filter AFL persistent-mode false positives
                    # (sig:04 SIGILL from __AFL_LOOP state corruption,
                    # sig:13 SIGPIPE, sig:07 SIGBUS) — these are unrelated to
                    # patching. Without the debug binary, _verify_crash_standalone
                    # short-circuits with "no unpatched_binary available" and
                    # returns True for every crash, so every persistent-mode
                    # artifact leaks into findings.yaml with cve_id=null,
                    # crash_type=UNKNOWN, and empty asan_error. The libsndfile
                    # sf_seek run on 2026-05-13 produced 21 sig:04 crashes that
                    # all open/seek/close cleanly in standalone — those should
                    # have been filtered here.
                    self.log.info("stage3.harness_only", func=target.func_name)
                    build_ok = self.symbolic.build_harness_only(result.harness)
                    if build_ok:
                        unpatched_ok = self.symbolic.build_unpatched_debug(result.harness)
                        if unpatched_ok:
                            debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
                            self.fuzzing.triager.unpatched_binary = debug_bin
                            self.log.info("unpatched.standalone_verify_ready", binary=str(debug_bin))
                        else:
                            self.fuzzing.triager.unpatched_binary = None
                            self.log.warning(
                                "unpatched.standalone_verify_unavailable",
                                func=target.func_name,
                                note="AFL persistent-mode artifacts will NOT be filtered",
                            )
                    else:
                        self.fuzzing.triager.unpatched_binary = None

            if not build_ok:
                # Fix 131: Last-resort fallback — try saved harness before giving up.
                # When all LLM variants + repairs fail compilation, a previously
                # validated harness (from config/targets/{lib}/harnesses/) can rescue
                # the target. Without this, targets like BackwardReferences silently
                # fail even though a working saved harness exists.
                saved_path = self._saved_harness_path(target.func_name)
                if saved_path.exists():
                    self.log.info(
                        "build.failed_trying_saved_harness",
                        func=target.func_name,
                        path=str(saved_path),
                    )
                    saved_code = saved_path.read_text()
                    if result.harness:
                        result.harness = result.harness.model_copy(
                            update={"c_code": saved_code},
                        )
                    else:
                        result.harness = HarnessSpec(
                            target_func=target.func_name,
                            input_format="",
                            c_code=saved_code,
                        )
                    # Propagate flags to saved harness
                    if getattr(target, "indirect_reach", False):
                        result.harness.indirect_reach = True
                    if getattr(target, "direct_internal", False):
                        result.harness.direct_internal = True
                    build_ok = self.symbolic.build_harness_only(result.harness)
                    if build_ok:
                        self.log.info(
                            "build.saved_harness_rescued",
                            func=target.func_name,
                        )
                        # Fix 132: rebuild debug binary with saved harness
                        # Without this, triage.crash_verify_skipped fires
                        # and FP crashes pass through unverified.
                        unpatched_ok = self.symbolic.build_unpatched_debug(
                            result.harness,
                        )
                        if unpatched_ok:
                            debug_bin = (
                                Path(self.config.target.debug_build_dir)
                                / "fuzz_nemesis_debug"
                            )
                            self.fuzzing.triager.unpatched_binary = debug_bin
                            self.log.info(
                                "unpatched.debug_binary.ready",
                                binary=str(debug_bin),
                            )
                        else:
                            self.fuzzing.triager.unpatched_binary = None

                if not build_ok:
                    self.log.warning("build.failed", func=target.func_name)
                    # Record planner hint failure for future cache lookups
                    if target.harness_hint:
                        self.library_memory.record_planner_hint(
                            func_name=target.func_name,
                            hint=target.harness_hint,
                            compiled=False,
                            reached=False,
                        )
                    result.status = PipelineStatus.FAILED
                    return result

            # ── Pre-fuzz profiling: check if harness reaches target ──
            # Fix 95: removed `not target.is_static` guard — static functions
            # ALSO need profiling + caller escalation (they are reached indirectly).
            if result.harness:
                reaches = self._verify_harness_reaches_target(target, result)
                if reaches is False:
                    # Fix 127 + 2026-05-08 audit: skip post-build caller
                    # escalation when the harness already proved
                    # reachable during variant-selection profiling. The
                    # post-build GDB single-seed probe is a false-negative
                    # magnet (cross-TU breakpoints don't fire reliably,
                    # public API targets like libtiff `TIFFReadRGBATileExt`
                    # also miss). The variant profiler is bitmap-aware
                    # (Fix 116) — if it says reached, trust it
                    # unconditionally. Bypass when ANY of:
                    #   - direct_internal: explicit YAML opt-in
                    #   - variant_function_reached / coverage_pct ≥ 100
                    #     (the variant profiler accepted the harness)
                    # The earlier (indirect_reach AND variant_reached)
                    # gate was too narrow — public API pins like
                    # TIFFReadRGBATileExt have indirect_reach=False yet
                    # still suffer the GDB false-negative.
                    variant_cov = (
                        getattr(result.harness, "variant_coverage_pct", None)
                        or getattr(result.harness, "coverage_pct", 0.0)
                        or 0.0
                    )
                    variant_reached = (
                        bool(getattr(result.harness, "variant_function_reached", False))
                        or bool(getattr(result.harness, "function_reached", False))
                        or variant_cov >= 100.0
                    )
                    bypass = (
                        bool(getattr(target, "direct_internal", False))
                        or variant_reached
                    )
                    if bypass:
                        self.log.info(
                            "profiling.direct_internal_bypass",
                            func=target.func_name,
                            direct_internal=bool(getattr(target, "direct_internal", False)),
                            indirect_reach=bool(getattr(target, "indirect_reach", False)),
                            is_static=bool(getattr(target, "is_static", False)),
                            variant_coverage_pct=variant_cov,
                            hint="trust variant-profile reachability; skip caller escalation, proceed to fuzz",
                        )
                    else:
                        self.log.warning(
                            "profiling.target_unreached",
                            func=target.func_name,
                            action="trying_caller_escalation",
                        )
                        # Fix 98: Before giving up, try caller escalation — build a harness
                        # targeting a higher-level function that calls the target internally.
                        # Skip if already proactively escalated (static functions).
                        escalated = False
                        if (
                            self._oracle is not None
                            and self._oracle.is_built()
                            and 2 in stage_list
                            and not target.is_static  # already proactively escalated
                        ):
                            callers = self._oracle.find_callers(target.func_name, k=5)
                            if callers:
                                self.log.info(
                                    "caller_escalation.profiling_fallback",
                                    func=target.func_name,
                                    callers=[c.name for c in callers[:3]],
                                )
                                escalated_harness = self.neural.generate_harness_via_caller(
                                    target.func_name, callers, context,
                                    previous_harness_code=result.harness.c_code if result.harness else "",
                                )
                                result.total_llm_cost_usd += self.neural.session_cost
                                if escalated_harness:
                                    self._propagate_target_flags(target, escalated_harness)
                                    build_ok = self.symbolic.build_harness_only(escalated_harness)
                                    if build_ok:
                                        result.harness = escalated_harness
                                        escalated = True
                                        self.log.info(
                                            "caller_escalation.profiling_fallback.built",
                                            func=target.func_name,
                                            caller_func=escalated_harness.target_func,
                                        )
                        if not escalated:
                            result.status = PipelineStatus.SKIPPED
                            return result

        # ── Stage 4: Fuzzing + feedback loop ────────────────
        if 4 in stage_list and result.harness:
            if is_harness:
                result = self._fuzz_with_harness_feedback(target, result, context, stage_list)
            else:
                result = self._fuzz_with_feedback(target, result, context, stage_list)

        if result.crashes:
            result.status = PipelineStatus.SUCCESS
        elif result.status == PipelineStatus.RUNNING:
            result.status = PipelineStatus.FAILED

        return result

    @staticmethod
    def _propagate_target_flags(target, harness) -> None:
        """Fix 127: re-propagate target flags to harness after any replacement.

        Multiple pipeline paths replace result.harness with a new HarnessSpec
        (caller escalation, refinement, repair). The new object loses flags
        like direct_internal/indirect_reach/is_static. Call this after every
        harness replacement to ensure compile flags (-I internal dirs) are added.
        """
        if getattr(target, "direct_internal", False):
            harness.direct_internal = True
        if getattr(target, "indirect_reach", False):
            harness.indirect_reach = True
        if getattr(target, "is_static", False):
            harness.is_static = True

    def _verify_harness_reaches_target(
        self,
        target,
        result: TargetResult,
    ) -> Optional[bool]:
        """Run the debug harness once with a seed to check if target function is reached.

        Uses gdb with a breakpoint on the target function. If the breakpoint is hit,
        the harness reaches the target. Returns True/False/None (None = inconclusive).

        Fix 99: ensure_seeds() populates format-specific seeds BEFORE profiling.
        Previously fell back to 64 null bytes → no format magic → always missed.
        Now tries up to 5 seeds (sorted by size) for better coverage.
        """
        import subprocess

        debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
        if not debug_bin.exists():
            return None  # can't verify without debug binary

        # Fix 99: generate format-specific seeds before profiling (idempotent).
        # Previously seeds only existed after Stage 4, so profiling always used
        # 64 null bytes → never reached any format parser → function_reached=False.
        if result.harness:
            self.fuzzing.ensure_seeds(
                result.harness,
                target_file_path=getattr(target, "file_path", ""),
            )

        # Find seed files to test with
        # Fix 100: prioritize format-specific seeds (prebuilt_*, seed.*) over
        # tiny corpus files (1-8 bytes) that can never trigger format parsers.
        # Previous sort (ascending size) always picked 1-8 byte corpus files
        # → no format magic → parser rejects → function_reached=False always.
        slug = target.func_name
        seeds_dir = Path(self.config.engine.work_dir) / "fuzzing" / "seeds" / slug
        seed_files: list[Path] = []
        if seeds_dir.exists():
            all_seeds = [
                f for f in seeds_dir.iterdir()
                if f.is_file() and f.stat().st_size > 0
                and not f.name.startswith(".")
            ]
            # Split: format seeds first (prebuilt_*, seed.*, *.tar, *.xar etc.)
            # then corpus files sorted by size descending (bigger = more likely valid)
            format_seeds = [f for f in all_seeds if not f.name.startswith("corpus_")]
            corpus_seeds = [f for f in all_seeds if f.name.startswith("corpus_")]
            format_seeds.sort(key=lambda f: f.stat().st_size, reverse=True)
            corpus_seeds.sort(key=lambda f: f.stat().st_size, reverse=True)
            seed_files = format_seeds + corpus_seeds
        if not seed_files:
            # Last-resort: minimal null seed (unlikely to reach deep functions)
            fallback = seeds_dir / "_profiling_seed"
            seeds_dir.mkdir(parents=True, exist_ok=True)
            fallback.write_bytes(b"\x00" * 64)
            seed_files = [fallback]

        # Fix 143: measure HIT RATE across all sampled seeds, not just "any hit".
        # Previously a single GDB hit returned True even when 1/247 seeds reached
        # the function — a frail signal because AFL's mutator quickly diverges
        # from that single seed and the function never gets re-exercised at the
        # mutation distribution. Now we sample up to 8 seeds and report the
        # ratio. Caller decides what threshold counts as "reachable enough".
        asan_env = {
            **os.environ,
            "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:halt_on_error=0",
        }
        sample = seed_files[:8]
        hits = 0
        first_hit_seed = ""
        seeds_tried = 0
        for seed_file in sample:
            seeds_tried += 1
            try:
                gdb_result = subprocess.run(
                    [
                        "gdb", "-batch",
                        "-ex", f"break {target.func_name}",
                        "-ex", f"run < {seed_file}",
                        "-ex", "info breakpoints",
                        str(debug_bin),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=asan_env,
                )
                output = gdb_result.stdout + gdb_result.stderr
                hit = (
                    f"Breakpoint 1, {target.func_name}" in output
                    or "breakpoint already hit" in output
                )
                if hit:
                    hits += 1
                    if not first_hit_seed:
                        first_hit_seed = seed_file.name
            except subprocess.TimeoutExpired:
                self.log.debug(
                    "profiling.timeout", func=target.func_name, seed=seed_file.name,
                )
                continue
            except (FileNotFoundError, OSError) as e:
                self.log.warning("profiling.error", func=target.func_name, error=str(e))
                return None  # binary or gdb missing — inconclusive

        if seeds_tried == 0:
            return False
        hit_rate = hits / seeds_tried
        # >=20% of sampled seeds reach the target → harness is robust enough.
        # 1/8 (12.5%) is the gray zone: function is reachable but the seed
        # distribution doesn't exercise it. Below 1/8, treat as "harness
        # essentially never invokes the target body" and refuse the green
        # light — pipeline should fall back to refinement / different harness.
        reaches = hit_rate >= 0.20
        self.log.info(
            "profiling.result",
            func=target.func_name,
            reaches_target=reaches,
            hit_rate=round(hit_rate, 3),
            hits=hits,
            seeds_tested=seeds_tried,
            first_hit_seed=first_hit_seed,
        )
        return reaches

    def _resolve_afl_queue_dir(self, slug: str) -> Optional[Path]:
        """Resolve the AFL queue directory for a given target slug.

        Fix 105: AFL writes to ``fuzzing/findings/{run_id}/{slug}/main/queue/``
        but several methods were looking in the non-existent
        ``fuzzing/afl_out/{slug}/main/queue/``.  Use the ``current`` symlink
        (always points to the active run) for a robust lookup.
        """
        base = Path(self.config.engine.work_dir) / "fuzzing" / "findings" / "current"
        queue = base / slug / "main" / "queue"
        if queue.exists():
            return queue
        # Fallback: some AFL configs put queue directly under slug
        queue = base / slug / "queue"
        if queue.exists():
            return queue
        return None

    def _run_ubsan_sweep(self, target_name: str) -> list[CrashReport]:
        """Run the AFL corpus through the UBSan binary to catch undefined behavior.

        Only runs if the target has a UBSan build directory configured and the
        UBSan harness binary exists (built by symbolic.build_ubsan_debug()).
        """
        ubsan_build_dir = Path(self.config.target.ubsan_build_dir) if self.config.target.ubsan_build_dir else None
        if not ubsan_build_dir or not str(ubsan_build_dir):
            return []
        ubsan_binary = ubsan_build_dir / "fuzz_nemesis_ubsan"
        if not ubsan_binary.exists():
            return []
        try:
            return self.fuzzing.sweep_corpus_ubsan(
                ubsan_binary=ubsan_binary,
                target_name=target_name,
            )
        except Exception as exc:
            self.log.debug("ubsan_sweep.error", func=target_name, error=str(exc))
            return []

    def _measure_post_fuzz_coverage(
        self,
        target,
        result: TargetResult,
    ) -> float:
        """Sample the AFL corpus and measure what % of inputs reach the target function.

        After AFL finishes, takes up to 10 files from the fuzz queue and runs the debug
        binary under gdb to check how many trigger the target function. Returns 0-100%.

        This is Fix C: function-level coverage signal.
        """
        import subprocess as _sp

        debug_bin = Path(self.config.target.debug_build_dir) / "fuzz_nemesis_debug"
        if not debug_bin.exists():
            self.log.info("post_fuzz_cov.no_debug_binary", func=target.func_name, path=str(debug_bin))
            return 0.0

        # Fix 105: use _resolve_afl_queue_dir (was looking in non-existent afl_out/)
        slug = target.func_name
        queue_dir = self._resolve_afl_queue_dir(slug)
        if not queue_dir:
            self.log.debug("post_fuzz_cov.no_queue", func=target.func_name)
            return 0.0

        # Sample up to 10 queue files (skip the dummy seed)
        queue_files = [
            f for f in sorted(queue_dir.iterdir())
            if f.is_file() and f.stat().st_size > 0 and not f.name.startswith(".")
        ][:10]
        if not queue_files:
            return 0.0

        hits = 0
        asan_env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:halt_on_error=0"}
        for corpus_file in queue_files:
            try:
                gdb_result = _sp.run(
                    [
                        "gdb", "-batch",
                        "-ex", f"break {target.func_name}",
                        "-ex", f"run < {corpus_file}",
                        "-ex", "info breakpoints",
                        str(debug_bin),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=asan_env,
                )
                out = gdb_result.stdout + gdb_result.stderr
                if (
                    f"Breakpoint 1, {target.func_name}" in out
                    or "breakpoint already hit" in out
                ):
                    hits += 1
            except (OSError, _sp.TimeoutExpired):
                pass

        pct = (hits / len(queue_files)) * 100.0
        self.log.info(
            "post_fuzz_cov.result",
            func=target.func_name,
            hits=hits,
            samples=len(queue_files),
            pct=round(pct, 1),
        )
        return pct

    def _measure_source_coverage(self, target, result: "TargetResult") -> float:
        """Measure real source-line coverage of target function using LLVM source coverage.

        Lazily builds the coverage library on first call. Uses LLVM profdata/cov
        to measure actual source-line coverage of the specific target function,
        which is directly comparable to OSS-Fuzz Introspector's runtime_coverage_percent.

        Returns 0.0-100.0 on success, -1.0 if measurement failed or not configured.
        """
        if not self.config.target.build.coverage_configure:
            return -1.0  # no coverage build configured

        # Lazy build: coverage library (once per run)
        if not getattr(self, "_coverage_library_built", False):
            ok = self.symbolic.build_coverage_library()
            self._coverage_library_built = ok
            if not ok:
                return -1.0

        # Fix 105: use _resolve_afl_queue_dir (was looking in non-existent afl_out/)
        slug = target.func_name
        queue_dir = self._resolve_afl_queue_dir(slug)
        if not queue_dir:
            return -1.0

        queue_files = [
            f for f in sorted(queue_dir.iterdir())
            if f.is_file() and f.stat().st_size > 0
            and not f.name.startswith(".")
        ]
        if not queue_files:
            return -1.0

        try:
            return self.symbolic.measure_function_source_coverage(
                result.harness, target.func_name, queue_files, n_samples=20,
            )
        except Exception as exc:
            self.log.debug("source_coverage.failed", error=str(exc))
            return -1.0

    @staticmethod
    def _compute_harness_quality_score(result: "TargetResult") -> float:
        """Composite harness quality score [0.0–1.0].

        Four observable signals, no LLM interpretation needed:
          compiled              (0.30) — binary gate: did it build at all?
          function_coverage_pct (0.30) — log-scaled to reward first gains over saturation
          corpus_paths          (0.20) — smooth: how much did AFL explore? (capped at 10)
          map_density_pct       (0.20) — proxy for execution depth (capped at 20%)

        Log scaling on coverage: log1p(5%) / log1p(100%) ≈ 0.37, whereas
        log1p(25%) / log1p(100%) ≈ 0.61 — distinguishes "dead" from "almost working".
        """
        import math

        compiled = result.status not in ("failed",) and result.harness is not None
        afl = result.afl_stats

        coverage_pct = max(result.function_coverage_pct, 0.0)  # treat -1 (not measured) as 0
        coverage_score = math.log1p(coverage_pct) / math.log1p(100.0)

        paths_score = min((afl.total_paths if afl else 0), 10) / 10.0
        density_score = min((afl.map_density_pct if afl else 0.0), 20.0) / 20.0

        score = (
            (1.0 if compiled else 0.0) * 0.30
            + coverage_score * 0.30
            + paths_score * 0.20
            + density_score * 0.20
        )
        return round(score, 4)

    def _build_diagnostics(self, result: "TargetResult") -> "HarnessExecutionDiagnostics":
        """Build a structured HarnessExecutionDiagnostics from current result state."""
        afl = result.afl_stats
        return HarnessExecutionDiagnostics(
            compiled=result.harness is not None and result.status != PipelineStatus.FAILED,
            function_reached=result.function_coverage_pct >= 0.0,
            function_coverage_pct=result.function_coverage_pct,
            corpus_paths=afl.total_paths if afl else 0,
            map_density_pct=afl.map_density_pct if afl else 0.0,
        )

    def _augment_seeds_once(self, harness, target_name: str) -> None:
        """Run the structural seed-augmentation pipeline once before fuzzing.

        Adds round-trip / Z3 / evolved seeds (each behind its own feature flag)
        into the AFL `-i` directory the fuzzing stage will use. Best-effort:
        any failure logs a warning and leaves the baseline seeds untouched.
        Called only on feedback iteration 0 — the produced seeds persist across
        iterations, so re-running every iteration would waste LLM/compile cost.
        """
        from nemesis.feature_flags import is_enabled
        if not any(is_enabled(f) for f in ("roundtrip", "z3_seedgen", "seed_evolve")):
            return
        try:
            slug = target_name or "default"
            seeds_dir = self.fuzzing.orchestrator.workspace / "seeds" / slug
            from nemesis.neural import LLMClient
            from nemesis.recon.seed_pipeline import SeedPipeline
            SeedPipeline(
                config=self.config,
                symbolic=self.symbolic,
                llm_client=LLMClient(self.config),
                log=self.log,
            ).augment(harness, seeds_dir, target_func=target_name)
        except Exception as exc:  # noqa: BLE001 — never block fuzzing on seed aug
            self.log.warning("seed_pipeline.augment_failed", error=str(exc))

    def _fuzz_with_feedback(
        self,
        target,
        result: TargetResult,
        context: AnalysisContext,
        stage_list: list[int],
    ) -> TargetResult:
        """
        Run fuzzing with self-healing feedback loop.

        If coverage doesn't expand, refine the patch through the LLM
        and retry (up to max_feedback_iterations).
        """
        max_iter = self.config.engine.max_feedback_iterations

        for iteration in range(max_iter + 1):
            self.log.info(
                "fuzz.start",
                func=target.func_name,
                iteration=iteration,
            )

            # Structural seed augmentation (round-trip / Z3 / evolve) — once.
            if iteration == 0:
                self._augment_seeds_once(result.harness, target.func_name)

            # Run AFL++
            afl_stats, crashes = self.fuzzing.run(
                result.harness,
                target_name=target.func_name,
                target_file_path=target.file_path,
            )
            result.afl_stats = afl_stats
            result.feedback_iterations = iteration

            # Check for crashes
            if crashes:
                result.crashes.extend(crashes)
                self.log.info(
                    "fuzz.crashes_found",
                    func=target.func_name,
                    count=len(crashes),
                    cwe=[c.cwe.value for c in crashes],
                )
                return result

            # Check coverage expansion
            coverage_delta = self.fuzzing.measure_coverage()

            if coverage_delta.success and iteration > 0:
                self.log.info(
                    "fuzz.bitmap_expanded",
                    func=target.func_name,
                    bitmap_delta=coverage_delta.total_expansion_pct,
                    iteration=iteration,
                )
                # Coverage expanded after refinement — exit loop
                return result

            # ── Self-healing: feed failure back to LLM ──────
            if iteration < max_iter and 2 in stage_list:
                self.log.info(
                    "feedback.refining",
                    func=target.func_name,
                    iteration=iteration + 1,
                    reason="no_coverage_expansion",
                )

                failure_reason = (
                    "no_crashes_no_coverage"
                    if not coverage_delta.success
                    else "no_crashes"
                )
                feedback = FeedbackContext(
                    original_proposal=result.patch,
                    coverage_delta=coverage_delta,
                    afl_stats=afl_stats,
                    error_log=self.fuzzing.get_error_log(),
                    iteration=iteration + 1,
                    failure_reason=failure_reason,
                    harness_code=result.harness.c_code if result.harness else "",
                )

                # Ask LLM to refine
                new_analysis = self.neural.refine(context, feedback)
                result.analysis = new_analysis
                result.patch = self.neural.generate_patch(new_analysis, context)
                result.harness = self.neural.generate_harness(new_analysis, context)
                result.total_llm_cost_usd += self.neural.session_cost

                # Reset work_root before applying the new patch — prevent contamination
                # from the previous iteration's patch
                if result.patch and result.harness:
                    self._sync_work_repo()
                    self.symbolic.apply_and_build(result.patch, result.harness)
            else:
                self.log.warning(
                    "feedback.exhausted",
                    func=target.func_name,
                    iterations=max_iter,
                )

        return result

    def _fuzz_with_harness_feedback(
        self,
        target,
        result: TargetResult,
        context: AnalysisContext,
        stage_list: list[int],
    ) -> TargetResult:
        """
        Strategy A feedback loop: fuzz with harness refinement (no patches).

        Same structure as _fuzz_with_feedback but:
        - On crash: sets patch_induced=False (no patch = real bugs by definition)
        - Feedback calls refine_harness() + generate_harness_strategy_a()
        - Rebuilds only the harness (library never modified)
        - No _sync_work_repo() needed
        """
        max_iter = self.config.engine.max_feedback_iterations

        # ── Load saved harness if one exists from a previous successful run ──
        saved_harness_path = self._saved_harness_path(target.func_name)
        if saved_harness_path.exists():
            saved_code = saved_harness_path.read_text()
            if result.harness:
                result.harness = result.harness.model_copy(update={"c_code": saved_code})
            else:
                result.harness = HarnessSpec(
                    target_func=target.func_name,
                    input_format="",
                    c_code=saved_code,
                )
            self.log.info("harness.loaded_saved", func=target.func_name, path=str(saved_harness_path))
            # Rebuild harness from saved code
            self.symbolic.build_harness_only(result.harness)

        for iteration in range(max_iter + 1):
            self.log.info(
                "fuzz_a.start",
                func=target.func_name,
                iteration=iteration,
            )

            # Feature C: Generate targeted seeds via LLM on first iteration
            # Fix 122: skip expensive LLM seed call when input_spec provides
            # deterministic synthesis (seeds already generated by SeedSynthesizer)
            if iteration == 0 and not (result.harness and result.harness.input_spec):
                try:
                    targeted_seeds = self.neural.generate_targeted_seeds(
                        target.func_name, context, n_seeds=3,
                    )
                    if targeted_seeds:
                        seeds_dir = (
                            Path(self.config.engine.work_dir)
                            / "fuzzing" / "seeds" / target.func_name / "targeted"
                        )
                        seeds_dir.mkdir(parents=True, exist_ok=True)
                        for i, seed_bytes in enumerate(targeted_seeds):
                            (seeds_dir / f"llm_seed_{i:02d}").write_bytes(seed_bytes)
                        self.log.info(
                            "seeds.targeted_generated",
                            func=target.func_name,
                            count=len(targeted_seeds),
                        )
                except Exception as exc:
                    self.log.debug("seeds.targeted_failed", error=str(exc))

            # Structural seed augmentation (round-trip / Z3 / evolve) — once.
            if iteration == 0:
                self._augment_seeds_once(result.harness, target.func_name)

            # Run AFL++
            afl_stats, crashes = self.fuzzing.run(
                result.harness,
                target_name=target.func_name,
                target_file_path=target.file_path,
            )
            result.afl_stats = afl_stats
            result.feedback_iterations = iteration

            # Post-fuzz UBSan corpus sweep: run AFL queue through UBSan binary
            # to catch undefined behavior that ASAN alone misses.
            ubsan_crashes = self._run_ubsan_sweep(target.func_name)
            if ubsan_crashes:
                crashes.extend(ubsan_crashes)
                self.log.info(
                    "ubsan_sweep.findings",
                    func=target.func_name,
                    count=len(ubsan_crashes),
                )

            # Check for crashes — all are real bugs (no patch applied)
            if crashes:
                for crash in crashes:
                    crash.patch_induced = False  # no patch = real bug
                result.crashes.extend(crashes)
                self.log.info(
                    "fuzz_a.crashes_found",
                    func=target.func_name,
                    count=len(crashes),
                    cwe=[c.cwe.value for c in crashes],
                    patch_induced=False,
                )
                # Fix 132: only persist harness when at least one crash
                # reproduces outside AFL (reproduces_in_app=True).
                # Without this, buggy harnesses that produce harness-induced
                # crashes get re-saved, perpetuating a false-positive loop.
                has_verified = any(c.reproduces_in_app for c in crashes)
                if result.harness and result.harness.c_code and has_verified:
                    self._save_harness(target.func_name, result.harness.c_code)
                elif result.harness and not has_verified:
                    self.log.warning(
                        "harness.save_skipped_no_verified_crash",
                        func=target.func_name,
                        crash_count=len(crashes),
                    )
                return result

            # Check coverage expansion
            coverage_delta = self.fuzzing.measure_coverage()

            if coverage_delta.success and iteration > 0:
                self.log.info(
                    "fuzz_a.bitmap_expanded",
                    func=target.func_name,
                    bitmap_delta=coverage_delta.total_expansion_pct,
                    iteration=iteration,
                )
                return result

            # Fix C: measure what % of AFL corpus inputs actually reach the target function.
            # Only run post-fuzz coverage check when no crashes were found and
            # this is the first iteration (avoid paying the gdb cost on retries).
            gcov_annotation = ""
            if not result.crashes:
                # Fix 126: measure coverage on ALL iterations (was iteration==0 only)
                # GDB post-fuzz check only on iteration 0 (expensive)
                if iteration == 0:
                    cov_pct = self._measure_post_fuzz_coverage(target, result)
                    result.function_coverage_pct = cov_pct
                    if cov_pct < 20.0:
                        self.log.warning(
                            "harness.low_function_reachability",
                            func=target.func_name,
                            pct=round(cov_pct, 1),
                            hint="gdb breakpoint check: target function not reached by most AFL inputs",
                        )

                # Measure real source-line coverage via LLVM source-based instrumentation
                src_cov = self._measure_source_coverage(target, result)
                result.source_coverage_pct = src_cov
                if src_cov >= 0:
                    self.log.info(
                        "source_coverage.result",
                        func=target.func_name,
                        line_cov_pct=round(src_cov, 2),
                        iteration=iteration,
                    )

            # Feature B: Collect gcov line-level coverage for refinement prompt.
            # Only when function coverage is low — gives LLM precise "which branch blocks?" data.
            if (
                not result.crashes
                and result.harness
                and result.function_coverage_pct < 20.0
            ):
                try:
                    # Fix 105: use _resolve_afl_queue_dir
                    slug = target.func_name
                    queue_dir = self._resolve_afl_queue_dir(slug)
                    if queue_dir:
                        queue_files = [
                            f for f in sorted(queue_dir.iterdir())
                            if f.is_file() and f.stat().st_size > 0
                            and not f.name.startswith(".")
                        ]
                        if queue_files:
                            gcov_annotation = self.symbolic.collect_gcov_around_function(
                                result.harness,
                                target.func_name,
                                queue_files,
                                n_samples=5,
                            )
                            if gcov_annotation:
                                self.log.info(
                                    "gcov.collected",
                                    func=target.func_name,
                                    lines=gcov_annotation.count("\n") + 1,
                                )
                except Exception as exc:
                    self.log.debug("gcov.collection_failed", error=str(exc))

            # Compute composite harness quality score after every AFL iteration
            result.harness_quality_score = self._compute_harness_quality_score(result)
            self.log.info(
                "harness.quality_score",
                func=target.func_name,
                score=result.harness_quality_score,
                iteration=iteration,
                line_cov=round(result.source_coverage_pct, 2) if result.source_coverage_pct >= 0 else "n/a",
            )

            # Record harness outcome in cross-run library memory
            if result.harness and result.harness.c_code:
                self.library_memory.record_harness_outcome(
                    harness_code=result.harness.c_code,
                    compiled=True,  # we only reach here if build succeeded
                    function_reached=result.function_coverage_pct >= 0.0,
                )

            # Record planner hint outcome for future cache lookups
            if target.harness_hint:
                self.library_memory.record_planner_hint(
                    func_name=target.func_name,
                    hint=target.harness_hint,
                    compiled=True,
                    reached=result.function_coverage_pct >= 0.0,
                )

            # ── Self-healing: refine harness via LLM ──────────
            # Fix 124: skip refinement if LLVM source coverage already high.
            # GDB breakpoint check (function_coverage_pct) often gives false negatives
            # for inlined/internal functions — source_coverage_pct is the ground truth.
            if (
                result.source_coverage_pct >= 50.0
                and iteration < max_iter
            ):
                self.log.info(
                    "feedback_a.skip_refinement_high_source_cov",
                    func=target.func_name,
                    source_cov=round(result.source_coverage_pct, 2),
                    iteration=iteration,
                    hint="LLVM source coverage high — GDB false negative, skipping refinement",
                )
                # Save the harness since it's working well
                if result.harness and result.harness.c_code:
                    self._save_harness(target.func_name, result.harness.c_code)
                return result

            if iteration < max_iter and 2 in stage_list:
                self.log.info(
                    "feedback_a.refining_harness",
                    func=target.func_name,
                    iteration=iteration + 1,
                    reason="no_coverage_expansion",
                )

                # Incorporate low function coverage into failure reason for LLM context.
                # function_coverage_pct == -1.0 means "not measured" (use original logic).
                if (
                    iteration == 0
                    and result.function_coverage_pct >= 0.0
                    and result.function_coverage_pct < 20.0
                ):
                    failure_reason = "low_function_coverage"
                elif not coverage_delta.success:
                    failure_reason = "no_crashes_no_coverage"
                else:
                    failure_reason = "no_crashes"
                feedback = FeedbackContext(
                    original_proposal=None,  # no patch in Strategy A
                    coverage_delta=coverage_delta,
                    afl_stats=afl_stats,
                    error_log=self.fuzzing.get_error_log(),
                    iteration=iteration + 1,
                    failure_reason=failure_reason,
                    harness_code=result.harness.c_code if result.harness else "",
                    diagnostics=self._build_diagnostics(result),
                    gcov_annotation=gcov_annotation,
                )

                # Fix E: Caller escalation — if deep function is unreachable after 2+ iterations
                # try harnessing a higher-level caller instead.
                diagnostics = self._build_diagnostics(result)
                caller_escalated = False
                # Fix 127: skip refinement-loop caller escalation for direct_internal targets.
                # Caller escalation replaces direct harness with public-API one → counterproductive.
                if (
                    iteration >= 1
                    and diagnostics.likely_early_exit
                    and result.function_coverage_pct < 20.0
                    and self._oracle is not None
                    and self._oracle.is_built()
                    and not getattr(target, "direct_internal", False)  # Fix 127
                ):
                    callers = self._oracle.find_callers(target.func_name, k=5)
                    if callers:
                        self.log.info(
                            "caller_escalation.triggered",
                            func=target.func_name,
                            iteration=iteration + 1,
                            callers=[c.name for c in callers[:3]],
                        )
                        escalated_harness = self.neural.generate_harness_via_caller(
                            target.func_name, callers, context,
                            previous_harness_code=result.harness.c_code if result.harness else "",
                        )
                        result.total_llm_cost_usd += self.neural.session_cost
                        if escalated_harness and escalated_harness.c_code:
                            escalated_harness.cmplog_binary = None  # will be set by build
                            self._propagate_target_flags(target, escalated_harness)  # Fix 127
                            build_ok = self.symbolic.build_harness_only(escalated_harness)
                            if build_ok:
                                result.harness = escalated_harness
                                caller_escalated = True
                                self.log.info(
                                    "caller_escalation.built",
                                    func=target.func_name,
                                    caller_func=escalated_harness.target_func,
                                )

                if not caller_escalated:
                    # Standard refinement path
                    new_analysis = self.neural.refine_harness(context, feedback)
                    result.analysis = new_analysis
                    result.harness = self.neural.generate_harness_strategy_a(
                        new_analysis, context,
                        library_memory_snippet=self.library_memory.build_prompt_snippet(),
                    )
                    result.total_llm_cost_usd += self.neural.session_cost

                    # Fix 127: re-propagate target flags after harness replacement
                    if result.harness:
                        self._propagate_target_flags(target, result.harness)

                    # Rebuild harness only (library unchanged)
                    if result.harness:
                        build_ok = self.symbolic.build_harness_only(result.harness)
                        if not build_ok:
                            self.log.warning(
                                "feedback_a.rebuild_failed",
                                func=target.func_name,
                                iteration=iteration + 1,
                            )
            else:
                self.log.warning(
                    "feedback_a.exhausted",
                    func=target.func_name,
                    iterations=max_iter,
                )

        return result

    def _select_best_harness_variant(
        self,
        analysis,
        context,
        library_memory_snippet: str = "",
    ) -> HarnessSpec:
        """Fix D: Generate N=3 harness variants, profile each for 2 min, pick best.

        Falls back to single-variant generation if:
        - Only 0-1 variants compile
        - Profiling is not available
        Best is chosen by corpus_paths (more AFL paths = more code exercised).

        Logs harness.variant_selected, harness.variant_N_paths.
        """
        n_variants = 3
        build_dir = Path(self.config.target.build_dir)

        variants = self.neural.generate_harness_variants(
            analysis, context, n=n_variants,
            library_memory_snippet=library_memory_snippet,
        )
        self.neural.session_cost  # already accumulated inside generate_harness_variants

        if not variants:
            # Fall back to single-variant
            self.log.warning(
                "variant_select.no_variants",
                func=context.target.func_name,
                fallback="single_harness",
            )
            harness = self.neural.generate_harness_strategy_a(
                analysis, context,
                library_memory_snippet=library_memory_snippet,
            )
            # Fix 125: propagate direct_internal/indirect_reach before any compilation
            if getattr(context.target, "direct_internal", False):
                harness.direct_internal = True
            if getattr(context.target, "indirect_reach", False):
                harness.indirect_reach = True
            if getattr(context.target, "is_static", False):
                harness.is_static = True
            return harness

        # Fix 125: propagate direct_internal/indirect_reach/is_static to variants
        # BEFORE profiling, so internal -I flags are added during compilation
        for h in variants:
            if getattr(context.target, "direct_internal", False):
                h.direct_internal = True
            if getattr(context.target, "indirect_reach", False):
                h.indirect_reach = True
            if getattr(context.target, "is_static", False):
                h.is_static = True

        # Fix 99: Pre-populate format-specific seeds so variant profiling uses
        # real format data instead of null-byte fallback.
        if variants:
            _first = variants[0]
            self.fuzzing.ensure_seeds(
                _first,
                target_file_path=getattr(context.target, "file_path", ""),
            )

        # Profile each compiled variant
        # scored: (corpus_paths, coverage_pct, variant_idx, harness)
        scored: list[tuple[int, float, int, HarnessSpec]] = []
        for i, h in enumerate(variants):
            compiled, cov_pct, corpus_paths = self.symbolic.profile_harness_variant(
                h, build_dir, timeout_sec=120,
            )
            self.log.info(
                "harness.variant_profiled",
                func=context.target.func_name,
                variant=i,
                compiled=compiled,
                corpus_paths=corpus_paths,
                coverage_pct=cov_pct,
            )
            if compiled:
                scored.append((corpus_paths, cov_pct, i, h))

        if not scored:
            self.log.warning(
                "variant_select.none_compiled",
                func=context.target.func_name,
                fallback="first_variant",
            )
            return variants[0]

        # Feature A: Partition into variants that reach the function vs those that don't.
        # Prefer reaching variants; among them, pick max corpus_paths.
        reaching = [(cp, cov, idx, h) for cp, cov, idx, h in scored if cov > 0]
        not_reaching = [(cp, cov, idx, h) for cp, cov, idx, h in scored if cov <= 0]

        if reaching:
            reaching.sort(key=lambda x: x[0], reverse=True)
            best_paths, best_cov, best_idx, best_harness = reaching[0]
            self.log.info(
                "harness.variant_selected_with_reach",
                func=context.target.func_name,
                variant=best_idx,
                corpus_paths=best_paths,
                total_reaching=len(reaching),
                total_variants=len(scored),
            )
        else:
            not_reaching.sort(key=lambda x: x[0], reverse=True)
            best_paths, best_cov, best_idx, best_harness = not_reaching[0]
            self.log.info(
                "harness.variant_selected_no_reach",
                func=context.target.func_name,
                variant=best_idx,
                corpus_paths=best_paths,
                total_variants=len(scored),
            )

        # 2026-05-08 audit: stash variant-profile reachability on the selected
        # harness. Used by `_process_target` post-build profile bypass to skip
        # the (false-negative-prone) GDB single-seed check when the variant
        # already proved reachable via AFL bitmap during profiling.
        # HarnessSpec is a Pydantic model — direct attribute assignment raises
        # ValueError on extra fields. Use object.__setattr__ to bypass model
        # validation (Pydantic stores it on __dict__, retrievable via getattr).
        try:
            object.__setattr__(best_harness, "variant_coverage_pct", best_cov)
            object.__setattr__(best_harness, "variant_corpus_paths", best_paths)
            object.__setattr__(best_harness, "variant_function_reached", best_cov > 0)
        except Exception:
            pass

            # Feature D1: Adaptive profiling — if no variant reached the target,
            # re-profile the best candidate with an extended 300s timeout.
            if len(scored) > 0:
                self.log.info("variant.extended_profiling", func=context.target.func_name)
                _, ext_cov, ext_paths = self.symbolic.profile_harness_variant(
                    best_harness, build_dir, timeout_sec=300,
                )
                if ext_cov > 0:
                    self.log.info(
                        "variant.extended_profiling.reached",
                        func=context.target.func_name,
                        corpus_paths=ext_paths,
                    )
                else:
                    self.log.info(
                        "variant.extended_profiling.no_reach",
                        func=context.target.func_name,
                        corpus_paths=ext_paths,
                    )

        return best_harness

    def _saved_harness_path(self, func_name: str) -> Path:
        """Return path for persisted harness: config/targets/{library}/harnesses/{func}.c"""
        config_dir = Path(__file__).parent.parent / "config" / "targets" / self.config.target.name / "harnesses"
        return config_dir / f"{func_name}.c"

    def _save_harness(self, func_name: str, c_code: str) -> None:
        """Persist a crash-producing harness for reuse in future scans."""
        path = self._saved_harness_path(func_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(c_code)
        self.log.info("harness.saved", func=func_name, path=str(path))

    def _triage_existing(
        self,
        target,
        result: TargetResult,
        stage_list: list[int],
        crashes_dir: Path,
        findings_dir: Path,
    ) -> TargetResult:
        """
        Re-triage crashes from a previous run without re-launching AFL.

        Rebuilds the harness via stages 2-3 (LLM cache hit, $0), then runs
        CrashTriager on the existing crash files.
        """
        # ── Stage 1 context ──────────────────────────────────
        if 1 in stage_list:
            context = self.recon.extract_context(target)
        else:
            context = AnalysisContext(target=target, call_chain=target)

        # ── Stage 2: Neural (from LLM cache) ─────────────────
        if 2 in stage_list:
            analysis = self.neural.analyze(context)
            result.analysis = analysis
            skip_patch = not analysis.has_blocker or target.force_no_blocker
            if not skip_patch:
                result.patch = self.neural.generate_patch(analysis, context)
            result.harness = self.neural.generate_harness(analysis, context)
            result.total_llm_cost_usd += self.neural.session_cost

        # ── Stage 3: Rebuild harness binary ──────────────────
        if 3 in stage_list and result.harness:
            has_patch = result.patch and result.patch.file_path
            if has_patch:
                build_ok = self.symbolic.apply_and_build(result.patch, result.harness)
            else:
                build_ok = self.symbolic.build_harness_only(result.harness)
            if not build_ok:
                self.log.warning("triage.build_failed", func=target.func_name)
                result.status = PipelineStatus.FAILED
                return result

        # ── Triage existing crashes ───────────────────────────
        self.fuzzing.triager.crashes_dir = crashes_dir
        self.fuzzing.coverage._findings_dir = findings_dir
        crashes = self.fuzzing.triager.triage_all()
        result.crashes = crashes

        if crashes:
            result.status = PipelineStatus.SUCCESS
            self.log.info(
                "triage.complete",
                func=target.func_name,
                crashes=len(crashes),
                cwe=[c.cwe.value for c in crashes],
            )
        else:
            result.status = PipelineStatus.FAILED
            self.log.warning("triage.no_crashes_classified", func=target.func_name)

        return result

    def _save_run(self, run: PipelineRun) -> None:
        """Persist pipeline run results to workspace."""
        run_dir = self.workspace / run.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        results_file = run_dir / "results.json"
        results_file.write_text(run.model_dump_json(indent=2))
        self.log.info("results.saved", path=str(results_file))

    # ── Fix 124: Checkpoint — auto-resume after crash/reboot ─

    def _config_fingerprint(self) -> str:
        """Short hash of the config knobs that determine WHAT gets built/fuzzed.

        A resume checkpoint is only valid when these are unchanged — otherwise
        --resume would skip funcs the user re-scoped via a different sanitizer
        profile, pinned_funcs, strategy, or build flags, silently resuming
        against a config that no longer matches what produced the checkpoint.
        """
        import hashlib
        import json as _json
        t = self.config.target
        payload = {
            "sanitizer_profile": getattr(t, "sanitizer_profile", ""),
            "strategy": self.config.fuzzing.strategy,
            "pinned": sorted(f"{p.func_name}:{p.file_path}" for p in t.pinned_funcs),
            "configure": t.build.configure,
            "make": t.build.make,
        }
        blob = _json.dumps(payload, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def _save_checkpoint(
        self,
        run_id: str,
        completed_funcs: list[str],
        target_name: str,
    ) -> None:
        """Save scan progress checkpoint so pipeline can resume after interruption."""
        import json as _json
        checkpoint_path = self.workspace / "checkpoint.json"
        data = {
            "run_id": run_id,
            "target_name": target_name,
            "config_hash": self._config_fingerprint(),
            "completed_funcs": completed_funcs,
            "timestamp": datetime.now().isoformat(),
        }
        checkpoint_path.write_text(_json.dumps(data, indent=2))

    def _load_checkpoint(self, target_name: str) -> tuple[str, set[str]]:
        """Load checkpoint for this target. Returns (run_id, completed_func_names).

        Ignores the checkpoint if the target name OR the config fingerprint
        differs from the current config (re-scoped run → start fresh).
        """
        import json as _json
        checkpoint_path = self.workspace / "checkpoint.json"
        if not checkpoint_path.exists():
            return "", set()
        try:
            data = _json.loads(checkpoint_path.read_text())
            if data.get("target_name") != target_name:
                return "", set()
            stored_hash = data.get("config_hash", "")
            if stored_hash and stored_hash != self._config_fingerprint():
                self.log.warning(
                    "checkpoint.config_changed",
                    hint="config differs from checkpoint — starting fresh, not resuming",
                )
                return "", set()
            return data.get("run_id", ""), set(data.get("completed_funcs", []))
        except (ValueError, KeyError):
            return "", set()

    def _clear_checkpoint(self) -> None:
        """Remove checkpoint file after successful completion."""
        checkpoint_path = self.workspace / "checkpoint.json"
        if checkpoint_path.exists():
            checkpoint_path.unlink()
            self.log.debug("checkpoint.cleared")
