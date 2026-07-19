"""Unified, quality-ordered seed-augmentation pipeline.

NEMESIS already has a battle-tested baseline seed flow inside the fuzzing stage
(`AFLOrchestrator._generate_seeds` + `run`): OSS-Fuzz corpus harvest → static
format seeds → deterministic InputSpec synthesis (Fix 122) → SeedMind generator
script (seedgen) → afl-cmin distillation. This module does NOT replace that —
it ADDS the higher-cost, higher-yield *structural* sources on top, behind
feature flags so each can be A/B-ablated:

    Stage 1  Structural   round-trip write-API producer        (flag: roundtrip)
    Stage 2  Symbolic     Z3 magic-value branch solving        (flag: z3_seedgen)
    Stage 3  Evolve       coverage-feedback winner breeding    (flag: seed_evolve)

All three write extra seed files into the same AFL `-i` directory the baseline
flow uses, so they merge naturally and the existing prevalidation / minset
stages clean up afterwards. Every stage is best-effort: a failure logs a
warning and contributes 0 seeds, never aborting the run.

Why a separate orchestrator (vs inlining in the fuzzing stage): Stage 1 must
compile a program that links the *target library*, which only the symbolic
stage knows how to do. Keeping the coordination here lets the pipeline pass in
both stages (`symbolic` for compilation, an LLM client for synthesis) without
giving the fuzzing stage a back-reference to the builder.

Deferred by design
------------------
* Adapter "generation mode" (#5) — running a mutator adapter as a seed emitter.
  Its output (structurally-valid seeds) is exactly what the round-trip producer
  (#1) already yields from the real encode API, which is strictly more faithful
  than an adapter reconstructing the format by hand. Not worth a second C path.
* Structured field-spec generation (#6) lives in `fieldspec_seedgen.py` and is
  wired as a robustness FALLBACK inside `seedgen` (when the freeform script is
  rejected), not as a separate SeedPipeline stage — it shares seedgen's flag.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from nemesis.feature_flags import is_enabled

if TYPE_CHECKING:
    import logging

    from nemesis.models import HarnessSpec


class SeedPipeline:
    """Coordinates the flag-gated structural seed sources for one target."""

    def __init__(
        self,
        config,
        symbolic,
        llm_client,
        log: logging.Logger,
        nemesis_root: Path | None = None,
    ) -> None:
        self.config = config
        self.symbolic = symbolic
        self.llm = llm_client
        self.log = log
        # config/targets is a sibling of nemesis/ — resolve two levels up from
        # this file, matching the convention used by mutator_synthesis.
        self.nemesis_root = nemesis_root or Path(__file__).resolve().parents[2]

    # ── public API ────────────────────────────────────────────────────────

    def augment(
        self,
        harness: HarnessSpec,
        seeds_dir: Path,
        target_func: str = "",
    ) -> int:
        """Run every enabled structural seed source into `seeds_dir`.

        Returns the total number of seeds added across all stages. Logs a
        per-stage and a summary line so the run record shows exactly which
        sources contributed (needed for the ablation chapter).
        """
        seeds_dir.mkdir(parents=True, exist_ok=True)
        before = self._count_seeds(seeds_dir)
        added = 0

        added += self._stage_roundtrip(harness, seeds_dir, target_func)
        added += self._stage_z3(harness, seeds_dir, target_func)
        added += self._stage_evolve(harness, seeds_dir, target_func)

        after = self._count_seeds(seeds_dir)
        self.log.info(
            "seed_pipeline.summary",
            added=added,
            seeds_before=before,
            seeds_after=after,
            roundtrip=is_enabled("roundtrip"),
            z3_seedgen=is_enabled("z3_seedgen"),
            seed_evolve=is_enabled("seed_evolve"),
        )
        return added

    # ── Stage 1: round-trip write-API producer ────────────────────────────

    def _stage_roundtrip(self, harness, seeds_dir: Path, target_func: str) -> int:
        if not is_enabled("roundtrip"):
            self.log.info("seed_pipeline.roundtrip_disabled")
            return 0
        try:
            from nemesis.recon import roundtrip_seedgen as _rt
        except Exception as exc:  # noqa: BLE001
            self.log.warning("seed_pipeline.roundtrip_import_failed", error=str(exc))
            return 0

        def _compile(src_c: Path, out_bin: Path) -> bool:
            builder = getattr(self.symbolic, "builder", self.symbolic)
            fn = getattr(builder, "build_seed_producer", None)
            if fn is None:
                self.log.warning("seed_pipeline.no_build_seed_producer")
                return False
            return bool(fn(src_c, out_bin))

        try:
            return _rt.synthesize_and_run(
                config=self.config,
                seeds_dir=seeds_dir,
                compile_fn=_compile,
                client=self.llm,
                nemesis_root=self.nemesis_root,
                log=self.log,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning("seed_pipeline.roundtrip_failed", error=str(exc))
            return 0

    # ── Stage 2: Z3 magic-value seed solving (wired in Phase 2) ────────────

    def _stage_z3(self, harness, seeds_dir: Path, target_func: str) -> int:
        if not is_enabled("z3_seedgen"):
            self.log.info("seed_pipeline.z3_disabled")
            return 0
        try:
            from nemesis.recon import z3_seedgen as _z3
        except Exception:  # noqa: BLE001 — module lands in Phase 2
            self.log.info("seed_pipeline.z3_not_available")
            return 0
        try:
            return _z3.synthesize_seeds(
                config=self.config,
                seeds_dir=seeds_dir,
                harness=harness,
                target_func=target_func,
                nemesis_root=self.nemesis_root,
                log=self.log,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning("seed_pipeline.z3_failed", error=str(exc))
            return 0

    # ── Stage 3: coverage-feedback evolution (wired in Phase 3) ────────────

    def _stage_evolve(self, harness, seeds_dir: Path, target_func: str) -> int:
        if not is_enabled("seed_evolve"):
            self.log.info("seed_pipeline.evolve_disabled")
            return 0
        try:
            from nemesis.recon import seed_evolve as _ev
        except Exception:  # noqa: BLE001 — module lands in Phase 3
            self.log.info("seed_pipeline.evolve_not_available")
            return 0
        try:
            return _ev.evolve(
                config=self.config,
                symbolic=self.symbolic,
                seeds_dir=seeds_dir,
                harness=harness,
                target_func=target_func,
                log=self.log,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning("seed_pipeline.evolve_failed", error=str(exc))
            return 0

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _count_seeds(seeds_dir: Path) -> int:
        try:
            return sum(1 for f in seeds_dir.iterdir() if f.is_file() and f.stat().st_size > 0)
        except OSError:
            return 0
