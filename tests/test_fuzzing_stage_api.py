"""Regression tests for FuzzingStage API wiring."""

from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.fuzzing import FuzzingStage
from nemesis.models import HarnessSpec


def test_fuzzing_stage_exposes_ensure_seeds(tmp_path: Path) -> None:
    """Pipeline should be able to call ensure_seeds on FuzzingStage."""
    cfg = NemesisConfig()
    cfg.engine.work_dir = tmp_path

    stage = FuzzingStage(cfg)
    harness = HarnessSpec(
        target_func="demo_target",
        input_format="",
        c_code="int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return 0; }",
    )

    # Pre-populate one seed so ensure_seeds returns fast without source-dependent generation.
    seeds_dir = tmp_path / "fuzzing" / "seeds" / harness.target_func
    seeds_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seeds_dir / "seed.bin"
    seed_file.write_bytes(b"seed")

    out_dir = stage.ensure_seeds(harness, target_file_path="libarchive/foo.c")

    assert out_dir == seeds_dir
    assert seed_file.exists()
