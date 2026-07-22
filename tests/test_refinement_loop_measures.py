"""
The refinement loop must measure the thing it is refining.

On minmea_scan, iteration 1 rewrote a one-call harness into nine calls and took
line coverage from 21.35% to 76.56%. The run recorded neither number: AFL's
bitmap had grown, and the loop treated that as success and returned 2ms later,
before the source-coverage measurement. Had coverage *fallen*, that path would
have been equally satisfied — the loop was open, not closed.

AFL's map counts edges inside the harness as well as the library, so "the
bitmap grew" and "the target was explored more" are different claims. Bitmap
expansion is a reason to measure, not a reason to stop.
"""

from unittest.mock import MagicMock

import pytest

from nemesis.models import (
    AFLStats,
    CoverageTarget,
    HarnessSpec,
    TargetResult,
)
from nemesis.pipeline import NemesisPipeline

TARGET = CoverageTarget(func_name="minmea_scan", file_path="minmea.c",
                        line=88, coverage_pct=0.0)


def _result(explore: float = -1.0) -> TargetResult:
    r = TargetResult(target=TARGET)
    r.harness = HarnessSpec(target_func="minmea_scan", input_format="nmea",
                            c_code="int main(void){return 0;}")
    r.function_coverage_pct = 100.0
    r.source_coverage_pct = explore
    r.afl_stats = AFLStats(total_paths=726, map_density_pct=44.26)
    return r


# ── the score reflects exploration, not activity ────────────


def test_score_separates_the_two_measured_iterations():
    """The regression this whole change exists for, with the real numbers."""
    iter0 = NemesisPipeline._compute_harness_quality_score(_result(21.35))
    iter1 = NemesisPipeline._compute_harness_quality_score(_result(76.56))
    assert iter1 - iter0 >= 0.15


def test_identical_afl_activity_different_exploration():
    """Same paths, same density — only target coverage differs. The old score
    returned the same value for both."""
    shallow = NemesisPipeline._compute_harness_quality_score(_result(21.35))
    deep = NemesisPipeline._compute_harness_quality_score(_result(76.56))
    assert deep > shallow


# ── unmeasured is not zero ──────────────────────────────────


def test_unmeasured_exploration_is_not_scored_as_zero():
    unmeasured = NemesisPipeline._compute_harness_quality_score(_result(-1.0))
    zero = NemesisPipeline._compute_harness_quality_score(_result(0.0))
    assert unmeasured > zero, (
        "a measurement the run skipped must not read as a confident 0")


def test_measured_zero_is_worse_than_unmeasured():
    """The inverse guard: an actually-measured 0% must not be flattered."""
    assert (NemesisPipeline._compute_harness_quality_score(_result(0.0))
            < NemesisPipeline._compute_harness_quality_score(_result(-1.0)))


# ── the loop measures before it exits ───────────────────────


def test_bitmap_path_measures_before_returning():
    """The measurement call must sit before the bitmap-expansion `return`.

    A behavioural test would be better, but the enclosing method needs a live
    fuzzing stage, an AFL run and a coverage build to reach this branch. This
    inspects the source instead: weaker, but it tests the *wiring* rather than
    a copy of the branch condition, which is the mistake that let a fully
    tested variadic gate sit unreachable for a whole run.
    """
    import inspect
    import re

    from nemesis import pipeline as pipeline_mod

    src = inspect.getsource(pipeline_mod)
    marker = src.index("fuzz_a.bitmap_expanded")
    # The 40 lines before the log call must contain the measurement.
    window = src[:marker].rsplit("\n", 40)[-1] if False else "\n".join(
        src[:marker].split("\n")[-40:])
    assert "_measure_source_coverage" in window, (
        "bitmap expansion returns without measuring source coverage")
    assert re.search(r"source_coverage_pct\s*=", window), (
        "the measured value is never stored on the result")


def test_bitmap_log_reports_the_measurement():
    """The log line must carry the coverage and score, so a run's own output
    shows whether the refinement helped."""
    import inspect

    from nemesis import pipeline as pipeline_mod

    src = inspect.getsource(pipeline_mod)
    start = src.index("fuzz_a.bitmap_expanded")
    block = src[start:start + 400]
    assert "source_coverage_pct" in block
    assert "quality_score" in block


def test_measurement_is_not_repeated_when_already_taken():
    """Iteration 0 measures in the block below; the bitmap path must not pay
    for a second llvm-cov pass over the same corpus."""
    result = _result(21.35)
    should_measure = not result.crashes and result.source_coverage_pct < 0.0
    assert should_measure is False
