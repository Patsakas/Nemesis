"""
Tests for the harness quality score, driven by a measured counterexample.

On minmea_scan the refinement loop took line coverage from 21.35% to 76.56% —
one `minmea_scan(buf, "t", type)` call became nine calls covering every format
directive. The score in place at the time moved 0.8824 → 1.0000, but not
because of that: reachability was saturated at 100% in both iterations and
`corpus_paths` was already past its cap, so the whole rise came from AFL map
density. Line coverage contributed nothing to either number.

The score therefore could not tell a harness that exercises 21% of its target
from one that exercises 76%, and a harness adding calls that all fail
immediately would have scored the same. These tests pin the property that was
missing: exploration must be what moves the score.
"""

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


def result(*, compiled=True, reach=100.0, explore=-1.0, paths=10, density=8.24):
    r = TargetResult(target=TARGET)
    if compiled:
        r.harness = HarnessSpec(target_func="minmea_scan", input_format="nmea",
                                c_code="int main(void){return 0;}")
    r.function_coverage_pct = reach
    r.source_coverage_pct = explore
    r.afl_stats = AFLStats(total_paths=paths, map_density_pct=density)
    return r


def score(**kw) -> float:
    return NemesisPipeline._compute_harness_quality_score(result(**kw))


# Named data points, because a bare 0.68 is not enough to identify a case.
# Writing this file, MEASURED_SHALLOW and SYNTHETIC_BUSY_SHALLOW were confused
# with each other: same reachability, same exploration, different AFL activity,
# different score. The scalar looked interchangeable; the situations are not.
# `source` distinguishes what a run actually produced from what was constructed
# to probe the formula.

MEASURED_UNREACHABLE = dict(  # minmea_getdatetime iteration 0, logged 0.4
    reach=0.0, explore=0.0, paths=726, density=44.26)
MEASURED_SHALLOW = dict(      # minmea_scan iteration 0, logged 0.6819
    reach=100.0, explore=21.35, paths=10, density=8.24)
SYNTHETIC_BUSY_SHALLOW = dict(  # constructed: many paths, still 21% explored
    reach=100.0, explore=21.35, paths=726, density=44.26)
SYNTHETIC_DEEP = dict(          # the 76.56% harness, at identical AFL activity
    reach=100.0, explore=76.56, paths=726, density=44.26)


# ── the measured counterexample ─────────────────────────────


def test_the_minmea_iterations_are_separated():
    """The two real harnesses, with their real numbers."""
    iter0 = score(reach=100.0, explore=21.35, paths=10, density=8.24)
    iter1 = score(reach=100.0, explore=76.56, paths=726, density=44.26)
    assert iter1 > iter0
    # And by a margin that reflects a 3.6x coverage gain, not a rounding wobble.
    assert iter1 - iter0 >= 0.15


def test_exploration_is_what_moves_it():
    """Hold everything else fixed; only line coverage differs."""
    low = score(reach=100.0, explore=21.35, paths=726, density=44.26)
    high = score(reach=100.0, explore=76.56, paths=726, density=44.26)
    assert high - low == pytest.approx(0.35 * (76.56 - 21.35) / 100.0, abs=1e-3)


def test_busy_but_shallow_harness_does_not_win():
    """Eight extra calls that all fail immediately: more edges, more density,
    same shallow exploration. This is the case the old score could not see."""
    shallow_busy = score(reach=100.0, explore=21.35, paths=726, density=44.26)
    deep_quiet = score(reach=100.0, explore=76.56, paths=10, density=8.24)
    assert deep_quiet > shallow_busy


# ── the terms still do their jobs ───────────────────────────


def test_not_compiled_scores_low():
    r = result(compiled=False, explore=76.56)
    assert NemesisPipeline._compute_harness_quality_score(r) < 0.8


def test_unreachable_target_is_penalised():
    assert score(reach=0.0, explore=50.0) < score(reach=100.0, explore=50.0)


def test_reachability_still_log_scaled():
    """First gains matter more than saturation — 0→20% should outweigh 80→100%."""
    early = score(reach=20.0, explore=50.0) - score(reach=0.0, explore=50.0)
    late = score(reach=100.0, explore=50.0) - score(reach=80.0, explore=50.0)
    assert early > late


def test_exploration_is_linear_not_log():
    """40→80% must read as a doubling; log scaling flattens the range that is
    actually worth optimising."""
    first = score(reach=100.0, explore=40.0) - score(reach=100.0, explore=0.0)
    second = score(reach=100.0, explore=80.0) - score(reach=100.0, explore=40.0)
    assert first == pytest.approx(second, abs=1e-6)


# ── unmeasured exploration ──────────────────────────────────


def test_unmeasured_exploration_does_not_read_as_zero():
    """The loop sometimes exits before measuring. Reporting a confident 0 for
    something never observed is worse than falling back to what was seen."""
    unmeasured = score(reach=100.0, explore=-1.0, paths=726, density=44.26)
    zero = score(reach=100.0, explore=0.0, paths=726, density=44.26)
    assert unmeasured > zero


def test_score_stays_in_range():
    for explore in (-1.0, 0.0, 21.35, 76.56, 100.0, 150.0):
        s = score(reach=100.0, explore=explore, paths=726, density=44.26)
        assert 0.0 <= s <= 1.0


# ── the documented bands ────────────────────────────────────


def test_unreachable_target_lands_in_the_ran_but_useless_band():
    """The floor is not zero — building and running are worth 0.40 before the
    target is touched. Anyone reading a raw score needs that, or 0.40 looks
    like partial success."""
    assert score(**MEASURED_UNREACHABLE) == pytest.approx(0.40, abs=0.01)


def test_reached_but_shallow_lands_above_never_reached():
    """The pipeline logged 0.6819 for exactly these inputs — note the modest
    AFL activity, which is what separates this from SYNTHETIC_BUSY_SHALLOW."""
    assert score(**MEASURED_SHALLOW) == pytest.approx(0.68, abs=0.01)
    assert score(**MEASURED_SHALLOW) > score(**MEASURED_UNREACHABLE)


def test_band_order_holds_at_identical_afl_activity():
    """Paths and density held constant, so the ordering comes from reachability
    and exploration rather than from how busy the fuzzer happened to be."""
    never = score(**MEASURED_UNREACHABLE)
    shallow = score(**SYNTHETIC_BUSY_SHALLOW)
    deep = score(**SYNTHETIC_DEEP)
    assert never < shallow < deep
    assert deep >= 0.75, "substantial exploration must reach the top band"


# ── properties, not fixtures ────────────────────────────────


@pytest.mark.parametrize("paths,density", [
    (0, 0.0), (10, 8.24), (100, 20.0), (726, 44.26), (10_000, 100.0),
])
def test_activity_cannot_lift_an_unreachable_harness(paths: int, density: float):
    """With the target never reached, no amount of fuzzer activity may raise
    the score above the "ran, touched nothing" ceiling.

    Stated as a property over the whole activity range rather than a single
    pair, because the failure it guards against is gradual: the old weighting
    gave activity 0.40 of the total, so a busy harness climbed steadily without
    ever reaching its target. Observed on minmea_getdatetime — bitmap grew by
    56.64 between iterations and the score stayed at 0.40.
    """
    assert score(reach=0.0, explore=0.0, paths=paths, density=density) <= 0.40


def test_exploration_outweighs_maximum_activity():
    """A quiet harness that exercises the target must beat a busy one that does
    not. Otherwise the score still rewards the fuzzer working hard in the wrong
    place."""
    busy_useless = score(reach=0.0, explore=0.0, paths=10_000, density=100.0)
    quiet_useful = score(reach=100.0, explore=50.0, paths=0, density=0.0)
    assert quiet_useful > busy_useless


@pytest.mark.parametrize("explore", [0.0, 10.0, 40.0, 80.0, 100.0])
def test_score_is_monotonic_in_exploration(explore: float):
    """More of the target exercised is never worth less, at fixed everything
    else."""
    lower = score(reach=100.0, explore=max(explore - 10.0, 0.0),
                  paths=100, density=20.0)
    higher = score(reach=100.0, explore=explore, paths=100, density=20.0)
    assert higher >= lower


def test_the_two_shallow_cases_are_not_the_same_point():
    """Same reachability, same exploration, different AFL activity — and so a
    different score. Conflating them is the mistake that made this file's
    fixtures named."""
    assert score(**MEASURED_SHALLOW) != pytest.approx(
        score(**SYNTHETIC_BUSY_SHALLOW), abs=0.01)
