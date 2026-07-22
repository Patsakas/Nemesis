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
    """minmea_getdatetime, measured: 0% reachability, 0% exploration, AFL busy.

    The floor is not zero — building and running are worth 0.40 before the
    target is touched. Anyone reading a raw score needs that, or 0.40 looks
    like partial success."""
    s = score(reach=0.0, explore=0.0, paths=726, density=44.26)
    assert s == pytest.approx(0.40, abs=0.01)


def test_reached_but_shallow_lands_above_never_reached():
    """minmea_scan iteration 0 as it actually ran: 100% reachability, 21.35%
    exploration, and modest AFL activity (10 paths, 8.24% density). The
    pipeline logged 0.6819 for exactly these inputs."""
    useless = score(reach=0.0, explore=0.0, paths=726, density=44.26)
    shallow = score(reach=100.0, explore=21.35, paths=10, density=8.24)
    assert shallow == pytest.approx(0.68, abs=0.01)
    assert shallow > useless


def test_band_order_holds_across_the_three_measured_cases():
    """Held at identical AFL activity so the ordering comes from reachability
    and exploration, not from how busy the fuzzer happened to be."""
    never = score(reach=0.0, explore=0.0, paths=726, density=44.26)
    shallow = score(reach=100.0, explore=21.35, paths=726, density=44.26)
    deep = score(reach=100.0, explore=76.56, paths=726, density=44.26)
    assert never < shallow < deep
    assert deep >= 0.75, "substantial exploration must reach the top band"
