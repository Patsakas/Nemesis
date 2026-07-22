"""
Tests for the pipeline health check — including that each check can fail.

A health check that cannot go red is decoration. Every check here is exercised
against three logs: one where the property holds, one where it is violated, and
one where nothing exercised it. The third matters as much as the others,
because "no failures" and "healthy" are different claims and conflating them is
the mistake the whole script exists to prevent.

`test_every_check_has_a_failing_case` enforces this structurally, so a check
added later cannot ship without evidence that it detects its own violation.
That requirement comes from the recurring defect of 2026-07-22: a component
that was correct, tested, and never reached by the production path — a pattern
that showed up four times, once inside this script.
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pipeline_health_check.py"

TS = "2026-07-22T20:00:00.0Z [info     ] "


def run(tmp_path: Path, lines: list[str]) -> dict:
    log = tmp_path / "run.log"
    log.write_text("\n".join(TS + ln for ln in lines) + "\n")
    proc = subprocess.run([sys.executable, str(SCRIPT), str(log), "--json"],
                          capture_output=True, text=True)
    return json.loads(proc.stdout)


def status_of(report: dict, name: str) -> str:
    return next(c["status"] for c in report["checks"] if c["name"] == name)


# ── log fragments ───────────────────────────────────────────

SCORE_OK = ("harness.quality_score func=f iteration=0 line_cov=76.56 "
            "score=0.918 stage=pipeline")
SCORE_NO_COV = ("harness.quality_score func=f iteration=0 line_cov=n/a "
                "score=0.6 stage=pipeline")
SCORE_FULL = ("harness.quality_score func=f iteration=0 line_cov=76.56 "
              "reachability=1.0 paths=726 density=44.26 score=0.918 "
              "stage=pipeline")
COV_OK = "source_coverage.result func=f line_cov_pct=76.56 iteration=1 stage=pipeline"
COV_INSANE = "source_coverage.result func=f line_cov_pct=1234.0 iteration=0 stage=pipeline"
BITMAP_OK = ("fuzz_a.bitmap_expanded bitmap_delta=44.26 func=f iteration=1 "
             "source_coverage_pct=76.56 quality_score=0.918 stage=pipeline")
BITMAP_BARE = "fuzz_a.bitmap_expanded bitmap_delta=44.26 func=f iteration=1 stage=pipeline"
BITMAP_UNMEASURED = ("fuzz_a.bitmap_expanded bitmap_delta=44.26 func=f iteration=1 "
                     "source_coverage_pct=-1.0 quality_score=0.9 stage=pipeline")
REJECTED = ("harness.variadic_arity_rejected func=minmea_scan "
            "findings=['arity_mismatch'] stage=symbolic.builder")


# ── variadic_gate [wiring] ──────────────────────────────────


def test_gate_pass(tmp_path):
    assert status_of(run(tmp_path, [REJECTED, COV_OK, SCORE_FULL, BITMAP_OK]),
                     "variadic_gate") == "pass"


def test_gate_not_exercised_when_nothing_was_rejected(tmp_path):
    """Zero rejections must never read as a pass — it is the absence of
    evidence, not evidence of the safeguard working."""
    assert status_of(run(tmp_path, [COV_OK, SCORE_OK]),
                     "variadic_gate") == "not_exercised"


def test_gate_fails_when_a_rejection_did_not_stop_the_build(tmp_path):
    """The gate logging instead of gating. A rejection followed straight by a
    successful build, with no regeneration between them, means the refusal had
    no effect — which is how the first version of the gate behaved: correct,
    tested, and not on the path that compiles harnesses."""
    r = run(tmp_path, [REJECTED,
                       "harness.compile.success binary=/tmp/fuzz stage=symbolic.builder",
                       COV_OK, SCORE_FULL])
    assert status_of(r, "variadic_gate") == "fail"


def test_gate_passes_when_rejection_is_followed_by_regeneration(tmp_path):
    """A rejection that leads to a repaired harness being built is the gate
    working, not failing."""
    r = run(tmp_path, [REJECTED,
                       "harness.preflight_llm_repair_applied func=f stage=symbolic",
                       "harness.compile.success binary=/tmp/fuzz stage=symbolic.builder",
                       COV_OK, SCORE_FULL])
    assert status_of(r, "variadic_gate") == "pass"


# ── closed_loop [observability] ─────────────────────────────


def test_closed_loop_pass(tmp_path):
    assert status_of(run(tmp_path, [COV_OK, BITMAP_OK]), "closed_loop") == "pass"


def test_closed_loop_fails_when_a_bitmap_exit_skips_measurement(tmp_path):
    """The exact pre-fix defect: the loop returned on AFL map growth without
    measuring anything about the target."""
    assert status_of(run(tmp_path, [COV_OK, BITMAP_BARE]), "closed_loop") == "fail"


def test_closed_loop_fails_on_a_mix(tmp_path):
    """One measuring branch must not mask another that does not — this is why
    the check is an equality and not "coverage appears somewhere"."""
    assert status_of(run(tmp_path, [COV_OK, BITMAP_OK, BITMAP_BARE]),
                     "closed_loop") == "fail"


def test_closed_loop_not_exercised_without_bitmap_exit(tmp_path):
    assert status_of(run(tmp_path, [COV_OK, SCORE_OK]),
                     "closed_loop") == "not_exercised"


# ── coverage_recorded [observability] ───────────────────────


def test_coverage_recorded_pass(tmp_path):
    assert status_of(run(tmp_path, [COV_OK]), "coverage_recorded") == "pass"


def test_coverage_recorded_fails_when_absent(tmp_path):
    assert status_of(run(tmp_path, [SCORE_NO_COV]), "coverage_recorded") == "fail"


def test_coverage_recorded_fails_on_impossible_value(tmp_path):
    """Recorded is not the same as plausible."""
    assert status_of(run(tmp_path, [COV_INSANE]), "coverage_recorded") == "fail"


# ── score_consumes_coverage [consumption] ───────────────────


def test_consumption_pass_on_both_paths(tmp_path):
    r = run(tmp_path, [COV_OK, SCORE_OK, BITMAP_OK])
    assert status_of(r, "score_consumes_coverage") == "pass"


def test_consumption_fails_when_normal_path_has_no_coverage(tmp_path):
    assert status_of(run(tmp_path, [COV_OK, SCORE_NO_COV]),
                     "score_consumes_coverage") == "fail"


def test_consumption_fails_when_bitmap_path_scores_on_unmeasured_coverage(tmp_path):
    """Degraded-but-continuing is more dangerous than not measuring: it makes a
    decision on a value that was never observed. Checking only the normal path
    would leave this branch — the one that failed in the real run —
    unexamined."""
    assert status_of(run(tmp_path, [COV_OK, BITMAP_UNMEASURED]),
                     "score_consumes_coverage") == "fail"


def test_consumption_fails_when_bitmap_scores_without_a_coverage_field(tmp_path):
    r = run(tmp_path, [COV_OK, BITMAP_BARE.replace(
        "stage=pipeline", "quality_score=0.9 stage=pipeline")])
    assert status_of(r, "score_consumes_coverage") == "fail"


# ── score_explainable [interpretability] ────────────────────


def test_explainable_pass_when_all_inputs_logged(tmp_path):
    assert status_of(run(tmp_path, [COV_OK, SCORE_FULL]),
                     "score_explainable") == "pass"


def test_explainable_fails_when_only_the_value_is_logged(tmp_path):
    """The current pipeline state: a score cannot be reproduced from the log,
    which is why explaining 0.8824 needed an offline reconstruction."""
    assert status_of(run(tmp_path, [COV_OK, SCORE_OK]),
                     "score_explainable") == "fail"


# ── metric_provenance [provenance] ──────────────────────────

COV_ITER1 = ("source_coverage.result func=minmea_scan line_cov_pct=76.56 "
             "iteration=1 stage=pipeline")
COV_ITER0 = ("source_coverage.result func=minmea_scan line_cov_pct=21.35 "
             "iteration=0 stage=pipeline")
BITMAP_ITER1 = ("fuzz_a.bitmap_expanded bitmap_delta=44.59 func=minmea_scan "
                "iteration=1 source_coverage_pct=76.56 quality_score=0.918 "
                "stage=pipeline")
BITMAP_ITER1_STALE = ("fuzz_a.bitmap_expanded bitmap_delta=44.59 "
                      "func=minmea_scan iteration=1 source_coverage_pct=21.35 "
                      "quality_score=0.7247 stage=pipeline")


def test_provenance_pass_when_value_measured_for_its_own_iteration(tmp_path):
    r = run(tmp_path, [COV_ITER0, COV_ITER1, BITMAP_ITER1, SCORE_FULL])
    assert status_of(r, "metric_provenance") == "pass"


def test_provenance_fails_on_a_value_carried_over_from_a_previous_iteration(tmp_path):
    """The observed bug: `TargetResult` outlives an iteration, so a guard on the
    field stopped firing after iteration 0 and iteration 1 reported iteration
    0's coverage. The log does not misreport the value — it misreports the
    context, so the check pairs values with measurement events rather than
    inspecting the numbers."""
    r = run(tmp_path, [COV_ITER0, BITMAP_ITER1_STALE, SCORE_FULL])
    assert status_of(r, "metric_provenance") == "fail"


def test_provenance_is_independent_of_consumption(tmp_path):
    """A stale value still *reaches* the score, so consumption is satisfied
    while provenance is not. Conflating them would hide this bug behind a
    passing check."""
    r = run(tmp_path, [COV_ITER0, BITMAP_ITER1_STALE, SCORE_FULL])
    assert status_of(r, "score_consumes_coverage") == "pass"
    assert status_of(r, "metric_provenance") == "fail"


def test_provenance_not_exercised_without_a_terminal_metric(tmp_path):
    assert status_of(run(tmp_path, [COV_ITER0, SCORE_FULL]),
                     "metric_provenance") == "not_exercised"


# ── reachability_confidence [provenance] ────────────────────

OVERRIDE = ("variant.profile.bitmap_reach_override bitmap_pct=63.85 "
            "func=minmea_getdatetime reason='GDB breakpoint missed but bitmap "
            "indicates code reached' stage=symbolic.builder")


def test_reachability_confidence_fails_when_reach_is_inferred(tmp_path):
    """The measured case: GDB reported 0 of 10 inputs reaching the target while
    the fallback saw 63.85% whole-binary bitmap and recorded 100%."""
    r = run(tmp_path, [OVERRIDE, COV_OK, SCORE_FULL, BITMAP_OK])
    assert status_of(r, "reachability_confidence") == "fail"


def test_reachability_confidence_not_exercised_without_a_fallback(tmp_path):
    """A run where every target was confirmed by breakpoint has nothing to
    report — which is not the same as the fallback being safe."""
    assert status_of(run(tmp_path, [COV_OK, SCORE_FULL]),
                     "reachability_confidence") == "not_exercised"


def test_inference_does_not_disturb_the_other_checks(tmp_path):
    """The objection is to the lost distinction, not to coverage being absent —
    everything else on the same log still passes."""
    r = run(tmp_path, [OVERRIDE, COV_ITER0, COV_ITER1, BITMAP_ITER1, SCORE_FULL])
    assert status_of(r, "coverage_recorded") == "pass"
    assert status_of(r, "metric_provenance") == "pass"
    assert status_of(r, "reachability_confidence") == "fail"


# ── rollup ──────────────────────────────────────────────────


def test_property_rollup_is_worst_wins(tmp_path):
    """observability has two checks. One passing must not offset one failing."""
    r = run(tmp_path, [COV_OK, BITMAP_BARE])
    assert status_of(r, "coverage_recorded") == "pass"
    assert status_of(r, "closed_loop") == "fail"
    assert r["by_property"]["observability"] == "FAIL"


def test_healthy_only_when_nothing_failed(tmp_path):
    assert run(tmp_path, [COV_OK, SCORE_FULL, BITMAP_OK])["healthy"] is True
    assert run(tmp_path, [COV_OK, SCORE_OK, BITMAP_BARE])["healthy"] is False


def test_exit_code_tracks_health(tmp_path):
    log = tmp_path / "r.log"
    log.write_text(TS + BITMAP_BARE + "\n")
    proc = subprocess.run([sys.executable, str(SCRIPT), str(log)],
                          capture_output=True, text=True)
    assert proc.returncode == 1


# ── the meta-requirement ────────────────────────────────────


def test_every_invariant_has_a_validated_negative_path():
    """Every check must have a test that injects a violation of its property
    and asserts *that* check fails.

    Not "the check can go red" — that would be satisfied by any assertion. The
    requirement is that a specific violation maps to the specific failure, so a
    check cannot silently answer a different question than the one it names.

    Applied here, this immediately caught `variadic_gate`: it could only return
    pass or not_exercised, so no violation mapped to a failure at all. It was
    an assumption wearing the shape of a guard — the same thing the pipeline
    defects it exists to catch were.
    """
    sys.path.insert(0, str(SCRIPT.parent))
    import pipeline_health_check as hc

    defined = {fn("").name for fn in hc.CHECKS}
    source = Path(__file__).read_text()
    missing = [name for name in defined
               if f'"{name}") == "fail"' not in source]
    assert not missing, (
        f"no validated negative path for: {missing} — a check whose violation "
        "has never been injected is an assumption, not a guard")
