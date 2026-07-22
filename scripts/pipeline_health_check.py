"""Health check over a run log: are the safeguards actually on the path?

Every defect found on 2026-07-22 was a violation of one of five properties,
never of the code itself:

  wiring           the component is called from the production path
  observability    the right measurement is recorded
  consumption      the measurement reaches the decision that needs it
  provenance       the value belongs to the run it is attributed to
  interpretability the log alone explains the outcome, with no reconstruction

Concretely: a variadic gate passed 23 unit tests and logged zero events because
the harness-variant path bypassed it; source coverage was measured on every
iteration by code the loop returned before reaching; a quality score moved in
the right direction for the wrong reason and needed an offline reconstruction
to explain; and the fix for the second went on to report one iteration's
coverage as the next one's, because TargetResult outlives an iteration. Each is
invisible to a test suite and obvious in a run log.

Each check reports one of three states, kept distinct on purpose:

  PASS           the safeguard was exercised and behaved correctly
  FAIL           it was exercised and did not
  NOT_EXERCISED  nothing in this run gave it the chance to be evaluated

Collapsing the third into PASS is the "zero failures means healthy" mistake:
a run where no unsound harness was generated is not evidence that the gate
would have caught one.

Property rollup, where several checks share a property:

  FAIL           if any constituent check fails
  PASS           if at least one was exercised and none failed
  NOT_EXERCISED  if no constituent check was exercised

Worst-wins rather than majority or average. `observability` currently has two
checks; on the pre-fix baseline one passes and one fails, and reporting that
property as half-healthy would hide a loop that skipped measurement on 2 of 2
opportunities.

Exit code is 0 when every check passes, 1 otherwise, so this can gate a run —
though report-only is the sensible first mode, since the checks describe
requirements that the pipeline does not yet fully meet.

usage: pipeline_health_check.py <run.log> [--json]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


class Check:
    def __init__(self, name: str, prop: str):
        self.name, self.prop = name, prop
        self.passed: bool | None = None
        self.detail = ""
        self.data: dict = {}

    def ok(self, detail: str = "", **data):
        self.passed, self.detail, self.data = True, detail, data
        return self

    def fail(self, detail: str, **data):
        self.passed, self.detail, self.data = False, detail, data
        return self

    def na(self, detail: str, **data):
        """Not exercised — reported separately from a pass, because "nothing
        happened" and "the safeguard worked" are different claims."""
        self.passed, self.detail, self.data = None, detail, data
        return self


def _events(log: str, name: str) -> list[str]:
    return re.findall(rf"{re.escape(name)}\s+(.*)", log)


def _floats(fields: str, key: str) -> float | None:
    m = re.search(rf"\b{key}=(-?[\d.]+)", fields)
    return float(m.group(1)) if m else None


def check_variadic_gate(log: str) -> Check:
    """Wiring. Zero rejections is not automatically a pass: it means either the
    gate held or nothing unsound was generated, and those must not be conflated.

    The detectable failure is not "the gate is missing" — a log from a run where
    every harness was sound cannot show that either way. It is a rejection that
    did not take effect: the gate refused a harness and the build proceeded
    anyway, with no repair in between. That is the gate logging instead of
    gating, which is exactly how the first version of it behaved.
    """
    c = Check("variadic_gate", "wiring")
    rejections = [m.start() for m in
                  re.finditer(r"harness\.variadic_arity_rejected", log)]
    if not rejections:
        return c.na("no rejections — no unsound harness was generated this run; "
                    "the gate is not evidenced either way by this log",
                    rejections=0)

    ineffective = 0
    for pos in rejections:
        rest = log[pos:]
        build = re.search(r"harness\.compile\.success", rest)
        repair = re.search(r"harness\.(preflight_llm_repair_applied|"
                           r"variant_generated)|harness_a\.start|"
                           r"refine_harness\.start", rest)
        if build and (repair is None or build.start() < repair.start()):
            ineffective += 1

    if ineffective:
        return c.fail(
            f"{ineffective} of {len(rejections)} rejection(s) were followed by a "
            "successful build with no regeneration in between — the gate logged "
            "but did not gate",
            rejections=len(rejections), ineffective=ineffective)
    return c.ok(f"{len(rejections)} unsound harness(es) refused before build",
                rejections=len(rejections), ineffective=0)


def check_closed_loop(log: str) -> Check:
    """Observability. Every bitmap-expansion exit must carry the coverage it
    was supposed to measure. Stated as an equality rather than "coverage
    appears somewhere", so a new early-exit branch that skips measurement is
    caught rather than masked by another branch that does measure."""
    c = Check("closed_loop", "observability")
    exits = _events(log, "fuzz_a.bitmap_expanded")
    if not exits:
        return c.na("no bitmap-expansion exit occurred", exits=0)
    carrying = [e for e in exits if "source_coverage_pct" in e]
    if len(carrying) == len(exits):
        return c.ok(f"all {len(exits)} bitmap exit(s) carry source coverage",
                    exits=len(exits), carrying=len(carrying))
    return c.fail(
        f"{len(exits) - len(carrying)} of {len(exits)} bitmap exit(s) returned "
        "without measuring source coverage",
        exits=len(exits), carrying=len(carrying))


def check_coverage_recorded(log: str) -> Check:
    """Observability + sanity. A recorded value must also be a plausible one."""
    c = Check("coverage_recorded", "observability")
    results = _events(log, "source_coverage.result")
    if not results:
        return c.fail("no source coverage recorded in the entire run", count=0)
    values = []
    for r in results:
        v = _floats(r, "line_cov_pct")
        if v is not None:
            values.append(v)
    out_of_range = [v for v in values if not 0.0 <= v <= 100.0]
    if out_of_range:
        return c.fail(f"coverage outside [0,100]: {out_of_range}",
                      count=len(values), out_of_range=out_of_range)
    iters = sorted({int(m) for r in results
                    for m in re.findall(r"iteration=(\d+)", r)})
    return c.ok(f"{len(values)} measurement(s) across iteration(s) {iters}",
                count=len(values), iterations=iters, values=values)


def check_score_consumes_coverage(log: str) -> Check:
    """Consumption. A measurement that never reaches the decision is decoration.

    Two levels, and the baseline satisfied only the first:

      code-level     the score formula takes source coverage as an input
      runtime-level  execution actually reaches a point where a valid coverage
                     value exists *before* the score is computed

    So this inspects both places a score is produced. `harness.quality_score`
    covers the normal path; the bitmap-expansion exit carries its score as a
    field on `fuzz_a.bitmap_expanded` instead, and that is precisely the branch
    that returned before measuring anything in the pre-fix run. Checking only
    the former would leave the branch that failed unexamined.
    """
    c = Check("score_consumes_coverage", "consumption")
    scores = _events(log, "harness.quality_score")
    bitmap = [e for e in _events(log, "fuzz_a.bitmap_expanded")
              if "quality_score" in e]

    if not scores and not bitmap:
        return c.na("no quality score computed anywhere", count=0)

    problems = []
    for s in scores:
        if "line_cov=n/a" in s:
            problems.append("harness.quality_score without coverage")
    for b in bitmap:
        cov = _floats(b, "source_coverage_pct")
        if cov is None:
            problems.append("bitmap exit scored without a coverage field")
        elif cov < 0.0:
            problems.append("bitmap exit scored with coverage=-1 (unmeasured)")

    total = len(scores) + len(bitmap)
    if problems:
        return c.fail(
            f"{len(problems)} of {total} score(s) computed without usable "
            f"coverage: {'; '.join(sorted(set(problems)))}",
            count=total, without_coverage=len(problems))
    return c.ok(
        f"all {total} score(s) had coverage available "
        f"({len(scores)} normal path, {len(bitmap)} bitmap exit)",
        count=total, normal_path=len(scores), bitmap_path=len(bitmap))


def check_score_explainable(log: str) -> Check:
    """Interpretability. Can a reader reproduce the score from the log?"""
    c = Check("score_explainable", "interpretability")
    scores = _events(log, "harness.quality_score")
    if not scores:
        return c.na("no quality score computed")
    needed = ("line_cov", "score")
    optional = ("reachability", "paths", "density")
    have_all = all(all(k in s for k in needed) for s in scores)
    have_inputs = any(all(k in s for k in optional) for s in scores)
    if have_all and have_inputs:
        return c.ok("score and every input are logged")
    if have_all:
        return c.fail(
            "score logs coverage but not reachability/paths/density — "
            "explaining a value still needs offline reconstruction",
            missing=list(optional))
    return c.fail("score log is missing coverage or the value itself")


def check_metric_provenance(log: str) -> Check:
    """Provenance. A value reported for an iteration must have been measured
    for that iteration.

    `TargetResult` lives for the whole target, not one iteration, so any
    "have we measured yet?" guard on a metric field stops firing after
    iteration 0 and the previous iteration's value gets reported as the current
    one's. Observed immediately: `minmea_scan` iteration 1 logged
    `source_coverage_pct=21.35`, exactly iteration 0's figure, for a harness
    that was a different program.

    The log did not misreport the field — it misreported the *context*. So this
    pairs every reported value with a measurement event for the same iteration
    rather than checking the value itself. A stale number is plausible; a
    missing measurement event is not.
    """
    c = Check("metric_provenance", "provenance")
    measured: dict[tuple[str, str], list[float]] = {}
    for e in _events(log, "source_coverage.result"):
        func = re.search(r"\bfunc=(\S+)", e)
        it = re.search(r"\biteration=(\d+)", e)
        val = _floats(e, "line_cov_pct")
        if func and it and val is not None:
            measured.setdefault((func.group(1), it.group(1)), []).append(val)

    reported = []
    for e in _events(log, "fuzz_a.bitmap_expanded"):
        val = _floats(e, "source_coverage_pct")
        if val is None:
            continue
        func = re.search(r"\bfunc=(\S+)", e)
        it = re.search(r"\biteration=(\d+)", e)
        if func and it:
            reported.append((func.group(1), it.group(1), val))

    if not reported:
        return c.na("no per-iteration metric reported at a terminal exit")

    unbacked = [(f, i, v) for f, i, v in reported if (f, i) not in measured]
    if unbacked:
        detail = "; ".join(
            f"{f} iteration {i} reported {v} with no measurement for that "
            f"iteration" for f, i, v in unbacked[:3])
        return c.fail(
            f"{len(unbacked)} of {len(reported)} reported value(s) carry no "
            f"measurement event for their own iteration: {detail}",
            reported=len(reported), unbacked=len(unbacked))
    return c.ok(f"all {len(reported)} reported value(s) were measured for the "
                "iteration they are attributed to", reported=len(reported))


def check_reachability_confidence(log: str) -> Check:
    """Provenance. Inferred reachability must not be reported as measured.

    `variant.profile` falls back to the AFL bitmap when a GDB breakpoint misses
    the target — reasonable, since breakpoints fail on inlined, static and
    renamed functions. But `bitmap_cvg` is the edge map for the whole binary,
    harness included, and the threshold is 3%, which any harness that runs at
    all clears. The result is then stated as a certainty:

        coverage_pct = 100.0 if function_reached else 0.0

    Measured on minmea_getdatetime: the GDB check reported `hits=0 pct=0.0`
    over ten inputs while the fallback saw 63.85% bitmap and recorded complete
    reachability.

    This does not object to the fallback. It objects to the loss of the
    distinction: a run where the override fired cannot tell a measured 100%
    from an inferred one, so any reachability figure downstream — including the
    quality score's 0.25 term — carries unearned confidence.
    """
    c = Check("reachability_confidence", "provenance")
    overrides = _events(log, "variant.profile.bitmap_reach_override")
    if not overrides:
        return c.na("no reachability inferred from the bitmap fallback",
                    overrides=0)

    # One event per harness variant, not per target — the profiler runs on each
    # candidate. Counting events as targets overstates the spread; reporting
    # both is what shows whether one awkward function or the whole run is
    # affected.
    by_func: dict[str, list[float]] = {}
    for e in overrides:
        func = re.search(r"\bfunc=(\S+)", e)
        pct = _floats(e, "bitmap_pct")
        by_func.setdefault(func.group(1) if func else "?", []).append(pct or 0.0)

    detail = "; ".join(
        f"{f} ({len(v)}x, bitmap {min(v)}–{max(v)}%)" for f, v in
        sorted(by_func.items())[:4])
    return c.fail(
        f"reachability inferred from whole-binary bitmap activity and recorded "
        f"as measured: {len(overrides)} variant profile(s) across "
        f"{len(by_func)} target(s) — {detail}",
        overrides=len(overrides), targets=len(by_func),
        lowest_bitmap_pct=min(min(v) for v in by_func.values()))


# Names an AFL harness necessarily defines. A target sharing one of these
    # cannot be told apart from the harness by symbol name alone.
HARNESS_OWN_SYMBOLS = frozenset({"main", "LLVMFuzzerTestOneInput",
                                 "LLVMFuzzerInitialize"})


def check_coverage_attribution(log: str) -> Check:
    """Attribution. Does the coverage belong to the target, or to the harness?

    Measured on minmea target 3: the target was `main` from `tests.c`, ten lines
    long. `source_coverage` reported 23/72 lines — 72 being the generated
    harness's own `main`. GDB was right that the target was never reached;
    llvm-cov was right about a function called `main`; they measured different
    functions, and the score credited 0.35 x 31.94% of exploration for the
    harness executing itself.

    The full invariant is `coverage.entity.file == target.file` and cannot be
    evaluated here: `source_coverage.result` records the function name but not
    the file the symbol was resolved in. Until the pipeline logs the measured
    entity, this flags the collision that makes attribution ambiguous rather
    than proving a specific misattribution.

    `main` is the obvious case. `init`, `parse`, `process` and `run` collide
    just as easily once a harness grows helpers.
    """
    c = Check("coverage_attribution", "attribution")
    targets: dict[str, str] = {}
    for e in _events(log, "target.start"):
        func = re.search(r"\bfunc=(\S+)", e)
        path = re.search(r"\bfile=(\S+)", e)
        if func:
            targets[func.group(1)] = path.group(1) if path else "?"

    if not targets:
        return c.na("no targets recorded")

    colliding = {f: p for f, p in targets.items() if f in HARNESS_OWN_SYMBOLS}
    measured = {re.search(r"\bfunc=(\S+)", e).group(1)
                for e in _events(log, "source_coverage.result")
                if re.search(r"\bfunc=(\S+)", e)}
    at_risk = {f: p for f, p in colliding.items() if f in measured}

    if not at_risk:
        if colliding:
            return c.ok(
                f"{len(colliding)} target(s) share a harness symbol but none had "
                "coverage measured against them", targets=len(targets))
        return c.ok(f"no target among {len(targets)} shares a name with a "
                    "harness-defined symbol", targets=len(targets))

    detail = "; ".join(f"{f} ({p})" for f, p in sorted(at_risk.items()))
    return c.fail(
        f"coverage measured for {len(at_risk)} target(s) whose name is also "
        f"defined by the harness, so the figure may describe the harness "
        f"rather than the target: {detail}",
        targets=len(targets), at_risk=len(at_risk),
        note="full check needs the measured symbol's file, not logged today")


CHECKS = [check_variadic_gate, check_closed_loop, check_coverage_recorded,
          check_score_consumes_coverage, check_score_explainable,
          check_metric_provenance, check_reachability_confidence,
          check_coverage_attribution]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    log = Path(sys.argv[1]).read_text(errors="replace")
    as_json = "--json" in sys.argv

    results = [fn(log) for fn in CHECKS]
    failed = [r for r in results if r.passed is False]

    # A property is only as good as its weakest check: any failure fails it,
    # and a property with nothing exercised is reported as such rather than
    # counted as healthy.
    by_property: dict[str, str] = {}
    for r in results:
        current = by_property.get(r.prop)
        status = {True: "PASS", False: "FAIL", None: "NOT_EXERCISED"}[r.passed]
        if current == "FAIL" or status == "FAIL":
            by_property[r.prop] = "FAIL"
        elif current == "PASS" or status == "PASS":
            by_property[r.prop] = "PASS"
        else:
            by_property[r.prop] = "NOT_EXERCISED"

    counts = {
        "pass": sum(1 for r in results if r.passed is True),
        "fail": len(failed),
        "not_exercised": sum(1 for r in results if r.passed is None),
    }

    if as_json:
        print(json.dumps({
            "healthy": not failed,
            "counts": counts,
            "by_property": by_property,
            "checks": [{"name": r.name, "property": r.prop,
                        "status": {True: "pass", False: "fail",
                                   None: "not_exercised"}[r.passed],
                        "detail": r.detail, **r.data} for r in results],
        }, indent=2))
    else:
        width = max(len(r.name) for r in results)
        print("Pipeline Health")
        print("─" * 60)
        for r in results:
            mark = {True: "PASS", False: "FAIL", None: " -- "}[r.passed]
            print(f"  {mark}  {r.name:<{width}}  [{r.prop}]")
            print(f"        {r.detail}")
        print()
        print(f"  PASS           {counts['pass']}")
        print(f"  FAIL           {counts['fail']}")
        print(f"  NOT_EXERCISED  {counts['not_exercised']}")
        print()
        print("By property:")
        for prop in ("wiring", "observability", "consumption", "provenance",
                     "attribution",
                     "interpretability"):
            if prop in by_property:
                print(f"  {prop:<18}{by_property[prop]}")
        print()
        print("Overall: " + ("HEALTHY" if not failed else "UNHEALTHY"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
