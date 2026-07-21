#!/usr/bin/env python3
"""Summarise a campaign results.csv — medians, spread, and whether to believe it.

AFL run-to-run variance on identical inputs is routinely larger than the effect
a seed-selection change produces. A table of means invites reading a difference
that is entirely noise, so this reports the median with the observed range
beside it, and refuses to call a winner when the arms' ranges overlap.

Usage:
  python scripts/bench_report.py /tmp/campaign/results.csv [--markdown]
"""

from __future__ import annotations

import argparse
import csv
import itertools
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def _u_statistic(x: list[float], y: list[float]) -> float:
    """Mann-Whitney U: pairs where x beats y, ties counted as half."""
    return sum(1 if a > b else 0.5 if a == b else 0 for a in x for b in y)


def exact_p(x: list[float], y: list[float], max_splits: int = 200_000) -> float | None:
    """Two-sided exact permutation test on U. None when too large to enumerate.

    Exact rather than the normal approximation because campaigns run a handful
    of repeats, where that approximation is not trustworthy. At five per arm
    there are 252 splits, so the whole distribution is enumerable and the p
    value is not an estimate.

    This exists because comparing min/max ranges is far too blunt: one
    exceptional baseline run makes ranges overlap even when every other
    comparison favours the other arm, and "the ranges overlap" then reads as
    "no difference" when the data says something more specific.
    """
    n = len(x)
    if n == 0 or len(y) == 0:
        return None
    from math import comb
    if comb(n + len(y), n) > max_splits:
        return None
    pool = list(x) + list(y)
    centre = n * len(y) / 2
    observed = abs(_u_statistic(x, y) - centre)
    hits = total = 0
    for idx in itertools.combinations(range(len(pool)), n):
        chosen = set(idx)
        g1 = [pool[i] for i in idx]
        g2 = [pool[i] for i in range(len(pool)) if i not in chosen]
        total += 1
        if abs(_u_statistic(g1, g2) - len(g1) * len(g2) / 2) >= observed:
            hits += 1
    return hits / total if total else None

# Metric, human label, whether more is better.
METRICS = [
    ("edges_found", "edges found", True),
    ("bitmap_cvg_pct", "bitmap %", True),
    ("corpus_count", "corpus", True),
    ("crashes", "crashes", True),
    ("hangs", "hangs", False),
    ("execs_per_sec", "execs/s", True),
    ("secs_to_last_find", "last find (s)", True),
]

ARM_LABELS = {
    "A": "real corpus",
    "B": "real + measured",
    "C": "real + random",
}


def load(path: Path) -> dict[str, list[dict]]:
    by_arm: dict[str, list[dict]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("bitmap_cvg_pct") == "ERROR":
                continue
            by_arm[row["arm"]].append(row)
    return by_arm


def values(rows: list[dict], key: str) -> list[float]:
    out = []
    for r in rows:
        try:
            out.append(float(r.get(key, "") or 0))
        except ValueError:
            continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--budget-secs", type=float, default=0,
                    help="per-run time budget, so plateau can be told from "
                         "truncation (see the verdict section)")
    ap.add_argument("--sensitivity", action="store_true",
                    help="re-run the plateau diagnosis across a grid of "
                         "thresholds, to show whether the verdict depends on "
                         "the two constants it uses")
    args = ap.parse_args()

    if not args.csv.exists():
        print(f"no such file: {args.csv}", file=sys.stderr)
        return 1

    by_arm = load(args.csv)
    if not by_arm:
        print("no usable rows — every run errored?", file=sys.stderr)
        return 1

    arms = sorted(by_arm)
    n_repeats = {a: len(by_arm[a]) for a in arms}
    print(f"repeats per arm: {n_repeats}")
    if min(n_repeats.values()) < 3:
        print("WARNING: fewer than 3 repeats — medians are not meaningful yet.")
    print()

    sep = " | " if args.markdown else "  "
    header = ["metric"] + [f"{a} ({ARM_LABELS.get(a, a)})" for a in arms]
    if args.markdown:
        print("| " + " | ".join(header) + " |")
        print("|" + "|".join(["---"] * len(header)) + "|")
    else:
        print(sep.join(f"{h:<22}" for h in header))
        print("-" * (24 * len(header)))

    stats: dict[str, dict[str, tuple[float, float, float]]] = {}
    for key, label, _ in METRICS:
        cells = []
        stats[key] = {}
        for a in arms:
            vals = values(by_arm[a], key)
            if not vals:
                cells.append("-")
                continue
            med, lo, hi = statistics.median(vals), min(vals), max(vals)
            stats[key][a] = (med, lo, hi)
            cells.append(f"{med:g} [{lo:g}-{hi:g}]")
        row = [label] + cells
        if args.markdown:
            print("| " + " | ".join(row) + " |")
        else:
            print(sep.join(f"{c:<22}" for c in row))

    # ── Plateau detection ───────────────────────────────────
    #
    # A run that stopped finding long before the budget expired has shown what
    # its corpus can do. A run still finding when the clock ran out was cut
    # short, and its number is a lower bound rather than a result. Comparing a
    # saturated arm against a truncated one measures the budget, not the seeds.
    #
    # Observed on libpng at 4 minutes: two A runs and a C run stopped finding
    # 60-80s before the end (and AFL reported 36-50 cycles with no new finds),
    # while every B run was still finding in the final 20s. Reading that as
    # "B is better" or as "inconclusive" would both miss what happened.
    PLATEAU_FRACTION = 0.85   # last find before this share of the budget → done
    plateaued: dict[str, list[bool]] = {}
    if args.budget_secs > 0:
        for a in arms:
            flags = []
            for v in values(by_arm[a], "secs_to_last_find"):
                if v < 0:
                    continue
                flags.append(v < args.budget_secs * PLATEAU_FRACTION)
            plateaued[a] = flags
        print()
        print(f"plateau (last find before {PLATEAU_FRACTION:.0%} of "
              f"{args.budget_secs:g}s budget):")
        for a in arms:
            f = plateaued.get(a, [])
            if f:
                print(f"  {a}: {sum(f)}/{len(f)} runs saturated, "
                      f"{len(f) - sum(f)} still finding at cutoff")

    print()
    key = "edges_found"
    if "A" not in stats.get(key, {}) or "B" not in stats[key]:
        return 0

    a_med, a_lo, a_hi = stats[key]["A"]
    b_med, b_lo, b_hi = stats[key]["B"]
    print(f"primary metric: {key}")
    print(f"  A {a_med:g} [{a_lo:g}-{a_hi:g}]   B {b_med:g} [{b_lo:g}-{b_hi:g}]")

    # Compare saturation RATES, not "did every run saturate". Requiring all of
    # A and C to have plateaued is too strict to ever fire: one lucky baseline
    # run that was still climbing at the cutoff would mask the fact that every
    # B run was. What matters is whether B is systematically less saturated
    # than the arms it is being compared against.
    def sat_rate(arm: str) -> float | None:
        flags = plateaued.get(arm)
        return (sum(flags) / len(flags)) if flags else None

    b_rate = sat_rate("B")
    ac_flags = [f for a in ("A", "C") for f in plateaued.get(a, [])]
    ac_rate = (sum(ac_flags) / len(ac_flags)) if ac_flags else None

    # A quarter of runs is a wide enough gap not to fire on one stray run.
    SATURATION_GAP = 0.25
    b_truncated = (
        b_rate is not None and ac_rate is not None
        and b_rate < ac_rate - SATURATION_GAP
    )

    if b_lo > a_hi:
        verdict = "COVERAGE SEPARATION"
        note = ("B's worst run beat A's best. If all arms also plateaued, this "
                "is a result; if B was still finding, it is a lower bound.")
    elif b_truncated:
        verdict = "BUDGET-LIMITED"
        note = (f"B saturated in {b_rate:.0%} of runs against {ac_rate:.0%} for "
                "A/C, so this compares a search that finished against one that "
                "did not. The fix is a LONGER BUDGET, not more repeats — "
                "repeating a truncated measurement only measures the "
                "truncation more precisely.")
    elif b_med > a_med:
        verdict = "NO EVIDENCE (overlapping ranges)"
        note = ("B's median is higher but the ranges overlap, and B is not "
                "systematically less saturated than A/C. Consistent with noise.")
    else:
        verdict = "NO ADVANTAGE"
        note = "B did not beat A on this metric."

    print(f"  verdict: {verdict}")
    print(f"  {note}")

    # ── Pairwise significance ───────────────────────────────
    #
    # B vs C is the comparison that answers the actual question. Both arms have
    # the same number of seeds, so a difference between them can only come from
    # which seeds. B vs A confounds "better seeds" with "more seeds", and C vs A
    # is the check that adding seeds alone changes nothing.
    print()
    print("  pairwise (exact permutation test on U):")
    raw = {a: values(by_arm[a], key) for a in arms}
    for lhs, rhs, meaning in (
        ("B", "C", "same seed count, different content — the real question"),
        ("B", "A", "confounded: more seeds AND different seeds"),
        ("C", "A", "control: does adding seeds alone do anything?"),
    ):
        if lhs not in raw or rhs not in raw or not raw[lhs] or not raw[rhs]:
            continue
        u = _u_statistic(raw[lhs], raw[rhs])
        n = len(raw[lhs]) * len(raw[rhs])
        p = exact_p(raw[lhs], raw[rhs])
        p_txt = "n/a" if p is None else f"p={p:.4f}"
        mark = "" if p is None else ("  SIGNIFICANT" if p < 0.05 else "  ns")
        print(f"    {lhs} vs {rhs}:  {u:g}/{n} pairs  {p_txt}{mark}")
        print(f"      ({meaning})")

    if "C" in stats[key]:
        c_med, c_lo, c_hi = stats[key]["C"]
        print(f"  control C {c_med:g} [{c_lo:g}-{c_hi:g}]")
        if c_med >= b_med:
            print("  C matched or beat B — the gain is from ADDING SEEDS, not from "
                  "which seeds. This is the result that would invalidate the claim.")
        elif c_med <= a_med:
            print("  C sat at A's level, so extra seeds alone bought nothing and "
                  "B's difference is attributable to seed content.")

    _distribution(by_arm, arms, key)

    if args.sensitivity and args.budget_secs > 0:
        _sensitivity(by_arm, arms, args.budget_secs)
    return 0


def _distribution(by_arm, arms, key: str) -> None:
    """Show every run, not just the summary.

    A median hides the shape, and the shape is what decides whether a result
    means anything. The first libpng campaign had four baseline runs at 311-312
    and one at 428; the median said 312, the range said "overlaps everything",
    and neither conveyed that a single run was doing all the work.

    What to look for: is one arm consistently ahead, or ahead on average
    because of a couple of jumps? An advantage that shows up in every run is a
    different claim from one that shows up in two.
    """
    print()
    print("per-run values (sorted) — check the shape, not just the median:")
    series = {}
    for a in arms:
        vals = sorted(values(by_arm[a], key))
        series[a] = vals
        if not vals:
            continue
        med = statistics.median(vals)
        # Flag values far from the rest of their own arm: with a handful of
        # runs, one outlier can carry a median or blow out a range.
        #
        # Distance must be large both relative to the arm's own spread AND in
        # absolute terms. Spread alone misfires on a tight arm: 383 and 389
        # against a median of 398 sit more than half the spread away only
        # because the spread is 15, and calling them outliers would be absurd.
        spread = max(vals) - min(vals)
        outliers = [
            v for v in vals
            if spread and abs(v - med) > 0.5 * spread and abs(v - med) > 0.1 * med
        ]
        tag = f"   outlier(s): {', '.join(f'{o:g}' for o in outliers)}" if outliers else ""
        print(f"  {a}: {', '.join(f'{v:g}' for v in vals)}{tag}")

    if "B" in series and series["B"]:
        for other in ("A", "C"):
            if other not in series or not series[other]:
                continue
            b, o = series["B"], series[other]
            wins = sum(1 for x in b for y in o if x > y)
            losses = sum(1 for x in b for y in o if x < y)
            worst_b, best_o = min(b), max(o)
            print(f"  B vs {other}: B ahead in {wins}/{len(b) * len(o)} pairings, "
                  f"behind in {losses}")
            if worst_b > best_o:
                print(f"    every B run beat every {other} run "
                      f"({worst_b:g} > {best_o:g}) — consistent, not driven by outliers")
            elif wins > losses:
                print(f"    B leads on average but {other} reaches {best_o:g} "
                      f"against B's worst {worst_b:g} — check whether the lead "
                      "comes from a few runs or all of them")


def _sensitivity(by_arm, arms, budget: float) -> None:
    """Re-diagnose across a grid of both constants.

    PLATEAU_FRACTION and SATURATION_GAP were chosen from one target at one
    budget. If the diagnosis holds across a range of both, it is a property of
    the data; if it flips inside that range, it is a property of the constants
    and must not be quoted as a finding.
    """
    print()
    print("sensitivity of the plateau diagnosis:")
    print(f"  {'plateau@':<10}" + "".join(f"gap {g:<6.2f}" for g in
                                          (0.15, 0.20, 0.25, 0.30, 0.35)))
    flips = set()
    for frac in (0.75, 0.80, 0.85, 0.90, 0.95):
        cells = []
        for gap in (0.15, 0.20, 0.25, 0.30, 0.35):
            rates = {}
            for a in arms:
                flags = [v < budget * frac
                         for v in values(by_arm[a], "secs_to_last_find") if v >= 0]
                rates[a] = (sum(flags) / len(flags)) if flags else None
            ac = [v for a in ("A", "C") for v in
                  ([rates[a]] if rates.get(a) is not None else [])]
            b_r, ac_r = rates.get("B"), (sum(ac) / len(ac)) if ac else None
            limited = (b_r is not None and ac_r is not None and b_r < ac_r - gap)
            cells.append("LIMITED" if limited else "-")
            flips.add(limited)
        print(f"  {frac:<10.0%}" + "".join(f"{c:<10}" for c in cells))

    print()
    if len(flips) == 1:
        print("  Diagnosis is identical across the whole grid — it does not "
              "depend on where the thresholds were set.")
    else:
        print("  Diagnosis FLIPS inside this grid. The thresholds are doing the "
              "work, not the data. Do not quote the verdict as a finding "
              "without reporting this table alongside it.")


if __name__ == "__main__":
    raise SystemExit(main())
