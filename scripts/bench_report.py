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
import statistics
import sys
from collections import defaultdict
from pathlib import Path

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

    # Verdict on the primary metric only. Coverage is what a short campaign can
    # measure; crash counts need far longer to separate.
    print()
    key = "edges_found"
    if "A" in stats.get(key, {}) and "B" in stats[key]:
        a_med, a_lo, a_hi = stats[key]["A"]
        b_med, b_lo, b_hi = stats[key]["B"]
        print(f"primary metric: {key}")
        print(f"  A {a_med:g} [{a_lo:g}-{a_hi:g}]   B {b_med:g} [{b_lo:g}-{b_hi:g}]")
        if b_lo > a_hi:
            print("  B's worst run beat A's best — separation is clean.")
        elif b_med > a_med:
            print("  B's median is higher but the ranges OVERLAP. This is consistent "
                  "with noise; more repeats or a longer budget are needed before "
                  "claiming an effect.")
        else:
            print("  no advantage for B on this metric.")

        if "C" in stats[key]:
            c_med, c_lo, c_hi = stats[key]["C"]
            print(f"  control C {c_med:g} [{c_lo:g}-{c_hi:g}]")
            if c_med >= b_med:
                print("  C matched or beat B — the gain is from ADDING SEEDS, not from "
                      "which seeds. This is the result that would invalidate the claim.")
            elif c_med <= a_med:
                print("  C sat at A's level, so extra seeds alone bought nothing and "
                      "B's gain is attributable to seed content.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
