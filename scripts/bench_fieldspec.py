#!/usr/bin/env python3
"""Seed-quality benchmark: does a MEASURED fieldspec beat the alternatives?

This is the cheap, deterministic half of evaluating byte-influence inference.
It does not fuzz. It asks a narrower question that a fuzzing campaign answers
slowly and noisily:

    Given N seeds generated from each source, how much of the target do they
    reach, and how many of them are distinguishable from each other?

Coverage of the generated corpus is a leading indicator for fuzzing outcome
(Rebert 2014: ~1% more coverage correlates with ~0.92% more bugs found), and
it is measurable in minutes rather than hours, with no LLM call and no
randomness beyond a fixed RNG seed.

Arms
----
  random     uniform random bytes of the same length — the floor. Anything
             that cannot beat this is not doing structural work.
  original   the single real seed the spec was measured from — the ceiling
             for "what we already had", since it is a genuine input.
  measured   seeds rendered from the coverage-derived fieldspec.
  llm        seeds rendered from the LLM-synthesised fieldspec (skipped
             unless --llm and a provider is configured).

Reported per arm: total unique edges across the corpus, mean edges per seed,
and how many seeds produced a distinct edge set. The last one matters most —
a generator that emits 200 files reaching the same 3 branches has produced one
seed, not two hundred.

Usage:
  python scripts/bench_fieldspec.py \
      --probe /tmp/probe_bin --corpus seeds/oss_fuzz_corpus_libtiff \
      --n-seeds 60
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nemesis.recon.byte_influence import (  # noqa: E402
    ShowmapRunner,
    cluster_fields,
    fields_from_groups,
    fields_to_fieldspec,
    fieldspec_variants,
    measure_baseline,
    probe_bytes,
    select_probe_seed,
)
from nemesis.recon.fieldspec_seedgen import (  # noqa: E402
    build_from_fieldspec,
    validate_fieldspec,
)


def corpus_stats(runner: ShowmapRunner, files: list[Path]) -> dict:
    """Edge statistics for a set of seed files."""
    per_seed: list[frozenset[str]] = []
    for f in files:
        per_seed.append(runner.edges_for(f))
    union: set[str] = set()
    for e in per_seed:
        union |= e
    distinct = len({e for e in per_seed if e})
    reached = [len(e) for e in per_seed]
    return {
        "seeds": len(files),
        "unique_edges_total": len(union),
        "mean_edges_per_seed": round(sum(reached) / len(reached), 1) if reached else 0,
        "max_edges_one_seed": max(reached) if reached else 0,
        "distinct_edge_sets": distinct,
        "dead_seeds": sum(1 for e in per_seed if not e),
    }


def render_arm(specs: list[dict], n: int, out_dir: Path, tag: str) -> list[Path]:
    """Render n seeds spread across the given specs, round-robin.

    A list rather than one spec because varying every field simultaneously
    destroys the input (see fieldspec_variants). Round-robin so the budget is
    spread across fields rather than exhausting the first.
    """
    d = out_dir / tag
    d.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if not specs:
        return written
    for i in range(n):
        spec = specs[i % len(specs)]
        data = build_from_fieldspec(spec.get("fields", []), random.Random(1000 + i))
        if not data:
            continue
        p = d / f"{tag}_{i:04d}.bin"
        p.write_bytes(data)
        written.append(p)
    return written


def random_arm(length: int, n: int, out_dir: Path) -> list[Path]:
    d = out_dir / "random"
    d.mkdir(parents=True, exist_ok=True)
    rng = random.Random(4242)
    out = []
    for i in range(n):
        p = d / f"random_{i:04d}.bin"
        p.write_bytes(bytes(rng.randrange(256) for _ in range(length)))
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True, help="probe binary (see recon/probe_build.py)")
    ap.add_argument("--corpus", required=True, help="directory of real seeds")
    ap.add_argument("--n-seeds", type=int, default=60)
    ap.add_argument("--max-seed-bytes", type=int, default=4000,
                    help="skip corpus files larger than this when choosing a probe seed")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--out", default="", help="write results JSON here")
    args = ap.parse_args()

    runner = ShowmapRunner(args.probe, timeout=15)
    corpus = sorted(p for p in Path(args.corpus).iterdir() if p.is_file())
    small = [p for p in corpus if p.stat().st_size <= args.max_seed_bytes]
    if not small:
        print("no corpus files under --max-seed-bytes", file=sys.stderr)
        return 1

    seed_path = select_probe_seed(runner, small)
    if seed_path is None:
        print("no seed reaches the target — is this the probe binary?", file=sys.stderr)
        return 1
    seed = seed_path.read_bytes()
    print(f"probe seed: {seed_path.name} ({len(seed)} bytes)")

    work = Path(tempfile.mkdtemp(prefix="bench_fieldspec_"))
    base, flaky = measure_baseline(runner, seed, work)
    print(f"baseline: {len(base)} edges ({len(flaky)} flaky, excluded)")

    kw = {"threshold": args.threshold} if args.threshold is not None else {}
    infl = probe_bytes(runner, seed, work, base, flaky)
    n_infl = sum(1 for i in infl if i.influential)
    fields = fields_from_groups(cluster_fields(infl, **kw))
    # all-at-once (the original approach) vs one-field-at-a-time
    whole = fields_to_fieldspec(fields, seed)
    variants = fieldspec_variants(fields, seed)
    ok, err = validate_fieldspec(whole)
    print(f"influential: {n_infl}/{len(seed)} "
          f"({100 * n_infl / len(seed):.1f}%)  fields: {len(fields)}  "
          f"variants: {len(variants)}  valid: {ok} {err}")

    arms: dict[str, list[Path]] = {
        "original": [seed_path],
        "random": random_arm(len(seed), args.n_seeds, work),
        "all-at-once": render_arm([whole], args.n_seeds, work, "whole"),
        "measured": render_arm(variants, args.n_seeds, work, "measured"),
    }

    print()
    print(f"{'arm':<10} {'seeds':>6} {'uniq edges':>11} {'mean/seed':>10} "
          f"{'max':>6} {'distinct':>9} {'dead':>5}")
    print("-" * 62)
    results = {}
    for name, files in arms.items():
        if not files:
            continue
        st = corpus_stats(runner, files)
        results[name] = st
        print(f"{name:<10} {st['seeds']:>6} {st['unique_edges_total']:>11} "
              f"{st['mean_edges_per_seed']:>10} {st['max_edges_one_seed']:>6} "
              f"{st['distinct_edge_sets']:>9} {st['dead_seeds']:>5}")

    print()
    r, m = results.get("random", {}), results.get("measured", {})
    if r and m:
        print("measured vs random:")
        print(f"  unique edges : {r['unique_edges_total']} -> {m['unique_edges_total']}")
        print(f"  mean per seed: {r['mean_edges_per_seed']} -> {m['mean_edges_per_seed']}")
        verdict = ("measured wins" if m["unique_edges_total"] > r["unique_edges_total"]
                   else "NO IMPROVEMENT over random")
        print(f"  verdict      : {verdict}")

    if args.out:
        payload = {
            "probe": args.probe, "corpus": args.corpus,
            "probe_seed": seed_path.name, "seed_bytes": len(seed),
            "baseline_edges": len(base),
            "influential_bytes": n_infl,
            "fields": len(fields), "arms": results,
        }
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
