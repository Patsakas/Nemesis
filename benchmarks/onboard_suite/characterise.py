#!/usr/bin/env python3
"""Describe what the frozen sample actually contains, before the baseline runs.

A funnel over 25 repositories says nothing on its own. If the draw happens to be
20 CMake projects and 23 parsers, the honest conclusion is bounded — "within this
benchmark scope" — not "for arbitrary C repositories". This script produces the
numbers that bound it, and is meant to be run *before* the first benchmark so the
scoping cannot be written to fit the result.

It never changes the sample. Its output is descriptive only.

Usage:
    python characterise.py                 # profile repos.yaml against pool.json
    python characterise.py --md profile.md
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent

# Words in a repo description that suggest an input-parsing library — the shape
# NEMESIS is strongest on. Counted, never filtered on: an over-representation
# here is a caveat to report, not a reason to redraw.
_PARSER_HINTS = (
    "parse", "parser", "decode", "decoder", "encode", "codec", "format",
    "reader", "serial", "deserial", "protocol", "image", "audio", "font",
    "compress", "archive", "json", "xml", "yaml", "toml", "csv",
)


def _age_days(iso: str) -> float:
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def profile(suite: dict[str, Any], pool: dict[str, Any]) -> dict[str, Any]:
    chosen = {r["full_name"] for r in suite["repos"]}
    meta = {c["full_name"]: c for c in pool["candidates"]}
    rows = [meta[n] for n in chosen if n in meta]
    missing = sorted(chosen - set(meta))

    sizes = [r["size_kb"] for r in rows]
    stars = [r["stars"] for r in rows]
    ages = [_age_days(r["pushed_at"]) for r in rows]

    def parser_like(r: dict[str, Any]) -> bool:
        blob = f"{r['full_name']} {r.get('description', '')}".lower()
        return any(h in blob for h in _PARSER_HINTS)

    n_parser = sum(1 for r in rows if parser_like(r))

    def stats(xs: list[float], nd: int = 1) -> dict[str, float]:
        if not xs:
            return {}
        return {
            "min": round(min(xs), nd),
            "median": round(statistics.median(xs), nd),
            "mean": round(statistics.mean(xs), nd),
            "max": round(max(xs), nd),
        }

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "suite": suite.get("suite"),
        "sample_size": len(rows),
        "pool_size": pool.get("count"),
        "sampling_fraction_pct": round(100.0 * len(rows) / pool["count"], 1)
        if pool.get("count") else None,
        "unresolved_in_pool": missing,
        "build_systems": dict(Counter(r["build_entry"] for r in rows).most_common()),
        "licenses": dict(Counter(r["license"] or "none" for r in rows).most_common()),
        "repo_size_kb": stats(sizes),
        "stars": stats(stars),
        "days_since_last_push": stats(ages),
        "parser_like": {
            "count": n_parser,
            "pct": round(100.0 * n_parser / len(rows), 1) if rows else 0.0,
            "note": "keyword heuristic over name+description; indicative only",
        },
        "scope_caveats": _caveats(rows, n_parser),
        "search_frame": pool.get("search_frame"),
        "dataset_construction_audit": _audit(pool),
        "eligible_by_star_band": _by_band(pool, chosen),
        "boundary_analysis": boundary_analysis(pool, chosen),
        "artifact_integrity": integrity_summary(pool, suite),
        # Per-repository covariates for the failure analysis that follows the
        # baseline. Joined to results on full_name. The heuristic lives here and
        # only here, so there is one definition of "parser-like" in the project.
        "sample_covariates": sorted(
            (
                {
                    "full_name": r["full_name"],
                    "stars": r["stars"],
                    "size_kb": r["size_kb"],
                    "build_entry": r["build_entry"],
                    "days_since_last_push": round(_age_days(r["pushed_at"])),
                    "parser_like": parser_like(r),
                }
                for r in rows
            ),
            key=lambda r: r["full_name"],
        ),
    }


def _audit(pool: dict[str, Any]) -> dict[str, Any]:
    """The attrition funnel, straight from pool.json. No hand-entered numbers."""
    a = pool.get("attrition") or {}
    order = [
        ("github_candidates", "raw candidates in the search frame"),
        ("dropped_too_large", "repository larger than the size cap"),
        ("dropped_no_license", "no license"),
        ("dropped_oss_fuzz", "already an OSS-Fuzz project"),
        ("dropped_no_build_entry", "no recognised build entry point"),
        ("dropped_no_commit", "commit SHA could not be pinned"),
    ]
    running = a.get("github_candidates", 0)
    steps = []
    for key, label in order:
        if key == "github_candidates":
            steps.append({"step": label, "removed": None, "remaining": running})
            continue
        removed = a.get(key, 0)
        running -= removed
        steps.append({"step": label, "removed": removed, "remaining": running})
    return {
        "funnel": steps,
        "final_pool": a.get("final_pool"),
        "sample_size": a.get("sample_size"),
        "exclusion_snapshot": (pool.get("oss_fuzz_exclusion") or {}).get(
            "projects_tree_sha"),
        "dominant_filter": max(
            ((k, a.get(k, 0)) for k, _ in order[1:]), key=lambda kv: kv[1],
            default=(None, 0))[0],
    }


def _by_band(pool: dict[str, Any], chosen: set[str]) -> list[dict[str, Any]]:
    """Eligibility per star band — the raw counts come from the search frame,
    the survivors from the pool itself.

    A single overall survival rate hides whether feasibility tracks project
    maturity. If the low-star bands survive at a fraction of the high-star ones,
    the honest claim is about maturity, not about C projects in general.
    """
    frame = (pool.get("search_frame") or {}).get("bands") or {}
    out = []
    for band, searched in frame.items():
        lo, hi = (int(x) for x in band.split("-"))
        eligible = [c for c in pool["candidates"] if lo <= c["stars"] <= hi]
        out.append({
            "band": f"{lo}-{hi} stars",
            "searched": searched,
            "saturated": searched >= (pool.get("search_frame") or {}).get(
                "search_result_cap", 1000),
            "eligible": len(eligible),
            "survival_pct": round(100.0 * len(eligible) / searched, 1) if searched else 0.0,
            "in_sample": sum(1 for c in eligible if c["full_name"] in chosen),
        })
    return sorted(out, key=lambda r: int(r["band"].split("-")[0]))


def integrity_summary(pool: dict[str, Any], suite: dict[str, Any]) -> dict[str, Any]:
    """Human-readable rendering of the checks the freeze gate already enforces.

    Deliberately delegates to `build_pool.pool_problems` rather than restating
    the rules — a display-only copy would be free to drift from the ones that
    actually block a freeze, and would then reassure about the wrong thing.
    """
    import importlib.util  # noqa: PLC0415 - build_pool is a sibling script, not a package

    spec = importlib.util.spec_from_file_location("_bp", HERE / "build_pool.py")
    bp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bp)

    problems = bp.pool_problems(pool)
    repos = suite.get("repos", [])
    checks = [
        ("pool passes every freeze-gate check", not problems,
         "; ".join(problems) if problems else f"{len(pool['candidates'])} candidates"),
        ("OSS-Fuzz snapshot pinned",
         bool((pool.get("oss_fuzz_exclusion") or {}).get("projects_tree_sha")),
         f"{(pool.get('oss_fuzz_exclusion') or {}).get('projects_count')} projects, "
         f"tree {((pool.get('oss_fuzz_exclusion') or {}).get('projects_tree_sha') or '')[:8]}"),
        ("freeze-time leakage re-check ran",
         (suite.get("oss_fuzz_leakage_check") or {}).get("leaked") == [],
         (suite.get("oss_fuzz_leakage_check") or {}).get("method", "not performed")),
        ("every selected repo has a commit SHA",
         bool(repos) and all(r.get("commit") for r in repos),
         f"{sum(1 for r in repos if r.get('commit'))}/{len(repos)} pinned"),
        ("benchmark instance identified", bool(suite.get("benchmark_instance_id")),
         str(suite.get("benchmark_instance_id"))),
    ]
    return {
        "all_pass": all(ok for _, ok, _ in checks),
        "checks": [{"check": c, "pass": ok, "detail": d} for c, ok, d in checks],
    }


def boundary_analysis(pool: dict[str, Any], chosen: set[str]) -> dict[str, Any]:
    """How close the pool sits to each predicate's cut-off.

    Objections cluster at the edges: a repository one star above the floor or a
    week inside the recency window is where "the filter decided this, not the
    data" is most arguable. Reporting the distribution near each boundary lets a
    reader judge that instead of taking the thresholds on trust.

    Only the four predicates that actually gate pool membership are analysed.
    LOC is deliberately absent — CRITERIA.md filters on repository *size* as a
    proxy and measures real LOC at run time without filtering on it, so there is
    no LOC boundary to be near.
    """
    cands = pool["candidates"]
    sample = [c for c in cands if c["full_name"] in chosen]

    def bucket(rows: list[dict[str, Any]]) -> dict[str, Any]:
        n = len(rows) or 1
        sizes = [r["size_kb"] for r in rows]
        stars = [r["stars"] for r in rows]
        ages = [_age_days(r["pushed_at"]) for r in rows]
        cap_kb = 50 * 1024
        cutoff_days = 24 * 30
        return {
            "size_vs_50mb_cap": {
                "under_10_pct_of_cap": sum(1 for s in sizes if s < cap_kb * 0.10),
                "10_to_50_pct": sum(1 for s in sizes if cap_kb * 0.10 <= s < cap_kb * 0.5),
                "over_50_pct": sum(1 for s in sizes if s >= cap_kb * 0.5),
                "within_10_pct_of_cap": sum(1 for s in sizes if s >= cap_kb * 0.9),
            },
            "stars_vs_band_edges": {
                "at_floor_50_to_60": sum(1 for s in stars if 50 <= s <= 60),
                "near_ceiling_4500_to_5000": sum(1 for s in stars if s >= 4500),
            },
            "recency_vs_24_month_cutoff": {
                "pushed_within_90d": sum(1 for a in ages if a <= 90),
                "pushed_within_last_60d_of_window": sum(
                    1 for a in ages if cutoff_days - 60 <= a <= cutoff_days),
            },
            "build_entry": dict(Counter(r["build_entry"] for r in rows).most_common()),
        }

    return {
        "note": (
            "Boundary counts, not a reason to move any threshold. Build-entry "
            "detection records the first recognised file only, so repositories "
            "carrying several build systems are not distinguishable here."
        ),
        "pool": bucket(cands),
        "sample": bucket(sample),
    }


def _caveats(rows: list[dict[str, Any]], n_parser: int) -> list[str]:
    """Say out loud where the sample is lopsided.

    Generated mechanically so the caveats cannot be softened after seeing how the
    benchmark went.
    """
    out: list[str] = []
    n = len(rows) or 1
    builds = Counter(r["build_entry"] for r in rows)
    top_build, top_n = builds.most_common(1)[0] if builds else ("?", 0)
    if top_n / n > 0.7:
        out.append(
            f"{top_n}/{n} repositories use {top_build}; results generalise to that "
            "build system far better than to the others."
        )
    if n_parser / n > 0.7:
        out.append(
            f"{n_parser}/{n} look like input parsers, the shape NEMESIS targets. "
            "Read the funnel as an upper bound for arbitrary C projects."
        )
    sizes = [r["size_kb"] for r in rows]
    if sizes and statistics.median(sizes) < 2000:
        out.append(
            f"median repository is {statistics.median(sizes):.0f} KB — small. Large "
            "codebases with vendored dependencies are under-represented."
        )
    if not out:
        out.append("No single dimension dominates the sample.")
    return out


def to_markdown(p: dict[str, Any]) -> str:
    lines = [
        f"# Sample profile — {p['suite']}",
        "",
        f"{p['sample_size']} repositories drawn from a pool of {p['pool_size']} "
        f"({p['sampling_fraction_pct']} %). Generated {p['generated_utc']}, "
        "before the baseline run.",
        "",
        "## Composition",
        "",
        "| Dimension | Value |",
        "|-----------|-------|",
    ]
    for k, v in p["build_systems"].items():
        lines.append(f"| build system `{k}` | {v} |")
    lines += [
        f"| parser-like (heuristic) | {p['parser_like']['count']} "
        f"({p['parser_like']['pct']} %) |",
        f"| repo size KB (median) | {p['repo_size_kb'].get('median')} |",
        f"| stars (median) | {p['stars'].get('median')} |",
        f"| days since last push (median) | {p['days_since_last_push'].get('median')} |",
        "",
        "## Scope caveats",
        "",
    ]
    lines += [f"- {c}" for c in p["scope_caveats"]]
    lines += ["", "## Artifact integrity", "", "```"]
    for c in p["artifact_integrity"]["checks"]:
        lines.append(f"{'PASS' if c['pass'] else 'FAIL'}  {c['check']:38s} {c['detail']}")
    lines += ["```"]
    lines += [
        "",
        "Any claim from this suite is bounded by the above. It measures onboarding "
        "within this scope, not onboarding of arbitrary C/C++ repositories.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", default=str(HERE / "repos.yaml"))
    ap.add_argument("--pool", default=str(HERE / "pool.json"))
    ap.add_argument("--out", default=str(HERE / "sample_profile.json"))
    ap.add_argument("--md", default=str(HERE / "SAMPLE_PROFILE.md"))
    args = ap.parse_args()

    for path in (args.suite, args.pool):
        if not Path(path).exists():
            raise SystemExit(f"{path} missing — build the pool and sample first")

    suite = yaml.safe_load(Path(args.suite).read_text(encoding="utf-8"))
    pool = json.loads(Path(args.pool).read_text(encoding="utf-8"))
    p = profile(suite, pool)

    Path(args.out).write_text(json.dumps(p, indent=2), encoding="utf-8")
    Path(args.md).write_text(to_markdown(p), encoding="utf-8")

    print(f"Sample: {p['sample_size']} of {p['pool_size']} "
          f"({p['sampling_fraction_pct']} %)")
    print(f"Build systems: {p['build_systems']}")
    print(f"Parser-like: {p['parser_like']['count']} ({p['parser_like']['pct']} %)")
    print("\nScope caveats:")
    for c in p["scope_caveats"]:
        print(f"  - {c}")
    print(f"\nWrote {args.out} and {args.md}")


if __name__ == "__main__":
    main()
