"""Build comparison.json from the two collected harness runs.

Reads a NEMESIS side and a CFLite side, each with fuzz_stats.json and a
coverage export, and emits the metrics table plus the API-surface ratio.

The ratio is the metric that carries the actual claim: an automatically
generated harness explores the public API broadly, a maintenance harness is
written to cover one thing well. Reported two ways, because they answer
different questions:

    entry_points_called   — functions the harness invokes directly (static)
    functions_covered     — functions llvm-cov saw executed (dynamic)

The second is always larger, since a parser calls its own helpers. Quoting only
the first understates both harnesses; quoting only the second hides the breadth
difference, which is the whole point.

usage: compare.py <nemesis_dir> <cflite_dir> <minmea_header> <out.json>
"""
import json
import re
import subprocess
import sys
from pathlib import Path

nemesis_dir, cflite_dir, header, out = (Path(sys.argv[1]), Path(sys.argv[2]),
                                        Path(sys.argv[3]), Path(sys.argv[4]))

PUBLIC_RE = re.compile(
    r"^(?:bool|int|float|uint8_t|const\s+char\s*\*|struct\s+\w+\s*\*|enum\s+[\w ]+)"
    r"\s*(minmea_\w+)\s*\(", re.MULTILINE)
public_api = sorted(set(PUBLIC_RE.findall(header.read_text())))


def load(d: Path) -> dict:
    return {
        "fuzz": json.loads((d / "fuzz_stats.json").read_text()),
        "coverage": json.loads((d / "coverage_summary.json").read_text()),
        "functions": json.loads((d / "functions_covered.json").read_text()),
        "harness": (d / "harness.c").read_text(),
    }


def harness_loc(src: str) -> int:
    """Non-blank, non-comment lines."""
    n = 0
    for line in src.splitlines():
        s = line.strip()
        if s and not s.startswith(("//", "/*", "*")):
            n += 1
    return n


def entry_points_called(src: str, api: list[str]) -> list[str]:
    """Public API functions the harness invokes directly."""
    return sorted(f for f in api if re.search(rf"\b{f}\s*\(", src))


def side(name: str, d: Path) -> dict:
    data = load(d)
    called = entry_points_called(data["harness"], public_api)
    covered = sorted(set(data["functions"]) & set(public_api))
    cov = data["coverage"]
    return {
        "name": name,
        "harness_loc": harness_loc(data["harness"]),
        "entry_points_called": called,
        "entry_points_called_n": len(called),
        "public_functions_covered": covered,
        "public_functions_covered_n": len(covered),
        "api_surface_ratio_called": round(len(called) / len(public_api), 3),
        "api_surface_ratio_covered": round(len(covered) / len(public_api), 3),
        "line_coverage_pct": cov["lines"]["percent"],
        "branch_coverage_pct": cov.get("branches", {}).get("percent"),
        "region_coverage_pct": cov["regions"]["percent"],
        "executions": data["fuzz"]["totals"]["execs_done"],
        "execs_per_sec": data["fuzz"]["totals"]["execs_per_sec"],
        "corpus_count": data["fuzz"]["totals"]["corpus_count"],
        "crashes": data["fuzz"]["totals"]["saved_crashes"],
        "hangs": data["fuzz"]["totals"]["saved_hangs"],
    }


nemesis, cflite = side("nemesis", nemesis_dir), side("cflite", cflite_dir)

result = {
    "target": "minmea",
    "question": ("how does an automatically generated broad harness compare "
                 "with a deliberately written maintenance harness?"),
    "not_a_claim": ("this is not AI vs human skill. The ClusterFuzzLite harness "
                    "was written to guard one parser inside a PR-time budget and "
                    "does that correctly; it was never trying to cover the API."),
    "controls": {
        "fuzzer": "AFL++ (same version, same instance count, same wall clock)",
        "sanitizer": "ASan, identical flags from config/targets/minmea.yaml",
        "seeds": "both start from the same single well-formed RMC sentence",
        "cflite_harness": "used unmodified; AFL++ libAFLDriver.a supplies main()",
        "coverage": "clean -fcoverage-mapping rebuild, each side replaying its own corpus",
    },
    "public_api": {"functions": public_api, "count": len(public_api)},
    "nemesis": nemesis,
    "cflite": cflite,
    "deltas": {
        "entry_points_called": nemesis["entry_points_called_n"] - cflite["entry_points_called_n"],
        "public_functions_covered": nemesis["public_functions_covered_n"] - cflite["public_functions_covered_n"],
        "line_coverage_pct": round(nemesis["line_coverage_pct"] - cflite["line_coverage_pct"], 2),
        "reached_only_by_nemesis": sorted(
            set(nemesis["public_functions_covered"]) - set(cflite["public_functions_covered"])),
        "reached_only_by_cflite": sorted(
            set(cflite["public_functions_covered"]) - set(nemesis["public_functions_covered"])),
    },
}
out.write_text(json.dumps(result, indent=2))

print(f"{'metric':<32}{'NEMESIS':>12}{'CFLite':>12}")
for label, key in [("harness LOC", "harness_loc"),
                   ("entry points called", "entry_points_called_n"),
                   ("public functions covered", "public_functions_covered_n"),
                   ("line coverage %", "line_coverage_pct"),
                   ("branch coverage %", "branch_coverage_pct"),
                   ("executions", "executions"),
                   ("crashes", "crashes")]:
    print(f"{label:<32}{str(nemesis[key]):>12}{str(cflite[key]):>12}")
print(f"\npublic API: {len(public_api)} functions")
print(f"only NEMESIS reached: {result['deltas']['reached_only_by_nemesis']}")
print(f"only CFLite reached:  {result['deltas']['reached_only_by_cflite']}")
