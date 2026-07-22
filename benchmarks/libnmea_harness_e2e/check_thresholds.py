"""Check a collected benchmark run against thresholds.json.

Bounds, not equalities: the harness is LLM-generated and AFL++ throughput is
machine-dependent, so this asserts the run still behaves like a working
end-to-end pipeline, not that it reproduced the reference numbers.

Exit 0 = pass. Any failed check exits 1 and prints every failure, so one run
tells you everything that regressed rather than only the first thing.

usage: check_thresholds.py <thresholds.json> <collected_out_dir>
"""
import json
import sys
from pathlib import Path

th = json.loads(Path(sys.argv[1]).read_text())
out = Path(sys.argv[2])

cov = json.loads((out / "coverage_summary.json").read_text())
fuzz = json.loads((out / "fuzz_stats.json").read_text())["totals"]
infl = json.loads((out / "input_influence.json").read_text())

failures: list[str] = []
lines: list[str] = []


def check(ok: bool, label: str, got, want: str) -> None:
    lines.append(f"  {'PASS' if ok else 'FAIL'}  {label:<26} got {got}  ({want})")
    if not ok:
        failures.append(f"{label}: got {got}, {want}")


check(cov["lines"]["percent"] >= th["min_line_coverage_pct"],
      "line coverage %", cov["lines"]["percent"],
      f"need >= {th['min_line_coverage_pct']}")

check(cov["functions"]["percent"] >= th["min_function_coverage_pct"],
      "function coverage %", cov["functions"]["percent"],
      f"need >= {th['min_function_coverage_pct']}")

check(cov["functions"]["covered"] >= th["min_functions_covered"],
      "functions covered", cov["functions"]["covered"],
      f"need >= {th['min_functions_covered']}")

check(fuzz["execs_done"] >= th["min_total_execs"],
      "total executions", f"{fuzz['execs_done']:,}",
      f"need >= {th['min_total_execs']:,}")

check(fuzz["corpus_count"] >= th["min_corpus_entries"],
      "corpus entries", fuzz["corpus_count"],
      f"need >= {th['min_corpus_entries']}")

check(fuzz["saved_crashes"] <= th["max_crashes"],
      "crashes", fuzz["saved_crashes"],
      f"need <= {th['max_crashes']} — a crash is a finding, investigate it")

check(fuzz["saved_hangs"] <= th["max_hangs"],
      "hangs", fuzz["saved_hangs"], f"need <= {th['max_hangs']}")

if th.get("require_input_influence"):
    check(infl["analysis_quality"] == "ok", "analysis quality",
          f"{infl['analysis_quality']}"
          + (f" ({infl['degraded_reason']})" if infl.get("degraded_reason") else ""),
          "need ok — degraded means per-input coverage was not measurable")
    check(infl["input_influence"], "input influence",
          f"{infl['distinct_execution_maps']} distinct maps "
          f"over {infl['inputs_tested']} inputs",
          f"need >= {infl['minimum_required']} — equal maps mean the harness "
          "ignores its input")

print("\n".join(lines))

if failures:
    print(f"\nFAILED ({len(failures)}):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print(f"\nall {len(lines)} checks passed")
