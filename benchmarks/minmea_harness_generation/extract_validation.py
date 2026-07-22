"""Build harness_validation_report.json from a run log.

The run keeps the harness that eventually passed. This keeps the part that
matters more: what was generated first, why it was rejected, and whether the
automatic repair recovered.

Two rates, deliberately separate:

    first-pass soundness  — how often the generator gets it right unaided.
                            Measures the model and the prompt.
    eventual soundness    — how often the pipeline ends with a valid harness.
                            Measures the product, repair loop included.

Infrastructure failures (provider timeouts) are counted apart from harness
failures; folding them together would make a flaky endpoint look like a bad
generator.

usage: extract_validation.py <run.log> <out.json>
"""
import json
import re
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text(errors="replace")
records: list[dict] = []

for line in log.splitlines():
    if "harness.validation" not in line:
        continue
    rec: dict = {}
    # structlog key=value rendering; values may be quoted or bracketed lists
    for m in re.finditer(r"(\w+)=('(?:[^']|\\')*'|\[[^\]]*\]|\S+)", line):
        key, raw = m.group(1), m.group(2)
        if key in ("stage", "event"):
            continue
        if raw.startswith("'") and raw.endswith("'"):
            raw = raw[1:-1]
        if raw in ("True", "False"):
            rec[key] = raw == "True"
        else:
            rec[key] = raw
    if rec:
        records.append(rec)

api_errors = len(re.findall(r"\[error\s*\]\s*api\.error", log))
timeouts = len(re.findall(r"Request timed out", log))

first_pass_ok = sum(1 for r in records if r.get("first_pass_passed"))
final_ok = sum(1 for r in records if r.get("final_passed"))
n = len(records)

report = {
    "harnesses_validated": n,
    "first_pass_sound": first_pass_ok,
    "first_pass_rate": round(first_pass_ok / n, 3) if n else None,
    "eventually_sound": final_ok,
    "eventual_rate": round(final_ok / n, 3) if n else None,
    "repaired_successfully": sum(
        1 for r in records
        if r.get("repair_attempted") and r.get("final_passed")),
    "repair_failed": sum(
        1 for r in records
        if r.get("repair_attempted") and not r.get("final_passed")),
    "variadic_targets": sum(1 for r in records if r.get("variadic")),
    "infrastructure": {
        "provider_errors": api_errors,
        "request_timeouts": timeouts,
        "note": ("counted separately from harness outcomes — a flaky endpoint "
                 "is not a bad generator"),
    },
    "records": records,
}
Path(sys.argv[2]).write_text(json.dumps(report, indent=2))

print(f"harnesses validated : {n}")
print(f"first-pass sound    : {first_pass_ok}/{n}")
print(f"eventually sound    : {final_ok}/{n}")
print(f"variadic targets    : {report['variadic_targets']}")
print(f"provider errors     : {api_errors} (timeouts: {timeouts})")
for r in records:
    print(f"  - {r.get('target'):<22} variadic={str(r.get('variadic')):<5} "
          f"first={str(r.get('first_pass_passed')):<5} "
          f"final={str(r.get('final_passed')):<5} {r.get('outcome')}")
