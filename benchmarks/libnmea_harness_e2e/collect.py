"""Collect the measurable outcome of a libnmea benchmark run.

Produces, in <out_dir>:
    fuzz_stats.json       per-instance and aggregate AFL++ counters
    coverage_report.txt   llvm-cov report over a CLEAN coverage rebuild
    coverage_summary.json line/function/region/branch totals
    input_influence.json  distinct probe coverage maps across corpus samples

The coverage build is wiped and redone rather than reused: a stale
build_coverage silently mixes objects from earlier runs, and the numbers it
produces cannot be attributed to this run.

`input_influence` is the check that distinguishes a working harness from one
that compiles, runs, and ignores its input. It replays corpus samples through
the offline analysis binary — never the AFL binary, which in persistent mode
receives nothing outside afl-fuzz and reports one identical map for every input.

usage: collect.py <target.yaml> <findings_dir_for_target> <out_dir>
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from nemesis.config import load_config
from nemesis.fuzzing import AFLOrchestrator
from nemesis.models import HarnessSpec
from nemesis.symbolic import SymbolicStage

target_yaml, findings_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
out_dir.mkdir(parents=True, exist_ok=True)
cfg = load_config(target_path=target_yaml)
func = findings_dir.name


# ── AFL counters ────────────────────────────────────────────

WANTED = ("run_time", "execs_done", "execs_per_sec", "corpus_count",
          "max_depth", "bitmap_cvg", "saved_crashes", "saved_hangs")

instances = {}
for stats in findings_dir.glob("*/fuzzer_stats"):
    d = {}
    for line in stats.read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    instances[stats.parent.name] = {k: d[k] for k in WANTED if k in d}

if not instances:
    sys.exit(f"no fuzzer_stats under {findings_dir}")

fuzz_stats = {
    "instances": instances,
    "totals": {
        "instances": len(instances),
        "execs_done": sum(int(v["execs_done"]) for v in instances.values()),
        "execs_per_sec": round(sum(float(v["execs_per_sec"]) for v in instances.values()), 1),
        "corpus_count": max(int(v["corpus_count"]) for v in instances.values()),
        "saved_crashes": sum(int(v["saved_crashes"]) for v in instances.values()),
        "saved_hangs": sum(int(v["saved_hangs"]) for v in instances.values()),
    },
}
(out_dir / "fuzz_stats.json").write_text(json.dumps(fuzz_stats, indent=2))
print(f"[stats] {fuzz_stats['totals']['execs_done']:,} execs across "
      f"{len(instances)} instances, {fuzz_stats['totals']['saved_crashes']} crashes")

corpus = sorted(p for p in findings_dir.rglob("id:*") if p.is_file())
if not corpus:
    sys.exit("empty corpus")


# ── input influence, via the offline analysis binary ─────────

MIN_DISTINCT_MAPS = 2

orch = AFLOrchestrator(cfg)
orch.run_id = "bench"
probe = orch.analysis_binary()

# Target-agnostic schema: the same shape is emitted for every benchmark, so a
# later target (minmea, mosquitto, …) needs no schema change.
influence = {
    "method": "probe_binary",
    "inputs_tested": 0,
    "distinct_execution_maps": 0,
    "minimum_required": MIN_DISTINCT_MAPS,
    "input_influence": False,
    **orch.analysis_quality,
}

if probe is not None:
    maps = set()
    for f in corpus[:40]:
        res = subprocess.run(["afl-showmap", "-o", "/dev/stdout", "-q",
                              "--", str(probe)],
                             stdin=open(f, "rb"), capture_output=True,
                             env={**os.environ, "AFL_QUIET": "1"}, timeout=20)
        maps.add(hashlib.sha1(res.stdout).hexdigest())
        influence["inputs_tested"] += 1
    influence["distinct_execution_maps"] = len(maps)
    influence["input_influence"] = len(maps) >= MIN_DISTINCT_MAPS
    print(f"[influence] {len(maps)} distinct maps over "
          f"{influence['inputs_tested']} inputs "
          f"(influence={influence['input_influence']})")
else:
    print(f"[influence] NOT MEASURABLE — analysis_quality="
          f"{influence['analysis_quality']} "
          f"reason={influence['degraded_reason']}")
(out_dir / "input_influence.json").write_text(json.dumps(influence, indent=2))


# ── clean coverage rebuild + full replay ────────────────────

harness_src = Path(f"config/targets/{cfg.target.name}/harnesses/{func}.c")
if not harness_src.exists():
    sys.exit(f"no saved harness at {harness_src}")

cov_dir = Path(os.path.expandvars(cfg.target.coverage_build_dir))
shutil.rmtree(cov_dir, ignore_errors=True)

stage = SymbolicStage(cfg)
harness = HarnessSpec(target_func=func, input_format="nmea sentence",
                      c_code=harness_src.read_text())
if not stage.build_coverage_library():
    sys.exit("coverage library build failed")
if not stage.build_coverage_harness(harness):
    sys.exit("coverage harness build failed")

cov_bin = cov_dir / "fuzz_nemesis_coverage"
prof = out_dir / "profraw"
shutil.rmtree(prof, ignore_errors=True)
prof.mkdir(parents=True)

ok = 0
for i, f in enumerate(corpus):
    try:
        with open(f, "rb") as fh:
            subprocess.run([str(cov_bin)], stdin=fh, timeout=5, capture_output=True,
                           env={**os.environ,
                                "LLVM_PROFILE_FILE": str(prof / f"c_{i}.profraw")})
        ok += 1
    except (subprocess.TimeoutExpired, OSError):
        continue
print(f"[coverage] replayed {ok}/{len(corpus)} corpus inputs")

merged = out_dir / "merged.profdata"
subprocess.run(["llvm-profdata", "merge", "-sparse",
                *[str(p) for p in prof.glob("*.profraw")], "-o", str(merged)],
               check=True, capture_output=True)

report = subprocess.run(["llvm-cov", "report", str(cov_bin),
                         f"-instr-profile={merged}"], capture_output=True, text=True)
(out_dir / "coverage_report.txt").write_text(report.stdout)

export = subprocess.run(["llvm-cov", "export", str(cov_bin),
                         f"-instr-profile={merged}", "--format=text",
                         "--summary-only"], capture_output=True, text=True)
totals = json.loads(export.stdout)["data"][0]["totals"]
summary = {k: {"count": totals[k]["count"], "covered": totals[k]["covered"],
               "percent": round(totals[k]["percent"], 2)}
           for k in ("lines", "functions", "regions", "branches") if k in totals}
summary["_scope"] = ("Only source files carrying LLVM coverage mapping. For libnmea "
                     "that is 4 of 11 files — the other sentence parsers are stripped "
                     "of mapping by the objcopy --redefine-sym PRE_LINK step. See "
                     "README.md.")
(out_dir / "coverage_summary.json").write_text(json.dumps(summary, indent=2))
print(f"[coverage] lines {summary['lines']['percent']}%  "
      f"functions {summary['functions']['percent']}%")
