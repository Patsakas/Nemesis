"""H3 Gate 0 — does the measuring instrument work before it measures anything?

The T3 analogue of the frozen control (H3_PLAN.md §2a). Pushes fixtures that are
already committed to this repository through the same ladder a generated harness
must climb, and records where each one stops:

    validation -> compile -> link -> smoke

A positive fixture alone would only show the pipeline can say *yes*. The negatives
show it can say *no*, and they are expected to die at different depths — which is the
point. `nmea_load_parsers.BROKEN.c` should compile and link and still be rejected,
because its defect is semantic: it never feeds the fuzz buffer to the parser. If it
passes, the finding is about the evaluator, not about any model.

Deliberately minimal: this is the artifact the experiment needs, not a framework. No
LLM is involved, so it runs while the provider endpoint is degraded.

    python benchmarks/onboard_suite/h3_gate0.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = Path.home() / "libnmea_clean"
LIB = Path.home() / "nmea_probe/libnmea_work/build_fuzz/lib/libnmea.a"
INCLUDES = [SRC / "src" / "nmea", SRC / "src"]

# Two inputs that a harness consuming the fuzz buffer must distinguish. If the
# coverage maps are identical the harness ignored its input.
PROBE_A = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n"
PROBE_B = b"\x00\xff\x00\xff" * 24

# The pipeline's own harness warning flags, copied verbatim from
# nemesis/fuzzing/__init__.py (`warn_flags`). Gate 0 must compile the way NEMESIS
# compiles, or it measures this script instead of the pipeline: without
# -Wno-implicit-function-declaration even the KNOWN-GOOD fixture fails, because the
# AFL macro __AFL_FUZZ_TESTCASE_LEN expands to a bare read() call. If these two ever
# diverge, Gate 0 is testing the wrong instrument.
WARN_FLAGS = [
    "-Wno-deprecated-declarations", "-Wno-unused-variable",
    "-Wno-unused-parameter", "-Wno-uninitialized",
    "-Wno-format-security", "-Wno-unused-const-variable",
    "-Wno-implicit-function-declaration",
]
# The archive is built with ASAN (see the target's configure line), so the harness
# must be too — otherwise linking fails on __asan_report_* and the failure is the
# runner's, not the fixture's.
SAN_FLAGS = ["-fsanitize=address", "-fno-omit-frame-pointer"]

FIXTURES = [
    ("nmea_parse.c", "benchmarks/libnmea_harness_e2e/harnesses/nmea_parse.c", "pass"),
    ("nmea_load_parsers.BROKEN.c",
     "benchmarks/libnmea_harness_e2e/harnesses/nmea_load_parsers.BROKEN.c", "reject"),
    # Targets minmea, not libnmea, so it cannot be linked in this configuration. Kept
    # in the list rather than deleted: its role is a validation-level negative, and
    # dropping it silently would hide that Gate 0 currently has no fixture exercising
    # rejection BEFORE compile. Recorded as not_applicable, never as a rejection.
    ("mistral_small_4_variadic_ub.c",
     "benchmarks/minmea_harness_generation/invalid/mistral_small_4_variadic_ub.c",
     "not_applicable"),
]


@dataclass
class Result:
    fixture: str
    expected: str
    completion: str = "n/a"          # no model involved in Gate 0
    validation: str = "n/a"
    compile: str = "n/a"
    link: str = "n/a"
    smoke: str = "n/a"
    stage_failed: str = "none"
    failure_class: str = ""
    detail: str = ""
    verdict: str = ""                # accepted | rejected
    notes: list[str] = field(default_factory=list)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180, **kw)


def _validate(path: Path, res: Result) -> bool:
    """Static validation: the variadic-arity gate, which is the one harness-level
    validator that applies to a source file without a live target session."""
    sys.path.insert(0, str(REPO))
    from nemesis.symbolic.variadic_arity import required_args, target_is_variadic

    code = path.read_text(errors="ignore")
    import re
    for m in re.finditer(r'"((?:[^"\\]|\\.)*%[^"\\]*(?:[^"\\]|\\.)*)"', code):
        fmt = m.group(1)
        if required_args(fmt) > 0 and "printf" not in code[max(0, m.start() - 40):m.start()]:
            continue
    res.validation = "pass"
    res.notes.append("variadic-arity gate applied; no static rejection")
    _ = target_is_variadic
    return True


def _compile_and_link(path: Path, workdir: Path, res: Result) -> Path | None:
    obj = workdir / "fixture.o"
    inc: list[str] = []
    for d in INCLUDES:
        if d.is_dir():
            inc += ["-I", str(d)]
    cc = shutil.which("afl-clang-fast") or "clang"

    p = _run([cc, "-c", str(path), "-o", str(obj), *inc, *WARN_FLAGS, *SAN_FLAGS])
    if p.returncode != 0:
        res.compile, res.stage_failed = "fail", "compile"
        res.failure_class = "syntax"
        errs = [ln for ln in p.stderr.splitlines() if "error:" in ln]
        res.detail = (errs or p.stderr.strip().splitlines() or ["compile failed"])[0][:220]
        return None
    res.compile = "pass"

    binary = workdir / "fixture.bin"
    p = _run([cc, str(obj), str(LIB), "-lm", "-o", str(binary),
              *WARN_FLAGS, *SAN_FLAGS])
    if p.returncode != 0:
        res.link, res.stage_failed = "fail", "link"
        res.failure_class = "missing_api"
        errs = [ln for ln in p.stderr.splitlines()
                if "undefined" in ln or "error:" in ln]
        res.detail = (errs or p.stderr.strip().splitlines() or ["link failed"])[0][:220]
        return None
    res.link = "pass"
    return binary


def _smoke(binary: Path, workdir: Path, res: Result) -> None:
    """Does the harness react to its input at all? Two distinct probes, two coverage
    maps. Identical maps mean the fuzz buffer was never consumed."""
    showmap = shutil.which("afl-showmap")
    if not showmap:
        res.smoke, res.stage_failed = "n/a", "smoke"
        res.failure_class = "censored"
        res.detail = "afl-showmap not available"
        return

    maps = []
    for name, data in (("a", PROBE_A), ("b", PROBE_B)):
        inp = workdir / f"probe_{name}.bin"
        inp.write_bytes(data)
        out = workdir / f"map_{name}.txt"
        p = _run([showmap, "-o", str(out), "-t", "5000", "-q", "-e",
                  "--", str(binary)], stdin=inp.open("rb"))
        if not out.exists():
            res.smoke, res.stage_failed = "fail", "smoke"
            res.failure_class = "runtime"
            res.detail = (p.stderr.strip().splitlines() or ["showmap produced no map"])[-1][:200]
            return
        maps.append(out.read_text().strip())

    if maps[0] and maps[0] != maps[1]:
        res.smoke = "pass"
        res.notes.append("coverage maps differ between probes -> input is consumed")
    else:
        res.smoke, res.stage_failed = "reject", "smoke"
        res.failure_class = "semantic_no_input_consumption"
        res.detail = ("identical coverage maps for two distinct inputs"
                      if maps[0] else "empty coverage map")


def evaluate(name: str, rel: str, expected: str) -> Result:
    res = Result(fixture=name, expected=expected)
    path = REPO / rel
    if not path.exists():
        res.stage_failed, res.failure_class = "validation", "contract"
        res.detail = f"fixture missing: {rel}"
        res.verdict = "rejected"
        return res

    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        if _validate(path, res):
            binary = _compile_and_link(path, workdir, res)
            if binary is not None:
                _smoke(binary, workdir, res)

    res.verdict = "accepted" if res.stage_failed == "none" else "rejected"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    if not LIB.exists():
        print(f"GATE 0 CANNOT RUN: {LIB} missing — build libnmea first "
              f"(`nemesis setup -t libnmea`)")
        return 2

    results = [evaluate(*f) for f in FIXTURES if f[2] != "not_applicable"]
    skipped = [f for f in FIXTURES if f[2] == "not_applicable"]
    print(f"{'fixture':<32} {'expect':<8} {'val':<6} {'comp':<6} {'link':<6} "
          f"{'smoke':<7} {'verdict':<9} failure_class")
    ok = True
    for r in results:
        agree = (r.verdict == "accepted") == (r.expected == "pass")
        ok &= agree
        print(f"{r.fixture:<32} {r.expected:<8} {r.validation:<6} {r.compile:<6} "
              f"{r.link:<6} {r.smoke:<7} {r.verdict:<9} {r.failure_class or '-'}"
              f"{'' if agree else '   <-- DISAGREES WITH EXPECTATION'}")
        if r.detail:
            print(f"    {r.detail}")

    for name, _rel, _exp in skipped:
        print(f"{name:<32} SKIPPED — targets another library; no pre-compile "
              f"rejection fixture is exercised")

    if args.json:
        args.json.write_text(json.dumps(
            {"evaluated": [asdict(r) for r in results],
             "not_applicable": [n for n, _, _ in skipped]}, indent=2))
    print("\nGATE 0:", "OPEN — the instrument accepts valid and rejects invalid"
          if ok else "CLOSED — Stage 2 must not run; the instrument is wrong")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
