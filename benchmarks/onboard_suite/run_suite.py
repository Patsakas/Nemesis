#!/usr/bin/env python3
"""Run the frozen onboarding suite and emit machine-readable results.

**Run this inside WSL.** It shells out to `nemesis`, clang and AFL++, none of
which exist on the Windows side of this checkout.

The runner is deliberately incapable of helping the tool under test. It never
retries a failed stage, never installs a missing dependency, never edits a
generated config or harness. Every recorded run is therefore
`intervention = NONE` by construction rather than by assertion — if a repository
needs a human, that is the result, not something to fix and re-run. Runs with
human help are recorded separately via --intervention, which refuses to write
into the unattended results file.

Outputs go to <workdir>/results/<run_id>/ — outside the repository, because a run
directory is an experiment artifact rather than source, and this checkout sits on
a synchronising filesystem. Override with --results-dir.

    baseline_<experiment_id>_<benchmark_instance_id>/
        preflight.txt        the preconditions that held
        baseline.lock        the identity that authorised the run
        environment.json     toolchain, NEMESIS state, LLM chain
        summary.json         funnel, failure distribution, medians
        matrix.md            per-repository tier grid
        <owner>__<repo>.json one per repository
        logs/<owner>__<repo>/T0_acquired.log … T5_fuzz_ready.log

Usage:
    python run_suite.py --workdir ~/bench            # full suite
    python run_suite.py --only nlohmann/json --verbose
    python run_suite.py --dry-run                    # print the plan, run nothing
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

import environment
import preflight
from schema import (
    DEFAULT_FAILURE,
    LOG_PATTERNS,
    TIER_LOCALITY,
    FailureClass,
    Intervention,
    Locality,
    Status,
    Tier,
)

HERE = Path(__file__).resolve().parent
NEMESIS_ROOT = HERE.parent.parent

# Per-tier wall-clock ceilings. A tier that blows its budget is a TIMEOUT result,
# not a crashed run: an unbounded build on one pathological repo would otherwise
# stall the whole suite.
TIER_TIMEOUT_SEC: dict[Tier, int] = {
    Tier.ACQUIRED: 300,
    Tier.CONFIG_GENERATED: 900,     # includes LLM round-trips
    Tier.LIBRARY_BUILT: 1800,
    Tier.HARNESS_GENERATED: 1200,
    Tier.HARNESS_COMPILED: 900,
    Tier.FUZZ_READY: 300,
}

FUZZ_SMOKE_SEC = 120

# A *benchmark-defined execution-activity threshold*, not a claim about whether
# the fuzzing was useful — this suite cannot measure that. Below this many execs
# in the smoke window the per-exec cost is ~100ms+, usually a harness that
# re-reads a file or re-initialises the world on every input. Scored as its own
# outcome rather than a pass, and named here so the number can be argued with.
ACTIVITY_FLOOR_EXECS = 1000

_T5_SPECIFIC = {
    FailureClass.FUZZER_START_FAILURE,
    FailureClass.ZERO_EXECUTIONS,
    FailureClass.BELOW_ACTIVITY_THRESHOLD,
}


class TierResult:
    def __init__(self, tier: Tier) -> None:
        self.tier = tier
        self.status = Status.NOT_RUN
        self.duration_sec = 0.0
        self.failure_class: FailureClass | None = None
        self.locality: Locality | None = None
        self.detail = ""
        self.command = ""
        self.log_path: str | None = None
        self.exit_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "status": self.status.value,
            "duration_sec": round(self.duration_sec, 1),
        }
        if self.command:
            d["command"] = self.command
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.log_path:
            d["log"] = self.log_path
        if self.failure_class:
            d["failure_class"] = self.failure_class.value
            d["locality"] = self.locality.value if self.locality else None
            d["detail"] = self.detail[:500]
        return d


def classify(log: str, tier: Tier) -> tuple[FailureClass, Locality, str]:
    """Map a failed tier's output onto the frozen vocabulary.

    Falls back to the tier's default class rather than inventing a category, so
    the distribution stays comparable across runs even as targets change.
    """
    low = log.lower()
    for pattern, fclass, locality in LOG_PATTERNS:
        m = re.search(pattern, low)
        if m:
            start = max(0, m.start() - 120)
            return fclass, locality, log[start:m.end() + 200].strip()
    return (
        DEFAULT_FAILURE[tier],
        TIER_LOCALITY[tier],
        "\n".join(log.strip().splitlines()[-8:]),
    )


def run_cmd(cmd: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None,
            verbose: bool = False) -> tuple[int, str, float]:
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), timeout=timeout, capture_output=True, text=True,
            env={**os.environ, **(env or {})}, check=False,
        )
        out = (p.stdout or "") + (p.stderr or "")
        if verbose:
            print(out[-3000:])
        return p.returncode, out, time.monotonic() - t0
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") + (e.stderr or "")
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return 124, partial, time.monotonic() - t0
    except FileNotFoundError as e:
        return 127, f"executable not found: {e}", time.monotonic() - t0


class RepoRun:
    """One repository through all six tiers."""

    def __init__(self, spec: dict[str, Any], workdir: Path, *,
                 verbose: bool = False, log_dir: Path | None = None) -> None:
        self.spec = spec
        # Full stdout+stderr per tier, kept on disk. The JSON keeps a 500-char
        # excerpt so the summary stays readable, but the excerpt is not the
        # evidence: two weeks later the useful artifact is not "T4 failed", it is
        # the linker line that says which symbol was missing.
        self.log_dir = log_dir
        self.full_name: str = spec["full_name"]
        self.slug = self.full_name.replace("/", "__")
        self.project = self.full_name.split("/")[1].replace(".", "_").replace("-", "_")
        # `nemesis onboard` writes `source_root: $HOME/{project}_clean` into the
        # generated config as a hardcoded convention (nemesis/onboard.py:1798) —
        # it reads the tree from --source-root but does not record that path.
        # Cloning anywhere else makes `nemesis setup` look for a directory that
        # does not exist, and every repository fails at T2 with a configure
        # error that says nothing about the repository. Clone where the tool
        # expects rather than fighting it.
        self.src = Path.home() / f"{self.project}_clean"
        self.workdir = workdir
        self.verbose = verbose
        self.results: dict[Tier, TierResult] = {t: TierResult(t) for t in Tier}
        self.highest = -1
        self.fuzz_signals: dict[str, Any] = {
            "fuzzer_started": False, "executions": 0,
            "exec_per_sec": 0.0, "meets_activity_threshold": False,
        }

    # ── tiers ───────────────────────────────────────────────

    def t0_acquire(self) -> bool:
        r = self.results[Tier.ACQUIRED]
        self.src.parent.mkdir(parents=True, exist_ok=True)
        if self.src.exists():
            shutil.rmtree(self.src, ignore_errors=True)
        r.command = f"git clone {self.spec['clone_url']} && git checkout {self.spec['commit'][:8]}"
        rc, log, dur = run_cmd(
            ["git", "clone", "--quiet", self.spec["clone_url"], str(self.src)],
            cwd=self.workdir, timeout=TIER_TIMEOUT_SEC[Tier.ACQUIRED], verbose=self.verbose,
        )
        if rc == 0:
            # Pin to the exact recorded commit — the whole suite depends on it.
            rc2, log2, d2 = run_cmd(
                ["git", "checkout", "--quiet", self.spec["commit"]],
                cwd=self.src, timeout=120, verbose=self.verbose,
            )
            rc, log, dur = rc2, log + log2, dur + d2
        return self._finish(Tier.ACQUIRED, rc, log, dur)

    def t1_config(self) -> bool:
        r = self.results[Tier.CONFIG_GENERATED]
        r.command = f"nemesis onboard --source-root {self.src} --project-name {self.project}"
        rc, log, dur = run_cmd(
            ["nemesis", "onboard", "--source-root", str(self.src),
             "--project-name", self.project],
            cwd=NEMESIS_ROOT, timeout=TIER_TIMEOUT_SEC[Tier.CONFIG_GENERATED],
            verbose=self.verbose,
        )
        cfg = NEMESIS_ROOT / "config" / "targets" / f"{self.project}.yaml"
        if rc == 0 and not cfg.exists():
            rc, log = 1, log + f"\nonboard exited 0 but {cfg} does not exist"
        return self._finish(Tier.CONFIG_GENERATED, rc, log, dur)

    def t2_library(self) -> bool:
        r = self.results[Tier.LIBRARY_BUILT]
        r.command = f"nemesis setup -t {self.project}"
        rc, log, dur = run_cmd(
            ["nemesis", "setup", "-t", self.project],
            cwd=NEMESIS_ROOT, timeout=TIER_TIMEOUT_SEC[Tier.LIBRARY_BUILT],
            verbose=self.verbose,
        )
        return self._finish(Tier.LIBRARY_BUILT, rc, log, dur)

    def t3_harness(self) -> bool:
        """Stages 1-2: recon then neural harness generation. Source only."""
        r = self.results[Tier.HARNESS_GENERATED]
        r.command = f"nemesis run -t {self.project} --stages 1,2 --max-targets 1"
        rc, log, dur = run_cmd(
            ["nemesis", "run", "-t", self.project, "--stages", "1,2",
             "--max-targets", "1", "--strategy", "harness"],
            cwd=NEMESIS_ROOT, timeout=TIER_TIMEOUT_SEC[Tier.HARNESS_GENERATED],
            verbose=self.verbose,
        )
        if rc == 0 and not self._harness_sources():
            rc, log = 1, log + "\nstage 2 exited 0 but emitted no harness source"
        return self._finish(Tier.HARNESS_GENERATED, rc, log, dur)

    def t4_compile(self) -> bool:
        """Stage 3 builds the harness binary. A generated file is not a harness."""
        r = self.results[Tier.HARNESS_COMPILED]
        r.command = f"nemesis run -t {self.project} --stages 3 --max-targets 1"
        rc, log, dur = run_cmd(
            ["nemesis", "run", "-t", self.project, "--stages", "3",
             "--max-targets", "1", "--strategy", "harness"],
            cwd=NEMESIS_ROOT, timeout=TIER_TIMEOUT_SEC[Tier.HARNESS_COMPILED],
            verbose=self.verbose,
        )
        if rc == 0 and not self._harness_binaries():
            rc, log = 1, log + "\nstage 3 exited 0 but produced no executable harness binary"
        return self._finish(Tier.HARNESS_COMPILED, rc, log, dur)

    def t5_fuzz(self) -> bool:
        r = self.results[Tier.FUZZ_READY]
        hours = round(FUZZ_SMOKE_SEC / 3600, 4)
        r.command = f"nemesis run -t {self.project} --stages 4 --timeout-hours {hours}"
        rc, log, dur = run_cmd(
            ["nemesis", "run", "-t", self.project, "--stages", "4",
             "--max-targets", "1", "--strategy", "harness",
             "--timeout-hours", str(hours)],
            cwd=NEMESIS_ROOT, timeout=TIER_TIMEOUT_SEC[Tier.FUZZ_READY],
            verbose=self.verbose,
        )
        started, execs = self._parse_fuzz_signals(log)
        self.fuzz_signals = {
            "fuzzer_started": started,
            "executions": execs,
            "exec_per_sec": round(execs / FUZZ_SMOKE_SEC, 1) if execs else 0.0,
            "meets_activity_threshold": execs >= ACTIVITY_FLOOR_EXECS,
        }

        # Three distinguishable failures, scored separately. A harness that
        # compiles, starts AFL and consumes nothing is a different engineering
        # problem from AFL never starting, and both differ from a harness that
        # runs but is too slow to be worth fuzzing.
        if rc == 0 and not started:
            rc, log = 1, log + "\nfuzzer never started"
            r.failure_class = FailureClass.FUZZER_START_FAILURE
        elif rc == 0 and execs == 0:
            rc, log = 1, log + "\nfuzzer started but recorded zero executions"
            r.failure_class = FailureClass.ZERO_EXECUTIONS
        elif rc == 0 and execs < ACTIVITY_FLOOR_EXECS:
            rc, log = 1, log + f"\nonly {execs} executions in {FUZZ_SMOKE_SEC}s"
            r.failure_class = FailureClass.BELOW_ACTIVITY_THRESHOLD

        ok = self._finish(Tier.FUZZ_READY, rc, log, dur)
        # _finish re-classifies from the log; keep the specific class we set.
        if not ok and r.failure_class in _T5_SPECIFIC:
            r.locality = Locality.RUNTIME
        return ok

    @staticmethod
    def _parse_fuzz_signals(log: str) -> tuple[bool, int]:
        """Pull (fuzzer_started, total executions) out of AFL++ output.

        AFL prints the count with thousands separators in the UI and plain in
        plot_data / the summary line, so both forms are matched.
        """
        started = bool(re.search(
            r"american fuzzy lop|afl\+\+|all set and ready to roll|entering queue cycle",
            log, re.I))
        execs = 0
        for pat in (r"execs?_done\s*[:=]\s*([\d,]+)",
                    r"total\s+execs?\s*[:=]?\s*([\d,]+)",
                    r"([\d,]+)\s+total\s+execs?"):
            m = re.search(pat, log, re.I)
            if m:
                execs = max(execs, int(m.group(1).replace(",", "")))
        return started, execs

    # ── helpers ─────────────────────────────────────────────

    def _workspace(self) -> Path:
        return NEMESIS_ROOT / "workspace" / self.project

    def _harness_sources(self) -> list[Path]:
        ws = self._workspace()
        if not ws.exists():
            return []
        return [p for p in ws.rglob("*harness*.c*") if p.stat().st_size > 0]

    def _harness_binaries(self) -> list[Path]:
        ws = self._workspace()
        if not ws.exists():
            return []
        return [
            p for p in ws.rglob("*")
            if p.is_file() and os.access(p, os.X_OK) and "harness" in p.name.lower()
            and p.suffix not in {".c", ".cc", ".cpp", ".h", ".log", ".yaml"}
        ]

    def _write_log(self, tier: Tier, rc: int, log: str, dur: float) -> str | None:
        if not self.log_dir:
            return None
        d = self.log_dir / self.slug
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{tier.value}.log"
        header = (
            f"# repo:     {self.full_name}\n"
            f"# commit:   {self.spec['commit']}\n"
            f"# tier:     {tier.value}\n"
            f"# command:  {self.results[tier].command}\n"
            f"# exit:     {rc}\n"
            f"# duration: {dur:.1f}s\n"
            f"{'-' * 72}\n"
        )
        path.write_text(header + log, encoding="utf-8", errors="replace")
        return str(path.relative_to(self.log_dir.parent))

    def _finish(self, tier: Tier, rc: int, log: str, dur: float) -> bool:
        r = self.results[tier]
        r.log_path = self._write_log(tier, rc, log, dur)
        r.exit_code = rc
        r.duration_sec = dur
        if rc == 0:
            r.status = Status.SUCCESS
            self.highest = max(self.highest, tier.index)
            return True
        if rc == 124:
            r.status = Status.TIMEOUT
            r.failure_class = FailureClass.TIMEOUT
            r.locality = TIER_LOCALITY[tier]
            r.detail = "\n".join(log.strip().splitlines()[-8:])
        else:
            r.status = Status.FAILED
            # A caller that already identified the failure precisely (T5) wins over
            # the log-pattern guess.
            if r.failure_class is None:
                r.failure_class, r.locality, r.detail = classify(log, tier)
            else:
                r.locality = TIER_LOCALITY[tier]
                r.detail = "\n".join(log.strip().splitlines()[-8:])
        return False

    def run(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        for step in (self.t0_acquire, self.t1_config, self.t2_library,
                     self.t3_harness, self.t4_compile, self.t5_fuzz):
            if not step():
                break
        reached = list(Tier)[self.highest] if self.highest >= 0 else None
        first_failure = next(
            (r for r in self.results.values()
             if r.status in (Status.FAILED, Status.TIMEOUT)), None
        )
        return {
            "repo": self.full_name,
            "commit": self.spec["commit"],
            "build_entry": self.spec.get("build_entry"),
            "started_at": started.isoformat(timespec="seconds"),
            "total_duration_sec": round(time.monotonic() - t0, 1),
            "tier_reached": reached.value if reached else None,
            "tier_reached_index": self.highest,
            "stages": {t.value: self.results[t].to_dict() for t in Tier},
            "first_failure": {
                "tier": first_failure.tier.value,
                "failure_class": first_failure.failure_class.value
                if first_failure.failure_class else None,
                "locality": first_failure.locality.value
                if first_failure.locality else None,
            } if first_failure else None,
            "fuzz_signals": self.fuzz_signals,
            "human_intervention": {"score": Intervention.NONE.value,
                                   "label": Intervention.NONE.name},
            # Measured inputs to any later effort estimate. Deliberately raw counts:
            # an "estimated manual equivalent in hours" would be a guess printed
            # next to measurements, and this project retracts those rather than
            # ships them.
            "effort_proxies": {
                "harness_sources": len(self._harness_sources()),
                "harness_binaries": len(self._harness_binaries()),
                "harness_loc": sum(
                    len(p.read_text(errors="replace").splitlines())
                    for p in self._harness_sources()
                ) if self._harness_sources() else 0,
            },
        }


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(results)
    funnel = {}
    for t in Tier:
        reached = sum(1 for r in results if r["tier_reached_index"] >= t.index)
        funnel[t.value] = {
            "count": reached,
            "pct": round(100.0 * reached / n, 1) if n else 0.0,
        }

    by_class: dict[str, int] = {}
    by_locality: dict[str, int] = {}
    for r in results:
        ff = r.get("first_failure")
        if not ff:
            continue
        by_class[ff["failure_class"]] = by_class.get(ff["failure_class"], 0) + 1
        by_locality[ff["locality"]] = by_locality.get(ff["locality"], 0) + 1

    def median(xs: list[float]) -> float:
        if not xs:
            return 0.0
        s = sorted(xs)
        m = len(s) // 2
        return round(s[m] if len(s) % 2 else (s[m - 1] + s[m]) / 2, 1)

    return {
        "repos": n,
        "funnel": funnel,
        "median_total_sec": median([r["total_duration_sec"] for r in results]),
        "median_stage_sec": {
            t.value: median([
                r["stages"][t.value]["duration_sec"] for r in results
                if r["stages"][t.value]["status"] == Status.SUCCESS.value
            ]) for t in Tier
        },
        "first_failure_by_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        "first_failure_by_locality": dict(sorted(by_locality.items(), key=lambda kv: -kv[1])),
        # The three T5 signals reported separately, since "reached T4" tells you
        # nothing about whether the harness was actually fuzzable.
        "fuzz_signals": {
            "reached_t4": sum(
                1 for r in results
                if r["tier_reached_index"] >= Tier.HARNESS_COMPILED.index),
            "fuzzer_started": sum(
                1 for r in results if r.get("fuzz_signals", {}).get("fuzzer_started")),
            "any_executions": sum(
                1 for r in results if r.get("fuzz_signals", {}).get("executions", 0) > 0),
            "meets_activity_threshold": sum(
                1 for r in results
                if r.get("fuzz_signals", {}).get("meets_activity_threshold")),
            "median_exec_per_sec": median([
                r["fuzz_signals"]["exec_per_sec"] for r in results
                if r.get("fuzz_signals", {}).get("executions", 0) > 0
            ]),
            "activity_floor_execs": ACTIVITY_FLOOR_EXECS,
        },
        "intervention_level": Intervention.NONE.value,
    }


def _tier_matrix(results: list[dict[str, Any]]) -> str:
    """One row per repository, one column per tier.

    Ordered by how far each repository got, so the shape of the failure is
    visible at a glance: a clean break at one tier reads differently from
    failures scattered across all of them.
    """
    mark = {Status.SUCCESS.value: "ok", Status.FAILED.value: "XX",
            Status.TIMEOUT.value: "TO", Status.NOT_RUN.value: " -",
            Status.SKIPPED.value: "sk"}
    head = "  ".join(t.value.split("_")[0] for t in Tier)
    lines = [
        "| repository | " + " | ".join(t.value.split("_")[0] for t in Tier)
        + " | first failure |",
        "|---" * (len(Tier) + 2) + "|",
    ]
    for r in sorted(results, key=lambda r: (-r["tier_reached_index"], r["repo"])):
        cells = [mark.get(r["stages"][t.value]["status"], "??") for t in Tier]
        ff = r.get("first_failure")
        why = f"{ff['failure_class']} @ {ff['locality']}" if ff else "—"
        lines.append(f"| {r['repo']} | " + " | ".join(cells) + f" | {why} |")
    return f"## Tier matrix\n\n<!-- {head} -->\n" + "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", default="~/nemesis-bench", help="Scratch dir for clones")
    ap.add_argument(
        "--results-dir", default=None,
        help="Where run artifacts go. Defaults to <workdir>/results — outside the "
             "repository on purpose: a run directory is an experiment artifact, not "
             "source, and this checkout lives on a synchronising filesystem. Keeping "
             "the whole baseline under one ext4 path also means it can be archived "
             "as a unit.",
    )
    ap.add_argument("--suite", default=str(HERE / "repos.yaml"))
    ap.add_argument("--only", action="append", default=[], help="Limit to repo(s), repeatable")
    ap.add_argument("--run-id", default=None, help="Defaults to a UTC timestamp")
    ap.add_argument("--dry-run", action="store_true", help="Print the plan, run nothing")
    ap.add_argument("--preflight", action="store_true",
                    help="Check readiness and write baseline.lock, then exit")
    ap.add_argument("--force", action="store_true",
                    help="With --preflight: overwrite an existing baseline.lock")
    ap.add_argument("--allow-warm-cache", action="store_true",
                    help="With --preflight: lock despite a populated LLM cache. "
                         "Recorded in the lock — the baseline then measures replay, "
                         "not onboarding capability.")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--intervention", type=int, default=0, choices=[i.value for i in Intervention],
        help="Record a run that needed human help. Writes to a separate file — "
             "assisted runs must never be mixed into the unattended baseline.",
    )
    args = ap.parse_args()

    suite_path = Path(args.suite)

    if args.preflight:
        lock_path = HERE / "baseline.lock"
        if lock_path.exists() and not args.force:
            sys.exit(f"{lock_path.name} already exists — the baseline is already "
                     "locked. Use --force only if you mean to redefine it.")
        env_snapshot = environment.capture(NEMESIS_ROOT)
        pf = preflight.run(HERE, env_snapshot, suite_path=suite_path,
                           allow_warm_cache=args.allow_warm_cache)
        preflight.report(pf)
        if pf.blocking:
            print(f"\n{len(pf.blocking)} blocking check(s) failed — not locking.")
            sys.exit(1)
        suite_doc = (yaml.safe_load(suite_path.read_text(encoding="utf-8"))
                     if suite_path.exists() else {})
        written = preflight.write_lock(HERE, env_snapshot, pf, suite_doc)
        # Keep the check output next to the lock. "The preconditions were met"
        # is part of the evidence for a run, not a debugging convenience, and
        # the runner copies both into the results directory.
        (HERE / "preflight.txt").write_text(
            "\n".join(
                f"{'ok  ' if c.ok else ('!!  ' if c.fatal else '..  ')}"
                f"{c.name:34s} {c.detail}"
                for c in pf.checks
            ) + f"\n\nexperiment_id: {preflight.experiment_id(env_snapshot)}\n"
                f"locked_utc:    {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n",
            encoding="utf-8",
        )
        print(f"\nexperiment_id: {preflight.experiment_id(env_snapshot)}")
        if pf.warnings:
            print(f"locked with {len(pf.warnings)} warning(s): "
                  f"{', '.join(c.name for c in pf.warnings)}")
        print(f"Locked: {written}\n\nThe baseline starts here. Do not change NEMESIS "
              "until the first run is recorded.")
        return

    if not suite_path.exists():
        sys.exit(f"{suite_path} missing — run build_pool.py --stage sample first")
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8"))
    repos = suite["repos"]
    if args.only:
        wanted = set(args.only)
        repos = [r for r in repos if r["full_name"] in wanted]
        if not repos:
            sys.exit(f"no suite entry matches {sorted(wanted)}")

    if args.dry_run:
        print(f"suite: {suite.get('suite')}  frozen={suite.get('frozen')}")
        for r in repos:
            print(f"  {r['full_name']:45s} @ {r['commit'][:8]}  ({r['build_entry']})")
        print(f"\n{len(repos)} repositories x 6 tiers; "
              f"worst-case {sum(TIER_TIMEOUT_SEC.values()) * len(repos) / 3600:.1f} h")
        return

    workdir = Path(os.path.expanduser(args.workdir))
    workdir.mkdir(parents=True, exist_ok=True)
    # Name the directory after the two identities rather than the clock. A
    # timestamp says when; these say *what* — which NEMESIS, on which repositories
    # — so two result directories can be compared without opening either.
    env_probe = environment.capture(NEMESIS_ROOT)
    exp_short = preflight.experiment_id(env_probe)[:8]
    inst_short = (suite.get("benchmark_instance_id") or "noinstance")[:8]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = "" if args.intervention == 0 else f"_assisted{args.intervention}"
    run_id = args.run_id or f"baseline_{exp_short}_{inst_short}{suffix}"
    results_root = (Path(os.path.expanduser(args.results_dir)) if args.results_dir
                    else workdir / "results")
    out_dir = results_root / run_id
    if out_dir.exists():
        # Never silently merge two runs into one directory: the second run's
        # logs would overwrite the first's tier-by-tier and the summary would
        # describe a mixture.
        out_dir = results_root / f"{run_id}_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Freeze the toolchain before anything runs. Written first so it survives even
    # if the suite is interrupted halfway.
    # Copy the freeze evidence in, so a results directory is self-contained: the
    # lock and the preflight output travel with the numbers they authorise.
    for name in ("baseline.lock", "preflight.txt"):
        src = HERE / name
        if src.exists():
            shutil.copy2(src, out_dir / name)

    env_snapshot = env_probe
    (out_dir / "environment.json").write_text(
        json.dumps(env_snapshot, indent=2), encoding="utf-8")
    nem = env_snapshot["nemesis"]
    print(f"NEMESIS {(nem['commit'] or '?')[:8]}"
          f"{' [DIRTY]' if nem['dirty'] else ''} on {env_snapshot['platform']['system']}"
          f"{' (WSL)' if env_snapshot['platform']['is_wsl'] else ''}")

    # Compare against the locked identity. Drift is not blocked — a later run
    # against a changed NEMESIS is the *point* — but it must be visible in the
    # results rather than discovered when the numbers disagree.
    current_id = preflight.experiment_id(env_snapshot)
    lock_path = HERE / "baseline.lock"
    locked_id = None
    if lock_path.exists():
        locked_id = json.loads(lock_path.read_text(encoding="utf-8")).get("experiment_id")
        if locked_id == current_id:
            print(f"experiment_id {current_id} — matches baseline.lock")
        else:
            print(f"experiment_id {current_id} — DIFFERS from locked {locked_id}",
                  file=sys.stderr)
            print("  this run is a different experiment than the baseline; the "
                  "results file records both ids", file=sys.stderr)
    else:
        print(f"experiment_id {current_id} — no baseline.lock "
              "(run --preflight first to mark the baseline)", file=sys.stderr)
    if nem["dirty"]:
        print(f"  warning: {nem['dirty_files']} uncommitted file(s) — this run is "
              "not reproducible by anyone else", file=sys.stderr)
    missing = [t for t in ("clang", "afl-fuzz", "cmake") if not env_snapshot["tools"].get(t)]
    if missing:
        print(f"  warning: not on PATH: {', '.join(missing)} — "
              "are you running inside WSL?", file=sys.stderr)

    results = []
    for i, spec in enumerate(repos, 1):
        print(f"\n[{i}/{len(repos)}] {spec['full_name']}")
        rec = RepoRun(spec, workdir, verbose=args.verbose,
                      log_dir=out_dir / "logs").run()
        if args.intervention:
            rec["human_intervention"] = {
                "score": args.intervention,
                "label": Intervention(args.intervention).name,
            }
        results.append(rec)
        (out_dir / f"{spec['full_name'].replace('/', '__')}.json").write_text(
            json.dumps(rec, indent=2), encoding="utf-8")
        reached = rec["tier_reached"] or "none"
        ff = rec.get("first_failure")
        print(f"    -> {reached}"
              + (f"  [{ff['failure_class']} @ {ff['locality']}]" if ff else "")
              + f"  {rec['total_duration_sec']:.0f}s")

    summary = aggregate(results)
    summary.update({
        "run_id": run_id,
        "suite": suite.get("suite"),
        "experiment_id": current_id,
        "baseline_experiment_id": locked_id,
        "matches_baseline": locked_id == current_id if locked_id else None,
        "benchmark_instance_id": suite.get("benchmark_instance_id"),
        "instance_inputs": suite.get("instance_inputs"),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # The per-repository matrix, not the funnel, is what identifies *which*
    # stage of the chain is weak. A funnel of 12/25 at T4 says the same thing
    # whether one repo class fails consistently or every repo fails somewhere
    # different — those are opposite engineering problems.
    matrix = _tier_matrix(results)
    (out_dir / "matrix.md").write_text(matrix, encoding="utf-8")
    print(f"\n{matrix}")

    print(f"\n{'=' * 60}\nFunnel ({summary['repos']} repos)")
    for tier, v in summary["funnel"].items():
        print(f"  {tier:26s} {v['count']:3d}  {v['pct']:5.1f}%")
    if summary["first_failure_by_locality"]:
        print("\nFirst failure by locality:")
        for k, v in summary["first_failure_by_locality"].items():
            print(f"  {k:26s} {v:3d}")
    print(f"\nResults: {out_dir}")


if __name__ == "__main__":
    main()
