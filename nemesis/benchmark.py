"""A/B benchmark runner for NEMESIS feature flags (Tier 1 #3, 2026-05-07).

Why this exists
---------------
We added five LLM-driven prompt-injection / synthesis features in
sequence (format_spec auto-synthesis, CVE bug-history injection, Locus
predicates, mutator synthesis, and seedgen). Each one is justified by
a paper or a research hypothesis; none of them is justified empirically
yet on our own benchmarks. Before adding more, we need to measure each
in isolation.

What this does
--------------
Given a target and a list of named configurations (each a set of
NEMESIS_DISABLE_* env vars), spawn `nemesis run -t TARGET --scan
--max-targets 1` once per configuration, capture its log, and parse
the AFL fuzzer_stats and structured log events to produce a comparison
table.

Metrics extracted per run:
  * saved_crashes       — AFL's de-duplicated crash count
  * unique_findings     — confirmed real bugs after triage
  * map_density_pct     — AFL bitmap coverage
  * line_cov_pct        — llvm-cov source line coverage
  * exec_per_sec        — AFL throughput (sanity check)
  * target_reached      — did the pinned function execute at all
  * predicates_count    — how many progress predicates were injected
  * predicates_named    — their names (helps diagnose drift across runs)
  * mutator_synthesised — did the LLM produce a mutator .so

Output: JSON + a Markdown comparison table.

Caveats
-------
v1 runs each config ONCE. Coverage-guided fuzzing is highly stochastic;
single-run deltas should be read as directional, not statistically
significant. Multi-iteration aggregation with Mann-Whitney U is a
follow-up (Tier 3). For now: if the variant beats the baseline by less
than ~30% we treat the result as inconclusive.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml


@dataclass
class RunMetrics:
    config_name: str
    duration_s: float = 0.0
    saved_crashes: int = 0
    unique_findings: int = 0
    map_density_pct: float = 0.0
    line_cov_pct: float = 0.0
    exec_per_sec: float = 0.0
    target_reached: bool = False
    predicates_count: int = 0
    predicates_named: list[str] = field(default_factory=list)
    mutator_synthesised: bool = False
    log_path: str = ""
    error: str = ""


# NEMESIS log lines use structlog kv format ("key=value") with no spaces
# inside the value. The events of interest emit either the AFL fuzzer_stats
# fields or NEMESIS-specific fields (bitmap_cvg_after, line_coverage_pct,
# reach_rate). We intentionally accept both base names (e.g. `bitmap_cvg`
# and `bitmap_cvg_after`) so the parser stays resilient to log-format drift
# between Tier 1/2 features.
_RE_SAVED_CRASHES = re.compile(r"saved_crashes=(\d+)")
_RE_EXEC_RATE = re.compile(r"execs_per_sec=([\d.]+)")
_RE_BITMAP_CVG = re.compile(r"bitmap_cvg(?:_after)?=([\d.]+)")
_RE_LINE_COV = re.compile(r"line_cov(?:erage)?(?:_pct)?=([\d.]+)")
_RE_TARGET_REACHED = re.compile(
    r"reach\.bitmap_override|harness\.reach_ok|reach\.confirmed|"
    r"reaches_target=True|reach_rate=(?:1\.0|0\.[1-9])",
    re.IGNORECASE,
)
_RE_PREDICATES = re.compile(
    r"harness\.progress_predicates_injected.*?count=(\d+).*?names=\[([^\]]*)\]"
)
_RE_MUTATOR_SYNTH = re.compile(r"afl\.custom_mutator_synthesized")


def _parse_log(log_path: Path, metrics: RunMetrics) -> None:
    """Walk the captured log line-by-line, populating `metrics` in place."""
    if not log_path.is_file():
        metrics.error = "log file not found"
        return

    text = log_path.read_text(errors="replace")

    # Crashes — last occurrence wins (final state)
    saved = _RE_SAVED_CRASHES.findall(text)
    if saved:
        metrics.saved_crashes = max(int(s) for s in saved)

    rates = _RE_EXEC_RATE.findall(text)
    if rates:
        # Use the median over the run, not the first or last (initial spikes
        # and final taper distort point estimates).
        nums = sorted(float(r) for r in rates if float(r) > 0)
        if nums:
            metrics.exec_per_sec = nums[len(nums) // 2]

    bitmaps = _RE_BITMAP_CVG.findall(text)
    if bitmaps:
        nums = [float(b) for b in bitmaps if b]
        if nums:
            metrics.map_density_pct = max(nums)

    lines = _RE_LINE_COV.findall(text)
    if lines:
        metrics.line_cov_pct = max(float(x) for x in lines)

    if _RE_TARGET_REACHED.search(text):
        metrics.target_reached = True

    pm = _RE_PREDICATES.search(text)
    if pm:
        metrics.predicates_count = int(pm.group(1))
        names_raw = pm.group(2)
        metrics.predicates_named = [
            n.strip().strip("'\"") for n in names_raw.split(",") if n.strip()
        ]

    if _RE_MUTATOR_SYNTH.search(text):
        metrics.mutator_synthesised = True


def _make_run_id(config_name: str) -> str:
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"benchmark_{config_name}_{ts}"


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the entire process group rooted at `proc`.

    `proc.kill()` only signals the immediate subprocess. NEMESIS spawns
    `afl-fuzz` (and `afl-fuzz` spawns the fuzz target binary) as
    grandchildren — those keep running on the simple kill, attached to
    init, and they continue writing to the per-target findings dir into
    the next benchmark config. We avoid that by launching with
    `start_new_session=True` and tearing the whole session down here.
    """
    import signal
    if proc.poll() is not None:
        return
    import contextlib
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, OSError):
        pass
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=10)


def _resolve_engine_workspace(nemesis_root: Path, target: str) -> Path:
    """Resolve the actual `engine.work_dir` from the merged config layers.

    NEMESIS reads work_dir from `config/default.yaml` (default
    `~/nemesis_workspace`) optionally overridden by
    `config/targets/<target>.yaml`. Earlier benchmarks erroneously
    cleaned `nemesis_root/workspace/` (a Windows-side stub) — the real
    AFL findings live under the resolved engine.work_dir, so prior-run
    crash files survived into the next config and inflated metrics.
    """
    cfg_data: dict = {}
    for p in (
        nemesis_root / "config" / "default.yaml",
        nemesis_root / "config" / "targets" / f"{target}.yaml",
    ):
        if not p.is_file():
            continue
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict):
            engine = data.get("engine", {})
            if isinstance(engine, dict) and "work_dir" in engine:
                cfg_data["work_dir"] = str(engine["work_dir"])

    raw = cfg_data.get("work_dir") or "~/nemesis_workspace"
    return Path(os.path.expanduser(os.path.expandvars(raw))).resolve()


def _ensure_clean_workspace(engine_workspace: Path) -> None:
    """Drop AFL findings + crash artefacts from prior runs.

    Preserves llm_cache (we don't want to pay for re-prompts during
    benchmarking — feature contributions, not prompt-cache hit rate, are
    what we're measuring) and any saved harnesses under config/targets/.

    Works on the resolved `engine.work_dir`, NOT on nemesis_root/workspace.
    """
    if not engine_workspace.exists():
        return
    for sub in ("fuzzing", "findings", "instrumented", "harnesses"):
        p = engine_workspace / sub
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)


def _count_findings_yaml(findings_yaml: Path) -> int:
    """Return the total number of recorded findings (all runs)."""
    if not findings_yaml.is_file():
        return 0
    try:
        with findings_yaml.open() as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return 0
    items = data.get("findings", [])
    return len(items) if isinstance(items, list) else 0


def _augment_from_fuzzer_stats(engine_workspace: Path, metrics: RunMetrics) -> None:
    """Pull AFL exec/sec + crash count from the fuzzer_stats file.

    NEMESIS does not log execs_per_sec as a structlog event. The number
    is in `<workspace>/fuzzing/findings/<hash>/<target>/main/fuzzer_stats`.
    We glob for it after the run completes and parse colon-delimited
    `key : value` lines.
    """
    pattern = engine_workspace / "fuzzing" / "findings" / "**" / "main" / "fuzzer_stats"
    candidates = list(engine_workspace.glob("fuzzing/findings/*/*/main/fuzzer_stats"))
    if not candidates:
        candidates = list(engine_workspace.glob("fuzzing/findings/*/*/default/fuzzer_stats"))
    if not candidates:
        return
    # Pick the most recently modified (this run's, in case stale dirs survived)
    stats_file = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        text = stats_file.read_text(errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().rstrip("%")
        try:
            if key == "execs_per_sec" and metrics.exec_per_sec == 0.0:
                metrics.exec_per_sec = float(val)
            elif key == "saved_crashes" and metrics.saved_crashes == 0:
                metrics.saved_crashes = int(val)
            elif key == "bitmap_cvg" and metrics.map_density_pct == 0.0:
                metrics.map_density_pct = float(val)
        except ValueError:
            pass
    _ = pattern  # quieten unused-import-style lint


def run_one(
    target: str,
    config_name: str,
    env_overrides: dict[str, str],
    nemesis_root: Path,
    out_dir: Path,
    duration_minutes: float = 15.0,
    keep_workspace: bool = False,
) -> RunMetrics:
    """Run nemesis once with the given env-flag set; return parsed metrics."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"{config_name}.log"
    run_id = _make_run_id(config_name)

    metrics = RunMetrics(config_name=config_name, log_path=str(log_path))

    # Resolve the actual engine workspace (e.g. ~/nemesis_workspace) and
    # snapshot the findings.yaml count BEFORE launching, so we can compute
    # the per-config delta even though NEMESIS picks its own internal run_id.
    engine_workspace = _resolve_engine_workspace(nemesis_root, target)
    findings_yaml = nemesis_root / "findings.yaml"
    findings_before = _count_findings_yaml(findings_yaml)
    if not keep_workspace:
        _ensure_clean_workspace(engine_workspace)

    env = os.environ.copy()
    env.update(env_overrides)
    env["NEMESIS_BENCHMARK_RUN_ID"] = run_id

    cmd = [
        sys.executable, "-u", "-m", "nemesis.cli",
        "run", "-t", target, "--scan", "--max-targets", "1",
    ]

    # Run the nemesis subprocess in its own process group so we can kill
    # the entire tree (nemesis CLI → AFL fuzz processes → fuzz target) on
    # timeout. Without this, `proc.kill()` only signals the immediate
    # subprocess, leaving AFL grandchildren orphaned and writing to the
    # findings dir while the next config tries to use it — corrupting both
    # configs' metrics.
    popen_kwargs: dict = {}
    if hasattr(os, "setsid"):  # POSIX
        popen_kwargs["start_new_session"] = True

    started = _dt.datetime.now()
    proc = None
    try:
        with log_path.open("w") as logf:
            proc = subprocess.Popen(
                cmd, cwd=str(nemesis_root), env=env,
                stdout=logf, stderr=subprocess.STDOUT,
                **popen_kwargs,
            )
            try:
                proc.wait(timeout=int(duration_minutes * 60 + 600))
            except subprocess.TimeoutExpired:
                _kill_process_group(proc)
                metrics.error = "subprocess timeout (cmd outlived budget+10min slack)"
    except Exception as exc:
        if proc is not None:
            _kill_process_group(proc)
        metrics.error = f"spawn failed: {exc}"
        return metrics

    metrics.duration_s = (_dt.datetime.now() - started).total_seconds()
    _parse_log(log_path, metrics)
    _augment_from_fuzzer_stats(engine_workspace, metrics)
    findings_after = _count_findings_yaml(findings_yaml)
    metrics.unique_findings = max(0, findings_after - findings_before)
    return metrics


def render_markdown_table(rows: list[RunMetrics]) -> str:
    """Produce a comparison table for stdout / report files."""
    if not rows:
        return "(no runs)"

    cols = [
        ("Config", lambda m: m.config_name),
        ("Crashes", lambda m: m.saved_crashes),
        ("Findings", lambda m: m.unique_findings),
        ("Map %", lambda m: f"{m.map_density_pct:.2f}"),
        ("Line %", lambda m: f"{m.line_cov_pct:.2f}"),
        ("Exec/s", lambda m: f"{m.exec_per_sec:.0f}"),
        ("Reach", lambda m: "Y" if m.target_reached else "N"),
        ("Preds", lambda m: m.predicates_count),
        ("Mutator", lambda m: "Y" if m.mutator_synthesised else "N"),
        ("Time(s)", lambda m: f"{m.duration_s:.0f}"),
    ]

    out: list[str] = []
    header = "| " + " | ".join(c[0] for c in cols) + " |"
    sep = "|" + "|".join("---" for _ in cols) + "|"
    out += [header, sep]
    for m in rows:
        out.append("| " + " | ".join(str(c[1](m)) for c in cols) + " |")
    if any(m.error for m in rows):
        out.append("")
        out.append("Errors:")
        for m in rows:
            if m.error:
                out.append(f"  - **{m.config_name}**: {m.error}")
    return "\n".join(out)


def run_ab(
    target: str,
    configs_path: Path,
    nemesis_root: Path,
    out_dir: Path,
    duration_minutes: float = 15.0,
) -> dict:
    """Top-level entry: load configs YAML, run each serially, write summary."""
    cfg_data = yaml.safe_load(configs_path.read_text())
    cfg_list = cfg_data.get("configs", [])
    if not isinstance(cfg_list, list) or not cfg_list:
        raise ValueError(
            f"configs file {configs_path} has no 'configs:' list"
        )

    rows: list[RunMetrics] = []
    for cfg in cfg_list:
        if not isinstance(cfg, dict):
            continue
        name = str(cfg.get("name", "unnamed"))
        env_overrides = cfg.get("env", {}) or {}
        env_overrides = {str(k): str(v) for k, v in env_overrides.items()}
        print(f"\n=== running config: {name} ===", flush=True)
        print(f"    env: {env_overrides or '(none — full stack)'}", flush=True)
        m = run_one(
            target=target,
            config_name=name,
            env_overrides=env_overrides,
            nemesis_root=nemesis_root,
            out_dir=out_dir,
            duration_minutes=duration_minutes,
        )
        rows.append(m)
        print(f"    crashes={m.saved_crashes} findings={m.unique_findings} "
              f"map={m.map_density_pct:.2f}% line={m.line_cov_pct:.2f}% "
              f"reach={'Y' if m.target_reached else 'N'} "
              f"preds={m.predicates_count} time={m.duration_s:.0f}s", flush=True)

    # JSON for machine consumers
    summary = {
        "target": target,
        "duration_minutes": duration_minutes,
        "configs_path": str(configs_path),
        "started": _dt.datetime.now().isoformat(),
        "runs": [asdict(m) for m in rows],
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    md = render_markdown_table(rows)
    (out_dir / "summary.md").write_text(md + "\n")
    print("\n" + md, flush=True)
    print(f"\nResults: {out_dir / 'summary.json'}\n         {out_dir / 'summary.md'}",
          flush=True)
    return summary


# ──────────────────────────────────────────────────────────────────────
# Predefined config presets
# ──────────────────────────────────────────────────────────────────────

# A "standard" two-arm A/B: vanilla AFL vs full NEMESIS stack.
PRESET_VANILLA_VS_FULL = {
    "configs": [
        {
            "name": "vanilla",
            "env": {
                "NEMESIS_DISABLE_FORMAT_SPEC": "1",
                "NEMESIS_DISABLE_BUG_HISTORY": "1",
                "NEMESIS_DISABLE_VALIDATION_GATES": "1",
                "NEMESIS_DISABLE_PREDICATES": "1",
                "NEMESIS_DISABLE_MUTATOR_SYNTHESIS": "1",
                "NEMESIS_DISABLE_SEEDGEN": "1",
                "NEMESIS_DISABLE_BIT_CURSOR": "1",
            },
        },
        {"name": "full_stack", "env": {}},
    ],
}

# Per-feature ablation: turn each feature off in isolation to measure
# individual contribution (one feature disabled, all others enabled).
PRESET_ABLATION = {
    "configs": [
        {"name": "full_stack", "env": {}},
        {"name": "no_predicates", "env": {"NEMESIS_DISABLE_PREDICATES": "1"}},
        {"name": "no_bug_history", "env": {"NEMESIS_DISABLE_BUG_HISTORY": "1"}},
        {"name": "no_format_spec", "env": {"NEMESIS_DISABLE_FORMAT_SPEC": "1"}},
        {"name": "no_mutator", "env": {"NEMESIS_DISABLE_MUTATOR_SYNTHESIS": "1"}},
    ],
}


def write_preset(preset_name: str, out_path: Path) -> None:
    """Write a built-in preset config to disk for editing or reuse."""
    presets = {
        "vanilla_vs_full": PRESET_VANILLA_VS_FULL,
        "ablation": PRESET_ABLATION,
    }
    if preset_name not in presets:
        raise KeyError(
            f"unknown preset {preset_name!r}; valid: {sorted(presets)}"
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(presets[preset_name], sort_keys=False))


def main(argv: list[str] | None = None) -> int:
    """Standalone CLI: nemesis benchmark-ab — see argparse help below."""
    import argparse

    p = argparse.ArgumentParser(
        prog="nemesis benchmark-ab",
        description="Run an A/B benchmark over NEMESIS feature flags.",
    )
    p.add_argument("--target", "-t", required=True, help="target name")
    p.add_argument(
        "--configs", "-c",
        help="path to a configs YAML (overrides --preset)",
    )
    p.add_argument(
        "--preset", choices=["vanilla_vs_full", "ablation"],
        default="vanilla_vs_full",
        help="built-in config preset (default: vanilla_vs_full)",
    )
    p.add_argument(
        "--out-dir", "-o",
        default="workspace/benchmark_ab",
        help="output dir for logs + summary (default: workspace/benchmark_ab)",
    )
    p.add_argument(
        "--duration", "-d", type=float, default=15.0,
        help="per-run duration in minutes (default 15)",
    )
    p.add_argument(
        "--write-preset",
        help="write the chosen preset to PATH and exit (no runs)",
    )
    args = p.parse_args(argv)

    nemesis_root = Path(__file__).resolve().parent.parent
    out_dir = (Path(args.out_dir) if Path(args.out_dir).is_absolute()
               else nemesis_root / args.out_dir)

    if args.write_preset:
        write_preset(args.preset, Path(args.write_preset))
        print(f"wrote preset {args.preset!r} → {args.write_preset}")
        return 0

    if args.configs:
        configs_path = Path(args.configs)
        if not configs_path.is_absolute():
            configs_path = nemesis_root / configs_path
    else:
        # Materialise the chosen preset to a temp file and use it.
        out_dir.mkdir(parents=True, exist_ok=True)
        configs_path = out_dir / f"_{args.preset}.yaml"
        write_preset(args.preset, configs_path)

    summary = run_ab(
        target=args.target,
        configs_path=configs_path,
        nemesis_root=nemesis_root,
        out_dir=out_dir,
        duration_minutes=args.duration,
    )

    # Exit nonzero when something is clearly broken (every run errored)
    if summary["runs"] and all(r.get("error") for r in summary["runs"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


# Silence ruff: shlex is intentionally available for downstream callers
# that want to escape env-overrides for log readability.
_ = shlex
