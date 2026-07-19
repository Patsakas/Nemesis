"""
NEMESIS CLI — command-line interface for the pipeline.

Usage:
    nemesis run --target libarchive           # Full pipeline
    nemesis recon --target libarchive         # Stage 1 only
    nemesis analyze --target libarchive       # Stage 2 only
    nemesis fuzz --target libarchive          # Stage 4 only
    nemesis report --run-id <id>              # Generate report from results
    nemesis config --show                     # Show resolved config
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nemesis.config import NemesisConfig, load_config
from nemesis.logging import get_logger, setup_logging
from nemesis.models import PipelineRun, PipelineStatus
from nemesis.reporter import (
    generate_cve_report,
    generate_report,
    load_findings,
    merge_crash_reports,
    save_cve_report,
    save_findings,
    update_finding_with_cve,
)

console = Console(stderr=True)

# ── ASCII banner ────────────────────────────────────────────

BANNER = r"""
[bold cyan]
    _   __ ______ __  ___ ______ _____ ____ _____
   / | / // ____//  |/  // ____// ___//  _// ___/
  /  |/ // __/  / /|_/ // __/   \__ \ / /  \__ \
 / /|  // /___ / /  / // /___  ___/ // /  ___/ /
/_/ |_//_____//_/  /_//_____/ /____/___/ /____/
[/bold cyan]
[dim]Neuro-Symbolic Exploit Mining Engine for Software Insecurities[/dim]
[dim]v0.1.0 — Georgios Patsakas[/dim]
"""


def _resolve_config(
    config_path: str | None,
    target: str | None,
) -> NemesisConfig:
    """Resolve and merge configuration files."""
    default = Path("config/default.yaml")
    target_cfg = None

    if config_path:
        default = Path(config_path)
    if target:
        target_cfg = Path(f"config/targets/{target}.yaml")

    return load_config(default_path=default, target_path=target_cfg)


# ── Main CLI group ──────────────────────────────────────────


@click.group()
@click.version_option(version="0.1.0", prog_name="nemesis")
def cli() -> None:
    """NEMESIS — Neuro-Symbolic Exploit Mining Engine."""
    pass


# ── nemesis run ─────────────────────────────────────────────


@cli.command()
@click.option("--target", "-t", default="", help="Target project name (e.g., libarchive)")
@click.option(
    "--targets", default="",
    help="Comma-separated target names or 'all' for every config/targets/*.yaml",
)
@click.option("--config", "-c", "config_path", default=None, help="Custom config file path")
@click.option("--dry-run", is_flag=True, help="Validate config and show plan without executing")
@click.option("--stages", "-s", default="1,2,3,4", help="Comma-separated stages to run (e.g., 1,2)")
@click.option("--max-targets", "-n", default=0, help="Max targets to process (0 = all)")
@click.option("--scan", is_flag=True, help="Scan mode: 15 min per target, up to 20 targets")
@click.option("--deep", is_flag=True, help="Deep mode: scan 15min x all -> deep fuzz top-3 x 4h each")
@click.option("--deep-top", default=3, help="Number of top targets to deep-fuzz (default 3)")
@click.option("--deep-hours", default=4.0, help="Per-target timeout for deep phase (default 4h)")
@click.option(
    "--timeout-hours", default=0.0, type=float,
    help="Fuzzing budget per target in hours (e.g. 0.5 = 30min, 2 = 2h). Overrides the "
         "15-minute default that --scan/--deep use. 0 keeps the preset.",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Resume: skip already-processed targets; triage-only for targets with existing crashes",
)
@click.option(
    "--strategy",
    type=click.Choice(["patch", "harness"]),
    default=None,
    help="Fuzzing strategy: 'patch' (bypass blockers) or 'harness' (no patches, smart harnesses)",
)
@click.option(
    "--auto-sanitizer",
    is_flag=True,
    help="Fix 153: LLM ranks sanitizers, pipeline runs top-K (default 2) as separate sequential passes; "
         "each pass mutates target.sanitizer_profile and re-invokes the pipeline. Findings aggregate "
         "into findings.yaml automatically. Hard rules (msan_supported / tsan_supported) zero out "
         "unreachable profiles before the LLM ranks the rest.",
)
@click.option(
    "--auto-sanitizer-top",
    default=2,
    type=int,
    help="Number of top-ranked sanitizers to run when --auto-sanitizer is set (default 2). "
         "Set to 1 for the single-best, 4 for full matrix.",
)
def run(
    target: str,
    targets: str,
    config_path: str | None,
    dry_run: bool,
    stages: str,
    max_targets: int,
    scan: bool,
    deep: bool,
    deep_top: int,
    deep_hours: float,
    timeout_hours: float,
    resume: bool,
    strategy: str | None,
    auto_sanitizer: bool,
    auto_sanitizer_top: int,
) -> None:
    """Run the full NEMESIS pipeline against a target."""
    console.print(BANNER)

    # Resolve multi-target mode
    target_list: list[str] = []
    if targets:
        if targets.lower() == "all":
            targets_dir = Path("config/targets")
            if targets_dir.exists():
                target_list = sorted(
                    p.stem for p in targets_dir.glob("*.yaml")
                )
        else:
            target_list = [t.strip() for t in targets.split(",") if t.strip()]

    if not target_list and not target:
        console.print("[red]Error: --target or --targets required.[/red]")
        sys.exit(1)

    if not target_list:
        target_list = [target]

    # Multi-library loop
    if len(target_list) > 1:
        console.print(f"[cyan]Multi-library scan:[/cyan] {', '.join(target_list)}")
        for lib_target in target_list:
            console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
            console.print(f"[bold cyan]  Library: {lib_target}[/bold cyan]")
            console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
            try:
                _run_single_target(
                    lib_target, config_path, dry_run, stages, max_targets,
                    scan, deep, deep_top, deep_hours, timeout_hours, resume, strategy,
                    auto_sanitizer, auto_sanitizer_top,
                )
            except SystemExit:
                console.print(f"[yellow]Skipping {lib_target} due to error.[/yellow]")
            except Exception as exc:
                console.print(f"[red]{lib_target} failed: {exc}[/red]")
        return

    # Single target (original path)
    _run_single_target(
        target_list[0], config_path, dry_run, stages, max_targets,
        scan, deep, deep_top, deep_hours, timeout_hours, resume, strategy,
        auto_sanitizer, auto_sanitizer_top,
    )


def _run_single_target(
    target: str,
    config_path: str | None,
    dry_run: bool,
    stages: str,
    max_targets: int,
    scan: bool,
    deep: bool,
    deep_top: int,
    deep_hours: float,
    timeout_hours: float,
    resume: bool,
    strategy: str | None,
    auto_sanitizer: bool = False,
    auto_sanitizer_top: int = 2,
) -> None:
    """Run the pipeline for a single target (extracted for multi-target support)."""

    cfg = _resolve_config(config_path, target)

    # -- Strategy override --------------------------------------------------
    if strategy:
        cfg.fuzzing.strategy = strategy

    # -- Scan mode overrides ------------------------------------------------
    if scan:
        cfg.fuzzing.timeout_hours = 0.25
        cfg.engine.max_feedback_iterations = 1  # scan: 1 feedback max (2 x 15min per target)
        if max_targets == 0:
            max_targets = 20

    # -- Deep mode overrides ------------------------------------------------
    if deep:
        scan = True  # deep implies scan as phase 1
        cfg.fuzzing.timeout_hours = 0.25
        cfg.engine.max_feedback_iterations = 1
        if max_targets == 0:
            max_targets = 20

    # -- Explicit budget wins over the scan/deep presets ---------------------
    if timeout_hours and timeout_hours > 0:
        cfg.fuzzing.timeout_hours = timeout_hours

    setup_logging(level=cfg.engine.log_level, fmt=cfg.engine.log_format)
    log = get_logger("cli")

    stage_list = [int(s.strip()) for s in stages.split(",")]

    # -- Fix 153: --auto-sanitizer multi-pass --------------------------------
    # When set, rank sanitizers via the LLM and run the pipeline once per
    # top-K profile. Each pass mutates target.sanitizer_profile and re-invokes
    # the build → execute → triage chain. Findings.yaml dedup is automatic.
    if auto_sanitizer:
        chosen_profiles = _resolve_auto_sanitizer_profiles(
            cfg, auto_sanitizer_top, log,
        )
        for i, prof in enumerate(chosen_profiles, 1):
            console.print(
                f"\n[bold magenta]══ auto-sanitizer pass {i}/{len(chosen_profiles)}: "
                f"{prof} ══[/bold magenta]\n"
            )
            cfg.target.sanitizer_profile = prof
            _execute_one_pass(
                cfg, target, stage_list, max_targets, scan, deep, deep_top,
                deep_hours, resume, log, dry_run,
            )
        return

    _execute_one_pass(
        cfg, target, stage_list, max_targets, scan, deep, deep_top,
        deep_hours, resume, log, dry_run,
    )


def _execute_one_pass(
    cfg: NemesisConfig,
    target: str,
    stage_list: list,
    max_targets: int,
    scan: bool,
    deep: bool,
    deep_top: int,
    deep_hours: float,
    resume: bool,
    log,
    dry_run: bool,
) -> None:
    """Build pipeline, execute once, show + save results. Extracted from
    _run_single_target so --auto-sanitizer can call it once per profile."""
    run_id = uuid.uuid4().hex[:12]
    mode_str = "deep" if deep else ("scan" if scan else None)
    _show_config_summary(cfg, stage_list, run_id, scan_mode=scan, resume=resume, deep_mode=deep)

    if dry_run:
        console.print("\n[yellow]Dry run — exiting without execution.[/yellow]")
        return

    log.info("pipeline.start", run_id=run_id, target=target, stages=stage_list,
             mode=mode_str or "normal",
             sanitizer_profile=cfg.target.sanitizer_profile)
    start_time = time.monotonic()

    pipeline_run = PipelineRun(run_id=run_id)

    try:
        from nemesis.pipeline import NemesisPipeline
        pipeline = NemesisPipeline(cfg)
        if deep:
            pipeline_run = pipeline.execute_deep(
                stage_list=stage_list,
                max_targets=max_targets,
                deep_top_n=deep_top,
                deep_timeout_hours=deep_hours,
            )
        else:
            pipeline_run = pipeline.execute(
                stage_list=stage_list,
                max_targets=max_targets,
                resume=resume,
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Pipeline interrupted by user.[/yellow]")
        log.warning("pipeline.interrupted", run_id=run_id)
    except Exception as e:
        console.print(f"\n[red]Pipeline failed: {e}[/red]")
        log.error("pipeline.failed", run_id=run_id, error=str(e), exc_info=True)
        sys.exit(1)

    elapsed = time.monotonic() - start_time
    _show_results_summary(pipeline_run, elapsed)
    log.info("pipeline.complete", run_id=run_id, duration_s=round(elapsed, 1))
    _update_findings(pipeline_run, cfg)

    # Run-level success gate: a run where no target was processable or every
    # target failed should NOT exit 0 (it previously looked like success).
    if pipeline_run.status == PipelineStatus.FAILED:
        reasons = "; ".join(pipeline_run.degraded_reasons) or "no targets produced results"
        console.print(f"\n[red]Run did not succeed: {reasons}[/red]")
        log.error("pipeline.unsuccessful", run_id=run_id,
                  reasons=pipeline_run.degraded_reasons)
        sys.exit(1)
    elif pipeline_run.degraded_reasons:
        console.print(
            f"\n[yellow]Completed with degradations: "
            f"{'; '.join(pipeline_run.degraded_reasons)}[/yellow]"
        )


def _resolve_auto_sanitizer_profiles(
    cfg: NemesisConfig, top_k: int, log,
) -> list[str]:
    """Run the LLM ranker against the first pinned_func; return top-K profiles.

    On any failure (no pinned_func, missing source, LLM error), returns
    ['asan_ubsan'] so at least one sanitizer pass runs.
    """
    import os

    from nemesis.recon.sanitizer_ranker import pick_top_k, rank_sanitizers

    pinned = cfg.target.pinned_funcs or []
    if not pinned:
        log.warning("auto_sanitizer.no_pinned_func",
                    note="cannot rank without a pinned_func; defaulting to asan_ubsan")
        return ["asan_ubsan"]

    pf = pinned[0]
    src_root = Path(os.path.expandvars(str(cfg.target.source_root)))
    src_path = src_root / pf.file_path
    snippet = ""
    if src_path.exists():
        try:
            text = src_path.read_text(errors="ignore")
            idx = text.find(pf.func_name + "(")
            if idx < 0:
                idx = text.find(pf.func_name)
            snippet = text[max(0, idx):idx + 6000] if idx >= 0 else text[:6000]
        except OSError as exc:
            log.warning("auto_sanitizer.source_read_failed", error=str(exc))

    client = None
    try:
        from nemesis.neural import LLMClient
        client = LLMClient(cfg)
    except Exception as exc:
        log.warning("auto_sanitizer.llm_client_unavailable", error=str(exc))

    ranking = rank_sanitizers(pf.func_name, snippet, cfg.target,
                              llm_client=client, log=log)
    chosen = pick_top_k(ranking, k=top_k)
    log.info("auto_sanitizer.chosen", source=ranking.source,
             profiles=chosen, scores=ranking.scores)
    for prof in chosen:
        if ranking.rationale.get(prof):
            log.info("auto_sanitizer.rationale", profile=prof,
                     reason=ranking.rationale[prof])
    return chosen


# ── nemesis onboard ─────────────────────────────────────────


@cli.command()
@click.option(
    "--source-root", required=True, type=click.Path(exists=True),
    help="Path to already-cloned library source tree",
)
@click.option("--project-name", required=True, help="Library name (e.g. libpng)")
@click.option(
    "--oss-fuzz-project", default="",
    help="OSS-Fuzz project name (defaults to project-name)",
)
@click.option(
    "--work-root", default="",
    help="Working copy path (defaults to $HOME/{name}_work)",
)
@click.option(
    "--output", default="",
    help="Output YAML path (defaults to config/targets/{name}.yaml)",
)
@click.option("--config", "-c", "config_path", default=None, help="Custom base config path")
def onboard(
    source_root: str,
    project_name: str,
    oss_fuzz_project: str,
    work_root: str,
    output: str,
    config_path: str | None,
) -> None:
    """Auto-generate a NEMESIS target config for a new C library."""
    console.print(BANNER)

    # Load default config (no target YAML yet — it doesn't exist)
    cfg = _resolve_config(config_path, None)
    setup_logging(level=cfg.engine.log_level, fmt=cfg.engine.log_format)

    from nemesis.neural import NeuralStage
    from nemesis.onboard import TargetOnboarder

    neural = NeuralStage(cfg)
    onboarder = TargetOnboarder(cfg)

    try:
        output_file = onboarder.generate_yaml(
            source_root=Path(source_root),
            project_name=project_name,
            oss_fuzz_project=oss_fuzz_project,
            work_root=work_root,
            output=output,
            neural=neural,
        )
    except Exception as exc:
        console.print(f"\n[red]Onboard failed: {exc}[/red]")
        sys.exit(1)

    console.print(f"\n[bold green]Config written:[/bold green] [cyan]{output_file}[/cyan]")
    console.print(
        f"\n[dim]Next steps:\n"
        f"  1. Review and adjust paths in {output_file}\n"
        f"  2. Validate:   nemesis run --target {project_name} --dry-run\n"
        f"  3. Quick scan: nemesis run --target {project_name} --scan --strategy harness[/dim]"
    )


# ── nemesis scout ───────────────────────────────────────────


@cli.command()
@click.option("--top", "-n", default=25, help="Number of candidates to show (default 25)")
@click.option("--round-trip-only", is_flag=True,
              help="Only show candidates where the differential/round-trip oracle applies")
@click.option("--out", "out_path", default="", help="Write the markdown report to this file")
@click.option("--year", default=2026, help="Reference year for recency scoring")
def scout(top: int, round_trip_only: bool, out_path: str, year: int) -> None:
    """Find un-fuzzed C/C++ parser libraries worth targeting for new bugs.

    Excludes everything already continuously fuzzed by OSS-Fuzz and ranks the
    rest by fuzzability × round-trip-oracle potential — the discovery strategy
    with actual odds of a NEW CVE.
    """
    console.print(BANNER)
    setup_logging(level="INFO", fmt="console")
    # Make sure .env (GITHUB_TOKEN etc.) is loaded for higher rate limits.
    from nemesis.config import load_dotenv_file
    load_dotenv_file()

    from nemesis.recon.target_scout import render_report
    from nemesis.recon.target_scout import scout as run_scout

    console.print("[cyan]Scouting GitHub for un-fuzzed C/C++ parser libraries…[/cyan]")
    results = run_scout(top_n=max(top, 1), now_year=year)
    if round_trip_only:
        results = [r for r in results if r["round_trip"]]

    if not results:
        console.print("[yellow]No candidates found (network/rate-limit?). "
                      "Set GITHUB_TOKEN in .env to raise limits.[/yellow]")
        return

    report = render_report(results)
    console.print(report)
    if out_path:
        Path(out_path).write_text(report, encoding="utf-8")
        console.print(f"\n[green]Report written to {out_path}[/green]")


# ── nemesis setup ───────────────────────────────────────────


@cli.command()
@click.option("--target", "-t", required=True, help="Target project name (e.g., brotli)")
@click.option("--config", "-c", "config_path", default=None, help="Custom config file path")
@click.option("--url", default="", help="Git URL to clone (if source doesn't exist)")
@click.option("--skip-build", is_flag=True, help="Only clone + rsync, skip builds")
def setup(target: str, config_path: str | None, url: str, skip_build: bool) -> None:
    """Auto-setup a target library: clone, prepare workspace, and verify builds."""
    console.print(BANNER)
    cfg = _resolve_config(config_path, target)
    setup_logging(level=cfg.engine.log_level, fmt=cfg.engine.log_format)

    from nemesis.setup import LibrarySetup

    lib_setup = LibrarySetup(cfg)

    if skip_build:
        # Only clone + rsync
        source_root = Path(cfg.target.source_root)
        work_root = Path(cfg.target.effective_work_root)
        if url and not source_root.exists():
            ok = lib_setup.clone(url, source_root)
            if not ok:
                console.print("[red]Clone failed.[/red]")
                sys.exit(1)
        ok = lib_setup.prepare_work_copy(source_root, work_root)
        if ok:
            lib_setup.create_build_dirs()
            console.print("[green]Workspace prepared (builds skipped).[/green]")
        else:
            console.print("[red]Rsync failed.[/red]")
            sys.exit(1)
        return

    results = lib_setup.full_setup(git_url=url)

    # Display results
    table = Table(title=f"Setup Results — {target}")
    table.add_column("Step", style="cyan")
    table.add_column("Status", justify="right")

    for step, status in results.items():
        if step.endswith("_error"):
            continue
        if status is True:
            style = "[green]OK[/green]"
        elif status is False:
            err = results.get(f"{step}_error", "")
            style = "[red]FAILED[/red]"
            if err:
                style += f"\n[dim]{str(err)[:80]}[/dim]"
        else:
            style = f"[yellow]{status}[/yellow]"
        table.add_row(step, style)

    console.print(table)

    # Summary
    failed = [k for k, v in results.items() if v is False]
    if failed:
        console.print(f"\n[red]Setup had failures: {', '.join(failed)}[/red]")
        console.print("[dim]Fix the issues and re-run nemesis setup.[/dim]")
        sys.exit(1)
    else:
        console.print(f"\n[bold green]Setup complete for {target}.[/bold green]")
        console.print(
            f"[dim]Next: nemesis run -t {target} --scan --max-targets 5[/dim]"
        )


# ── nemesis verify-crashes ──────────────────────────────────


@cli.command("verify-crashes")
@click.option("--target", "-t", required=True, help="Target project name (e.g., libarchive)")
@click.option("--config", "-c", "config_path", default=None)
def verify_crashes(target: str, config_path: str | None) -> None:
    """
    Offline crash verification: determine which crashes are real bugs vs patch-induced.

    For each crash found by AFL++, rebuilds the unpatched (original) target library
    and tests whether the crash reproduces. Real bugs are CVE candidates; patch-induced
    crashes are false positives created by the LLM reachability patch.
    """
    console.print(BANNER)
    cfg = _resolve_config(config_path, target)
    setup_logging(level=cfg.engine.log_level, fmt=cfg.engine.log_format)

    from rich.table import Table

    from nemesis.recon import ReconStage
    from nemesis.verifier import OfflineCrashVerifier

    console.print("[cyan]Phase 1:[/cyan] Running recon to enumerate targets...")
    recon = ReconStage(cfg)
    targets = recon.run()
    console.print(f"[dim]Found {len(targets)} targets from recon.[/dim]\n")

    console.print("[cyan]Phase 2:[/cyan] Running unpatched verification on crash files...")
    verifier = OfflineCrashVerifier(cfg)
    results = verifier.run(targets)

    if not results:
        console.print("[yellow]No crash files found to verify.[/yellow]")
        return

    # Display results table
    table = Table(title="Unpatched Crash Verification Results")
    table.add_column("Function", style="cyan")
    table.add_column("Total crashes", justify="right")
    table.add_column("Real (CVE candidate)", justify="right", style="green")
    table.add_column("Patch-induced", justify="right", style="yellow")
    table.add_column("Verdict", style="bold")

    real_bug_targets = []
    for r in results:
        real = len(r.real_crashes)
        induced = len(r.patch_induced)
        verdict = r.verdict
        style = "green" if real > 0 else "yellow"
        table.add_row(
            r.func_name,
            str(len(r.crash_files)),
            str(real),
            str(induced),
            f"[{style}]{verdict}[/{style}]",
        )
        if real > 0:
            real_bug_targets.append(r)

    console.print(table)

    if real_bug_targets:
        console.print(
            f"\n[bold green]Found {len(real_bug_targets)} target(s) with real pre-existing bugs:[/bold green]"
        )
        for r in real_bug_targets:
            console.print(f"  [green]✓[/green] {r.func_name}: {len(r.real_crashes)} crash(es) reproduce unpatched")
        console.print("\n[dim]Run 'nemesis run --target <target>' to add these to findings.yaml[/dim]")
    else:
        console.print("\n[yellow]All crashes were patch-induced (false positives). No new CVE candidates.[/yellow]")


# ── nemesis recon ───────────────────────────────────────────


@cli.command()
@click.option("--target", "-t", required=True, help="Target project name")
@click.option("--config", "-c", "config_path", default=None)
@click.option("--output", "-o", default=None, help="Output JSON file for targets")
def recon(target: str, config_path: str | None, output: str | None) -> None:
    """Run Stage 1 (Recon) only — identify low-coverage targets."""
    console.print(BANNER)

    cfg = _resolve_config(config_path, target)
    setup_logging(level=cfg.engine.log_level, fmt=cfg.engine.log_format)

    from nemesis.recon import ReconStage

    stage = ReconStage(cfg)
    targets = stage.run()

    # Display results
    table = Table(title=f"Recon Results — {target}")
    table.add_column("Function", style="cyan")
    table.add_column("File", style="dim")
    table.add_column("Coverage", justify="right")
    table.add_column("Memory Ops", justify="center")
    table.add_column("Ptr Arith", justify="center")

    for t in targets:
        table.add_row(
            t.func_name,
            t.file_path,
            f"{t.coverage_pct:.1f}%",
            "✓" if t.has_memory_ops else "",
            "✓" if t.has_pointer_arith else "",
        )

    console.print(table)

    if output:
        import json
        Path(output).write_text(
            json.dumps([t.model_dump() for t in targets], indent=2)
        )
        console.print(f"\n[green]Results saved to {output}[/green]")


# ── nemesis config ──────────────────────────────────────────


@cli.command("config")
@click.option("--target", "-t", default=None, help="Target project name")
@click.option("--config", "-c", "config_path", default=None)
@click.option("--show", is_flag=True, help="Show resolved configuration")
@click.option("--validate", is_flag=True, help="Validate configuration only")
def config_cmd(
    target: str | None,
    config_path: str | None,
    show: bool,
    validate: bool,
) -> None:
    """Show or validate NEMESIS configuration."""
    try:
        cfg = _resolve_config(config_path, target)
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    if validate:
        console.print("[green]Configuration is valid.[/green]")
        return

    if show:
        import json
        console.print_json(json.dumps(cfg.model_dump(mode="json"), indent=2, default=str))


# ── nemesis report ──────────────────────────────────────────


@cli.command()
@click.option("--run-id", default="", help="Pipeline run ID (optional — defaults to all findings)")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default="markdown")
@click.option("--output", "-o", default="", help="Write report to file instead of stdout")
@click.option("--findings-path", default="findings.yaml", help="Path to findings.yaml")
def report(run_id: str, fmt: str, output: str, findings_path: str) -> None:
    """Generate a findings report from findings.yaml or a specific run."""
    findings = load_findings(findings_path)

    if not findings:
        console.print("[yellow]No findings to report.[/yellow]")
        return

    # Filter by run_id if specified
    if run_id:
        findings = [f for f in findings if f.get("run_id") == run_id]
        if not findings:
            console.print(f"[yellow]No findings for run {run_id}.[/yellow]")
            return
        console.print(f"[dim]Filtering to run {run_id}: {len(findings)} finding(s)[/dim]")

    if fmt == "json":
        import json
        report_text = json.dumps(findings, indent=2, default=str)
    elif fmt == "markdown":
        report_text = generate_report(findings)
    else:
        # Text summary
        lines = [f"NEMESIS Findings Report — {len(findings)} finding(s)\n"]
        for f in findings:
            fid = f.get("id", "?")
            func = f.get("function", "?")
            cwe = f.get("cwe", "?")
            sev = f.get("severity", "?").upper()
            status = f.get("status", "?")
            cve = "CVE-worthy" if f.get("cve_worthy") else ""
            lines.append(f"  {fid}  {sev:8s}  {cwe:10s}  {func:40s}  {status:12s}  {cve}")
        report_text = "\n".join(lines)

    if output:
        Path(output).write_text(report_text)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(report_text)


# ── nemesis benchmark-ab ────────────────────────────────────


@cli.command(name="benchmark-ab")
@click.option("--target", "-t", required=True, help="Target project name")
@click.option(
    "--configs", "-c", "configs_path",
    default=None,
    help="Path to a configs YAML (overrides --preset)",
)
@click.option(
    "--preset",
    type=click.Choice(["vanilla_vs_full", "ablation"]),
    default="vanilla_vs_full",
    help="Built-in config preset",
)
@click.option(
    "--out-dir", "-o",
    default="workspace/benchmark_ab",
    help="Output dir for logs + summary.{json,md}",
)
@click.option(
    "--duration", "-d", type=float, default=15.0,
    help="Per-run duration in minutes (default 15)",
)
@click.option(
    "--write-preset",
    default=None,
    help="Materialise the chosen preset to PATH and exit (no runs).",
)
def benchmark_ab(
    target: str,
    configs_path: str | None,
    preset: str,
    out_dir: str,
    duration: float,
    write_preset: str | None,
) -> None:
    """Run an A/B benchmark over NEMESIS feature flags.

    Spawns `nemesis run -t TARGET --scan --max-targets 1` once per
    configuration with the configured NEMESIS_DISABLE_* env vars set,
    captures stdout to per-config log files, parses metrics (saved
    crashes, AFL bitmap %, line coverage %, target reach, predicate
    count, mutator synthesised), and writes summary.json + summary.md.
    """
    from nemesis.benchmark import (
        run_ab,
    )
    from nemesis.benchmark import (
        write_preset as _write_preset,
    )

    nemesis_root = Path(__file__).resolve().parent.parent
    out_dir_p = (Path(out_dir) if Path(out_dir).is_absolute()
                 else nemesis_root / out_dir)

    if write_preset:
        _write_preset(preset, Path(write_preset))
        console.print(f"[green]Wrote preset {preset!r} -> {write_preset}[/green]")
        return

    if configs_path:
        cfg_p = Path(configs_path)
        if not cfg_p.is_absolute():
            cfg_p = nemesis_root / cfg_p
    else:
        out_dir_p.mkdir(parents=True, exist_ok=True)
        cfg_p = out_dir_p / f"_{preset}.yaml"
        _write_preset(preset, cfg_p)

    run_ab(
        target=target,
        configs_path=cfg_p,
        nemesis_root=nemesis_root,
        out_dir=out_dir_p,
        duration_minutes=duration,
    )


# ── nemesis serve ───────────────────────────────────────────


@cli.command()
@click.option(
    "--host", default="127.0.0.1", show_default=True,
    help="Bind host. Loopback by default: the dashboard can launch scans and "
         "rewrite target configs, so it is not safe to expose. Pass 0.0.0.0 "
         "only on a network you trust.",
)
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option("--workspace", default="workspace", show_default=True, help="Workspace directory")
@click.option("--findings", "findings_path", default="findings.yaml", show_default=True)
@click.option("--reload", is_flag=True, help="Enable auto-reload (dev mode)")
def serve(host: str, port: int, workspace: str, findings_path: str, reload: bool) -> None:
    """Start the NEMESIS web dashboard (FastAPI + React)."""
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        console.print(
            "[red]uvicorn not installed. Run:[/red] pip install -e '.[web]'"
        )
        sys.exit(1)

    reports_dir = str(Path(workspace) / "reports")
    console.print(BANNER)
    console.print(
        Panel(
            f"[cyan]Host:[/cyan]      {host}:{port}\n"
            f"[cyan]Workspace:[/cyan] {workspace}\n"
            f"[cyan]Findings:[/cyan]  {findings_path}\n"
            f"[cyan]Reports:[/cyan]   {reports_dir}\n"
            f"[cyan]UI:[/cyan]        http://localhost:{port}",
            title="NEMESIS Dashboard",
            border_style="cyan",
        )
    )

    # Pass paths via env vars so the module-level `app` object (used by
    # uvicorn's import-string reload mode) picks them up correctly.
    import os  # noqa: PLC0415
    os.environ["NEMESIS_WORKSPACE"] = str(Path(workspace).resolve())
    os.environ["NEMESIS_FINDINGS"] = str(Path(findings_path).resolve())
    os.environ["NEMESIS_REPORTS_DIR"] = str(Path(reports_dir).resolve())

    if reload:
        # --reload requires an import string, not an app instance
        uvicorn.run(
            "nemesis.api.app:app",
            host=host,
            port=port,
            reload=True,
            log_level="info",
        )
    else:
        from nemesis.api.app import create_app  # noqa: PLC0415

        app = create_app(
            workspace=workspace,
            findings_yaml=findings_path,
            reports_dir=reports_dir,
        )
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=False,
            log_level="info",
        )


# ── nemesis daemon ──────────────────────────────────────────


@cli.command()
@click.option(
    "--targets", "-t", default="all",
    help="Comma-separated target names or 'all' (default: all)",
)
@click.option("--schedule", default="", help="Cron schedule (e.g., '0 2 * * *' for 2am daily)")
@click.option("--interval", default=0.0, help="Run every N hours (alternative to --schedule)")
@click.option("--once", is_flag=True, help="Run one cycle and exit")
@click.option("--max-targets", "-n", default=10, help="Max targets per library scan")
@click.option("--strategy", default="harness", help="Fuzzing strategy")
@click.option("--webhook", default="", help="Webhook URL for notifications")
def daemon(
    targets: str,
    schedule: str,
    interval: float,
    once: bool,
    max_targets: int,
    strategy: str,
    webhook: str,
) -> None:
    """Run NEMESIS as a background daemon with scheduled scans."""
    console.print(BANNER)

    # Resolve target list
    if targets.lower() == "all":
        targets_dir = Path("config/targets")
        target_list = sorted(p.stem for p in targets_dir.glob("*.yaml")) if targets_dir.exists() else []
    else:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]

    if not target_list:
        console.print("[red]No targets configured in config/targets/[/red]")
        sys.exit(1)

    from nemesis.daemon import NemesisDaemon

    d = NemesisDaemon(
        targets=target_list,
        max_targets=max_targets,
        strategy=strategy,
        webhook_url=webhook,
    )

    console.print(
        Panel(
            f"[cyan]Targets:[/cyan]  {', '.join(target_list)}\n"
            f"[cyan]Schedule:[/cyan] {schedule or f'every {interval}h' if interval else 'once'}\n"
            f"[cyan]Strategy:[/cyan] {strategy}\n"
            f"[cyan]Webhook:[/cyan]  {webhook or 'disabled'}",
            title="NEMESIS Daemon",
            border_style="cyan",
        )
    )

    if once:
        d.run_once()
    elif schedule:
        d.run_cron(schedule)
    elif interval > 0:
        d.run_interval(interval)
    else:
        console.print("[red]Specify --schedule, --interval, or --once[/red]")
        sys.exit(1)


# ── Display helpers ─────────────────────────────────────────


def _show_config_summary(
    cfg: NemesisConfig,
    stages: list[int],
    run_id: str,
    scan_mode: bool = False,
    resume: bool = False,
    deep_mode: bool = False,
) -> None:
    """Print a config summary panel."""
    stage_names = {1: "Recon", 2: "Neural", 3: "Symbolic", 4: "Fuzzing"}
    active = ", ".join(f"{s}:{stage_names.get(s, '?')}" for s in stages)

    # Report the provider that will actually be tried first. `llm.model` only
    # feeds the legacy single-provider path, so printing it was misleading
    # whenever a provider chain is configured — which is the normal case.
    providers = getattr(cfg.llm, "providers", None) or []
    if providers:
        extra = len(providers) - 1
        llm_desc = providers[0].model + (f"  (+{extra} fallback{'s' if extra != 1 else ''})" if extra else "")
    else:
        llm_desc = cfg.llm.model

    lines = [
        f"[cyan]Run ID:[/cyan]        {run_id}",
        f"[cyan]Target:[/cyan]        {cfg.target.name or 'generic'}",
        f"[cyan]Source:[/cyan]        {cfg.target.source_root}",
        f"[cyan]Stages:[/cyan]        {active}",
        f"[cyan]LLM:[/cyan]           {llm_desc}",
        f"[cyan]Strategy:[/cyan]      {cfg.fuzzing.strategy}",
        f"[cyan]Fuzzer:[/cyan]        {cfg.fuzzing.fuzzer} × {cfg.fuzzing.instances}",
        f"[cyan]Solver:[/cyan]        {cfg.symbolic.solver}",
        f"[cyan]Feedback:[/cyan]      max {cfg.engine.max_feedback_iterations} iterations",
        f"[cyan]Timeout:[/cyan]       {cfg.fuzzing.timeout_hours}h per target",
    ]

    if deep_mode:
        lines.append("[bold magenta]Mode:[/bold magenta]          deep mode (scan 15min → score → deep fuzz top-N)")
    elif scan_mode:
        lines.append("[yellow]Mode:[/yellow]          scan mode (15 min × up to 20 targets)")
    if resume:
        lines.append("[yellow]Resume:[/yellow]        skip processed targets; triage-only for existing crashes")

    console.print(Panel("\n".join(lines), title="Pipeline Configuration", border_style="cyan"))


def _show_results_summary(run: PipelineRun, elapsed: float) -> None:
    """Print a results summary table."""
    table = Table(title="Pipeline Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Targets processed", str(run.targets_processed))
    table.add_row("Targets with crashes", str(run.targets_successful))
    table.add_row("Total crashes", str(run.total_crashes))
    table.add_row("CVE candidates", str(run.total_cves))
    table.add_row("LLM cost", f"${run.total_llm_cost_usd:.4f}")
    table.add_row("Duration", f"{elapsed:.1f}s")

    console.print(table)

    if run.total_crashes > 0:
        console.print(
            f"\n[bold green]Found {run.total_crashes} crash(es) "
            f"across {run.targets_successful} target(s).[/bold green]"
        )
    else:
        console.print("\n[yellow]No crashes found in this run.[/yellow]")


# ── Reporter integration ─────────────────────────────────────


def _extract_source_context(config: NemesisConfig, file_path: str, crash_location: str) -> str:
    """Extract ~20 lines of source around a crash location."""
    if not crash_location or ":" not in crash_location:
        return ""

    # Parse crash_location — format is "func_name at file:line" or "file:line"
    parts = crash_location.split(":")
    try:
        line_no = int(parts[-1])
    except (ValueError, IndexError):
        return ""

    # Try to find the source file
    source_root = Path(config.target.source_root)
    # crash_location may contain "func at path:line" — extract path
    loc_path = ":".join(parts[:-1])
    if " at " in loc_path:
        loc_path = loc_path.split(" at ")[-1]

    src_file = source_root / loc_path
    if not src_file.exists():
        # Try searching under source_subdir
        if config.target.source_subdir:
            src_file = source_root / config.target.source_subdir / Path(loc_path).name
        if not src_file.exists():
            return ""

    try:
        lines = src_file.read_text(errors="replace").splitlines()
        start = max(0, line_no - 10)
        end = min(len(lines), line_no + 10)
        context_lines = []
        for i in range(start, end):
            marker = " ← CRASH" if i + 1 == line_no else ""
            context_lines.append(f"{i + 1:5d}: {lines[i]}{marker}")
        return "\n".join(context_lines)
    except OSError:
        return ""


def _update_findings(run: PipelineRun, config: NemesisConfig | None = None) -> None:
    """
    Merge pipeline crashes into findings.yaml, run CVE analysis, and print report.

    Called after every successful pipeline run (even if no new crashes).
    """
    findings_path = Path("findings.yaml")
    findings = load_findings(findings_path)

    new_entries = 0
    # Track which func_names had their existing entry upgraded (better CWE / reproducibility)
    upgraded_funcs: set[str] = set()
    for result in run.results:
        if not result.crashes:
            continue
        before = len(findings)
        # Snapshot state of existing entries before merge to detect upgrades
        pre_merge_state = {
            str(f.get("function", "")).lower(): (f.get("cwe"), f.get("reproduces_in_app"))
            for f in findings
        }
        findings = merge_crash_reports(
            findings=findings,
            crashes=result.crashes,
            run_id=run.run_id,
            func_name=result.target.func_name,
            file_path=result.target.file_path,
            library=config.target.name if config else None,
        )
        new_entries += len(findings) - before
        # Detect upgrades: CWE changed from unknown OR reproduces_in_app became True
        fn_lower = result.target.func_name.lower()
        if fn_lower in pre_merge_state:
            old_cwe, old_repro = pre_merge_state[fn_lower]
            updated_entry = next(
                (f for f in findings if str(f.get("function", "")).lower() == fn_lower), None
            )
            if updated_entry:
                new_cwe = updated_entry.get("cwe")
                new_repro = updated_entry.get("reproduces_in_app")
                if (old_cwe != new_cwe) or (not old_repro and new_repro):
                    upgraded_funcs.add(fn_lower)

    save_findings(findings, findings_path)

    # -- CVE analysis for new or upgraded CVE-worthy crashes ----------------------------
    if config and (new_entries > 0 or upgraded_funcs):
        from nemesis.neural import NeuralStage

        log = get_logger("cli")
        neural = NeuralStage(config)
        library_name = config.target.name or "unknown"
        reports_dir = Path(config.engine.work_dir) / "reports"
        cve_reports_generated = 0

        for result in run.results:
            if not result.crashes:
                continue
            for crash in result.crashes:
                func_name = result.target.func_name
                # Skip patch-induced crashes
                if crash.patch_induced is True:
                    continue
                # Only process if this is a new entry or an upgraded entry
                fn_lower = func_name.lower()
                is_new = any(
                    f.get("function", "").lower() == fn_lower and f.get("run_id") == run.run_id
                    for f in findings
                )
                is_upgraded = fn_lower in upgraded_funcs
                if not is_new and not is_upgraded:
                    continue
                matching = [
                    f for f in findings
                    if f.get("function", "").lower() == func_name.lower()
                    and f.get("cve_worthy")
                ]
                if not matching:
                    continue
                finding = matching[0]

                # Skip if already assessed
                if finding.get("cve_assessment"):
                    continue

                # Extract source context around crash
                source_context = _extract_source_context(
                    config, result.target.file_path, crash.crash_location,
                )

                try:
                    console.print(
                        f"  [cyan]CVE analysis:[/cyan] {func_name} "
                        f"({crash.cwe.value})..."
                    )
                    assessment = neural.analyze_cve(
                        crash=crash,
                        library_name=library_name,
                        source_file=result.target.file_path,
                        source_context=source_context,
                    )

                    # Update finding with CVE assessment
                    findings = update_finding_with_cve(
                        findings, finding["id"], assessment,
                    )

                    # Generate and save CVE report
                    report_md = generate_cve_report(
                        finding, assessment, crash, source_context,
                    )
                    report_path = save_cve_report(
                        report_md, finding["id"], reports_dir,
                    )
                    cve_reports_generated += 1

                    status = "KNOWN" if assessment.is_known_cve else "NOVEL"
                    console.print(
                        f"    [{status}] CVSS {assessment.cvss_estimate:.1f} "
                        f"→ [cyan]{report_path}[/cyan]"
                    )
                except Exception as e:
                    log.warning(
                        "cve_analysis.failed",
                        func=func_name,
                        error=str(e),
                    )

        # Save updated findings with CVE data
        if cve_reports_generated > 0:
            save_findings(findings, findings_path)
            console.print(
                f"\n[bold green]CVE Analysis:[/bold green] generated "
                f"{cve_reports_generated} report(s) in [cyan]{reports_dir}[/cyan]"
            )

    if new_entries > 0:
        console.print(
            f"\n[bold green]Reporter:[/bold green] added {new_entries} new finding(s) "
            f"to [cyan]{findings_path.resolve()}[/cyan]"
        )
        # Print the markdown summary
        report_md = generate_report(findings)
        console.print(
            Panel(
                report_md,
                title="NEMESIS Findings Report",
                border_style="green",
            )
        )
    else:
        console.print(
            f"\n[dim]Reporter: findings.yaml up-to-date ({len(findings)} total) "
            f"— {findings_path.resolve()}[/dim]"
        )


# ── Entry point ─────────────────────────────────────────────

if __name__ == "__main__":
    cli()
