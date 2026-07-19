"""
NEMESIS daemon — background scheduler for automated scanning.

Runs scans on a configurable schedule (cron-style), rotates through
configured libraries, and sends notifications on findings.

Usage (via CLI):
    nemesis daemon --schedule "0 2 * * *"   # nightly at 02:00
    nemesis daemon --interval 6             # every 6 hours
    nemesis daemon --once                   # run once and exit
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from nemesis.logging import get_logger


class NemesisDaemon:
    """Background scan scheduler."""

    def __init__(
        self,
        targets: list[str],
        scan: bool = True,
        max_targets: int = 10,
        strategy: str = "harness",
        webhook_url: str = "",
        workspace: str = "workspace",
    ) -> None:
        self.targets = targets
        self.scan = scan
        self.max_targets = max_targets
        self.strategy = strategy
        self.webhook_url = webhook_url
        self.workspace = Path(workspace)
        self.log = get_logger("daemon")
        self._running = True

        # Handle SIGTERM/SIGINT gracefully
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, frame) -> None:
        self.log.info("daemon.signal", signal=signum)
        self._running = False

    def run_once(self) -> dict[str, str]:
        """Run one complete scan cycle across all targets."""
        results: dict[str, str] = {}
        self.log.info("daemon.cycle_start", targets=self.targets)

        for target in self.targets:
            if not self._running:
                break

            self.log.info("daemon.target_start", target=target)
            start = time.monotonic()

            cmd = [
                sys.executable, "-m", "nemesis.cli", "run",
                "-t", target,
                "--max-targets", str(self.max_targets),
                "--strategy", self.strategy,
                "--resume",
            ]
            if self.scan:
                cmd.append("--scan")

            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=7200,  # 2h hard timeout per library
                )
                elapsed = time.monotonic() - start
                if proc.returncode == 0:
                    results[target] = "success"
                    self.log.info(
                        "daemon.target_ok",
                        target=target,
                        duration_min=round(elapsed / 60, 1),
                    )
                else:
                    results[target] = f"failed (rc={proc.returncode})"
                    self.log.error(
                        "daemon.target_failed",
                        target=target,
                        stderr=proc.stderr[-500:] if proc.stderr else "",
                    )
            except subprocess.TimeoutExpired:
                results[target] = "timeout"
                self.log.error("daemon.target_timeout", target=target)
            except Exception as exc:
                results[target] = f"error: {exc}"
                self.log.error("daemon.target_error", target=target, error=str(exc))

        # Check for new findings
        self._check_and_notify(results)

        self.log.info("daemon.cycle_done", results=results)
        return results

    def run_interval(self, hours: float) -> None:
        """Run scan cycles at fixed intervals."""
        interval_s = hours * 3600
        self.log.info("daemon.start_interval", hours=hours, targets=self.targets)

        while self._running:
            self.run_once()
            if not self._running:
                break
            self.log.info("daemon.sleeping", next_in_hours=hours)
            # Sleep in small increments so we can respond to signals
            sleep_until = time.monotonic() + interval_s
            while time.monotonic() < sleep_until and self._running:
                time.sleep(min(30, sleep_until - time.monotonic()))

        self.log.info("daemon.stopped")

    def run_cron(self, cron_expr: str) -> None:
        """Run scan cycles on a cron schedule.

        Simplified cron: only supports "H M * * *" (hour:minute daily).
        For full cron support, use an external scheduler (systemd timer, crontab).
        """
        parts = cron_expr.strip().split()
        if len(parts) < 2:
            self.log.error("daemon.invalid_cron", expr=cron_expr)
            return

        try:
            target_minute = int(parts[0])
            target_hour = int(parts[1])
        except ValueError:
            self.log.error("daemon.invalid_cron", expr=cron_expr)
            return

        self.log.info("daemon.start_cron", schedule=cron_expr, targets=self.targets)

        while self._running:
            now = datetime.now()
            # Calculate next run time
            next_run = now.replace(
                hour=target_hour, minute=target_minute, second=0, microsecond=0,
            )
            if next_run <= now:
                # Already past today's time, schedule for tomorrow
                from datetime import timedelta
                next_run += timedelta(days=1)

            wait_s = (next_run - now).total_seconds()
            self.log.info("daemon.next_run", at=next_run.isoformat(), wait_hours=round(wait_s / 3600, 1))

            # Wait until next run
            sleep_until = time.monotonic() + wait_s
            while time.monotonic() < sleep_until and self._running:
                time.sleep(min(60, sleep_until - time.monotonic()))

            if self._running:
                self.run_once()

        self.log.info("daemon.stopped")

    def _check_and_notify(self, cycle_results: dict[str, str]) -> None:
        """Check for new findings and send webhook notification."""
        if not self.webhook_url:
            return

        findings_path = Path("findings.yaml")
        if not findings_path.exists():
            return

        try:
            from nemesis.reporter import load_findings
            findings = load_findings(findings_path)
            # Count today's findings
            today = datetime.now().strftime("%Y-%m-%d")
            new_today = [f for f in findings if f.get("discovered_date") == today]
            if not new_today:
                return

            # Send webhook
            payload = {
                "text": (
                    f"NEMESIS: {len(new_today)} new finding(s) today\n"
                    f"Targets: {', '.join(cycle_results.keys())}\n"
                    f"Results: {json.dumps(cycle_results)}"
                ),
            }
            import httpx
            httpx.post(self.webhook_url, json=payload, timeout=10)
            self.log.info("daemon.webhook_sent", findings=len(new_today))
        except Exception as exc:
            self.log.warning("daemon.webhook_failed", error=str(exc))
