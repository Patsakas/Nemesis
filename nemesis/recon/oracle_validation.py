"""Cross-config validation for the Targeted Oracle Expansion (Fix 148-150).

Background:
  Fix 148 (differential_reference), Fix 149 (MSan profile), and Fix 150 (TSan
  profile + threaded_oracle) introduced configuration combinations that are
  individually valid but jointly nonsensical — e.g. selecting `sanitizer_profile:
  tsan` without any `threaded_oracle: true` pinned function. The hard gates
  in `_resolve_sanitizer_flags` already block known-broken cases (raise
  ValueError). This module catches the SOFT cases that produce a wasted run
  rather than a hard failure.

  Each check returns a structured warning. The pipeline logs them at
  startup so the user sees the misconfiguration before AFL spends an hour
  finding nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nemesis.config import NemesisConfig


@dataclass(frozen=True)
class OracleWarning:
    """A non-fatal cross-config issue with one of the oracle modes."""
    key: str            # short stable identifier for the log event
    message: str        # human-readable description
    suggestion: str     # how to fix it


def _pinned_funcs(config: NemesisConfig) -> list:
    return list(getattr(config.target, "pinned_funcs", None) or [])


def _check_tsan_profile_without_threaded_oracle(config: NemesisConfig) -> list[OracleWarning]:
    profile = (getattr(config.target, "sanitizer_profile", "") or "").strip()
    if profile != "tsan":
        return []
    threaded_pins = [pf for pf in _pinned_funcs(config)
                     if getattr(pf, "threaded_oracle", False)]
    if threaded_pins:
        return []
    return [OracleWarning(
        key="tsan_without_threaded_oracle",
        message=(
            "sanitizer_profile='tsan' is set but no pinned_func has "
            "threaded_oracle=true. TSan can only report races when the harness "
            "drives the target from multiple threads — the run will produce "
            "ASAN-equivalent coverage at worse throughput and find no races."
        ),
        suggestion=(
            "Either set `threaded_oracle: true` on at least one pinned_func, "
            "or revert sanitizer_profile to the default `asan_ubsan`."
        ),
    )]


def _check_threaded_oracle_without_tsan(config: NemesisConfig) -> list[OracleWarning]:
    profile = (getattr(config.target, "sanitizer_profile", "") or "asan_ubsan").strip()
    if profile == "tsan":
        return []
    threaded_pins = [pf for pf in _pinned_funcs(config)
                     if getattr(pf, "threaded_oracle", False)]
    if not threaded_pins:
        return []
    names = ", ".join(pf.func_name for pf in threaded_pins[:3])
    if len(threaded_pins) > 3:
        names += f", … (+{len(threaded_pins) - 3} more)"
    return [OracleWarning(
        key="threaded_oracle_without_tsan",
        message=(
            f"threaded_oracle=true is set on {len(threaded_pins)} pinned_func(s) "
            f"({names}) but sanitizer_profile is '{profile}', not 'tsan'. The "
            "multi-threaded harness will run but only deadlocks (via AFL hang "
            "timeout) and memory-safety races will be detected — true data races "
            "stay silent without TSan."
        ),
        suggestion=(
            "Run a parallel TSan instance: copy the target YAML, set "
            "sanitizer_profile: tsan and tsan_supported: true, and launch as a "
            "separate `nemesis run -t <target>_tsan` campaign."
        ),
    )]


def _check_differential_reference_visible(config: NemesisConfig) -> list[OracleWarning]:
    """Best-effort: warn if differential_reference symbol is not findable in source."""
    refs = [(pf.func_name, getattr(pf, "differential_reference", "") or "")
            for pf in _pinned_funcs(config)]
    refs = [(fn, ref) for (fn, ref) in refs if ref.strip()]
    if not refs:
        return []
    source_root = getattr(config.target, "source_root", None)
    if not source_root or not Path(source_root).exists():
        return []
    warnings: list[OracleWarning] = []
    for fn, ref in refs:
        bare = ref.split("::")[-1].strip()
        if not bare or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", bare):
            continue
        if not _symbol_appears_in_tree(Path(source_root), bare):
            warnings.append(OracleWarning(
                key="differential_reference_not_found",
                message=(
                    f"pinned_func '{fn}' references differential_reference='{ref}' "
                    f"but the symbol '{bare}' does not appear in the source tree "
                    f"at {source_root}. The harness build will likely fail with "
                    "an undefined reference."
                ),
                suggestion=(
                    "Verify the reference impl name. If it lives in another "
                    "library, ensure that library's headers are in harness_includes "
                    "and its lib is in link_libs."
                ),
            ))
    return warnings


def _symbol_appears_in_tree(root: Path, symbol: str) -> bool:
    """Quick grep: does any .c/.h file mention this identifier?

    Best-effort, not exhaustive. Bounded by file count and per-file size to
    keep startup cost trivial; on miss we fall through to "not found", which
    is the worst case (false-positive warning, not a hard error).
    """
    pat = re.compile(rf"\b{re.escape(symbol)}\b")
    files_scanned = 0
    for path in root.rglob("*.[ch]"):
        if files_scanned >= 2000:
            return False  # gave up — symbol may exist past our scan budget
        files_scanned += 1
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if pat.search(text):
            return True
    return False


_CHECKS = (
    _check_tsan_profile_without_threaded_oracle,
    _check_threaded_oracle_without_tsan,
    _check_differential_reference_visible,
)


def validate_oracle_config(config: NemesisConfig) -> list[OracleWarning]:
    """Run every cross-config oracle check and collect non-fatal warnings.

    Hard failures (msan/tsan profile without _supported flag) are raised by
    `_resolve_sanitizer_flags` at build time. This function only reports
    misconfigurations the user should know about before launching a run.
    """
    out: list[OracleWarning] = []
    for check in _CHECKS:
        out.extend(check(config))
    return out
