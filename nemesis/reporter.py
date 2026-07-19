"""
NEMESIS Bug Reporter — maintains findings.yaml from pipeline results.

Provides:
  load_findings()       — load existing findings.yaml
  merge_crash_reports() — merge new CrashReport objects into findings (dedup by function)
  save_findings()       — write back to YAML with clean formatting
  generate_report()     — produce a Markdown summary string
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from nemesis.logging import get_logger
from nemesis.models import AppReproStatus, CrashReport, CVEAssessment, SanitizerClass

# ── Constants ───────────────────────────────────────────────

FINDINGS_PATH = Path("findings.yaml")

_SEVERITY_BADGE = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "info": "[INFO]",
}

_STATUS_ICON = {
    "confirmed": "CONFIRMED",
    "potential": "POTENTIAL",
    "wontfix": "WONTFIX",
    "fixed": "FIXED",
}

# ── ID generation ────────────────────────────────────────────


def _next_id(findings: list[dict[str, Any]]) -> str:
    """Generate the next NEMESIS-YYYY-NNN id."""
    year = date.today().year
    prefix = f"NEMESIS-{year}-"
    existing = [
        f["id"]
        for f in findings
        if isinstance(f.get("id"), str) and f["id"].startswith(prefix)
    ]
    nums = []
    for eid in existing:
        m = re.search(r"-(\d+)$", eid)
        if m:
            nums.append(int(m.group(1)))
    next_num = (max(nums) + 1) if nums else 1
    return f"{prefix}{next_num:03d}"


# ── Public API ──────────────────────────────────────────────


def load_findings(path: str | Path = FINDINGS_PATH) -> list[dict[str, Any]]:
    """
    Load the findings database from YAML.

    Args:
        path: Path to findings.yaml (default: project-root findings.yaml)

    Returns:
        List of finding dicts. Empty list if file does not exist.
    """
    p = Path(path)
    if not p.exists():
        return []
    # Pin UTF-8: the file is written UTF-8 (see save_findings) and Nemesis deploys
    # on Linux; relying on the platform default made a Windows-authored file (cp1252)
    # unreadable on Linux. errors="replace" tolerates any legacy bytes.
    with open(p, encoding="utf-8", errors="replace") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("findings", [])


def _norm_location(loc: str) -> str:
    """Normalize a crash location string for dedup (strip whitespace)."""
    return (loc or "").strip()


def _crash_dedup_key(func_name: str, crash: CrashReport) -> tuple[str, str]:
    """Dedup key for a fresh crash: (function, crash_location).

    Falls back to (function, "cwe:<CWE>") when the crash has no parsed
    location, so distinct bug classes in the same function don't collapse.
    """
    loc = _norm_location(crash.crash_location)
    if loc:
        return (func_name.lower(), loc)
    return (func_name.lower(), f"cwe:{crash.cwe.value}")


def _finding_dedup_key(f: dict[str, Any]) -> tuple[str, str]:
    """Dedup key for an existing finding dict — mirrors _crash_dedup_key."""
    func = str(f.get("function", "")).lower()
    loc = _norm_location(str(f.get("crash_location", "")))
    if loc:
        return (func, loc)
    return (func, f"cwe:{f.get('cwe', 'CWE-unknown')}")


# Generic source-tree directory names that are NOT library names. The old
# fallback returned split("/")[0], which emitted "lib" for expat's
# "lib/xmlparse.c" and "src" for libsndfile's "src/sndfile.c" — junk that made
# findings unattributable. These are skipped when scanning path components.
_GENERIC_PATH_TOKENS = frozenset({
    "lib", "libs", "src", "srcs", "source", "sources", "include", "includes",
    "build", "build_debug", "build_fuzz", "obj", "out", "dist", "tmp",
    # Filesystem roots — absolute crash paths (/home/<user>/<lib>/…) must not
    # resolve to "home"/"usr"; skip these so the real library dir wins.
    "home", "users", "usr", "mnt", "opt", "var", "root",
})


def _derive_library(file_path: str, library: str | None) -> str:
    """Library name for a finding.

    Prefers the explicit ``library`` (from config ``target.name``). Falls back to
    the first *meaningful* path component — skipping generic directory names
    (lib/src/build/…) and drive letters — and, as a last resort, the crash
    file's stem. Never emits "lib", "src", or "unknown" when any real token is
    available, so findings stay attributable even when config.target.name is unset.
    """
    if library and library.strip().lower() not in _GENERIC_PATH_TOKENS:
        return library.strip()
    parts = [
        p for p in re.split(r"[\\/]", file_path)
        if p not in ("", ".", "..") and not re.fullmatch(r"[A-Za-z]:", p)  # drop drive letter
    ]
    if not parts:
        return "unknown"
    # Scan directory components nearest-to-file first: in
    # "/home/u/libtiff_clean/libtiff/tif.c" the library dir ("libtiff") sits
    # next to the file, while the leading segments are user/checkout noise.
    for p in reversed(parts[:-1]):
        if p.lower() not in _GENERIC_PATH_TOKENS:
            return p
    # Only generic dirs or a bare filename remain: use the filename stem rather
    # than "unknown" — a real token (e.g. "cjson" from "cJSON.c") beats junk.
    stem = re.split(r"\.", parts[-1])[0]
    return stem.lower() if stem else "unknown"


def merge_crash_reports(
    findings: list[dict[str, Any]],
    crashes: list[CrashReport],
    run_id: str,
    func_name: str,
    file_path: str,
    library: str | None = None,
) -> list[dict[str, Any]]:
    """
    Merge new CrashReport objects into the findings list.

    Deduplication rule: skip if a finding with the same (``function``,
    ``crash_location``) already exists (case-insensitive on function). Keying on
    function alone collapsed DISTINCT bugs in the same function (e.g. a heap
    overflow AND a separate UAF in the same parser) into one finding; keying on
    the crash site as well keeps them separate while still merging genuine
    re-discoveries of the same bug across runs.

    CVE-worthiness requires ALL of:
      - severity HIGH or MEDIUM (not LOW/INFO)
      - known CWE (not CWE-UNKNOWN)
      - patch_induced is not True  (False = real pre-existing bug, None = no patch = always real)

    Args:
        findings:  Existing findings list (from load_findings).
        crashes:   CrashReport objects produced by Stage 4.
        run_id:    Pipeline run ID string (e.g. "32d072ffd630").
        func_name: Name of the fuzzed function (used as the finding function).
        file_path: Source file path reported by the target CoverageTarget.

    Returns:
        Updated findings list (new entries appended).
    """
    log = get_logger("reporter")

    existing_by_key: dict[tuple[str, str], dict[str, Any]] = {
        _finding_dedup_key(f): f for f in findings
    }

    for crash in crashes:
        crash_key = _crash_dedup_key(func_name, crash)
        if crash_key in existing_by_key:
            # Same (function, crash-site) already recorded — try to upgrade it.
            existing = existing_by_key[crash_key]
            if existing:
                upgraded = False
                # Upgrade CWE if existing is unknown and new crash has a known CWE
                if (
                    existing.get("cwe", "CWE-unknown") in ("CWE-unknown", "CWE-UNKNOWN")
                    and crash.cwe.value not in ("CWE-unknown", "CWE-UNKNOWN")
                ):
                    existing["cwe"] = crash.cwe.value
                    existing["cwe_name"] = _cwe_name(crash.cwe.value)
                    existing["asan_error"] = _first_asan_line(crash.asan_output) or existing.get("asan_error", "")
                    existing["crash_location"] = crash.crash_location or existing.get("crash_location", "")
                    # Re-evaluate cve_worthy — any real (non-patch-induced) crash qualifies
                    not_patch_induced = existing.get("patch_induced") is not True
                    existing["cve_worthy"] = not_patch_induced
                    if existing["cve_worthy"] and existing.get("cve_status") == "n/a":
                        existing["cve_status"] = "requested"
                    upgraded = True
                    log.info("reporter.upgraded_cwe", func=func_name, cwe=crash.cwe.value, id=existing["id"])
                # Upgrade reproducibility if new crash reproduces in app
                if crash.reproduces_in_app and not existing.get("reproduces_in_app"):
                    existing["reproduces_in_app"] = True
                    existing["app_repro"] = crash.app_repro.value
                    existing["status"] = "confirmed"
                    upgraded = True
                    log.info("reporter.upgraded_reproduces", func=func_name, id=existing["id"])
                if not upgraded:
                    log.info(
                        "reporter.skip_duplicate",
                        func=func_name,
                        reason="function already in findings (no upgrade needed)",
                    )
            continue

        new_id = _next_id(findings)
        today = date.today().isoformat()

        # Build call_chain from stack_trace if available
        call_chain: list[str] = list(crash.stack_trace) if crash.stack_trace else []

        # CVE worthiness: any real crash is a CVE candidate — severity is determined
        # by the LLM CVE analysis (CVSS score), not pre-filtered here.
        not_patch_induced = crash.patch_induced is not True
        cve_worthy = not_patch_induced

        # Patch-induced verdict string
        if crash.patch_induced is True:
            patch_verdict = "patch-induced (false positive — LLM patch created the bug)"
            cve_status = "n/a"
        elif crash.patch_induced is False:
            patch_verdict = "real pre-existing bug (reproduces without patch)"
            cve_status = "requested" if cve_worthy else "n/a"
        else:
            patch_verdict = "no patch applied (directly reachable)"
            cve_status = "requested" if cve_worthy else "n/a"

        # Do NOT auto-request a CVE for a crash that was actually replayed against
        # the real application binary and did not reproduce there — that is the
        # artifact-suspect case (harness-induced false positive). NOT_TESTABLE
        # (no repro_binary, e.g. fuzz-target-only libs) is left untouched: it is
        # legitimately unverified, not disproven.
        if crash.app_repro == AppReproStatus.NOT_REPRODUCED and cve_status == "requested":
            cve_status = "n/a"
            cve_worthy = False
            patch_verdict += " — CVE request withheld: does not reproduce in app binary"

        # Auto-generate description from ASAN output + crash location
        description = _auto_description(crash, func_name)

        # Auto-generate reproduction steps
        reproduction = _build_reproduction(crash, func_name)

        entry: dict[str, Any] = {
            "id": new_id,
            "status": "confirmed" if crash.reproduces_in_app else "potential",
            "cve_worthy": cve_worthy,
            "cve_status": cve_status,
            "cve_id": None,
            "patch_induced": crash.patch_induced,
            "patch_verdict": patch_verdict,
            "discovered_date": today,
            "discovered_by": "AFL++ (NEMESIS automated)",
            "library": _derive_library(file_path, library),
            "file": file_path,
            "function": func_name,
            "line": int(crash.crash_location.split(":")[-1])
            if ":" in crash.crash_location
            else 0,
            "crash_location": crash.crash_location,
            "call_chain": call_chain,
            "cwe": crash.cwe.value,
            "cwe_name": _cwe_name(crash.cwe.value),
            "severity": crash.severity.value,
            "crash_type": _asan_to_signal(crash.asan_output),
            "asan_error": _first_asan_line(crash.asan_output),
            "description": description,
            "root_cause": crash.proposed_fix or "",
            "trigger": f"Malformed input reaching {func_name}() via AFL++ fuzzing",
            "reproduces_in_app": crash.reproduces_in_app,
            "app_repro": crash.app_repro.value,
            "minimized_input": crash.minimized_input,
            "upstream_status": crash.upstream_status,
            "upstream_detail": crash.upstream_detail,
            "reproduction": reproduction,
            "crash_files": [crash.input_file] if crash.input_file else [],
            "run_id": run_id,
            "detected_by": crash.detected_by.value,
            "reproduces_clean": crash.reproduces_clean,
            "reproduces_asan": crash.reproduces_asan,
            "reproduces_ubsan": crash.reproduces_ubsan,
            "pre_report_warnings": _pre_report_checks(crash),
            "notes": "",
        }

        findings.append(entry)
        existing_by_key[crash_key] = entry

        # Log pre-report warnings prominently so operator sees them
        warnings = entry["pre_report_warnings"]
        if warnings:
            for w in warnings:
                log.warning("reporter.pre_report_warning", id=new_id, warning=w)

        log.info(
            "reporter.new_finding",
            id=new_id,
            func=func_name,
            cwe=crash.cwe.value,
            severity=crash.severity.value,
            cve_worthy=cve_worthy,
            patch_induced=crash.patch_induced,
            detected_by=crash.detected_by.value,
        )

    return findings


def save_findings(
    findings: list[dict[str, Any]],
    path: str | Path = FINDINGS_PATH,
) -> None:
    """
    Write findings back to YAML.

    Args:
        findings: List of finding dicts.
        path:     Destination path (default: findings.yaml in cwd).
    """
    p = Path(path)
    data = {"findings": findings}

    # Use block style for readability; allow unicode; don't sort keys
    content = yaml.dump(
        data,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )
    header = (
        "# NEMESIS Bug Findings Database\n"
        "# Auto-updated by reporter.py after each pipeline run\n\n"
    )
    # Pin UTF-8 (yaml.dump emits unicode via allow_unicode=True); the platform
    # default would write cp1252 on Windows and break Linux readers.
    p.write_text(header + content, encoding="utf-8")

    log = get_logger("reporter")
    log.info("reporter.saved", path=str(p), count=len(findings))


def generate_report(findings: list[dict[str, Any]]) -> str:
    """
    Produce a Markdown findings report.

    Args:
        findings: List of finding dicts (from load_findings).

    Returns:
        Multi-line Markdown string ready for printing or writing.
    """
    today = date.today().isoformat()

    total = len(findings)
    cve_worthy = sum(1 for f in findings if f.get("cve_worthy"))
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    fixed = sum(1 for f in findings if f.get("status") == "fixed")

    lines: list[str] = [
        "# NEMESIS Findings Report",
        f"Generated: {today}",
        "",
        "## Summary",
        "| Total | CVE-worthy | Confirmed | Fixed |",
        "|-------|-----------|-----------|-------|",
        f"| {total}     | {cve_worthy}          | {confirmed}         | {fixed}     |",
        "",
        "## Findings",
        "",
    ]

    for f in findings:
        fid = f.get("id", "UNKNOWN")
        cwe = f.get("cwe", "CWE-unknown")
        cwe_name = f.get("cwe_name", "Unknown")
        severity = f.get("severity", "unknown").upper()
        status = f.get("status", "unknown")
        cve_worthy_flag = " CVE-worthy" if f.get("cve_worthy") else ""

        badge = _SEVERITY_BADGE.get(f.get("severity", ""), f"[{severity}]")
        status_label = _STATUS_ICON.get(status, status.upper())

        heading = (
            f"### {fid} — {cwe} {cwe_name} {badge}"
            + (" ⚠️" if f.get("cve_worthy") else "")
            + (f"{cve_worthy_flag}" if f.get("cve_worthy") else "")
        )
        lines.append(heading)
        lines.append("")

        # Metadata table
        lines.append(f"**Status:** {status_label}  ")
        # CVE verdict
        if f.get("cve_worthy"):
            cve_str = f.get("cve_id") or f"pending ({f.get('cve_status', 'n/a')})"
            lines.append(f"**CVE:** {cve_str}  ")
        patch_verdict = f.get("patch_verdict", "")
        if patch_verdict:
            icon = "✅" if "real pre-existing" in patch_verdict or "no patch" in patch_verdict else "❌"
            lines.append(f"**Verification:** {icon} {patch_verdict}  ")
        lines.append(f"**Library:** {f.get('library', 'unknown')}  ")
        lines.append(f"**File:** `{f.get('file', '')}`  ")
        lines.append(f"**Function:** `{f.get('function', '')}`")
        if f.get("crash_location"):
            lines.append(f" @ `{f['crash_location']}`  ")
        elif f.get("line"):
            lines.append(f" @ line {f['line']}  ")
        else:
            lines.append("  ")
        lines.append(f"**Discovered:** {f.get('discovered_date', 'unknown')} by {f.get('discovered_by', 'unknown')}  ")
        lines.append(f"**Crash type:** {f.get('crash_type', 'unknown')}  ")
        if f.get("asan_error"):
            lines.append(f"**ASAN:** `{f['asan_error']}`  ")
        lines.append("")

        if f.get("description"):
            lines.append("**Description:**")
            lines.append(f"> {f['description'].strip()}")
            lines.append("")

        if f.get("root_cause"):
            lines.append("**Root cause:**")
            lines.append(f"> {f['root_cause'].strip()}")
            lines.append("")

        if f.get("call_chain"):
            lines.append("**Call chain:**")
            for step in f["call_chain"]:
                lines.append(f"- `{step}`")
            lines.append("")

        repro = f.get("reproduction", {})
        if repro:
            lines.append("**Reproduction:**")
            if repro.get("direct"):
                lines.append(f"```bash\n{repro['direct']}\n```")
            if repro.get("bsdtar"):
                lines.append(f"```bash\n# Via bsdtar (real-world trigger)\n{repro['bsdtar']}\n```")
            if repro.get("note"):
                lines.append(f"> {repro['note']}")
            lines.append("")

        if f.get("crash_files"):
            lines.append("**Crash files:**")
            for cf in f["crash_files"]:
                lines.append(f"- `{cf}`")
            lines.append("")

        if f.get("notes"):
            lines.append(f"**Notes:** {f['notes']}")
            lines.append("")

        if f.get("run_id"):
            lines.append(f"**Run ID:** `{f['run_id']}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── CVE Report Generation ──────────────────────────────────


def generate_cve_report(
    finding: dict[str, Any],
    assessment: CVEAssessment,
    crash: CrashReport,
    source_context: str = "",
) -> str:
    """Generate a structured Markdown CVE report for a single finding."""
    fid = finding.get("id", "UNKNOWN")
    cwe = finding.get("cwe", "CWE-unknown")
    cwe_name_str = _cwe_name(cwe)
    severity = finding.get("severity", "unknown").upper()
    func = finding.get("function", "unknown")
    file_path = finding.get("file", "unknown")

    # CVE status
    if assessment.is_known_cve:
        cve_status = f"Known CVE: **{assessment.cve_id}** (confidence: {assessment.cve_confidence:.0%})"
    else:
        cve_status = f"Potentially novel vulnerability (confidence no known CVE match: {1 - assessment.cve_confidence:.0%})"

    lines = [
        f"# {fid} — {cwe} {cwe_name_str}",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Finding ID** | {fid} |",
        f"| **CWE** | {cwe} — {cwe_name_str} |",
        f"| **Severity** | {severity} |",
        f"| **CVSS Estimate** | {assessment.cvss_estimate:.1f} / 10.0 |",
        f"| **Function** | `{func}` |",
        f"| **File** | `{file_path}` |",
        f"| **Crash Location** | `{crash.crash_location}` |",
        f"| **Discovered** | {finding.get('discovered_date', 'unknown')} |",
        "",
        "## CVE Assessment",
        "",
        cve_status,
        "",
        f"**Rationale:** {assessment.rationale}",
        "",
    ]

    if assessment.affected_versions:
        lines.append(f"**Affected Versions:** {assessment.affected_versions}")
        lines.append("")

    if assessment.similar_cves:
        lines.append("**Similar CVEs:** " + ", ".join(assessment.similar_cves))
        lines.append("")

    lines.append("> **Disclaimer:** CVE matching is based on LLM analysis of crash signatures "
                 "against known vulnerability databases. Manual verification is required before "
                 "reporting to MITRE or the project maintainers.")
    lines.append("")

    # Root Cause
    lines.extend([
        "## Root Cause Analysis",
        "",
        assessment.root_cause_analysis or finding.get("root_cause", "Not analyzed."),
        "",
    ])

    # Reproduction
    repro = finding.get("reproduction", {})
    if repro:
        lines.extend([
            "## Reproduction",
            "",
        ])
        if repro.get("direct"):
            lines.append(f"```bash\n{repro['direct']}\n```")
        if repro.get("note"):
            lines.append(f"> {repro['note']}")
        lines.append("")

    # Stack Trace
    if crash.stack_trace:
        lines.extend([
            "## Stack Trace",
            "",
            "```",
        ])
        for frame in crash.stack_trace[:30]:
            lines.append(f"  {frame}")
        lines.extend(["```", ""])

    # ASAN Output
    if crash.asan_output:
        lines.extend([
            "## ASAN Output",
            "",
            "```",
            crash.asan_output[-2000:],
            "```",
            "",
        ])

    # Source Context
    if source_context:
        lines.extend([
            "## Source Context",
            "",
            "```c",
            source_context,
            "```",
            "",
        ])

    # Mitigation
    if assessment.suggested_mitigation:
        lines.extend([
            "## Suggested Mitigation",
            "",
            assessment.suggested_mitigation,
            "",
        ])

    lines.extend([
        "---",
        "*Generated by NEMESIS — Neuro-Symbolic Exploit Mining Engine*",
    ])

    return "\n".join(lines)


def save_cve_report(report_md: str, finding_id: str, reports_dir: str | Path = "") -> Path:
    """Save a CVE report to workspace/reports/{finding_id}.md."""
    if not reports_dir:
        reports_dir = Path("workspace/reports")
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_path = reports_dir / f"{finding_id}.md"
    report_path.write_text(report_md, encoding="utf-8")

    log = get_logger("reporter")
    log.info("cve_report.saved", path=str(report_path), finding=finding_id)
    return report_path


# ── Coordinated-disclosure package ───────────────────────────────────────────


def _hexdump(data: bytes, max_bytes: int = 512) -> str:
    """Classic offset/hex/ascii dump, capped at max_bytes (with a truncation note)."""
    shown = data[:max_bytes]
    lines = []
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes truncated)")
    return "\n".join(lines)


def load_reproducer(finding: dict[str, Any]) -> bytes | None:
    """Best-effort read of a finding's reproducer bytes.

    Prefers the minimized_input (small, curated) and falls back to the first raw
    crash_files entry. Returns None when neither is present/readable.
    """
    candidates: list[str] = []
    mi = finding.get("minimized_input")
    if mi:
        candidates.append(mi)
    candidates.extend(finding.get("crash_files") or [])
    for c in candidates:
        try:
            p = Path(c)
            if p.is_file():
                return p.read_bytes()
        except OSError:
            continue
    return None


def generate_disclosure_report(
    finding: dict[str, Any],
    patch_diff: str = "",
    reproducer: bytes | None = None,
    project_url: str = "",
) -> str:
    """Assemble a coordinated-disclosure report (Markdown) for one confirmed finding.

    Unlike generate_cve_report (MITRE-oriented), this targets the project maintainer:
    it embeds a minimized reproducer hexdump, the ASAN evidence, and — when supplied
    — a suggested source patch, in a GitHub-issue tone. ``patch_diff`` should be a
    verified unified diff (e.g. from a NeuralStage.generate_patch PatchProposal that
    passed build/Z3 verification); when empty it falls back to the finding's
    ``proposed_patch`` field, then to root-cause guidance.

    The reproducer is taken from ``reproducer`` if given, else auto-loaded from the
    finding's minimized_input/crash_files via load_reproducer().
    """
    lib = finding.get("library", "the library")
    func = finding.get("function", "unknown")
    cwe = finding.get("cwe", "CWE-unknown")
    cwe_name_str = _cwe_name(cwe)
    severity = str(finding.get("severity", "unknown")).upper()
    loc = finding.get("crash_location", "unknown")
    upstream_status = finding.get("upstream_status", "unknown")
    upstream_detail = finding.get("upstream_detail", "")

    if reproducer is None:
        reproducer = load_reproducer(finding)
    if not patch_diff:
        patch_diff = finding.get("proposed_patch", "") or ""

    title = f"# {lib}: {cwe_name_str} in `{func}()` via crafted input"
    lines: list[str] = [title, ""]

    # Upstream freshness banner — the reader needs to know this up front.
    if upstream_status == "up_to_date":
        lines.append(f"> Reproduces on the **latest upstream** code. {upstream_detail}".rstrip())
    elif upstream_status == "behind":
        lines.append(
            f"> ⚠️ The tested checkout is **behind upstream** ({upstream_detail}); the bug "
            "may already be fixed on the current default branch — please verify before triaging."
        )
    lines.append("")

    lines.extend([
        "## Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Library** | {lib} |",
        f"| **Weakness** | {cwe} — {cwe_name_str} |",
        f"| **Severity** | {severity} |",
        f"| **Crash site** | `{loc}` |",
        f"| **Reachable via** | `{func}()` on attacker-controlled input |",
        f"| **Upstream status** | {upstream_status} |",
    ])
    if project_url:
        lines.append(f"| **Project** | {project_url} |")
    lines.extend(["", "## Impact", ""])
    lines.append(
        f"A memory-safety violation ({cwe_name_str}) is triggered while processing a "
        f"malformed input through `{func}()`. Any application that feeds untrusted data to "
        f"this API is affected. Detected by ASAN during automated fuzzing."
    )
    lines.append("")

    # Root cause
    lines.extend([
        "## Root Cause",
        "",
        finding.get("root_cause") or finding.get("description") or "See stack trace below.",
        "",
    ])

    # Minimized reproducer
    lines.extend(["## Minimized Reproducer", ""])
    if reproducer is not None:
        lines.append(f"{len(reproducer)} bytes (delta-debug minimized):")
        lines.append("")
        lines.append("```")
        lines.append(_hexdump(reproducer))
        lines.append("```")
    else:
        lines.append("_Reproducer file not available in this environment._")
    lines.append("")

    # ASAN evidence + call chain
    if finding.get("asan_error"):
        lines.extend(["## Sanitizer Evidence", "", "```", str(finding["asan_error"]), "```", ""])
    call_chain = finding.get("call_chain") or []
    if call_chain:
        lines.extend(["## Call Chain", "", "```"])
        lines.extend(f"  {frame}" for frame in call_chain[:15])
        lines.extend(["```", ""])

    # Suggested fix
    lines.extend(["## Suggested Fix", ""])
    if patch_diff.strip():
        lines.append("Proposed patch (compile-verified):")
        lines.append("")
        lines.append("```diff")
        lines.append(patch_diff.strip())
        lines.append("```")
    else:
        lines.append(
            finding.get("root_cause")
            or "Add bounds/length validation before the flagged access (see Root Cause)."
        )
        lines.append("")
        lines.append("_No auto-generated patch attached; the root cause above indicates the fix._")
    lines.append("")

    lines.extend([
        "## Disclosure",
        "",
        "Reported under coordinated disclosure: please acknowledge and, once a fix is "
        "available, we can request a CVE if warranted. Reproducer and full ASAN log "
        "available on request.",
        "",
        "---",
        "*Generated by NEMESIS — Neuro-Symbolic Exploit Mining Engine*",
    ])

    return "\n".join(lines)


def save_disclosure_report(report_md: str, finding_id: str, reports_dir: str | Path = "") -> Path:
    """Save a coordinated-disclosure report to workspace/reports/disclosure/{finding_id}.md."""
    if not reports_dir:
        reports_dir = Path("workspace/reports/disclosure")
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_path = reports_dir / f"{finding_id}.md"
    report_path.write_text(report_md, encoding="utf-8")

    log = get_logger("reporter")
    log.info("disclosure_report.saved", path=str(report_path), finding=finding_id)
    return report_path


def update_finding_with_cve(
    findings: list[dict[str, Any]],
    finding_id: str,
    assessment: CVEAssessment,
) -> list[dict[str, Any]]:
    """Update a finding entry with CVE assessment data."""
    for f in findings:
        if f.get("id") == finding_id:
            f["cve_status"] = "known_cve" if assessment.is_known_cve else "potentially_novel"
            if assessment.is_known_cve:
                f["cve_id"] = assessment.cve_id
            f["root_cause"] = assessment.root_cause_analysis or f.get("root_cause", "")
            f["cvss_estimate"] = assessment.cvss_estimate
            f["cve_assessment"] = {
                "is_known_cve": assessment.is_known_cve,
                "cve_id": assessment.cve_id,
                "cve_confidence": assessment.cve_confidence,
                "rationale": assessment.rationale,
                "cvss_estimate": assessment.cvss_estimate,
                "similar_cves": assessment.similar_cves,
                "suggested_mitigation": assessment.suggested_mitigation,
            }
            break
    return findings


# ── Helpers ─────────────────────────────────────────────────


def _cwe_name(cwe: str) -> str:
    """Map CWE id string to a short human-readable name."""
    mapping = {
        "CWE-476": "NULL Pointer Dereference",
        "CWE-122": "Heap-based Buffer Overflow",
        "CWE-121": "Stack-based Buffer Overflow",
        "CWE-416": "Use After Free",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-125": "Out-of-bounds Read",
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-789": "Uncontrolled Memory Allocation",
        "CWE-787": "Out-of-bounds Write",
        "CWE-770": "Uncontrolled Resource Consumption",
        "CWE-415": "Double Free",
        "CWE-758": "Undefined Behavior",
        "CWE-UNKNOWN": "Unknown Weakness",
    }
    return mapping.get(cwe, "Unknown Weakness")


def _asan_to_signal(asan_output: str) -> str:
    """Derive crash signal from ASAN output string."""
    lo = asan_output.lower()
    if "segv" in lo or "null" in lo:
        return "SIGSEGV"
    if "abort" in lo or "heap-buffer-overflow" in lo or "stack-buffer-overflow" in lo:
        return "SIGABRT"
    if "use-after-free" in lo:
        return "SIGABRT"
    return "UNKNOWN"


def _first_asan_line(asan_output: str) -> str:
    """Return the first meaningful ASAN summary line."""
    for line in asan_output.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("="):
            return stripped[:120]
    return asan_output[:120] if asan_output else ""


def _auto_description(crash: CrashReport, func_name: str) -> str:
    """
    Generate a human-readable description from ASAN output + crash metadata.

    Produces a 2-3 sentence summary: what crashed, where, and what the
    ASAN error type indicates about exploitability.
    """
    asan = crash.asan_output.lower()
    loc = crash.crash_location or func_name

    # Determine crash class — UBSan-specific patterns checked first
    if "runtime error:" in asan:
        crash_class = "undefined behavior"
        impact = (
            "Detected by UBSan. Does not crash in a standard (non-sanitizer) build, "
            "but constitutes a C standard violation that may become exploitable under "
            "aggressive compiler optimizations."
        )
    elif "heap-buffer-overflow" in asan:
        crash_class = "heap-based buffer overflow"
        impact = "Depending on input control, this may be exploitable for code execution."
    elif "stack-buffer-overflow" in asan:
        crash_class = "stack-based buffer overflow"
        impact = "Stack-based overflows on writable stacks can allow code execution."
    elif "use-after-free" in asan:
        crash_class = "use-after-free"
        impact = "UAF bugs can be exploitable for code execution or information disclosure."
    elif "null" in asan or "segv" in asan or "unknown address 0x0" in asan:
        crash_class = "NULL pointer dereference"
        impact = "Typically a denial-of-service (process crash) when parsing malformed input."
    elif "out of memory" in asan or "allocator" in asan:
        crash_class = "uncontrolled memory allocation (OOM)"
        impact = "Results in process abort via allocator; in production calloc may return NULL (handled). DoS only."
    elif "integer-overflow" in asan or "signed-integer-overflow" in asan:
        crash_class = "integer overflow"
        impact = "Integer overflows in size calculations can lead to incorrect allocation sizes."
    else:
        crash_class = "memory safety violation"
        impact = "Exact exploitability depends on crash context."

    # Build location string
    if crash.stack_trace:
        top_frame = crash.stack_trace[0] if crash.stack_trace else loc
        location_str = f"in {top_frame}"
    else:
        location_str = f"at {loc}"

    # Dynamic sanitizer name based on detected_by
    _SANITIZER_NAMES = {
        "asan": "AddressSanitizer (ASAN)",
        "ubsan": "UndefinedBehaviorSanitizer (UBSan)",
        "msan": "MemorySanitizer (MSan)",
        "signal": "signal-based crash detection",
    }
    sanitizer_name = _SANITIZER_NAMES.get(
        crash.detected_by.value, "sanitizer instrumentation"
    )

    # Multi-build confidence qualifier
    confidence = ""
    if crash.reproduces_clean is True and crash.reproduces_asan is True:
        confidence = " Crashes in all build configurations (high confidence)."
    elif crash.reproduces_clean is False and crash.reproduces_asan is True:
        confidence = " Detected by sanitizers; does not crash in a standard build."
    elif crash.reproduces_ubsan is True and crash.reproduces_asan is not True:
        confidence = (
            " Undefined behavior detected by UBSan only; does not crash in "
            "standard or ASAN builds."
        )

    return (
        f"AFL++ triggered a {crash_class} {location_str} when parsing a malformed input file. "
        f"The crash was detected by {sanitizer_name} and confirmed by reproduction."
        f"{confidence} {impact}"
    )


def _build_reproduction(crash: CrashReport, func_name: str) -> dict[str, str]:
    """
    Generate reproduction commands for a crash.

    Returns a dict with:
      direct  — run the NEMESIS fuzzer binary directly with the crash file
      bsdtar  — reproduce via the real bsdtar application (if applicable)
      note    — any caveats
    """
    crash_file = crash.input_file or "<crash_file>"
    asan_env = "ASAN_OPTIONS=abort_on_error=0:detect_leaks=0"

    # Sanitizer-specific reproduction environment
    if crash.detected_by.value == "ubsan":
        sanitizer_note = " (UBSan-only finding — requires -fsanitize=undefined to trigger)"
    elif crash.detected_by.value == "msan":
        sanitizer_note = " (MSan finding — requires -fsanitize=memory to trigger)"
    else:
        sanitizer_note = ""

    repro: dict[str, str] = {
        "direct": f"{asan_env} ./build_fuzz/fuzz_nemesis < {crash_file}",
        "bsdtar": f"{asan_env} bsdtar -xOf {crash_file} 2>&1 | head -30",
        "note": (
            "Build fuzz_nemesis with: "
            "CC=afl-clang-fast cmake .. -DCMAKE_C_COMPILER=afl-clang-fast && make -j$(nproc)"
            + sanitizer_note
        ),
    }

    # Patch-induced crashes can't be reproduced on unpatched source
    if crash.patch_induced is True:
        repro["note"] = (
            "WARNING: patch-induced crash — only reproduces with LLM patch applied. "
            "Does NOT reproduce on unpatched source. Not a CVE candidate."
        )
    elif crash.patch_induced is False:
        repro["note"] = (
            "Reproduces on UNPATCHED source (no LLM patch needed). "
            "Build unpatched: git stash && mkdir build_debug && cd build_debug && "
            "CC=clang cmake .. -DCMAKE_C_FLAGS='-g -O1 -fsanitize=address,undefined' && "
            "make -j$(nproc) archive && git stash pop"
        )

    return repro


def _pre_report_checks(crash: CrashReport) -> list[str]:
    """Return list of warnings about a finding's quality.

    Logged prominently so the operator sees them before any GitHub issue is filed.
    """
    warnings: list[str] = []
    if crash.detected_by == SanitizerClass.UBSAN and not crash.reproduces_clean:
        warnings.append("UBSan-only: does not crash in a standard build")
    if crash.detected_by == SanitizerClass.UNKNOWN:
        warnings.append("Sanitizer class not determined")
    if not crash.reproduces_in_app:
        warnings.append("Not reproduced in application binary")
    if crash.reproduces_clean is False and crash.reproduces_asan is False:
        warnings.append("Does not reproduce in any standalone build")
    return warnings
