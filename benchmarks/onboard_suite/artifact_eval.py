"""H2b evaluator — is the selected archive the one that can satisfy the link?

Deliberately mechanical. The classification is a membership test over `nm` output and
nothing else:

    required symbols  ->  nm -g --defined-only  ->  set membership  ->  class

There is no fuzzy matching, no demangling heuristic, no alias inference and no symbol
normalisation. Every one of those would move judgement out of the pre-registered rule
and into the instrument, and the instrument would then be part of what it measures.

This lives in the benchmark rather than in `nemesis/` on purpose: it is the measurement,
and the measurement must not sit inside the system under test. It also never imports the
oracle — ownership is the operator's input, symbol containment is the evaluator's, and
H2b_PLAN.md §4 forbids either from borrowing the other.

Classification (H2b_PLAN.md §5.1), fixed before the run:

    satisfied     selected archive defines every required symbol   -> correct
    partial       defines some but not all                         -> INCORRECT
    unsatisfied   defines none                                     -> INCORRECT
    no_resolution resolver returned no path                        -> not a selection error
    no_candidate  no archive in the tree satisfies the requirement  -> not a selection error
    undetermined  required-symbol set unavailable                  -> excluded, never success
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

NEMESIS_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(NEMESIS_ROOT))

from nemesis.library_resolver import LibraryResolver  # noqa: E402

# The onboarder's harness template ships this literal as a placeholder. It is not a
# symbol, and treating it as one would silently inflate the sample.
PLACEHOLDER = "function_name"
_TARGET_FUNC = re.compile(r'"target_func"\s*:\s*"(\w+)"')
# `nm` prints "<addr> <type> <name>"; --defined-only already removes undefined entries.
_NM_LINE = re.compile(r"^[0-9a-fA-F]*\s+([A-Za-z])\s+(\S+)$")


@dataclass
class Trace:
    """Everything needed to explain one resolution without reproducing the run."""
    project: str
    requested_library: str = ""
    resolver_candidate: str = ""        # what name-based resolution selected
    resolver_strategy: str = ""
    identity_verdict: str = ""          # unchanged | identity_ownership | n/a
    final_selected_archive: str = ""
    evaluation_class: str = ""
    required_symbols: list[str] = field(default_factory=list)
    required_source: str = ""           # pinned_target_func | undetermined
    missing_symbols: list[str] = field(default_factory=list)
    satisfying_archives: list[str] = field(default_factory=list)


def required_symbols(config_text: str) -> tuple[set[str], str]:
    """Route 1 only: the concretely pinned target function in the frozen config.

    Route 2 (declarations parsed from `harness_includes` headers) is NOT implemented
    here. It is unvalidated, and an unvalidated extraction would enlarge the sample
    without enlarging the evidence — H2b_PLAN.md §5 reports n=2 rather than doing that.
    """
    found = {s for s in _TARGET_FUNC.findall(config_text) if s and s != PLACEHOLDER}
    return (found, "pinned_target_func") if found else (set(), "undetermined")


def defined_symbols(archive: Path) -> set[str]:
    """Symbols an archive defines, verbatim. Exact strings, no transformation."""
    try:
        out = subprocess.run(["nm", "-g", "--defined-only", str(archive)],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return set()
    return {m.group(2) for line in out.stdout.splitlines()
            if (m := _NM_LINE.match(line.strip()))}


def archives(build_dir: Path) -> list[Path]:
    return sorted(p for ext in ("*.a", "*.so", "*.dylib")
                  for p in build_dir.rglob(ext) if p.is_file())


def classify(selected: Path | None, required: set[str],
             build_dir: Path) -> tuple[str, list[str], list[str]]:
    """→ (class, missing symbols, archives that would have satisfied the requirement)."""
    if not required:
        return "undetermined", [], []
    satisfying = [str(a.relative_to(build_dir)) for a in archives(build_dir)
                  if required <= defined_symbols(a)]
    if selected is None:
        return "no_resolution", sorted(required), satisfying
    have = defined_symbols(selected)
    missing = sorted(required - have)
    if not missing:
        return "satisfied", [], satisfying
    if not satisfying:
        # Nothing in the tree could have satisfied it: not a selection error.
        return "no_candidate", missing, satisfying
    return ("partial" if have & required else "unsatisfied"), missing, satisfying


def evaluate(project: str, identity_aware: bool) -> Trace:
    cfg_path = NEMESIS_ROOT / "config" / "targets" / f"{project}.yaml"
    text = cfg_path.read_text(errors="ignore")
    doc = yaml.safe_load(text) or {}
    target = doc.get("target") or {}
    build_dir = Path(os.path.expanduser(os.path.expandvars(target.get("build_dir", ""))))
    name = target.get("library_name", "")

    t = Trace(project=project, requested_library=name)
    req, source = required_symbols(text)
    t.required_symbols, t.required_source = sorted(req), source

    base = LibraryResolver(source_subdir=target.get("source_subdir", "")).resolve(
        build_dir, name)
    t.resolver_candidate = str(base.path) if base.path else ""
    t.resolver_strategy = base.strategy

    res = base
    if identity_aware:
        res = LibraryResolver(source_subdir=target.get("source_subdir", ""),
                              identity_aware=True).resolve(build_dir, name)
        t.identity_verdict = ("identity_ownership" if res.strategy == "identity_ownership"
                              else "unchanged")
    else:
        t.identity_verdict = "n/a"

    t.final_selected_archive = str(res.path) if res.path else ""
    if not build_dir.is_dir():
        t.evaluation_class = "no_build_dir"
        return t
    cls, missing, satisfying = classify(res.path, req, build_dir)
    t.evaluation_class, t.missing_symbols, t.satisfying_archives = cls, missing, satisfying
    return t


def main() -> None:
    projects = sys.argv[1:] or ["astera", "onomondo_uicc", "bcg729", "gensio",
                                "tiny_AES_c", "pg_ivm", "libdc"]
    out = {"control": {}, "h2b": {}}
    for project in projects:
        for arm, flag in (("control", False), ("h2b", True)):
            out[arm][project] = asdict(evaluate(project, flag))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
