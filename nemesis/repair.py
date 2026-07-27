"""H2a — build-target inference & validation (deterministic repair operator).

Motivated and shaped by the H2a validation probe (see H2_PLAN.md). The onboarder
guesses a specific build target — a bare name, or `-C subdir artifact` — that is
frequently wrong (`tiny_AES_c` instead of the real CMake target), bypasses the
build graph (`-C glib` before its parent `lib/` is built), or names a library the
project does not produce at all (`libgifsicle.la` — gifsicle is an application).

**v1 (frozen — see H2a_RESULTS.md) replaced every specific target with the default
build.** That validated the hypothesis (4 genuine recoveries, 1 false success
caught) but was falsified as a policy: it regressed two repos whose target was
already correct. v2 therefore decides *whether* a target deserves replacement
before replacing it. The requirement is evidence-derived, not a preference.

The validity predicate (H2a_V2_DESIGN.md) is evaluated in two phases, because its
last conjunct is only observable after a build:

    valid_target :=  declared
                   ∧ belongs_to_project_build_graph      ← Phase 0, static
                   ∧ produces_non_vendored_project_artifact   ← Phase 2, post-build

  Phase 0 — target validation (v2). Static, deterministic: is the configured
  target declared by *this project's* build files, and is it reached through the
  project's own build graph? A declared target is not automatically a valid one —
  astera's `glfw` is a perfectly valid CMake target belonging to a *vendored
  dependency* (H2a_astera_audit.md).

  Phase 1 — target correction. Only for targets Phase 0 rejects: fall back to the
  build system's **default** build, which respects dependency ordering. The default
  is derived from the build system actually in use — substituting `make` into a
  meson/ninja build directory is what broke pg_ivm in v1.

  Phase 2 — genuine-target oracle (unchanged from v1). Build success is NECESSARY
  but INSUFFICIENT: the produced artifact must be a real project library — not an
  application with no library (gifsicle), not a vendored dependency (astera).

Design constraint (H2_PLAN repair-independence): few deterministic rules, a recorded
repair trace, an explicit reason on every decision — so results can say not only
"H2a raised genuine T2 by X" but "and prevented Y false successes", each attributable.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from nemesis.logging import get_logger

log = get_logger("repair")

# Subtrees whose build artifacts are third-party, never the project's own target.
_VENDOR_DIRS = frozenset({
    "dep", "deps", "third_party", "thirdparty", "vendor", "external", "contrib",
    "3rdparty", "subprojects", "extern",
})


@dataclass
class RepairRecord:
    """One repair decision, recorded for the trace (H2_PLAN)."""
    operator: str = "H2a"
    action: str = ""            # replace_invalid_target | keep_target | genuine_target_oracle
    before: str = ""
    after: str = ""
    build_exit: int | None = None
    oracle: str = "n/a"         # accept | reject | n/a
    reason: str = ""
    artifact: str = ""

    def as_dict(self) -> dict:
        return {
            "operator": self.operator, "action": self.action,
            "before": self.before, "after": self.after,
            "build_exit": self.build_exit, "oracle": self.oracle,
            "reason": self.reason, "artifact": self.artifact,
        }


# ── Build-command parsing ───────────────────────────────────
# Default build command per build system. v1 hardcoded `make`, which is invalid in a
# meson/ninja build directory (pg_ivm regression).
_DEFAULT_BUILD = {"make": "make -j$(nproc)", "ninja": "ninja"}
_DEFAULT_MAKE = _DEFAULT_BUILD["make"]          # kept: v1 name, used by callers/tests

# Options whose value is a separate token, so the value is not a target name.
_OPTS_WITH_ARG = frozenset({"-C", "-f", "-o", "-W", "-I", "--directory", "--file"})
_SEGMENT_SPLIT = re.compile(r"\|\||&&|;")


@dataclass
class ParsedBuild:
    """What a build command actually asks for. Deterministic token scan — the shell
    is not invoked and build files are not parsed here."""
    build_system: str = "unknown"   # make | ninja | unknown
    target: str = ""                # positional target of the first segment ("" = default)
    subdir: str = ""                # -C value ("" = none)
    segments: int = 0               # recognised build invocations in the command
    has_default_segment: bool = False   # some segment is a bare default build


def _parse_segment(seg: str) -> tuple[str, str, str] | None:
    """→ (build_system, target, subdir) for one shell segment, or None if the
    segment is not a recognised build invocation (e.g. `/bin/true`, `cd x`)."""
    toks = seg.split()
    if not toks:
        return None
    prog = os.path.basename(toks[0])
    if prog not in _DEFAULT_BUILD:
        return None

    target, subdir, i = "", "", 1
    while i < len(toks):
        t = toks[i]
        if t in _OPTS_WITH_ARG:
            if i + 1 < len(toks):
                if t in ("-C", "--directory"):
                    subdir = toks[i + 1]
                i += 1
        elif t.startswith("--directory="):
            subdir = t.split("=", 1)[1]
        elif t.startswith("-C") and len(t) > 2:
            subdir = t[2:]
        elif t == "-j" and i + 1 < len(toks) and toks[i + 1].isdigit():
            i += 1                          # `-j 4` — the count is not a target
        elif t.startswith("-"):
            pass
        elif "=" in t:
            pass                            # VAR=value overrides are not targets
        elif not target:
            target = t
        i += 1
    return prog, target, subdir


def parse_build_command(cmd: str) -> ParsedBuild:
    """Parse a (possibly compound) build command. `a || b` matters: pg_ivm's
    `ninja libpg_ivm.a || ninja` already falls back to the default build itself."""
    out = ParsedBuild()
    for seg in _SEGMENT_SPLIT.split(cmd or ""):
        parsed = _parse_segment(seg)
        if parsed is None:
            continue
        bs, target, subdir = parsed
        if out.segments == 0:
            out.build_system, out.target, out.subdir = bs, target, subdir
        out.segments += 1
        if not target and not subdir:
            out.has_default_segment = True
    return out


def target_is_specific(make_cmd: str) -> bool:
    """True if the command targets a specific artifact or subdirectory rather than
    the default build. v1 primitive, kept for the ablation arm and its tests."""
    toks = make_cmd.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "-C":
            return True                 # -C subdir bypasses the top-level build graph
        if t == "make" or t.startswith("-"):
            i += 1
            continue
        return True                     # a bare token is a specific target name
    return False


# ── Phase 0: target validation (v2) ─────────────────────────
_BUILD_FILES = ("CMakeLists.txt", "Makefile.am", "meson.build", "Makefile", "GNUmakefile")
_SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", "node_modules", ".github", "__pycache__",
    "build", "build_fuzz", "build_debug", "build_ubsan", "build_coverage",
})
_COMMENT = re.compile(r"#.*$", re.M)
_CMAKE_PROJECT = re.compile(r"\bproject\s*\(\s*([A-Za-z0-9_.+-]+)", re.I)
_CMAKE_SET = re.compile(r"\bset\s*\(\s*([A-Za-z0-9_]+)\s+\"?([A-Za-z0-9_.+-]+)\"?\s*\)", re.I)
_CMAKE_TARGET = re.compile(r"\badd_(?:library|executable)\s*\(\s*([^\s\)]+)", re.I)
_AM_DECL = re.compile(r"^[A-Za-z0-9_]+_(?:LTLIBRARIES|LIBRARIES|PROGRAMS)\s*\+?=\s*(.*)$", re.M)
_MESON_TARGET = re.compile(
    r"\b(?:static_library|shared_library|shared_module|both_libraries|library|executable)"
    r"\s*\(\s*([^,\)]+)", re.I)
_MESON_ASSIGN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*'([^']+)'\s*$", re.M)
_MAKE_RULE = re.compile(r"^([A-Za-z0-9_./+-]+)\s*:(?!=)", re.M)
_VAR_REF = re.compile(r"\$[{(]([A-Za-z0-9_]+)[})]")


def _expand(name: str, variables: dict[str, str]) -> str:
    """Resolve `${PROJECT_NAME}` / `$(VAR)` against locally-known values. Deliberately
    shallow: a build-file *interpreter* is out of scope — one substitution pass over
    variables defined in the same file (plus the root project name) is what the
    astera/tiny-AES-c evidence actually requires."""
    return _VAR_REF.sub(lambda m: variables.get(m.group(1), m.group(0)), name).strip('"\'')


def _declared_names(path: Path, root_project: str) -> set[str]:
    """Target/artifact names declared by one build file."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return set()
    text = _COMMENT.sub("", text)           # a commented-out add_library declares nothing
    names: set[str] = set()

    if path.name == "CMakeLists.txt":
        variables: dict[str, str] = {}
        m = _CMAKE_PROJECT.search(text)
        variables["PROJECT_NAME"] = m.group(1) if m else root_project
        for m in _CMAKE_SET.finditer(text):
            variables.setdefault(m.group(1), m.group(2))
        for m in _CMAKE_TARGET.finditer(text):
            name = _expand(m.group(1), variables)
            if name and "::" not in name:   # skip IMPORTED/ALIAS targets
                names.add(name)

    elif path.name == "Makefile.am":
        joined = text.replace("\\\n", " ")
        for m in _AM_DECL.finditer(joined):
            names.update(t for t in m.group(1).split() if not t.startswith("$"))

    elif path.name == "meson.build":
        variables = {m.group(1): m.group(2) for m in _MESON_ASSIGN.finditer(text)}
        for m in _MESON_TARGET.finditer(text):
            raw = m.group(1).strip()
            name = variables.get(raw, raw).strip('"\'')
            if name:
                names.add(name)

    else:                                    # Makefile / GNUmakefile
        names.update(m.group(1) for m in _MAKE_RULE.finditer(text)
                     if not m.group(1).startswith("."))
    return names


def _target_aliases(target: str) -> set[str]:
    """The forms a configured target may take: a logical build-system target name
    (`uicc`, `png_static`) or an artifact path (`src/libsmk.a`, `libgensio.la`).

    No `-`/`_` normalisation: tiny-AES-c's configured `tiny_AES_c` must NOT match the
    declared `tiny-AES-c` — that mismatch is a real build failure and a v1 recovery."""
    base = target.rsplit("/", 1)[-1]
    aliases = {target, base}
    m = re.fullmatch(r"lib(.+)\.(?:a|la|so|dylib)", base)
    if m:
        aliases.add(m.group(1))
    return {a for a in aliases if a}


def _is_vendored(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(p.lower() in _VENDOR_DIRS for p in parts)


def find_declaration(target: str, source_root: Path) -> tuple[Path | None, bool]:
    """Locate the build file declaring `target`.

    → (declaring file, is_vendored). Non-vendored declarations win: a name declared
    both by the project and by a bundled dependency belongs to the project."""
    root = Path(source_root)
    aliases = _target_aliases(target)
    root_project = ""
    root_cml = root / "CMakeLists.txt"
    if root_cml.is_file():
        m = _CMAKE_PROJECT.search(_COMMENT.sub("", root_cml.read_text(errors="ignore")))
        root_project = m.group(1) if m else ""

    vendored_hit: Path | None = None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn not in _BUILD_FILES:
                continue
            path = Path(dirpath) / fn
            if not (aliases & _declared_names(path, root_project)):
                continue
            if _is_vendored(path, root):
                vendored_hit = vendored_hit or path
            else:
                return path, False
    return vendored_hit, vendored_hit is not None


def validate_target(make_cmd: str, source_root: Path | str | None) -> RepairRecord:
    """Phase 0 (v2). Decide whether the configured target deserves to be kept.

    Requirement 1 (conservative replacement) — a declared, project-owned target is
    kept (onomondo-uicc, pg_ivm regressed in v1 because it was not).
    Requirement 2 (ownership-aware validation) — a declared target that belongs to a
    vendored dependency is replaced (astera's `glfw`).
    Requirement 3 (build-system awareness) — a command that is not a recognised build
    invocation, or that already falls back to its own default build, is left alone."""
    rec = RepairRecord(action="", before=make_cmd, after=make_cmd)
    p = parse_build_command(make_cmd)

    # Distinct action names: a Phase-0 *verdict* is not a Phase-1 *action*, and the
    # repair trace must not conflate "decided to replace" with "replaced".
    def keep(reason: str) -> RepairRecord:
        rec.action, rec.reason = "validate_keep_target", reason
        return rec

    def replace(reason: str) -> RepairRecord:
        rec.action, rec.reason = "validate_replace_target", reason
        return rec

    if p.build_system == "unknown":
        return keep("no_recognised_build_command")
    if p.segments == 1 and p.has_default_segment:
        return keep("already_default_build")
    if p.has_default_segment:
        # pg_ivm / smk: `ninja <artifact> || ninja` already recovers by itself.
        return keep("command_falls_back_to_default_build")
    if p.subdir:
        # gensio: building a leaf inside `-C glib` never builds its parent `lib/`.
        return replace("subdir_invocation_bypasses_root_build_graph")
    if not source_root or not Path(source_root).is_dir():
        return replace("source_root_unavailable_for_validation")

    declaring, vendored = find_declaration(p.target, Path(source_root))
    if declaring is None:
        return replace("undeclared_target")
    rec.artifact = str(declaring)
    if vendored:
        return replace("declared_in_vendored_subtree")
    return keep("declared_project_target")


# ── Phase 1: target correction ──────────────────────────────
def correct_target(make_cmd: str) -> RepairRecord:
    """Phase 1. Return a repair record; if the target is specific/subdir, `after`
    holds the default build to use instead — of the build system actually in use."""
    if not target_is_specific(make_cmd):
        return RepairRecord(action="keep_target", before=make_cmd, after=make_cmd,
                            reason="already_default_build")
    build_system = parse_build_command(make_cmd).build_system
    return RepairRecord(
        action="replace_invalid_target", before=make_cmd,
        after=_DEFAULT_BUILD.get(build_system, _DEFAULT_MAKE),
        reason="specific_or_subdir_target_bypasses_build_graph",
    )


# ── Phase 2: genuine-target oracle ──────────────────────────
def genuine_oracle(build_dir: Path, build_ok: bool) -> RepairRecord:
    """Phase 2. Build success is necessary but insufficient: accept T2 only if a
    non-vendored library artifact was produced. Reject with an explicit reason
    otherwise, so a false T2 is a recorded outcome, not a silent pass."""
    rec = RepairRecord(action="genuine_target_oracle",
                       build_exit=0 if build_ok else 1)
    if not build_ok:
        rec.oracle, rec.reason = "n/a", "build_failed"
        return rec

    all_libs = [p for ext in ("*.a", "*.so", "*.dylib") for p in build_dir.rglob(ext)]
    project_libs = [p for p in all_libs if not _is_vendored(p, build_dir)]

    if project_libs:
        best = max(project_libs, key=lambda p: p.stat().st_size)
        rec.oracle, rec.reason, rec.artifact = "accept", "project_library_present", str(best)
    elif all_libs:
        rec.oracle, rec.reason = "reject", "only_vendored_artifact"
    else:
        rec.oracle, rec.reason = "reject", "no_project_library_artifact"
    return rec
