"""H2a — build-target inference & validation (deterministic repair operator).

Motivated and shaped by the H2a validation probe (see H2_PLAN.md). The onboarder
guesses a specific build target — a bare name, or `-C subdir artifact` — that is
frequently wrong (`tiny_AES_c` instead of the real CMake target), bypasses the
build graph (`-C glib` before its parent `lib/` is built), or names a library the
project does not produce at all (`libgifsicle.la` — gifsicle is an application).

The operator is two deterministic phases:

  Phase 1 — target correction. Replace a specific/subdir build target with the
  build-system **default** build, which respects dependency ordering. One rule, no
  LLM, no build-file guessing.

  Phase 2 — genuine-target oracle. Build success is NECESSARY but INSUFFICIENT.
  The produced artifact must be a real project library: not an application with no
  library (gifsicle), not a vendored dependency (astera). Validated post-build.

Design constraint (H2_PLAN repair-independence): few deterministic rules, a recorded
repair trace, an explicit rejection reason — so results can say not only "H2a raised
genuine T2 by X" but "and prevented Y false successes", each attributable.
"""

from __future__ import annotations

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


# ── Phase 1: target correction ──────────────────────────────
_DEFAULT_MAKE = "make -j$(nproc)"


def target_is_specific(make_cmd: str) -> bool:
    """True if the make command targets a specific artifact or subdirectory rather
    than the default build. `make -j$(nproc)` is default; `make -C src libX.la` and
    `make foo` are specific. Deterministic token scan — no build-file parsing."""
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
        # (unreachable)
    return False


def correct_target(make_cmd: str) -> RepairRecord:
    """Phase 1. Return a repair record; if the target is specific/subdir, `after`
    holds the default build to use instead."""
    if not target_is_specific(make_cmd):
        return RepairRecord(action="keep_target", before=make_cmd, after=make_cmd,
                            reason="already_default_build")
    return RepairRecord(
        action="replace_invalid_target", before=make_cmd, after=_DEFAULT_MAKE,
        reason="specific_or_subdir_target_bypasses_build_graph",
    )


# ── Phase 2: genuine-target oracle ──────────────────────────
def _is_vendored(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(p.lower() in _VENDOR_DIRS for p in parts)


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
