"""Single source of truth for "where is the built library?".

There used to be two answers. `SymbolicStage._find_library` walked
`source_subdir/`, the build root, `lib/`, then a recursive search, then a fuzzy
glob for cmake-renamed outputs. `AFLOrchestrator.analysis_binary` concatenated
`build_dir / library_name`.

They agreed on every target until libnmea, which sets ARCHIVE_OUTPUT_DIRECTORY
and puts the archive at `build_fuzz/lib/libnmea.a`. The harness compile found it
and succeeded; the probe build did not and failed with `undefined reference to
nmea_parse`. `analysis_binary()` returned None, afl-cmin fell back to the AFL
binary and minimised nothing, and the run reported success throughout. One
divergent path resolver silently degraded every per-input coverage consumer.

`LibraryResolution` carries provenance rather than a bare path, because the
question that actually gets asked during debugging is not "what did it pick"
but "what did it try, and why that one". It is JSON-serialisable so benchmark
artifacts can record it alongside the decision trace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class LibraryResolution:
    """Where a built library was found, and how."""

    requested: str
    path: Path | None = None
    kind: str = "unknown"
    strategy: str = "not_found"
    candidates_checked: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.path is not None

    def as_dict(self) -> dict:
        return {
            "requested": self.requested,
            "path": str(self.path) if self.path else None,
            "kind": self.kind,
            "strategy": self.strategy,
            "found": self.found,
            "candidates_checked": self.candidates_checked,
        }


def _kind_of(path: Path) -> str:
    suffix = path.suffix
    if suffix == ".a":
        return "static_archive"
    if suffix in (".so", ".dylib") or ".so." in path.name:
        return "shared_object"
    return "unknown"


class LibraryResolver:
    """Locate a built library in a build tree.

    Strategies are tried in order and the winning one is recorded:

    1. ``exact_path``       — ``source_subdir/``, build root, then ``lib/``.
    2. ``recursive_search`` — the exact filename anywhere under build_dir.
    3. ``fuzzy_glob``       — cmake renames outputs via
       ``set_target_properties(... OUTPUT_NAME ...)``; libpng's
       ``add_library(png_static STATIC)`` produces ``libpng16d.a``. Glob for
       variants and take the largest, which is the main library rather than a
       helper.
    """

    def __init__(self, source_subdir: str = "", log=None) -> None:
        self.source_subdir = source_subdir
        self.log = log

    def resolve(self, build_dir: Path, name: str) -> LibraryResolution:
        if not name:
            return LibraryResolution(requested=name, strategy="no_name_configured")

        checked: list[str] = []

        # ── 1. exact paths, most specific first ─────────────
        candidates: list[Path] = []
        if self.source_subdir:
            candidates.append(build_dir / self.source_subdir / name)
        candidates += [build_dir / name, build_dir / "lib" / name]

        for candidate in candidates:
            checked.append(str(candidate))
            if candidate.exists():
                return self._hit(name, candidate, "exact_path", checked)

        # ── 2. exact filename, anywhere in the tree ─────────
        # Sorted so a tree with several copies resolves the same way on every
        # machine; the previous implementation took whatever `find` emitted
        # first, which is filesystem order.
        # `name` may legitimately be a pattern here — NemesisConfig defaults
        # library_name to `lib*.a`, and rglob treats it as the glob it is,
        # which is how an unconfigured target finds its archive at all.
        try:
            hits = sorted(p for p in build_dir.rglob(Path(name).name) if p.is_file())
        except (OSError, ValueError):
            hits = []
        checked.append(f"rglob:{Path(name).name}")
        if hits:
            return self._hit(name, hits[0], "recursive_search", checked)

        # ── 3. fuzzy glob for cmake-renamed outputs ─────────
        # The configured name may itself be a pattern — `lib*.a` is the default
        # in NemesisConfig — so strip glob metacharacters before interpolating.
        # Leaving them in builds `lib**.a`, and pathlib rejects `**` inside a
        # path component with a ValueError that aborts the whole resolution.
        base = Path(name).stem
        base = base[3:] if base.startswith("lib") else base
        if base.endswith("_static"):
            base = base[: -len("_static")]
        base = "".join(ch for ch in base if ch not in "*?[]")

        globs: list[str] = []
        if base:
            globs.append(f"lib{base}*.a")
            globs.append(f"lib{base[0]}*.a")
        globs.append("lib*.a")

        seen: set[str] = set()
        for pattern in globs:
            checked.append(f"glob:{pattern}")
            best: tuple[int, Path] | None = None
            try:
                for hit in build_dir.rglob(pattern):
                    if not hit.is_file() or str(hit) in seen:
                        continue
                    seen.add(str(hit))
                    size = hit.stat().st_size
                    if best is None or size > best[0]:
                        best = (size, hit)
            except (OSError, ValueError):
                continue
            if best is not None:
                res = self._hit(name, best[1], "fuzzy_glob", checked)
                if self.log:
                    self.log.info("library.renamed_output", requested=name,
                                  actual=str(best[1]), glob=pattern, size=best[0])
                return res

        resolution = LibraryResolution(requested=name, strategy="not_found",
                                       candidates_checked=checked)
        if self.log:
            self.log.warning("library.not_found", requested=name,
                             build_dir=str(build_dir),
                             candidates_checked=len(checked))
        return resolution

    def _hit(self, name: str, path: Path, strategy: str,
             checked: list[str]) -> LibraryResolution:
        resolution = LibraryResolution(
            requested=name, path=path, kind=_kind_of(path),
            strategy=strategy, candidates_checked=checked,
        )
        if self.log:
            self.log.debug("library.resolved", **resolution.as_dict())
        return resolution
