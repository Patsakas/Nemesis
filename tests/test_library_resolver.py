"""
Tests for LibraryResolver — the single answer to "where is the built library?".

There were two answers before this. The symbolic stage searched
source_subdir/, the build root, lib/, then the whole tree, then globbed for
cmake-renamed outputs. The fuzzing stage concatenated `build_dir /
library_name`. They agreed on every target until libnmea, which sets
ARCHIVE_OUTPUT_DIRECTORY: the harness compile found the archive, the probe
build did not, `analysis_binary()` returned None, and afl-cmin silently fell
back to the AFL binary and minimised nothing while the run reported success.

So the invariant under test is not only "finds the file" but "both callers get
the same answer", and the resolution carries enough provenance to debug a
wrong pick without re-running anything.
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.fuzzing import AFLOrchestrator
from nemesis.library_resolver import LibraryResolver
from nemesis.symbolic import SymbolicStage


def _archive(p: Path, size: int = 8) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"!<arch>\n" + b"\0" * size)
    return p


# ── strategy 1: exact paths ─────────────────────────────────


def test_build_root(tmp_path: Path):
    want = _archive(tmp_path / "libnmea.a")
    r = LibraryResolver().resolve(tmp_path, "libnmea.a")
    assert r.path == want
    assert r.strategy == "exact_path"
    assert r.kind == "static_archive"
    assert r.found


def test_lib_subdir(tmp_path: Path):
    """The libnmea layout that broke the old concatenation."""
    want = _archive(tmp_path / "lib" / "libnmea.a")
    r = LibraryResolver().resolve(tmp_path, "libnmea.a")
    assert r.path == want
    assert r.strategy == "exact_path"


def test_source_subdir_wins(tmp_path: Path):
    """libais declares source_subdir=src/libais; that is more specific than
    the build root and must be preferred."""
    want = _archive(tmp_path / "src" / "libais" / "libais.a")
    _archive(tmp_path / "libais.a")
    r = LibraryResolver(source_subdir="src/libais").resolve(tmp_path, "libais.a")
    assert r.path == want


def test_build_root_preferred_over_lib(tmp_path: Path):
    want = _archive(tmp_path / "libnmea.a")
    _archive(tmp_path / "lib" / "libnmea.a")
    assert LibraryResolver().resolve(tmp_path, "libnmea.a").path == want


# ── strategy 2: recursive search ────────────────────────────


def test_nested_subproject(tmp_path: Path):
    want = _archive(tmp_path / "sub" / "proj" / "out" / "libnmea.a")
    r = LibraryResolver().resolve(tmp_path, "libnmea.a")
    assert r.path == want
    assert r.strategy == "recursive_search"


def test_recursive_search_is_deterministic(tmp_path: Path):
    """Several copies in the tree must resolve identically on every machine —
    the old implementation took whatever `find` printed first."""
    _archive(tmp_path / "b" / "libnmea.a")
    _archive(tmp_path / "a" / "libnmea.a")
    picks = {LibraryResolver().resolve(tmp_path, "libnmea.a").path for _ in range(5)}
    assert len(picks) == 1


# ── strategy 3: fuzzy glob for renamed outputs ──────────────


def test_cmake_renamed_output(tmp_path: Path):
    """libpng: add_library(png_static) actually produces libpng16d.a."""
    want = _archive(tmp_path / "libpng16d.a", size=4096)
    r = LibraryResolver().resolve(tmp_path, "libpng_static.a")
    assert r.path == want
    assert r.strategy == "fuzzy_glob"


def test_fuzzy_glob_prefers_the_largest(tmp_path: Path):
    """The main library, not a helper archive built alongside it."""
    _archive(tmp_path / "libpng_helper.a", size=10)
    want = _archive(tmp_path / "libpng16d.a", size=100_000)
    assert LibraryResolver().resolve(tmp_path, "libpng_static.a").path == want


# ── not found ───────────────────────────────────────────────


def test_missing_library(tmp_path: Path):
    r = LibraryResolver().resolve(tmp_path, "libnmea.a")
    assert r.path is None
    assert r.found is False
    assert r.strategy == "not_found"


def test_no_name_configured(tmp_path: Path):
    r = LibraryResolver().resolve(tmp_path, "")
    assert r.found is False
    assert r.strategy == "no_name_configured"


# ── the configured name may itself be a glob ────────────────


def test_default_wildcard_name_finds_the_archive(tmp_path: Path):
    """NemesisConfig defaults library_name to `lib*.a`. An unconfigured target
    relies on that being treated as the pattern it is."""
    want = _archive(tmp_path / "sub" / "libwhatever.a")
    r = LibraryResolver().resolve(tmp_path, "lib*.a")
    assert r.path == want
    assert r.strategy == "recursive_search"


def test_wildcard_name_with_no_match_does_not_raise(tmp_path: Path):
    """Interpolating `lib*.a` into the fuzzy globs builds `lib**.a`, which
    pathlib rejects with ValueError — it must not abort resolution."""
    r = LibraryResolver().resolve(tmp_path, "lib*.a")
    assert r.found is False
    assert r.strategy == "not_found"


@pytest.mark.parametrize("name", ["lib*.a", "lib?.a", "lib[abc].a", "*.a"])
def test_pattern_names_never_raise(tmp_path: Path, name: str):
    assert LibraryResolver().resolve(tmp_path, name).found is False


# ── provenance ──────────────────────────────────────────────


def test_candidates_checked_is_recorded(tmp_path: Path):
    """"What did it try" is the question asked when it picks the wrong one."""
    _archive(tmp_path / "lib" / "libnmea.a")
    r = LibraryResolver().resolve(tmp_path, "libnmea.a")
    assert any("libnmea.a" in c for c in r.candidates_checked)
    assert len(r.candidates_checked) >= 2


def test_resolution_is_json_serialisable(tmp_path: Path):
    import json
    _archive(tmp_path / "libnmea.a")
    d = LibraryResolver().resolve(tmp_path, "libnmea.a").as_dict()
    assert json.loads(json.dumps(d))["strategy"] == "exact_path"


def test_shared_object_kind(tmp_path: Path):
    _archive(tmp_path / "libnmea.so")
    assert LibraryResolver().resolve(tmp_path, "libnmea.so").kind == "shared_object"


# ── the invariant that motivated the refactor ───────────────


@pytest.mark.parametrize("layout", ["libnmea.a", "lib/libnmea.a",
                                    "src/nmea/libnmea.a", "deep/nest/libnmea.a"])
def test_both_stages_agree(tmp_path: Path, layout: str):
    """SymbolicStage and AFLOrchestrator must resolve to the same file for
    every layout. Divergence here is what silently disabled per-input coverage
    on libnmea."""
    want = _archive(tmp_path / layout)

    cfg = NemesisConfig()
    cfg.target.library_name = "libnmea.a"
    cfg.target.source_subdir = "src/nmea"
    cfg.target.build_dir = str(tmp_path)
    cfg.engine.work_dir = str(tmp_path / "ws")

    symbolic = SymbolicStage(cfg).builder._find_library(tmp_path, "libnmea.a")
    fuzzing = AFLOrchestrator(cfg)._resolve_library_archive(tmp_path)

    assert symbolic == str(want)
    assert fuzzing == want
