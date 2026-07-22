"""
Tests for locating the static archive when building the analysis binary.

The analysis binary exists so that afl-cmin and byte-influence probing get
honest per-input coverage instead of the fuzzing binary's uniform answer. It was
resolving the archive as `build_dir / library_name`, which assumes cmake writes
it to the build root. libnmea sets ARCHIVE_OUTPUT_DIRECTORY, so the archive
lands at `build_fuzz/lib/libnmea.a`.

The failure was invisible in the obvious places: the harness compile succeeded
(it resolves through the symbolic builder, which knows about `lib/`), so the run
reported healthy while the probe build died with `undefined reference to
nmea_parse`, no analysis binary was produced, and afl-cmin minimised nothing —
logging `seeds.cmin_empty_result` with no indication of why.
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.fuzzing import AFLOrchestrator


@pytest.fixture
def stage(tmp_path: Path) -> AFLOrchestrator:
    cfg = NemesisConfig()
    cfg.target.library_name = "libnmea.a"
    cfg.target.build_dir = str(tmp_path / "build_fuzz")
    return AFLOrchestrator(cfg)


def _touch(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"!<arch>\n")
    return p


def test_archive_at_build_root(stage: AFLOrchestrator, tmp_path: Path):
    build = tmp_path / "build_fuzz"
    want = _touch(build / "libnmea.a")
    assert stage._resolve_library_archive(build) == want


def test_archive_under_lib_subdir(stage: AFLOrchestrator, tmp_path: Path):
    """The libnmea layout — the case that was silently failing."""
    build = tmp_path / "build_fuzz"
    want = _touch(build / "lib" / "libnmea.a")
    assert stage._resolve_library_archive(build) == want


def test_build_root_wins_over_lib_subdir(stage: AFLOrchestrator, tmp_path: Path):
    """Both present: prefer the canonical location, do not start searching."""
    build = tmp_path / "build_fuzz"
    want = _touch(build / "libnmea.a")
    _touch(build / "lib" / "libnmea.a")
    assert stage._resolve_library_archive(build) == want


def test_source_subdir_takes_priority(tmp_path: Path):
    """libais-style: the archive lives under the configured source_subdir."""
    cfg = NemesisConfig()
    cfg.target.library_name = "libais.a"
    cfg.target.source_subdir = "src/libais"
    build = tmp_path / "build_fuzz"
    want = _touch(build / "src" / "libais" / "libais.a")
    _touch(build / "libais.a")
    assert AFLOrchestrator(cfg)._resolve_library_archive(build) == want


def test_deeply_nested_archive_found_by_search(stage: AFLOrchestrator, tmp_path: Path):
    """Nested subproject builds put it somewhere none of the guesses cover."""
    build = tmp_path / "build_fuzz"
    want = _touch(build / "sub" / "project" / "out" / "libnmea.a")
    assert stage._resolve_library_archive(build) == want


def test_missing_archive_returns_none(stage: AFLOrchestrator, tmp_path: Path):
    """Must return None so the caller falls back — never a bogus path that
    produces a confusing `undefined reference` from the linker."""
    build = tmp_path / "build_fuzz"
    build.mkdir(parents=True)
    assert stage._resolve_library_archive(build) is None


def test_no_library_name_configured(tmp_path: Path):
    cfg = NemesisConfig()
    cfg.target.library_name = ""
    assert AFLOrchestrator(cfg)._resolve_library_archive(tmp_path) is None
