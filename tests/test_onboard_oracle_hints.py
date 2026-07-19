"""
Tests for Fix 152 — onboard.py oracle-candidacy probe.

Verifies _probe_oracle_candidates() correctly detects TSan/MSan candidacy
and _format_oracle_hints_comment() renders actionable YAML guidance.
"""

from pathlib import Path

from nemesis.onboard import (
    _format_oracle_hints_comment,
    _msan_external_deps,
    _probe_oracle_candidates,
    _scan_threading_evidence,
)


# ── Threading evidence detection ────────────────────────────


def test_threading_evidence_finds_pthread(tmp_path: Path):
    (tmp_path / "worker.c").write_text(
        "#include <pthread.h>\nvoid* worker(void* arg) { return NULL; }\n"
    )
    hits = _scan_threading_evidence(tmp_path)
    assert "worker.c" in hits


def test_threading_evidence_finds_atomic(tmp_path: Path):
    (tmp_path / "counter.c").write_text(
        "#include <stdatomic.h>\n_Atomic int counter = 0;\n"
    )
    hits = _scan_threading_evidence(tmp_path)
    assert any("counter.c" in h for h in hits)


def test_threading_evidence_finds_openmp(tmp_path: Path):
    (tmp_path / "parallel.c").write_text(
        "#include <omp.h>\nvoid loop(void) {\n#pragma omp parallel for\n}\n"
    )
    hits = _scan_threading_evidence(tmp_path)
    assert any("parallel.c" in h for h in hits)


def test_threading_evidence_skips_test_dirs(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "thread_test.c").write_text(
        "#include <pthread.h>\n"
    )
    hits = _scan_threading_evidence(tmp_path)
    assert hits == []


def test_threading_evidence_empty_when_single_threaded(tmp_path: Path):
    (tmp_path / "parser.c").write_text(
        "#include <stdio.h>\nint parse(const char* s) { return 0; }\n"
    )
    hits = _scan_threading_evidence(tmp_path)
    assert hits == []


# ── MSan external deps detection ────────────────────────────


def test_msan_external_deps_empty_link_libs():
    assert _msan_external_deps("") == []


def test_msan_external_deps_only_safe_libs():
    """Math + dl + pthread + rt are MSan-safe baseline."""
    assert _msan_external_deps("-lm -ldl -lpthread -lrt") == []


def test_msan_external_deps_flags_zlib():
    """Compression libs need MSan-rebuild to avoid false positives."""
    deps = _msan_external_deps("-lz -lbz2 -lm")
    assert "-lz" in deps
    assert "-lbz2" in deps
    assert "-lm" not in deps


def test_msan_external_deps_ignores_non_l_flags():
    """-L paths and -W flags are not deps."""
    deps = _msan_external_deps("-L/usr/lib -Wl,--no-as-needed -lz")
    assert deps == ["-lz"]


# ── Combined probe ──────────────────────────────────────────


def test_probe_self_contained_threaded_lib(tmp_path: Path):
    """Self-contained threaded library → both candidates YES."""
    (tmp_path / "mt.c").write_text("#include <pthread.h>\n")
    result = _probe_oracle_candidates(tmp_path, "")
    assert result["tsan_candidate"] is True
    assert result["msan_candidate"] is True
    assert result["msan_blockers"] == []


def test_probe_external_deps_single_threaded(tmp_path: Path):
    """Single-threaded library with external deps → both candidates NO/MAYBE."""
    (tmp_path / "parser.c").write_text("int parse(void) { return 0; }\n")
    result = _probe_oracle_candidates(tmp_path, "-lz -lbz2")
    assert result["tsan_candidate"] is False
    assert result["msan_candidate"] is False
    assert "-lz" in result["msan_blockers"]


def test_probe_threaded_with_external_deps(tmp_path: Path):
    """Threaded but heavy deps → TSan YES, MSan MAYBE."""
    (tmp_path / "mt.c").write_text("#include <pthread.h>\n")
    result = _probe_oracle_candidates(tmp_path, "-lssl -lcrypto -lpthread")
    assert result["tsan_candidate"] is True
    assert result["msan_candidate"] is False
    assert "-lssl" in result["msan_blockers"]


# ── Comment rendering ──────────────────────────────────────


def test_format_comment_yes_yes(tmp_path: Path):
    hints = {
        "tsan_candidate": True,
        "threading_evidence": ["worker.c", "io.c"],
        "msan_candidate": True,
        "msan_blockers": [],
    }
    text = _format_oracle_hints_comment(hints)
    assert "TSan candidate:  YES" in text
    assert "MSan candidate:  YES" in text
    assert "worker.c" in text
    assert "threaded_oracle: true" in text
    assert "msan_supported: true" in text


def test_format_comment_no_maybe():
    hints = {
        "tsan_candidate": False,
        "threading_evidence": [],
        "msan_candidate": False,
        "msan_blockers": ["-lz", "-lssl"],
    }
    text = _format_oracle_hints_comment(hints)
    assert "TSan candidate:  NO" in text
    assert "MSan candidate:  MAYBE" in text
    assert "-lz" in text
    assert "-lssl" in text


def test_format_comment_truncates_long_evidence_list():
    """If many threading files, only first 3 listed + summary tail."""
    hints = {
        "tsan_candidate": True,
        "threading_evidence": [f"file{i}.c" for i in range(10)],
        "msan_candidate": True,
        "msan_blockers": [],
    }
    text = _format_oracle_hints_comment(hints)
    assert "file0.c" in text
    assert "file2.c" in text
    assert "+ 7 more" in text
    # file9.c not individually listed (only first 3)
    assert "file9.c" not in text
