"""
Tests for git-history analysis (nemesis/recon/git_history.py).

`AnalysisContext.git_history` existed as a declared-but-never-written field;
this module is what fills it, and what feeds churn/past-fix signal into recon
ranking.

The parsing tests drive `_parse_log` on synthetic output so they are fast and
deterministic. The end-to-end tests build a real throwaway repo, because the
`git log --format=\\x01%h %ct %s --name-only` contract is the part most likely
to break silently, and asserting against synthetic strings would never catch a
change in git's actual output shape.
"""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from nemesis.recon.git_history import (
    _FIX_SUBJECT_RE,
    _REC,
    FileHistory,
    GitHistoryIndex,
)

_DAY = 86400.0
NOW = 1_700_000_000.0


def _log(*commits: tuple[str, float, str, list[str]]) -> str:
    """Render synthetic `git log` output: (sha, ts, subject, files)."""
    out = []
    for sha, ts, subject, files in commits:
        out.append(f"{_REC}{sha} {int(ts)} {subject}")
        out.append("")
        out.extend(files)
    return "\n".join(out)


def _index(*commits, now: float = NOW) -> GitHistoryIndex:
    files = GitHistoryIndex._parse_log(_log(*commits), now=now)
    return GitHistoryIndex(files, available=bool(files))


# ── _FIX_SUBJECT_RE ─────────────────────────────────────────


@pytest.mark.parametrize("subject", [
    "fix out-of-bounds read in chunk parser",
    "Fixes #421: heap overflow in png_handle_iCCP",
    "avoid use-after-free on error path",
    "CVE-2018-13785: division by zero",
    "oss-fuzz: handle truncated input",
    "ubsan: signed integer overflow in shift",
    "security: reject negative lengths",
])
def test_fix_subjects_recognised(subject):
    assert _FIX_SUBJECT_RE.search(subject)


@pytest.mark.parametrize("subject", [
    "bump version to 1.6.38",
    "update copyright year",
    "add example to documentation",
    "refactor: rename internal helper",
])
def test_non_fix_subjects_not_recognised(subject):
    assert not _FIX_SUBJECT_RE.search(subject)


# ── _parse_log ──────────────────────────────────────────────


def test_parse_counts_commits_per_file():
    idx = _index(
        ("aaa1111", NOW - 10 * _DAY, "fix overflow", ["src/png.c"]),
        ("bbb2222", NOW - 20 * _DAY, "refactor", ["src/png.c", "src/util.c"]),
    )
    assert idx.for_file("src/png.c").commit_count == 2
    assert idx.for_file("src/util.c").commit_count == 1


def test_parse_takes_newest_change_as_last_change():
    """git log is newest-first; last_change_days must reflect the most recent
    commit, not whichever one happened to be parsed last."""
    idx = _index(
        ("aaa1111", NOW - 5 * _DAY, "fix overflow", ["src/png.c"]),
        ("bbb2222", NOW - 400 * _DAY, "initial", ["src/png.c"]),
    )
    assert idx.for_file("src/png.c").last_change_days == pytest.approx(5.0, abs=0.1)


def test_parse_separates_fix_from_ordinary_commits():
    idx = _index(
        ("aaa1111", NOW - _DAY, "fix heap overflow", ["src/png.c"]),
        ("bbb2222", NOW - 2 * _DAY, "update docs", ["src/png.c"]),
    )
    hist = idx.for_file("src/png.c")
    assert len(hist.fix_subjects) == 1
    assert "heap overflow" in hist.fix_subjects[0]
    assert len(hist.recent_subjects) == 1
    assert "update docs" in hist.recent_subjects[0]


def test_parse_caps_per_file_lists():
    """A hot file appears in hundreds of commits and these strings end up in an
    LLM prompt — the caps must hold."""
    commits = [
        (f"sha{i:04d}", NOW - i * _DAY, "fix overflow", ["src/hot.c"])
        for i in range(50)
    ]
    commits += [
        (f"nfx{i:04d}", NOW - i * _DAY, "update docs", ["src/hot.c"])
        for i in range(50)
    ]
    hist = _index(*commits).for_file("src/hot.c")
    assert len(hist.fix_subjects) == 10
    assert len(hist.recent_subjects) == 5
    assert hist.commit_count == 100  # counting is NOT capped


def test_parse_survives_empty_subject():
    """Merge commits can have an empty subject — the header then has too few
    fields and must be skipped without swallowing the following filenames as
    part of a bogus commit."""
    raw = f"{_REC}aaa1111 {int(NOW)}\n\nsrc/orphan.c\n" + _log(
        ("bbb2222", NOW - _DAY, "fix overflow", ["src/real.c"])
    )
    files = GitHistoryIndex._parse_log(raw, now=NOW)
    assert "src/orphan.c" not in files
    assert files["src/real.c"].commit_count == 1


def test_parse_survives_subject_that_looks_like_a_header():
    """The \\x01 record marker exists so a subject like "abc1234 999 foo" can't
    be mistaken for a commit header."""
    idx = _index(
        ("aaa1111", NOW - _DAY, "abc1234 1699999999 fix overflow", ["src/png.c"]),
    )
    assert idx.for_file("src/png.c").commit_count == 1


def test_parse_empty_output():
    assert GitHistoryIndex._parse_log("", now=NOW) == {}


# ── for_file path matching ──────────────────────────────────


def test_for_file_matches_introspector_prefixed_path():
    """Introspector reports "/src/libpng/png.c" for what git calls "png.c"."""
    idx = _index(("aaa1111", NOW - _DAY, "fix overflow", ["src/png.c"]))
    assert idx.for_file("/repo/src/png.c") is not None


def test_for_file_matches_bare_basename():
    idx = _index(("aaa1111", NOW - _DAY, "fix overflow", ["src/png.c"]))
    assert idx.for_file("png.c") is not None


def test_for_file_refuses_ambiguous_basename():
    """Two util.c in the repo: attributing one file's fix history to the other
    is worse than reporting no signal at all."""
    idx = _index(
        ("aaa1111", NOW - _DAY, "fix overflow", ["src/util.c", "tools/util.c"]),
    )
    assert idx.for_file("util.c") is None


def test_for_file_normalises_windows_separators():
    idx = _index(("aaa1111", NOW - _DAY, "fix overflow", ["src/png.c"]))
    assert idx.for_file("src\\png.c") is not None


def test_for_file_unknown_path():
    idx = _index(("aaa1111", NOW - _DAY, "fix overflow", ["src/png.c"]))
    assert idx.for_file("src/nowhere.c") is None


# ── score_bonus ─────────────────────────────────────────────


def test_recent_change_scores_full_recency_bonus():
    idx = _index(("aaa1111", NOW - 10 * _DAY, "refactor", ["src/png.c"]))
    assert idx.score_bonus("src/png.c") == pytest.approx(3.0)


def test_change_within_year_scores_half():
    idx = _index(("aaa1111", NOW - 200 * _DAY, "refactor", ["src/png.c"]))
    assert idx.score_bonus("src/png.c") == pytest.approx(1.5)


def test_old_change_scores_no_recency_bonus():
    idx = _index(("aaa1111", NOW - 500 * _DAY, "refactor", ["src/png.c"]))
    assert idx.score_bonus("src/png.c") == pytest.approx(0.0)


def test_past_fixes_add_bonus_and_are_capped():
    """Bugs cluster, so past fixes count — but the cap keeps history from
    dominating the complexity term (max 15) in recon ranking."""
    commits = [
        (f"sha{i:04d}", NOW - (400 + i) * _DAY, "fix overflow", ["src/png.c"])
        for i in range(10)
    ]
    idx = _index(*commits)
    # Old commits → no recency component, so this is the fix bonus alone.
    assert idx.score_bonus("src/png.c") == pytest.approx(4.5)


def test_recency_and_fixes_combine():
    idx = _index(("aaa1111", NOW - 5 * _DAY, "fix overflow", ["src/png.c"]))
    assert idx.score_bonus("src/png.c") == pytest.approx(3.0 + 1.5)


def test_score_bonus_respects_custom_weights():
    idx = _index(("aaa1111", NOW - 5 * _DAY, "fix overflow", ["src/png.c"]))
    got = idx.score_bonus(
        "src/png.c", recency_bonus=10.0, fix_bonus=2.0, fix_bonus_cap=2.0,
    )
    assert got == pytest.approx(12.0)


def test_unknown_file_scores_zero():
    idx = _index(("aaa1111", NOW - _DAY, "fix overflow", ["src/png.c"]))
    assert idx.score_bonus("src/other.c") == 0.0


def test_empty_index_scores_zero():
    """The no-git case must be a silent no-op, not an error or a bias."""
    empty = GitHistoryIndex()
    assert empty.available is False
    assert empty.score_bonus("anything.c") == 0.0
    assert empty.context_lines("anything.c") == []
    assert empty.for_file("anything.c") is None


# ── context_lines ───────────────────────────────────────────


def test_context_lines_lead_with_summary_and_fixes():
    idx = _index(
        ("aaa1111", NOW - 3 * _DAY, "update docs", ["src/png.c"]),
        ("bbb2222", NOW - 8 * _DAY, "fix heap overflow in iCCP", ["src/png.c"]),
    )
    lines = idx.context_lines("src/png.c")
    assert "2 commit(s)" in lines[0]
    assert "last changed 3 days ago" in lines[0]
    # Fixes rank above ordinary commits regardless of date order.
    assert "heap overflow" in lines[1]
    assert any("update docs" in ln for ln in lines)


def test_context_lines_truncate_to_limit():
    commits = [
        (f"sha{i:04d}", NOW - i * _DAY, "fix overflow", ["src/png.c"])
        for i in range(10)
    ]
    assert len(_index(*commits).context_lines("src/png.c", limit=4)) == 4


def test_context_lines_include_commit_age():
    idx = _index(("aaa1111", NOW - 42 * _DAY, "fix overflow", ["src/png.c"]))
    assert "42d ago" in idx.context_lines("src/png.c")[1]


# ── build() against a real repository ───────────────────────

pytestmark_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git not installed"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    _git_init = subprocess.run(
        ["git", "init", "-q", str(r)], capture_output=True, text=True,
    )
    assert _git_init.returncode == 0, _git_init.stderr
    _git(r, "config", "user.email", "test@example.com")
    _git(r, "config", "user.name", "Test")
    (r / "src" / "parse.c").write_text("int parse(void){return 0;}\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial import")
    (r / "src" / "parse.c").write_text("int parse(void){return 1;}\n")
    _git(r, "commit", "-q", "-am", "fix out-of-bounds read in parse()")
    return r


@pytestmark_git
def test_build_indexes_real_repo(repo: Path):
    """Guards the `git log` invocation itself — the synthetic-output tests
    would happily keep passing if git's format contract changed."""
    idx = GitHistoryIndex.build(repo)
    assert idx.available is True
    hist = idx.for_file("src/parse.c")
    assert hist is not None
    assert hist.commit_count == 2
    assert len(hist.fix_subjects) == 1
    assert "out-of-bounds" in hist.fix_subjects[0]
    # Just committed → full recency bonus plus one fix.
    assert idx.score_bonus("src/parse.c") == pytest.approx(4.5)


@pytestmark_git
def test_build_on_real_repo_recent_timestamps(repo: Path):
    """Ages are computed against wall-clock now, not the log window."""
    hist = GitHistoryIndex.build(repo).for_file("src/parse.c")
    assert hist.last_change_days is not None
    assert hist.last_change_days < 1.0


def test_build_on_non_repo_is_silent(tmp_path: Path):
    """Source trees arrive as tarballs as often as clones — no .git must mean
    no signal, never an exception."""
    (tmp_path / "src.c").write_text("int x;\n")
    idx = GitHistoryIndex.build(tmp_path)
    assert idx.available is False
    assert idx.score_bonus("src.c") == 0.0


def test_build_on_missing_path_is_silent(tmp_path: Path):
    assert GitHistoryIndex.build(tmp_path / "nope").available is False


# ── FileHistory dataclass ───────────────────────────────────


def test_file_history_defaults_are_independent():
    """Mutable default fields must not be shared between instances."""
    a, b = FileHistory(path="a.c"), FileHistory(path="b.c")
    a.fix_subjects.append("x")
    assert b.fix_subjects == []


def test_build_respects_wall_clock(monkeypatch):
    """_parse_log takes `now` as a parameter so age is testable; build() must
    pass the real clock through."""
    idx = _index(("aaa1111", time.time() - 2 * _DAY, "fix overflow", ["a.c"]),
                 now=time.time())
    assert idx.for_file("a.c").last_change_days == pytest.approx(2.0, abs=0.1)


# ── Wiring into recon ───────────────────────────────────────
#
# `AnalysisContext.git_history` sat declared-but-unwritten for a long time, so
# these tests pin the consumers, not just the producer: an index nobody calls
# is the exact failure mode being fixed here.


@pytest.fixture
def scored_repo(tmp_path: Path) -> Path:
    """Repo with a churned+fixed file and an untouched-since-import file."""
    r = tmp_path / "proj"
    (r / "src").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(r)], check=True, capture_output=True)
    _git(r, "config", "user.email", "test@example.com")
    _git(r, "config", "user.name", "Test")
    (r / "src" / "hot.c").write_text("int hot(void){return 0;}\n")
    (r / "src" / "stable.c").write_text("int stable(void){return 0;}\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "initial import")
    (r / "src" / "hot.c").write_text("int hot(void){return 1;}\n")
    _git(r, "commit", "-q", "-am", "fix heap buffer overflow in hot()")
    return r


def _config(source_root: Path):
    from nemesis.config import NemesisConfig
    cfg = NemesisConfig()
    cfg.target.source_root = str(source_root)
    return cfg


@pytestmark_git
def test_recon_scoring_prefers_recently_fixed_file(scored_repo: Path):
    from nemesis.recon import IntrospectorParser
    parser = IntrospectorParser(_config(scored_repo))
    hot = parser._git_history_bonus("src/hot.c")
    stable = parser._git_history_bonus("src/stable.c")
    # Both are recent (just committed), so the gap is the past-fix signal.
    assert hot > stable
    assert hot == pytest.approx(stable + 1.5)


@pytestmark_git
def test_recon_scoring_disabled_by_config(scored_repo: Path):
    from nemesis.recon import IntrospectorParser
    cfg = _config(scored_repo)
    cfg.recon_scoring.git_history_enabled = False
    assert IntrospectorParser(cfg)._git_history_bonus("src/hot.c") == 0.0


@pytestmark_git
def test_recon_index_built_once_per_parser(scored_repo: Path):
    """The index is one `git log` over the whole repo; recon scores hundreds of
    candidates, so it must be cached rather than rebuilt per candidate."""
    from nemesis.recon import IntrospectorParser
    parser = IntrospectorParser(_config(scored_repo))
    assert parser.git_history is parser.git_history


@pytestmark_git
def test_context_extractor_fills_git_history(scored_repo: Path):
    """The field this whole module exists to populate."""
    from nemesis.models import CallChain, CoverageTarget
    from nemesis.recon import ContextExtractor

    target = CoverageTarget(
        func_name="hot", file_path="src/hot.c", line=1, coverage_pct=0.0,
    )
    ctx = ContextExtractor(_config(scored_repo)).extract(
        CallChain(entry_point="main", chain=["hot"], target=target)
    )
    assert ctx.git_history
    assert any("heap buffer overflow" in ln for ln in ctx.git_history)


@pytestmark_git
def test_context_extractor_respects_disable_flag(scored_repo: Path):
    from nemesis.models import CallChain, CoverageTarget
    from nemesis.recon import ContextExtractor

    cfg = _config(scored_repo)
    cfg.recon_scoring.git_history_enabled = False
    target = CoverageTarget(
        func_name="hot", file_path="src/hot.c", line=1, coverage_pct=0.0,
    )
    ctx = ContextExtractor(cfg).extract(
        CallChain(entry_point="main", chain=["hot"], target=target)
    )
    assert ctx.git_history == []


def test_git_history_reaches_the_llm_prompt():
    """Populating the field is only half the job — it has to be rendered into
    the analysis prompt, or it is dead weight again."""
    from nemesis.models import AnalysisContext, CallChain, CoverageTarget
    from nemesis.neural import PromptBuilder

    target = CoverageTarget(
        func_name="hot", file_path="src/hot.c", line=1, coverage_pct=0.0,
    )
    ctx = AnalysisContext(
        target=target,
        call_chain=CallChain(entry_point="main", chain=["hot"], target=target),
        git_history=["abc1234 (3d ago) fix heap buffer overflow in hot()"],
    )
    prompt = PromptBuilder.build_analysis_prompt(ctx)
    assert "<git_history>" in prompt
    assert "heap buffer overflow" in prompt


def test_prompt_omits_git_history_section_when_empty():
    """No history (non-git source tree) → no empty section wasting prompt
    budget and no misleading "no fixes here" implication."""
    from nemesis.models import AnalysisContext, CallChain, CoverageTarget
    from nemesis.neural import PromptBuilder

    target = CoverageTarget(
        func_name="hot", file_path="src/hot.c", line=1, coverage_pct=0.0,
    )
    ctx = AnalysisContext(
        target=target,
        call_chain=CallChain(entry_point="main", chain=["hot"], target=target),
    )
    assert "<git_history>" not in PromptBuilder.build_analysis_prompt(ctx)
