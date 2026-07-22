"""
Tests that a run records which code produced it.

Without this a run log is unattributable. Reading `metric_provenance: FAIL` in
an archived log tells you only that the defect existed when the log was
written, not whether it still does — and separating those for the 2026-07-22
runs meant comparing commit timestamps against run start times by hand.

`dirty` is not a detail: during development most runs execute a working tree
that matches no commit, and a sha alone would claim otherwise.
"""

import subprocess
from unittest.mock import patch

from nemesis.pipeline import _code_version


def test_reports_sha_and_dirty_state():
    info = _code_version()
    assert set(info) == {"code_version", "git_sha", "git_dirty",
                         "git_diff_hash", "git_error"}
    assert info["code_version"]
    assert isinstance(info["git_dirty"], (bool, type(None)))


def test_dirty_tree_gets_an_identity():
    """A sha alone invites a reader to check that commit out and expect the
    same behaviour. The diff hash distinguishes two runs of different
    uncommitted code without storing the diff."""
    info = _code_version()
    if info["git_dirty"]:
        assert info["git_diff_hash"], "a dirty tree must be identifiable"
        assert len(info["git_diff_hash"]) == 16


def test_clean_tree_has_no_diff_hash():
    with patch("subprocess.run") as run:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        info = _code_version()
    assert info["git_dirty"] is False
    assert info["git_diff_hash"] is None


def test_same_diff_gives_the_same_hash():
    def _with_diff(diff_text: str) -> str:
        with patch("subprocess.run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
                subprocess.CompletedProcess([], 0, stdout=" M f.py\n", stderr=""),
                subprocess.CompletedProcess([], 0, stdout=diff_text, stderr=""),
            ]
            return _code_version()["git_diff_hash"]

    assert _with_diff("--- a\n+++ b\n+x\n") == _with_diff("--- a\n+++ b\n+x\n")
    assert _with_diff("--- a\n+++ b\n+x\n") != _with_diff("--- a\n+++ b\n+y\n")


def test_failure_reason_is_recorded_not_swallowed():
    """An unexplained "unknown" is the same absence-without-a-reason the field
    exists to avoid."""
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            [], 128, stdout="", stderr="fatal: not a git repository\n")
        info = _code_version()
    assert info["git_sha"] == "unknown"
    assert info["git_error"] and "not a git repository" in info["git_error"]


def test_sha_looks_like_a_sha_in_a_git_checkout():
    sha = _code_version()["git_sha"]
    assert sha == "unknown" or (7 <= len(sha) <= 40 and
                                all(c in "0123456789abcdef" for c in sha))


def test_dirty_is_distinguished_from_clean():
    """A working tree matching no commit must not be reported as that commit."""
    with patch("subprocess.run") as run:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" M nemesis/pipeline.py\n",
                                        stderr=""),
            # a dirty tree is then diffed to give it an identity
            subprocess.CompletedProcess([], 0, stdout="--- a\n+++ b\n+x\n",
                                        stderr=""),
        ]
        assert _code_version()["git_dirty"] is True

    with patch("subprocess.run") as run:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="abc1234\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        assert _code_version()["git_dirty"] is False


def test_missing_git_does_not_break_a_run():
    """Version reporting is diagnostic; it must never be the reason a run
    fails to start."""
    with patch("subprocess.run", side_effect=OSError("git not found")):
        info = _code_version()
    assert info["git_sha"] == "unknown"
    assert info["code_version"]


def test_git_failure_exit_code_is_tolerated():
    with patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 128, stdout="",
                                                       stderr="not a repository")
        info = _code_version()
    assert info["git_sha"] == "unknown"
