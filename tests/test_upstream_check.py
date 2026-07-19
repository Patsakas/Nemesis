"""Tests for the reproduce-on-latest-upstream freshness check.

Uses real throwaway git repos (local path remotes, no network) to exercise the
up_to_date / behind / unknown verdicts of check_upstream_freshness.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nemesis.upstream import check_upstream_freshness

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")

_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com",
}


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                   text=True, env=_ENV, check=True)


def _commit(repo, name, content):
    (Path(repo) / name).write_text(content)
    _git(repo, "add", name)
    _git(repo, "commit", "-m", f"add {name}")


def _init_origin(tmp_path) -> Path:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init")
    _commit(origin, "a.txt", "one")
    return origin


def test_up_to_date_when_checkout_matches_tip(tmp_path):
    origin = _init_origin(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", str(origin), str(clone)], capture_output=True,
                   text=True, env=_ENV, check=True)

    us = check_upstream_freshness(clone)
    assert us.status == "up_to_date"
    assert us.current_commit and us.current_commit == us.upstream_commit


def test_behind_when_upstream_advances(tmp_path):
    origin = _init_origin(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", str(origin), str(clone)], capture_output=True,
                   text=True, env=_ENV, check=True)
    # Advance upstream after cloning.
    _commit(origin, "b.txt", "two")

    us = check_upstream_freshness(clone)
    assert us.status == "behind"
    assert us.current_commit != us.upstream_commit
    assert "behind" in us.detail


def test_unknown_when_not_a_git_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    us = check_upstream_freshness(plain)
    assert us.status == "unknown"
    assert "not a git repository" in us.detail


def test_unknown_when_no_remote(tmp_path):
    repo = tmp_path / "noremote"
    repo.mkdir()
    _git(repo, "init")
    _commit(repo, "a.txt", "one")
    us = check_upstream_freshness(repo)
    assert us.status == "unknown"
    assert us.current_commit  # HEAD resolved even though remote is absent
