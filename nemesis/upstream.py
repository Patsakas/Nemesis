"""Upstream freshness check for a target's source checkout.

Answers "is the source_root we fuzzed the LATEST upstream code?" so a finding can
be qualified: if the checkout is at the upstream tip, a crash that reproduces now
reproduces on the latest release (candidate novel/unpatched bug); if the checkout
is behind, the bug may already be fixed upstream and must be re-verified before
claiming novelty.

Strictly READ-ONLY with respect to source_root: uses ``git ls-remote`` (queries
the remote without fetching objects or updating any local ref), plus local
``rev-parse`` / ``merge-base`` / ``rev-list``. It never fetches, checks out, or
mutates the working tree — honouring the "never modify source_root" rule.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class UpstreamStatus:
    """Result of an upstream freshness check.

    status:
      - "up_to_date" — HEAD is at (or ahead of) the upstream branch tip.
      - "behind"     — upstream has commits the checkout does not; bug may be fixed.
      - "unknown"    — not a git repo, no remote, offline, or otherwise undetermined.
    """

    status: str = "unknown"
    current_commit: str = ""
    upstream_commit: str = ""
    upstream_ref: str = ""
    commits_behind: int = 0
    detail: str = ""


def check_upstream_freshness(
    source_root: str | Path,
    branch: str = "",
    *,
    timeout_s: int = 30,
) -> UpstreamStatus:
    """Compare a local git checkout against its upstream branch tip.

    Args:
        source_root: path to the pristine source checkout.
        branch:      upstream branch to compare against; empty = resolve the
                     remote's default branch (origin/HEAD).
        timeout_s:   per-git-command timeout (ls-remote hits the network).
    """
    root = str(source_root)

    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", root, *args],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )

    try:
        r = git("rev-parse", "--is-inside-work-tree")
        if r.returncode != 0 or r.stdout.strip() != "true":
            return UpstreamStatus(detail="not a git repository")

        current = git("rev-parse", "HEAD").stdout.strip()

        # Resolve the upstream tip via ls-remote — no fetch, no ref mutation.
        if branch:
            ls = git("ls-remote", "origin", f"refs/heads/{branch}")
            upstream_ref = f"origin/{branch}"
            upstream_commit = ls.stdout.split()[0] if (ls.returncode == 0 and ls.stdout.strip()) else ""
        else:
            ls = git("ls-remote", "--symref", "origin", "HEAD")
            upstream_ref, upstream_commit = "origin/HEAD", ""
            if ls.returncode == 0 and ls.stdout.strip():
                for line in ls.stdout.splitlines():
                    if line.startswith("ref:"):
                        m = re.search(r"refs/heads/(\S+)", line)
                        if m:
                            upstream_ref = f"origin/{m.group(1)}"
                    elif "\tHEAD" in line:
                        upstream_commit = line.split()[0]

        if not upstream_commit:
            return UpstreamStatus(
                current_commit=current[:12],
                detail="could not resolve upstream tip (offline, no 'origin' remote, or no such branch)",
            )

        if upstream_commit == current:
            return UpstreamStatus(
                status="up_to_date",
                current_commit=current[:12],
                upstream_commit=upstream_commit[:12],
                upstream_ref=upstream_ref,
                detail=f"HEAD == {upstream_ref}: reproduces on the latest upstream code",
            )

        # HEAD may already contain the upstream tip (local at/ahead of remote).
        anc = git("merge-base", "--is-ancestor", upstream_commit, "HEAD")
        if anc.returncode == 0:
            return UpstreamStatus(
                status="up_to_date",
                current_commit=current[:12],
                upstream_commit=upstream_commit[:12],
                upstream_ref=upstream_ref,
                detail=f"HEAD is at or ahead of {upstream_ref}",
            )

        # Behind (or diverged). Count only if the object is present locally.
        rl = git("rev-list", "--count", f"{current}..{upstream_commit}")
        n = rl.stdout.strip()
        behind = int(n) if (rl.returncode == 0 and n.isdigit()) else 0
        n_str = str(behind) if behind else "some"
        return UpstreamStatus(
            status="behind",
            current_commit=current[:12],
            upstream_commit=upstream_commit[:12],
            upstream_ref=upstream_ref,
            commits_behind=behind,
            detail=(
                f"{n_str} commit(s) behind {upstream_ref} — the bug may already be "
                f"fixed upstream; re-verify against the latest checkout before claiming novel"
            ),
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return UpstreamStatus(detail=f"git check failed: {exc}")
