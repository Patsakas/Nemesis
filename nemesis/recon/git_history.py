"""Git-history analysis for target ranking and LLM context.

Two signals, both cheap and both well-supported by the empirical bug-prediction
literature:

  **Churn** — code that changed recently is more likely to carry a fresh bug
  than code that has been untouched for a decade. A parser last modified two
  months ago has had far less exposure than one stable since 2009.

  **Past fixes** — bugs cluster. A file that has already needed "fix
  out-of-bounds read in chunk parser" is a better place to look for the *next*
  out-of-bounds read than a file with a clean history. This is the strongest
  single signal in the file-level defect-prediction work.

Both are derived from ONE `git log` pass over the whole repository rather than
a per-function `git log -L`: recon ranks hundreds of candidates, and spawning
a git process per candidate would dominate stage-1 runtime. File granularity
is a deliberate trade — it's what the underlying research measures anyway, and
it costs one subprocess instead of hundreds.

Every entry point degrades to "no signal" (empty index, zero bonus) rather than
raising: source trees arrive as tarballs or shallow copies with no .git as
often as they arrive as clones, and a missing history must never fail a run.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from nemesis.logging import get_logger

# Commit-subject patterns that mark a bug fix — especially a memory-safety one.
# Deliberately broad: a false positive costs a small ranking nudge, while a
# missed security fix loses the strongest signal we have about a file.
_FIX_SUBJECT_RE = re.compile(
    r"\b("
    r"fix(e[sd])?|bug|regression|crash|segfault|hang"
    r"|overflow|underflow|out[- ]of[- ]bounds|oob"
    r"|use[- ]after[- ]free|uaf|double[- ]free|memory[- ]leak"
    r"|null[- ]deref\w*|invalid[- ]read|invalid[- ]write"
    r"|sanitiz\w*|asan|ubsan|msan|oss-fuzz|fuzz\w*"
    r"|cve-\d{4}-\d+|security|vulnerab\w*"
    r")\b",
    re.IGNORECASE,
)

# Record separator: git subjects are single-line and cannot contain \x01, so a
# leading \x01 unambiguously marks a commit header even when a subject happens
# to look like "abc1234 1699999999 something".
_REC = "\x01"

_SECONDS_PER_DAY = 86400.0


@dataclass
class FileHistory:
    """Per-file summary of what git knows about a source file."""

    path: str
    commit_count: int = 0
    last_change_days: float | None = None  # None → never seen in the window
    fix_subjects: list[str] = field(default_factory=list)
    recent_subjects: list[str] = field(default_factory=list)


class GitHistoryIndex:
    """Per-file churn and fix history, built from a single `git log` pass.

    Use `GitHistoryIndex.build(source_root)`; it never raises. An index built
    from a non-repo (or a git that timed out) is empty and scores everything
    zero, so callers need no special-casing.
    """

    def __init__(self, files: dict[str, FileHistory] | None = None,
                 available: bool = False) -> None:
        self._files = files or {}
        self.available = available
        self.log = get_logger("recon.git_history")

    # ── Construction ─────────────────────────────────────────

    @classmethod
    def build(
        cls,
        source_root: str | Path,
        months: int = 24,
        max_commits: int = 4000,
        timeout: int = 30,
    ) -> "GitHistoryIndex":
        """Walk `git log` once and index every file it touched.

        `months` bounds how far back "recent" reaches; `max_commits` bounds the
        work on repositories with very deep histories (libtiff and libxml2 both
        carry 20+ years of commits). Both caps only ever cost signal on old
        code, which is exactly the code the churn signal deprioritizes anyway.
        """
        log = get_logger("recon.git_history")
        root = Path(source_root)
        if not (root / ".git").exists():
            log.debug("git_history.not_a_repo", path=str(root))
            return cls()

        try:
            result = subprocess.run(
                [
                    "git", "-C", str(root), "log",
                    f"--since={months}.months.ago",
                    f"-n{max_commits}",
                    f"--format={_REC}%h %ct %s",
                    "--name-only",
                    # Renames would otherwise report the file under both names
                    # and double-count its churn.
                    "--no-renames",
                ],
                capture_output=True, text=True, timeout=timeout,
                errors="replace",
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            log.warning("git_history.failed", error=str(exc), path=str(root))
            return cls()

        if result.returncode != 0:
            log.warning(
                "git_history.git_error",
                path=str(root), stderr=(result.stderr or "")[-200:],
            )
            return cls()

        files = cls._parse_log(result.stdout, now=time.time())
        log.info(
            "git_history.indexed",
            path=str(root), files=len(files),
            fix_files=sum(1 for f in files.values() if f.fix_subjects),
        )
        return cls(files, available=bool(files))

    @staticmethod
    def _parse_log(stdout: str, now: float) -> dict[str, FileHistory]:
        """Parse `--format=\\x01%h %ct %s --name-only` output into per-file entries."""
        files: dict[str, FileHistory] = {}
        cur_ts: float | None = None
        cur_line = ""
        is_fix = False

        for raw in stdout.splitlines():
            if raw.startswith(_REC):
                header = raw[len(_REC):]
                parts = header.split(" ", 2)
                if len(parts) < 3:
                    # Merge commits with an empty subject, or a truncated line.
                    cur_ts, cur_line, is_fix = None, "", False
                    continue
                sha, ts_str, subject = parts
                try:
                    cur_ts = float(ts_str)
                except ValueError:
                    cur_ts = None
                age_days = (now - cur_ts) / _SECONDS_PER_DAY if cur_ts else 0.0
                cur_line = f"{sha} ({age_days:.0f}d ago) {subject}"
                is_fix = bool(_FIX_SUBJECT_RE.search(subject))
                continue

            path = raw.strip()
            if not path or cur_ts is None:
                continue

            entry = files.get(path)
            if entry is None:
                entry = FileHistory(path=path)
                files[path] = entry
            entry.commit_count += 1
            age_days = (now - cur_ts) / _SECONDS_PER_DAY
            # git log is newest-first, so the first sighting is the latest change.
            if entry.last_change_days is None or age_days < entry.last_change_days:
                entry.last_change_days = age_days
            # Cap the per-file lists: a hot file can appear in hundreds of
            # commits and these strings end up in an LLM prompt.
            if is_fix and len(entry.fix_subjects) < 10:
                entry.fix_subjects.append(cur_line)
            elif not is_fix and len(entry.recent_subjects) < 5:
                entry.recent_subjects.append(cur_line)

        return files

    # ── Lookup ───────────────────────────────────────────────

    def for_file(self, rel_path: str) -> FileHistory | None:
        """History for a repo-relative path, tolerating path-shape mismatches.

        Introspector reports paths in several shapes for the same file
        ("/src/libpng/png.c", "./png.c", "png.c") while git always reports
        repo-relative. Exact match first, then a unique basename match — a
        basename that is ambiguous within the repo (several `util.c`) is
        rejected rather than guessed, since attributing another file's fix
        history to this target is worse than having no signal.
        """
        if not self._files:
            return None
        norm = rel_path.replace("\\", "/").lstrip("./")
        if norm in self._files:
            return self._files[norm]
        # Suffix match handles the "/src/<project>/png.c" prefix Introspector
        # adds for OSS-Fuzz builds.
        suffix_hits = [f for p, f in self._files.items() if p.endswith("/" + norm)]
        if len(suffix_hits) == 1:
            return suffix_hits[0]
        base = norm.rsplit("/", 1)[-1]
        base_hits = [f for p, f in self._files.items() if p.rsplit("/", 1)[-1] == base]
        if len(base_hits) == 1:
            return base_hits[0]
        return None

    def score_bonus(
        self,
        rel_path: str,
        recency_bonus: float = 3.0,
        fix_bonus: float = 1.5,
        fix_bonus_cap: float = 4.5,
    ) -> float:
        """Ranking bonus for a file, on the same scale as the other recon signals.

        Sized deliberately below the complexity term (max 15): history is a
        genuine prior, but it should reorder comparable candidates rather than
        float an untouched trivial function above a complex parser.
        """
        hist = self.for_file(rel_path)
        if hist is None:
            return 0.0
        bonus = 0.0
        days = hist.last_change_days
        if days is not None:
            if days <= 90:
                bonus += recency_bonus
            elif days <= 365:
                bonus += recency_bonus / 2.0
        if hist.fix_subjects:
            bonus += min(len(hist.fix_subjects) * fix_bonus, fix_bonus_cap)
        return bonus

    def context_lines(self, rel_path: str, limit: int = 8) -> list[str]:
        """Human-readable history lines for the LLM analysis context.

        Fix commits come first: when the budget truncates this list, "previously
        fixed an OOB read here" is worth far more to the analysis than "bumped
        the copyright year".
        """
        hist = self.for_file(rel_path)
        if hist is None:
            return []
        lines: list[str] = []
        if hist.last_change_days is not None:
            lines.append(
                f"# {hist.path}: {hist.commit_count} commit(s) in window, "
                f"last changed {hist.last_change_days:.0f} days ago"
            )
        lines.extend(hist.fix_subjects)
        lines.extend(hist.recent_subjects)
        return lines[:limit]
