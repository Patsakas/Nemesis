"""Capture the toolchain a benchmark run happened on.

"Why did it fail for me and not for you" is the first question anyone asks of a
build-heavy benchmark, and without this file it is unanswerable. Written once per
run, next to the results, never edited afterwards.

Deliberately records *which* LLM providers are configured and which models are
selected, never the keys themselves — this file is meant to be committed.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Tools whose version can change a build outcome. Each entry is
# (binary, args, regex to pull a version out of the output).
_TOOLS: list[tuple[str, list[str], str]] = [
    ("clang", ["--version"], r"version\s+(\S+)"),
    ("gcc", ["--version"], r"\)\s+(\S+)"),
    ("ld", ["--version"], r"([\d.]+)\s*$"),
    ("cmake", ["--version"], r"version\s+(\S+)"),
    ("make", ["--version"], r"Make\s+(\S+)"),
    ("meson", ["--version"], r"(\S+)"),
    ("autoconf", ["--version"], r"autoconf\)\s+(\S+)"),
    ("pkg-config", ["--version"], r"(\S+)"),
    ("git", ["--version"], r"version\s+(\S+)"),
    ("afl-fuzz", ["-h"], r"afl-fuzz\+*\s+([\d.]+\S*)"),
    ("afl-clang-fast", ["--version"], r"version\s+(\S+)"),
    ("afl-cmin", ["-h"], r"([\d.]+\S*)"),
]

# Env vars that change what the pipeline does. Values are recorded only when they
# are not secret; key-shaped variables are reduced to a presence flag.
_SECRET_HINT = re.compile(r"KEY|TOKEN|SECRET|PASSWORD", re.I)
_RELEVANT_ENV = re.compile(r"^(NEMESIS_|AFL_|ASAN_|UBSAN_|MSAN_|CC$|CXX$|CFLAGS$|LDFLAGS$)")


def _probe(binary: str, args: list[str], pattern: str) -> str | None:
    try:
        p = subprocess.run([binary, *args], capture_output=True, text=True,
                           timeout=20, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    blob = (p.stdout or "") + (p.stderr or "")
    if not blob.strip():
        return None
    m = re.search(pattern, blob, re.M)
    return m.group(1) if m else blob.strip().splitlines()[0][:80]


def _git(repo: Path, args: list[str]) -> str | None:
    try:
        p = subprocess.run(["git", *args], cwd=str(repo), capture_output=True,
                           text=True, timeout=20, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    return p.stdout.strip() or None


def _nemesis_version(root: Path) -> dict[str, Any]:
    """Pin the NEMESIS revision under test.

    `dirty` matters more than the SHA: a benchmark run against uncommitted
    changes cannot be reproduced by anyone, so the flag has to survive into the
    results rather than being noticed later.

    When the tree *is* dirty the diff is fingerprinted rather than stored — a
    hash plus `--stat` is enough to prove two runs used the same working tree,
    without committing scratch files or copying source into the results.
    """
    sha = _git(root, ["rev-parse", "HEAD"])
    status = _git(root, ["status", "--porcelain"])
    out: dict[str, Any] = {
        "commit": sha,
        "branch": _git(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": bool(status) if status is not None else None,
        "dirty_files": len(status.splitlines()) if status else 0,
        "diff_hash": None,
        "diff_stat": None,
    }
    if status:
        diff = _git(root, ["diff", "HEAD"]) or ""
        out["diff_hash"] = hashlib.sha256(diff.encode()).hexdigest()[:16] if diff else None
        stat = _git(root, ["diff", "--stat", "HEAD"])
        out["diff_stat"] = stat.splitlines()[-1].strip() if stat else None

        # Line-ending drift makes diff_hash environment-dependent. This repo has
        # no .gitattributes, so Windows git (core.autocrlf=true) and WSL git
        # (unset) disagree about the same working tree: one reports 2 modified
        # files, the other 30 with ~11k phantom line changes. Since diff_hash
        # feeds the experiment identity, the discrepancy has to be visible rather
        # than silently baked into the hash.
        ws_stat = _git(root, ["diff", "--ignore-all-space", "--stat", "HEAD"])
        out["diff_stat_ignoring_whitespace"] = (
            ws_stat.splitlines()[-1].strip() if ws_stat else None)
        out["whitespace_only_files"] = _count_files(stat) - _count_files(ws_stat)
    return out


def _count_files(stat: str | None) -> int:
    """Files touched, from the summary line of `git diff --stat`."""
    if not stat:
        return 0
    m = re.search(r"(\d+) files? changed", stat.splitlines()[-1])
    return int(m.group(1)) if m else 0


def _tree_hash(*dirs: Path) -> dict[str, Any]:
    """Content hash over the prompt and template files.

    Prompts and Jinja templates decide what the LLM is asked, and editing one
    changes results without changing any Python. They are often uncommitted while
    being tuned, so a git SHA does not pin them — the file contents do.
    """
    h = hashlib.sha256()
    files = 0
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            # Templates here are C scaffolds and headers as well as prose prompts,
            # so the set is deliberately wide — anything that shapes what the LLM
            # is asked or what it is asked to fill in.
            if not p.is_file() or p.suffix not in {
                ".md", ".txt", ".j2", ".jinja", ".yaml", ".yml", ".c", ".h", ".cc", ".py"
            }:
                continue
            h.update(str(p.relative_to(d)).encode())
            h.update(p.read_bytes())
            files += 1
    return {"files": files, "sha256": h.hexdigest()[:16] if files else None}


def _llm_cache_state(llm: Any) -> dict[str, Any]:
    """Record whether the LLM response cache was warm.

    This is the difference between a run that queried the models and one that
    replayed earlier answers. A baseline taken against a warm cache is not
    comparable to a cold re-run months later, and the entry count is the only
    cheap way to notice.
    """
    enabled = bool(getattr(llm, "cache_enabled", False))
    raw_dir = getattr(llm, "cache_dir", "") or ""
    d = Path(os.path.expanduser(str(raw_dir))) if raw_dir else None
    entries = 0
    if d and d.is_dir():
        entries = sum(1 for p in d.rglob("*") if p.is_file())
    return {
        "enabled": enabled,
        "dir": str(raw_dir),
        "exists": bool(d and d.is_dir()),
        "entries": entries,
        "warm": bool(enabled and entries > 0),
    }


def _llm_config(root: Path) -> dict[str, Any]:
    """Freeze which models were actually used.

    Without this, a re-run months later cannot separate "NEMESIS improved" from
    "the provider silently changed the model behind an alias" — the single most
    likely way this benchmark's history becomes uninterpretable.
    """
    out: dict[str, Any] = {"resolved": False}
    prev_cwd = os.getcwd()
    try:
        sys.path.insert(0, str(root))
        from nemesis.config import load_config  # noqa: PLC0415

        # load_config() resolves config/default.yaml relative to the working
        # directory. Called from anywhere else it silently falls back to the
        # bare Pydantic defaults (anthropic/claude-sonnet-4) instead of the
        # configured NVIDIA chain — recording a model that was never used is
        # worse than recording none, so pin the cwd for the duration.
        os.chdir(root)
        cfg = load_config()
        llm = getattr(cfg, "llm", None)
        if llm is None:
            out["error"] = "config has no 'llm' section"
            return out
        out["resolved"] = True
        # The fallback chain is ordered and the order is load-bearing: a run that
        # fell through to provider 4 is not the same experiment as one served by
        # provider 1, so the position is recorded with the name.
        out["provider_chain"] = [
            {"position": i, "name": getattr(p, "name", None),
             "model": getattr(p, "model", None),
             "base_url": getattr(p, "base_url", None),
             "api_key_env": getattr(p, "api_key_env", None),
             "reasoning_effort": getattr(p, "reasoning_effort", None) or None}
            for i, p in enumerate(getattr(llm, "providers", []) or [])
        ]
        # `onboarder` is the role this benchmark actually exercises — swapping that
        # model changes the T1 number directly, so it must be pinned by name.
        for role in ("onboarder", "architect", "debugger"):
            rc = getattr(llm, role, None)
            if rc is not None:
                out[role] = {
                    "name": getattr(rc, "name", None),
                    "model": getattr(rc, "model", None),
                    "temperature": getattr(rc, "temperature", None),
                    "max_tokens": getattr(rc, "max_tokens", None),
                    "context_window": getattr(rc, "context_window", None),
                    "api_key_env": getattr(rc, "api_key_env", None),
                    "reasoning_effort": getattr(rc, "reasoning_effort", None) or None,
                }
        out["defaults"] = {
            "provider": getattr(llm, "provider", None),
            "model": getattr(llm, "model", None),
            "fallback_model": getattr(llm, "fallback_model", None),
            "temperature": getattr(llm, "temperature", None),
            "max_tokens": getattr(llm, "max_tokens", None),
        }
        out["cache"] = _llm_cache_state(llm)
    except Exception as exc:  # noqa: BLE001 - config problems must not abort a run
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        os.chdir(prev_cwd)
    return out


def _dotenv_keys(root: Path) -> set[str]:
    """Names of keys defined in .env — names only, values never read out.

    NEMESIS loads .env itself at startup, so a key that exists only there is
    still live at run time. Probing os.environ alone under-reports which
    providers are usable and would let a preflight pass while the head of the
    fallback chain has no credential.
    """
    names: set[str] = set()
    for p in (root / ".env", Path(".env")):
        if not p.is_file():
            continue
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip().removeprefix("export ").lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if val.strip().strip("'\""):
                names.add(key.strip())
        break
    return names


def _llm_providers(root: Path) -> dict[str, Any]:
    """Which provider credentials exist — never the credentials themselves."""
    known = ["NVIDIA_API_KEY", "GROQ_API_KEY", "CEREBRAS_API_KEY", "GOOGLE_AI_KEY",
             "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    from_env_file = _dotenv_keys(root)
    out: dict[str, Any] = {}
    for k in known:
        label = k.removesuffix("_API_KEY").removesuffix("_AI_KEY").lower()
        out[label] = {
            "key_env": k,
            "present": bool(os.environ.get(k, "").strip()) or k in from_env_file,
            "source": "environ" if os.environ.get(k, "").strip()
            else ("dotenv" if k in from_env_file else None),
        }
    return out


def _relevant_env() -> dict[str, str]:
    out = {}
    for k, v in sorted(os.environ.items()):
        if not _RELEVANT_ENV.search(k):
            continue
        out[k] = "<set>" if _SECRET_HINT.search(k) else v[:200]
    return out


def capture(nemesis_root: Path) -> dict[str, Any]:
    return {
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "uname": " ".join(platform.uname()),
            # WSL is not incidental here: the whole toolchain lives there, and a
            # native-Linux run is not the same environment.
            "is_wsl": "microsoft" in platform.release().lower(),
            "cpu_count": os.cpu_count(),
        },
        "python": {
            "version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "tools": {name: _probe(name, args, pat) for name, args, pat in _TOOLS},
        "nemesis": _nemesis_version(nemesis_root),
        "llm_providers_configured": _llm_providers(nemesis_root),
        "llm_config": _llm_config(nemesis_root),
        "prompts_and_templates": _tree_hash(
            nemesis_root / "prompts", nemesis_root / "nemesis" / "templates"),
        "env": _relevant_env(),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(capture(Path(__file__).resolve().parent.parent.parent), indent=2))
