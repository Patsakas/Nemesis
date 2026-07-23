"""Preflight gate — the explicit line before which the baseline has not started.

Nothing here is technically required to run the suite. It exists so that when the
report is written months later there is one file answering "what was true at the
moment the baseline began", instead of a reconstruction from timestamps.

The output is `baseline.lock`, containing an **experiment identity**: a hash over
the NEMESIS commit, the uncommitted diff, the prompt/template contents, and the
resolved LLM configuration. Two runs share results only if they share that hash.

    python run_suite.py --preflight        # check, write baseline.lock
    python run_suite.py --preflight --force  # overwrite an existing lock
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REQUIRED_BINARIES = ("git", "clang", "cmake", "afl-fuzz", "nemesis")
MIN_FREE_GB = 20


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    fatal: bool = True          # a non-fatal failure warns and still locks


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "", *, fatal: bool = True) -> None:
        self.checks.append(Check(name, ok, detail, fatal))

    @property
    def blocking(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.fatal]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and not c.fatal]


def experiment_id(env: dict[str, Any]) -> str:
    """Hash the things that, if changed, make two runs different experiments."""
    nem = env.get("nemesis", {})
    llm = env.get("llm_config", {})
    parts = [
        nem.get("commit") or "",
        nem.get("diff_hash") or "",
        (env.get("prompts_and_templates") or {}).get("sha256") or "",
        json.dumps(llm.get("provider_chain", []), sort_keys=True),
        json.dumps({k: llm.get(k) for k in ("onboarder", "architect", "debugger")},
                   sort_keys=True),
    ]
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:16]


def run(here: Path, env: dict[str, Any], *, suite_path: Path,
        allow_warm_cache: bool = False) -> Preflight:
    pf = Preflight()

    # ── the frozen sample ───────────────────────────────────
    if suite_path.exists():
        suite = yaml.safe_load(suite_path.read_text(encoding="utf-8")) or {}
        repos = suite.get("repos", [])
        pinned = all(r.get("commit") for r in repos)
        pf.add("sample frozen", bool(repos) and suite.get("frozen") and pinned,
               f"{len(repos)} repos, all pinned={pinned}")
        pf.add("benchmark instance identified", bool(suite.get("benchmark_instance_id")),
               f"instance {suite.get('benchmark_instance_id')} "
               f"(oss-fuzz tree "
               f"{(suite.get('instance_inputs') or {}).get('oss_fuzz_projects_tree_sha', '?')[:8]}"
               f", pool {(suite.get('instance_inputs') or {}).get('pool_digest')})")
    else:
        pf.add("sample frozen", False, f"{suite_path.name} missing")

    pf.add("pool recorded", (here / "pool.json").exists(),
           "pool.json documents the attrition curve")
    pf.add("sample profiled", (here / "SAMPLE_PROFILE.md").exists(),
           "run characterise.py before the baseline, not after", fatal=False)

    # ── provenance ──────────────────────────────────────────
    nem = env.get("nemesis", {})
    pf.add("git state captured", bool(nem.get("commit")), f"commit={nem.get('commit', '')[:8]}")
    if nem.get("dirty"):
        pf.add("working tree clean", False,
               f"{nem.get('dirty_files')} uncommitted file(s), diff_hash="
               f"{nem.get('diff_hash')} — recorded, but nobody else can reproduce this",
               fatal=False)
    else:
        pf.add("working tree clean", True)

    # A diff dominated by line-ending noise makes experiment_id depend on which
    # git normalised the checkout, not on what changed. Two people on the same
    # commit would then lock different baselines.
    ws_only = nem.get("whitespace_only_files") or 0
    pf.add("diff free of line-ending noise", ws_only == 0,
           f"{ws_only} file(s) differ only in whitespace/line endings — "
           "add a .gitattributes (`* text=auto eol=lf`) or run with "
           "core.autocrlf matching the checkout, else diff_hash is not portable"
           if ws_only else (nem.get("diff_stat") or "clean"))

    pt = env.get("prompts_and_templates", {})
    pf.add("prompts/templates hashed", bool(pt.get("sha256")),
           f"{pt.get('files', 0)} files -> {pt.get('sha256')}")

    # ── LLM configuration ───────────────────────────────────
    llm = env.get("llm_config", {})
    pf.add("LLM config resolved", bool(llm.get("resolved")),
           llm.get("error", "config/default.yaml loaded"))

    chain = llm.get("provider_chain", [])
    pf.add("provider chain recorded", bool(chain),
           f"{len(chain)} providers, head={chain[0]['model'] if chain else '-'}")

    onboarder = llm.get("onboarder") or {}
    pf.add("onboarder model pinned", bool(onboarder.get("model")),
           f"{onboarder.get('model')} @ temp {onboarder.get('temperature')}")

    # "Some key exists" is the wrong question. If the *head* provider has no
    # credential the chain falls through on the first call and the run silently
    # becomes a different experiment than the one baseline.lock records.
    configured = env.get("llm_providers_configured", {})
    present_envs = {v.get("key_env") for v in configured.values() if v.get("present")}
    head_key = chain[0].get("api_key_env") if chain else None
    pf.add("head provider credential", bool(head_key and head_key in present_envs),
           f"{head_key} for {chain[0]['name']}" if chain else "no chain"
           if not head_key else
           f"{head_key} missing — the chain will fall through to provider 1")

    onboarder_key = onboarder.get("api_key_env")
    pf.add("onboarder credential", bool(onboarder_key and onboarder_key in present_envs),
           f"{onboarder_key} — the role this benchmark measures"
           if onboarder_key else "onboarder has no api_key_env")

    pf.add("providers with credentials", bool(present_envs),
           ", ".join(sorted(present_envs)) or "none configured")

    # Blocking by decision, not by necessity. The suite measures onboarding
    # *capability*; an answer served from a previous run's cache measures neither
    # the model nor the pipeline. Caching is a runtime optimisation and belongs in
    # later experiments with its policy stated, not in the baseline.
    cache = llm.get("cache", {})
    pf.add("LLM cache cold", not cache.get("warm"),
           f"{cache.get('entries', 0)} entries in {cache.get('dir')} — clear it or set "
           "cache_enabled: false; pass --allow-warm-cache to override deliberately",
           fatal=not allow_warm_cache)

    # ── toolchain ───────────────────────────────────────────
    tools = env.get("tools", {})
    for binary in REQUIRED_BINARIES:
        if binary == "nemesis":
            pf.add("nemesis on PATH", shutil.which("nemesis") is not None,
                   "run inside WSL with the venv active")
        else:
            pf.add(f"{binary} available", bool(tools.get(binary)),
                   str(tools.get(binary) or "not found — are you inside WSL?"))

    plat = env.get("platform", {})
    pf.add("running on Linux/WSL", plat.get("system") == "Linux",
           f"{plat.get('system')} (is_wsl={plat.get('is_wsl')})")

    free_gb = shutil.disk_usage(str(here)).free / 1e9
    pf.add("disk space", free_gb >= MIN_FREE_GB,
           f"{free_gb:.0f} GB free, need >= {MIN_FREE_GB} for 25 clones + builds")

    return pf


def write_lock(here: Path, env: dict[str, Any], pf: Preflight, suite: dict[str, Any]) -> Path:
    lock = {
        "locked_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # Two independent identities, both required to call a later run a
        # comparison: experiment_id is what NEMESIS was, benchmark_instance_id is
        # which repositories it was measured on.
        "experiment_id": experiment_id(env),
        "benchmark_instance_id": suite.get("benchmark_instance_id"),
        "instance_inputs": suite.get("instance_inputs"),
        "suite": suite.get("suite"),
        "repos": len(suite.get("repos", [])),
        "identity": {
            "nemesis_commit": env["nemesis"].get("commit"),
            "diff_hash": env["nemesis"].get("diff_hash"),
            "dirty": env["nemesis"].get("dirty"),
            "prompts_sha256": (env.get("prompts_and_templates") or {}).get("sha256"),
            "provider_chain": [p.get("model") for p in
                               env.get("llm_config", {}).get("provider_chain", [])],
            "onboarder_model": (env.get("llm_config", {}).get("onboarder") or {}).get("model"),
        },
        "checks": [
            {"name": c.name, "ok": c.ok, "fatal": c.fatal, "detail": c.detail}
            for c in pf.checks
        ],
        "warnings": [c.name for c in pf.warnings],
        "llm_cache_at_lock": (env.get("llm_config", {}) or {}).get("cache", {}),
        "note": (
            "The baseline starts here. Results produced under a different "
            "experiment_id are not comparable to it."
        ),
    }
    path = here / "baseline.lock"
    path.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    return path


def report(pf: Preflight) -> None:
    for c in pf.checks:
        mark = "  ok  " if c.ok else ("  !!  " if c.fatal else "  ..  ")
        print(f"{mark} {c.name:32s} {c.detail}")
