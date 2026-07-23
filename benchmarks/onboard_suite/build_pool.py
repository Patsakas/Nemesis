#!/usr/bin/env python3
"""Build the frozen onboarding-benchmark suite from mechanical predicates.

The rules live in CRITERIA.md and were written before any repository was looked
at. This script only executes them. Nothing here consults NEMESIS: the tool under
evaluation must not choose its own exam set, so the pool comes from the GitHub API
and the sample from a hash, never from `nemesis scout`.

Two outputs, both committed:

  pool.json   every candidate that passed the predicates, with the metadata the
              decision was made on. Published so the sampling can be re-checked
              by anyone without re-querying GitHub.
  repos.yaml  the 25 selected repositories, pinned to exact commit SHAs. Frozen —
              see CRITERIA.md.

Rate limits: unauthenticated GitHub allows 10 search requests/minute and 60 core
requests/hour, which is not enough to build the pool in one pass. Set GITHUB_TOKEN
(a bare read-only PAT is sufficient) to lift both. The script throttles itself and
degrades to a slower run rather than failing when the token is absent.

Usage:
    python build_pool.py --stage pool     # query GitHub, write pool.json
    python build_pool.py --stage sample   # pool.json -> repos.yaml (offline)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent

# Fixed at suite creation. Changing it reshuffles the sample and invalidates every
# historical comparison, which is the entire point of pinning it here.
SALT = "nemesis-onboard-suite-v1"
SAMPLE_SIZE = 25

# CRITERIA.md predicates 3-5.
MAX_AGE_MONTHS = 24
STARS_MIN, STARS_MAX = 50, 5000
MAX_REPO_SIZE_KB = 50 * 1024

BUILD_ENTRY_POINTS = {"CMakeLists.txt", "configure.ac", "Makefile.am", "meson.build"}

API = "https://api.github.com"
_UA = "nemesis-onboard-benchmark"


# ── HTTP ────────────────────────────────────────────────────


def _load_env() -> None:
    """Read ``GITHUB_TOKEN`` from the repo ``.env`` if it is not already set.

    Deliberately a local re-implementation of ``nemesis.config.load_dotenv_file``
    rather than an import: CRITERIA.md promises the pool is reproducible from this
    file alone, so a third party checking the sampling must not need the NEMESIS
    package installed. A real shell env var always wins.
    """
    if os.environ.get("GITHUB_TOKEN"):
        return
    for env_path in (HERE / ".env", HERE.parent.parent / ".env", Path(".env")):
        if not env_path.is_file():
            continue
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip().removeprefix("export ").lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() != "GITHUB_TOKEN":
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            if val:
                os.environ["GITHUB_TOKEN"] = val
                return
        return


def _headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "User-Agent": _UA}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url: str, *, retries: int = 4) -> Any:
    """GET with backoff on the two failures that actually happen: secondary rate
    limiting (403 with a Retry-After) and transient 5xx."""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=_headers())
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429):
                wait = int(e.headers.get("Retry-After", 0) or 0)
                if not wait:
                    reset = e.headers.get("X-RateLimit-Reset")
                    wait = max(1, int(reset) - int(time.time())) if reset else 60
                wait = min(wait, 300)
                print(f"    rate limited, sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if 500 <= e.code < 600 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(2**attempt)
    return None


# ── predicate 7: the OSS-Fuzz exclusion set ─────────────────


def oss_fuzz_projects() -> tuple[set[str], set[str], dict[str, Any]]:
    """Return (project names, main_repo URLs) currently in OSS-Fuzz.

    Name matching alone is not enough — OSS-Fuzz names are frequently not the
    GitHub repo name (`libjpeg-turbo` vs `libjpeg_turbo`, vendored forks). The
    `main_repo` URL in each project.yaml is the reliable key, so both are used.
    """
    # The contents API silently caps a directory listing at 1000 entries and
    # gives no truncation signal. OSS-Fuzz has 1366 projects, so it returned a
    # neat 1000 and quietly dropped the alphabetical tail — zstd, zxing, zydis
    # and 363 others would have passed the "not already fuzzed" predicate. The
    # trees API returns the whole subtree in one request and reports truncation
    # explicitly, so the exclusion set can be trusted.
    # Pin the snapshot, not just the count. OSS-Fuzz gains projects continuously,
    # so "1366 projects" is only meaningful alongside the tree it came from — a
    # re-run in six months excludes a different universe, and without this the
    # two pools would look comparable when they are not.
    head = _get(f"{API}/repos/google/oss-fuzz/commits/master") or {}
    root = _get(f"{API}/repos/google/oss-fuzz/git/trees/master")
    projects_sha = next(
        (e["sha"] for e in (root or {}).get("tree", []) if e["path"] == "projects"), None)
    if not projects_sha:
        raise RuntimeError("cannot locate the oss-fuzz projects/ tree — refusing to "
                           "build a pool with an unverified exclusion set")
    tree = _get(f"{API}/repos/google/oss-fuzz/git/trees/{projects_sha}") or {}
    if tree.get("truncated"):
        raise RuntimeError("oss-fuzz projects/ tree came back truncated — the "
                           "exclusion set would be incomplete")
    names = {e["path"] for e in tree.get("tree", []) if e.get("type") == "tree"}

    print(f"  OSS-Fuzz projects: {len(names)}")

    # Resolving every project.yaml costs one request each. Do it via the git tree
    # in one shot instead, then fetch raw files only for the names we might hit.
    repos: set[str] = set()
    for name in sorted(names):
        raw = (
            "https://raw.githubusercontent.com/google/oss-fuzz/master/projects/"
            f"{name}/project.yaml"
        )
        try:
            req = urllib.request.Request(raw, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                meta = yaml.safe_load(r.read().decode()) or {}
        except Exception:  # noqa: BLE001 - a missing project.yaml must not abort the pool
            continue
        mr = str(meta.get("main_repo", "")).strip().rstrip("/")
        if mr:
            repos.add(_normalise_repo_url(mr))
    print(f"  OSS-Fuzz main_repo URLs resolved: {len(repos)}")

    provenance = {
        "source": "google/oss-fuzz",
        "head_commit": head.get("sha"),
        "head_committed_utc": (head.get("commit", {}).get("committer", {}) or {}).get("date"),
        "projects_tree_sha": projects_sha,
        "projects_count": len(names),
        "main_repo_urls_resolved": len(repos),
        "truncated": bool(tree.get("truncated")),
        "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": (
            "Exclusion universe is a snapshot. A pool built against a different "
            "projects_tree_sha excluded a different set and is not directly "
            "comparable."
        ),
    }
    return names, repos, provenance


def _normalise_repo_url(url: str) -> str:
    u = url.lower().removesuffix(".git").rstrip("/")
    for prefix in ("https://", "http://", "git://", "ssh://git@", "git@"):
        u = u.removeprefix(prefix)
    return u.replace("github.com:", "github.com/")


# ── predicates 1-6, 8 ───────────────────────────────────────


def search_candidates(max_pages: int = 10) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """GitHub repo search under predicates 1-4, 8.

    Search returns at most 1000 results per query. Banding the star range widens
    the frame but does NOT remove the cap — measured, every band except the top
    one saturates at exactly 1000. The frame is therefore "the 1000
    most-recently-updated repositories in each star band", not "every repository
    matching the predicates", and the per-band counts are recorded so that limit
    is visible in the artifact rather than only in this docstring.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_MONTHS * 30)).date()
    bands = [(50, 120), (121, 300), (301, 800), (801, 2000), (2001, 5000)]
    out: dict[str, dict[str, Any]] = {}
    per_band: dict[str, int] = {}

    for lo, hi in bands:
        band_key = f"{lo}-{hi}"
        per_band[band_key] = 0
        for page in range(1, max_pages + 1):
            q = (
                f"language:c stars:{lo}..{hi} pushed:>={cutoff}"
                " archived:false fork:false is:public"
            )
            url = (
                f"{API}/search/repositories?q={urllib.parse.quote(q)}"
                f"&per_page=100&page={page}&sort=updated&order=desc"
            )
            data = _get(url)
            items = (data or {}).get("items", [])
            if not items:
                break
            for it in items:
                out[it["full_name"]] = it
            per_band[band_key] += len(items)
            print(f"  stars {lo}-{hi} page {page}: +{len(items)} (pool {len(out)})")
            if len(items) < 100:
                break
            time.sleep(2 if os.environ.get("GITHUB_TOKEN") else 7)

    frame = {
        "bands": per_band,
        "search_result_cap": 1000,
        "saturated_bands": [b for b, n in per_band.items() if n >= 1000],
        "total_unique": len(out),
        "note": (
            "GitHub search returns at most 1000 results per query. Bands that hit "
            "that number were truncated, so the frame is the most-recently-updated "
            "1000 per band rather than every matching repository. Any claim from "
            "this benchmark is bounded by that frame."
        ),
    }
    return list(out.values()), frame


def root_build_entry(full_name: str, default_branch: str) -> str | None:
    """Predicate 6 — a recognised build entry point in the repo root."""
    tree = _get(f"{API}/repos/{full_name}/git/trees/{default_branch}")
    if not tree:
        return None
    for entry in tree.get("tree", []):
        if entry.get("type") == "blob" and entry.get("path") in BUILD_ENTRY_POINTS:
            return entry["path"]
    return None


def head_sha(full_name: str, default_branch: str) -> str | None:
    ref = _get(f"{API}/repos/{full_name}/commits/{default_branch}")
    return ref.get("sha") if ref else None


# ── stages ──────────────────────────────────────────────────


def build_pool() -> None:
    print("Fetching OSS-Fuzz exclusion set...")
    of_names, of_urls, of_provenance = oss_fuzz_projects()

    print("Searching candidates...")
    raw, frame = search_candidates()
    print(f"  raw candidates: {len(raw)}")

    # Attrition is part of the result. Reporting "25 repositories" without showing
    # how many thousands they were drawn from, and what removed the rest, leaves
    # the obvious question — whether the survivors were picked to suit — open.
    attrition = {
        "github_candidates": len(raw),
        "dropped_too_large": 0,
        "dropped_no_license": 0,
        "dropped_oss_fuzz": 0,
        "dropped_no_build_entry": 0,
        "dropped_no_commit": 0,
    }

    pool: list[dict[str, Any]] = []
    for i, r in enumerate(raw, 1):
        full = r["full_name"]
        name = r["name"].lower()

        if r.get("size", 0) > MAX_REPO_SIZE_KB:
            attrition["dropped_too_large"] += 1
            continue
        if not r.get("license"):
            attrition["dropped_no_license"] += 1
            continue
        if name in of_names or _normalise_repo_url(r["html_url"]) in of_urls:
            attrition["dropped_oss_fuzz"] += 1
            continue

        entry = root_build_entry(full, r["default_branch"])
        if not entry:
            attrition["dropped_no_build_entry"] += 1
            continue
        sha = head_sha(full, r["default_branch"])
        if not sha:
            attrition["dropped_no_commit"] += 1
            continue

        pool.append({
            "full_name": full,
            "clone_url": r["clone_url"],
            "default_branch": r["default_branch"],
            "commit": sha,
            "stars": r["stargazers_count"],
            "size_kb": r["size"],
            "pushed_at": r["pushed_at"],
            "license": (r.get("license") or {}).get("spdx_id"),
            "build_entry": entry,
            "description": (r.get("description") or "")[:200],
        })
        print(f"  [{i}/{len(raw)}] kept {full} ({entry})")
        if not os.environ.get("GITHUB_TOKEN"):
            time.sleep(1)

    (HERE / "pool.json").write_text(
        json.dumps(
            {
                "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "criteria": "see CRITERIA.md",
                "salt": SALT,
                "count": len(pool),
                "search_frame": frame,
                "attrition": {**attrition, "final_pool": len(pool),
                              "sample_size": SAMPLE_SIZE},
                "oss_fuzz_exclusion": of_provenance,
                "candidates": sorted(pool, key=lambda c: c["full_name"]),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nAttrition:")
    print(f"  GitHub candidates          {attrition['github_candidates']:6d}")
    for k in ("dropped_too_large", "dropped_no_license", "dropped_oss_fuzz",
              "dropped_no_build_entry", "dropped_no_commit"):
        print(f"  {k:26s} {-attrition[k]:6d}")
    print(f"  {'final pool':26s} {len(pool):6d}")
    print(f"  {'sample':26s} {SAMPLE_SIZE:6d}")
    print(f"\nPool: {len(pool)} candidates -> pool.json")


def _assert_pool_valid(data: dict[str, Any], path: Path) -> None:
    """Hard gate: refuse to sample from a pool that fails any integrity check."""
    problems = pool_problems(data)
    if problems:
        sys.exit(
            f"refusing to sample from {path.name}:\n  - "
            + "\n  - ".join(problems)
            + "\n\nRebuild with: python build_pool.py --stage pool"
        )


def pool_problems(data: dict[str, Any]) -> list[str]:
    """Every integrity complaint about a pool, as a list. Empty means sound.

    Split out from the hard gate so the same checks can be *reported* by
    characterise.py without terminating — one implementation, two presentations.
    A second copy of these rules for display purposes would be free to drift
    from the ones that actually block a freeze.

    A naming convention is not a guard — a stale `pool.json` sitting on disk is
    read just as happily as a good one. Pools produced before the OSS-Fuzz
    exclusion fix look structurally identical to correct ones: same schema, same
    candidate objects, plausible count. The only difference is the provenance
    block they lack, so that is what gets checked.
    """
    problems = []
    if data.get("status") == "invalid" or data.get("do_not_use"):
        problems.append(f"marked unusable: {data.get('reason', 'no reason given')}")

    excl = data.get("oss_fuzz_exclusion")
    if not excl:
        problems.append(
            "no oss_fuzz_exclusion provenance — built before the exclusion-set fix, "
            "when the contents API silently capped the project list at 1000 of 1366 "
            "and the pool could contain already-fuzzed repositories")
    else:
        if not excl.get("projects_tree_sha"):
            problems.append("oss_fuzz_exclusion has no projects_tree_sha")
        if excl.get("truncated"):
            problems.append("oss_fuzz_exclusion was truncated")
        if not excl.get("projects_count"):
            problems.append("oss_fuzz_exclusion has no projects_count")

    if "attrition" not in data:
        problems.append("no attrition record — the dataset audit cannot be generated")

    if "search_frame" not in data:
        problems.append(
            "no search_frame — the pool cannot state which population it was drawn "
            "from. GitHub search caps every query at 1000 results, so the frame is "
            "the most-recently-updated 1000 per star band, and a pool that does not "
            "record that cannot bound its own claim")

    # Internal consistency: every block must describe the same rebuild. All of
    # them are written in one pass at the end of build_pool(), so a mismatch
    # means the file was hand-edited or assembled from two runs — in which case
    # the provenance chain is decorative rather than real.
    frame, attr = data.get("search_frame") or {}, data.get("attrition") or {}
    if frame and attr:
        seen, counted = frame.get("total_unique"), attr.get("github_candidates")
        if seen is not None and counted is not None and seen != counted:
            problems.append(
                f"search_frame.total_unique ({seen}) != attrition.github_candidates "
                f"({counted}) — these count the same set and must agree; the blocks "
                "come from different runs")
    if attr:
        drops = sum(v for k, v in attr.items() if k.startswith("dropped_"))
        expected = attr.get("github_candidates", 0) - drops
        if attr.get("final_pool") is not None and expected != attr["final_pool"]:
            problems.append(
                f"attrition does not balance: {attr.get('github_candidates')} raw "
                f"- {drops} dropped = {expected}, but final_pool is "
                f"{attr['final_pool']} — a candidate was discarded without being "
                "counted, so the audit funnel would misreport why")
        if len(data.get("candidates", [])) != attr.get("final_pool"):
            problems.append(
                f"final_pool ({attr.get('final_pool')}) != candidates recorded "
                f"({len(data.get('candidates', []))})")

    if excl and data.get("generated_utc") and excl.get("fetched_utc"):
        try:
            gen = datetime.fromisoformat(data["generated_utc"])
            fetched = datetime.fromisoformat(excl["fetched_utc"])
            gap_h = (gen - fetched).total_seconds() / 3600
            if gap_h < 0:
                problems.append(
                    "oss_fuzz_exclusion.fetched_utc is after generated_utc — the "
                    "exclusion set was not the one used to build this pool")
            elif gap_h > 6:
                problems.append(
                    f"exclusion set fetched {gap_h:.1f}h before the pool was written; "
                    "too far apart to be the same run")
        except ValueError:
            problems.append("unparseable timestamps in pool.json")

    return problems


def _rank(full_name: str) -> str:
    return hashlib.sha256((full_name + SALT).encode()).hexdigest()


def sample() -> None:
    """Content-addressed draw. Offline and idempotent: same pool, same 25."""
    pool_path = HERE / "pool.json"
    if not pool_path.exists():
        sys.exit("pool.json missing — run --stage pool first")

    data = json.loads(pool_path.read_text(encoding="utf-8"))
    _assert_pool_valid(data, pool_path)
    cands = data["candidates"]
    if len(cands) < SAMPLE_SIZE:
        sys.exit(f"pool has {len(cands)} candidates, need >= {SAMPLE_SIZE}")

    ordered = sorted(cands, key=lambda c: _rank(c["full_name"]))
    rank_of = {c["full_name"]: i for i, c in enumerate(ordered)}
    chosen = ordered[:SAMPLE_SIZE]
    chosen.sort(key=lambda c: c["full_name"])

    # The sample is only reproducible if all three inputs match. Hashing them
    # together turns "I re-ran the benchmark" into a checkable claim: a different
    # exclusion snapshot, a different pool, or a different salt all yield a
    # different instance, even when the script and the sample size are identical.
    excl = data.get("oss_fuzz_exclusion", {})
    pool_digest = hashlib.sha256(
        "\x00".join(c["full_name"] + ":" + c["commit"] for c in cands).encode()
    ).hexdigest()[:16]
    instance_id = hashlib.sha256(
        "\x00".join([excl.get("projects_tree_sha") or "", pool_digest, SALT]).encode()
    ).hexdigest()[:16]

    # Independent re-verification, not a re-read of the pool. The exclusion bug
    # lived in pool construction, so a check that trusts pool.json would have
    # missed it entirely. This re-queries OSS-Fuzz and tests the 25 selected
    # repositories directly — construction-time exclusion and freeze-time
    # validation now have to agree.
    print("Re-verifying OSS-Fuzz exclusion against the selected 25...")
    fresh_names, fresh_urls, fresh_prov = oss_fuzz_projects()
    leaked = [
        c["full_name"] for c in chosen
        if c["full_name"].split("/")[1].lower() in fresh_names
        or _normalise_repo_url("https://github.com/" + c["full_name"]) in fresh_urls
    ]
    if leaked:
        sys.exit(
            "OSS-Fuzz leakage in the selected sample — refusing to freeze:\n  - "
            + "\n  - ".join(leaked)
            + "\n\nThe pool was built against a stale or incomplete exclusion set. "
              "Rebuild with --stage pool."
        )
    print(f"  clean: 0/{len(chosen)} selected repos are in OSS-Fuzz "
          f"({fresh_prov['projects_count']} projects checked)")

    out = {
        "suite": "nemesis-onboard-v1",
        "frozen": True,
        "benchmark_instance_id": instance_id,
        "oss_fuzz_leakage_check": {
            "performed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "method": "independent re-query at freeze time, not a re-read of pool.json",
            "projects_checked": fresh_prov["projects_count"],
            "projects_tree_sha": fresh_prov["projects_tree_sha"],
            "leaked": [],
            "matches_pool_snapshot":
                fresh_prov["projects_tree_sha"] == excl.get("projects_tree_sha"),
        },
        "instance_inputs": {
            "oss_fuzz_projects_tree_sha": excl.get("projects_tree_sha"),
            "pool_digest": pool_digest,
            "salt": SALT,
        },
        "salt": SALT,
        "pool_size": len(cands),
        "pool_generated_utc": data["generated_utc"],
        "note": (
            "Frozen suite — see CRITERIA.md. Do not add, remove or re-pin entries: "
            "every NEMESIS version must run against these exact commits for the "
            "numbers to be comparable. Comparability requires all three of "
            "oss_fuzz_projects_tree_sha, pool_digest and salt to be unchanged — "
            "together they are benchmark_instance_id. A run against a different "
            "instance_id measured different repositories and is a new benchmark, "
            "not a re-run of this one."
        ),
        # selection_context is recorded for *post-hoc* analysis only — after the
        # baseline, the first question is "what did the failures have in common",
        # and answering it needs the covariates alongside the outcome. None of it
        # influences selection, which is already fixed by the hash ordering.
        #
        # Measured facts only. Derived signals like "does this look like a
        # parser" stay in characterise.py: a second implementation of a heuristic
        # is free to drift from the first, and then two artifacts disagree about
        # the same repository.
        "repos": [
            {
                "full_name": c["full_name"],
                "clone_url": c["clone_url"],
                "commit": c["commit"],
                "build_entry": c["build_entry"],
                "stars": c["stars"],
                "license": c["license"],
                "selection_context": {
                    "stars": c["stars"],
                    "size_kb": c["size_kb"],
                    "pushed_at": c["pushed_at"],
                    "build_entry": c["build_entry"],
                    "license": c["license"],
                    "description": c.get("description", ""),
                    # Position in the deterministic draw over the whole pool.
                    # A low rank is not "better" — it only shows where the hash
                    # placed this repository, which makes the draw auditable.
                    "pool_rank": rank_of[c["full_name"]],
                    "pool_size": len(cands),
                },
            }
            for c in chosen
        ],
    }
    (HERE / "repos.yaml").write_text(
        yaml.safe_dump(out, sort_keys=False, width=100), encoding="utf-8"
    )
    print(f"Selected {len(chosen)}/{len(cands)} -> repos.yaml")
    for c in chosen:
        print(f"  {c['full_name']:45s} {c['build_entry']:16s} {c['stars']:>5}*")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", choices=("pool", "sample"), required=True)
    args = ap.parse_args()
    if args.stage == "pool":
        _load_env()
        if not os.environ.get("GITHUB_TOKEN"):
            print(
                "warning: no GITHUB_TOKEN — unauthenticated limits (10 searches/min,\n"
                "         60 core requests/hour) make this stage take hours.\n"
                "         Add GITHUB_TOKEN=... to .env and re-run.\n",
                file=sys.stderr,
            )
        build_pool()
    else:
        sample()


if __name__ == "__main__":
    main()
