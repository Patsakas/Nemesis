"""CVE-history fetcher for prompt-injection bias (Tier 1 #1, 2026-05-07).

Background
----------
Mut4All (arxiv 2507.19275) showed that mining bug-report text for the
fields and code-paths a library has historically gotten wrong is high-
leverage signal for an LLM-driven mutator: the model biases its
mutations toward those fields rather than uniformly across the format.

Our adaptation: at onboarding time, query the NVD JSON API for recent
CVEs filed against the target library, cache the top N descriptions on
disk, and inject them as a `<bug_history>` block into the
mutator-synthesis (and later predicate-synthesis) prompts.

Generality
----------
Lookup uses NVD's `keywordSearch` parameter, which is fuzzy enough to
match "libpng" → CVE-2018-13785 and "lz4" → CVE-2021-3520 without per-
library CPE mappings. Failures (network down, NVD rate-limited, unknown
library) return an empty list — the calling stage falls back to its
existing prompt without any bug history. No manual per-library config
required.

Cache
-----
`config/targets/<lib>/cve_history.json` — refreshed only when missing
or `force_refresh=True`. CVEs change rarely; once-per-onboard is plenty.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT_S = 15

# NVD's keywordSearch returns results in undocumented order (empirically
# by-keyword-relevance, NOT by date). We can't restrict by publication
# range either — NVD caps pubStartDate/pubEndDate windows at 120 days.
# So we over-fetch a large page, then sort newest-first locally before
# truncating. resultsPerPage caps at 2000 unauthenticated; 200 is plenty
# for any one library.
_DEFAULT_FETCH_N = 200


def _cache_path(library_name: str, targets_dir: Path) -> Path:
    return targets_dir / library_name / "cve_history.json"


def _read_cache(path: Path) -> list[dict] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, list) else None


def _write_cache(path: Path, records: list[dict]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(records, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    except OSError:
        pass  # cache is best-effort


def _query_nvd(library_name: str, fetch_n: int) -> list[dict]:
    """Raw NVD query. Returns the `vulnerabilities` array or [] on failure."""
    params = urllib.parse.urlencode({
        "keywordSearch": library_name,
        "resultsPerPage": str(fetch_n),
    })
    url = f"{_NVD_API}?{params}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "nemesis-fuzzing-research/1.0"},
    )
    with urllib.request.urlopen(req, timeout=_DEFAULT_TIMEOUT_S) as r:
        payload = json.load(r)
    vulns = payload.get("vulnerabilities", [])
    return vulns if isinstance(vulns, list) else []


def _english_description(cve_obj: dict) -> str:
    for d in cve_obj.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return str(d.get("value", "")).strip()
    return ""


def _matches_library_cpe(cve_obj: dict, library_name: str) -> bool:
    """Return True iff some affected CPE's product field names this library.

    NVD's `keywordSearch` parameter matches anywhere in the CVE description,
    which surfaces CVEs about third-party libraries that merely USE the
    target (e.g. clickhouse/scylladb CVEs that mention "lz4" but are not
    about the lz4 C library itself). Those entries actively mislead the
    mutator-synthesis prompt — they describe attacks on the wrapper, not
    the library's own bug surface.

    We resolve this by walking the structured `configurations` field and
    accepting only CVEs that have at least one CPE whose product token
    matches the library name (or its `lib`-prefix variant). This filter
    is purely string-based — no per-library CPE allow-list needed.
    """
    target = library_name.lower()
    target_alt = target.removeprefix("lib") if target.startswith("lib") else f"lib{target}"
    accept = {target, target_alt}

    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for cpe_match in node.get("cpeMatch", []) or []:
                criteria = str(cpe_match.get("criteria", ""))
                # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                parts = criteria.split(":")
                if len(parts) < 5:
                    continue
                product = parts[4].lower()
                if product in accept:
                    return True
    return False


def _rank_references(refs: list[dict]) -> list[str]:
    """Prefer GitHub commit/PR links — those carry patch hunks the LLM can mine."""
    urls = [str(r.get("url", "")) for r in refs if r.get("url")]
    urls = [u for u in urls if u]

    def _key(u: str) -> int:
        ul = u.lower()
        if "github.com" in ul and "/commit/" in ul:
            return 0
        if "github.com" in ul and ("/pull/" in ul or "/issues/" in ul):
            return 1
        if "git" in ul and "commitdiff" in ul:
            return 2
        if "bugs.chromium.org" in ul or "bugzilla" in ul:
            return 3
        return 9

    urls.sort(key=_key)
    return urls


def fetch_cve_history(
    library_name: str,
    targets_dir: Path,
    max_cves: int = 3,
    force_refresh: bool = False,
    log: logging.Logger | None = None,
) -> list[dict]:
    """Return up to `max_cves` recent CVE records for `library_name`.

    Each record: {"id", "description", "references", "published"}.
    Cached at `<targets_dir>/<library_name>/cve_history.json`.
    On any error returns []; caller falls back to the unadorned prompt.
    """
    cache = _cache_path(library_name, targets_dir)
    if not force_refresh:
        cached = _read_cache(cache)
        if cached is not None:
            return cached[:max_cves]

    try:
        # Over-fetch heavily — NVD's keyword search isn't date-sorted, so we
        # need a wide pool to find the most-recent N after local sorting.
        vulns = _query_nvd(library_name, fetch_n=_DEFAULT_FETCH_N)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        if log:
            log.warning("cve_history.fetch_failed",
                        library=library_name, error=str(exc))
        return []

    records: list[dict] = []
    dropped_third_party = 0
    for v in vulns:
        cve = v.get("cve") if isinstance(v, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        desc = _english_description(cve)
        if not desc:
            continue
        if not _matches_library_cpe(cve, library_name):
            dropped_third_party += 1
            continue
        refs = _rank_references(cve.get("references", []) or [])
        records.append({
            "id": cve_id,
            "description": desc[:600],  # keep prompt budget bounded
            "references": refs[:3],
            "published": str(cve.get("published", "")),
        })

    if log and dropped_third_party:
        log.info("cve_history.filtered_third_party",
                 library=library_name, dropped=dropped_third_party)

    # Sort newest-first so the highest-quality (most-recent code-aware) signal
    # leads the prompt.
    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    records = records[:max_cves]

    _write_cache(cache, records)
    if log:
        log.info("cve_history.fetched",
                 library=library_name, count=len(records))
    return records


def format_bug_history_block(records: list[dict]) -> str:
    """Render a `<bug_history>` block for direct prompt injection.

    Returns "" when `records` is empty so callers can branch on truthiness.
    """
    if not records:
        return ""
    lines = [
        "<bug_history>",
        "Recent CVEs filed against this library. Use them to bias mutations",
        "toward the fields and code paths that have been historically buggy.",
        "Each entry summarises the trigger; the references point at the",
        "fixing commit when available.",
        "",
    ]
    for rec in records:
        lines.append(f"  {rec['id']} ({rec.get('published', '')[:10]}):")
        lines.append(f"    {rec['description']}")
        for ref in rec.get("references", [])[:2]:
            lines.append(f"    ref: {ref}")
        lines.append("")
    lines.append("</bug_history>")
    return "\n".join(lines)


def get_or_fetch(
    library_name: str,
    targets_dir: Path,
    max_cves: int = 3,
    log: logging.Logger | None = None,
) -> list[dict]:
    """Convenience: cache-first lookup, fall through to a single NVD query."""
    return fetch_cve_history(
        library_name=library_name,
        targets_dir=targets_dir,
        max_cves=max_cves,
        force_refresh=False,
        log=log,
    )
