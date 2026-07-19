"""
NEMESIS Target Scout — find CVE-discovery candidates worth onboarding.

The discovery strategy that actually has odds of a NEW bug is: target C/C++
parser/decoder libraries that are NOT already fuzzed 24/7 by OSS-Fuzz, and that
expose a round-trip (encode/decode) surface where NEMESIS's differential oracle
sees bugs plain-ASAN OSS-Fuzz cannot.

This module:
  1. fetches the public OSS-Fuzz project list (the exclusion set),
  2. searches GitHub for candidate C/C++ parser/codec libraries,
  3. scores each on fuzzability × un-fuzzed-ness × round-trip potential,
  4. returns a ranked candidate list (+ an onboard command per candidate).

Network calls are best-effort (httpx). The scoring logic is pure and unit
tested; an optional GITHUB_TOKEN (env or .env) raises GitHub rate limits.
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from nemesis.logging import get_logger

log = get_logger("recon.scout")

# ── Keyword vocabularies (lowercase) ────────────────────────────────────────

# A library must show a parser/decoder surface to be a candidate at all.
_PARSER_TOKENS = (
    "parser", "parse", "decoder", "decode", "codec", "deserialize",
    "deserializer", "reader", "loader", "demux", "unmarshal", "lexer",
    "format", "interpreter",
)
# Handling untrusted/structured input → security-relevant attack surface.
_UNTRUSTED_INPUT_TOKENS = (
    "file", "format", "image", "font", "audio", "video", "document",
    "protocol", "network", "packet", "archive", "compression", "compress",
    "serialization", "binary", "json", "xml", "yaml", "asn1", "mpeg",
    "pdf", "elf", "dwarf", "subtitle", "metadata", "container",
)
# Encode side and decode side — both present → round-trip oracle applies.
_DECODE_TOKENS = ("decode", "deserialize", "parse", "read", "decompress", "load", "unmarshal")
_ENCODE_TOKENS = ("encode", "serialize", "write", "compress", "dump", "save", "marshal")

# Things that are NOT a core C/C++ library to fuzz (bindings, wrappers, apps).
_BINDING_TOKENS = (
    "binding", "bindings", "wrapper", "-sys", "ffi", "python", "rust", "golang",
    "node", "ruby", "dotnet", "java ", "php", "swift", "tutorial", "example",
    "awesome", "cheatsheet",
)

# Belt-and-suspenders: a few projects that are heavily fuzzed even if the
# OSS-Fuzz list fetch fails (matching is normalized, so variants are caught).
_KNOWN_FUZZED = {
    "libpng", "libxml2", "libtiff", "cjson", "expat", "brotli", "openssl",
    "freetype", "harfbuzz", "zlib", "libjpeg", "libjpegturbo", "sqlite3",
    "curl", "ffmpeg", "libarchive", "boringssl", "pcre2", "lz4", "zstd",
    "libwebp", "libavif", "wireshark", "tinyxml2", "yaml", "jsoncpp",
}


def _normalize_name(s: str) -> str:
    """Lowercase, strip non-alphanumerics — so 'libFoo-bar' ~ 'foobar'."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def normalize_oss_fuzz_set(names) -> set[str]:
    """Normalize a collection of OSS-Fuzz project names for matching."""
    out: set[str] = set()
    for n in names:
        norm = _normalize_name(n)
        if not norm:
            continue
        out.add(norm)
        out.add(norm[3:] if norm.startswith("lib") else "lib" + norm)  # lib-variant
    return out


def is_oss_fuzz_covered(name: str, oss_projects: set[str]) -> bool:
    """True if `name` matches a project already continuously fuzzed by OSS-Fuzz."""
    norm = _normalize_name(name)
    if not norm:
        return False
    variants = {norm, norm[3:] if norm.startswith("lib") else "lib" + norm}
    return bool(variants & oss_projects) or bool(variants & _KNOWN_FUZZED)


def _year_of(iso_ts: Optional[str]) -> Optional[int]:
    """Extract the year from an ISO timestamp like '2024-08-12T...'. None if absent."""
    if not iso_ts:
        return None
    m = re.match(r"(\d{4})-", iso_ts)
    return int(m.group(1)) if m else None


def _star_score(stars: int) -> tuple[float, str]:
    """Popularity sweet spot: obscure repos rarely yield CVEs, hyper-popular
    ones are already audited/fuzzed. Peak in the middle."""
    if stars < 30:
        return -8.0, f"obscure ({stars}★)"
    if stars < 100:
        return 4.0, f"small ({stars}★)"
    if stars <= 3000:
        return 12.0, f"sweet-spot ({stars}★)"
    if stars <= 12000:
        return 6.0, f"popular ({stars}★)"
    return -4.0, f"likely-audited ({stars}★)"


def _recency_score(year: Optional[int], now_year: int) -> tuple[float, str]:
    """Maintained → a reported bug can get fixed/assigned; very stale → maybe
    abandoned (CVE harder to land)."""
    if year is None:
        return -2.0, "activity unknown"
    age = now_year - year
    if age <= 2:
        return 10.0, f"maintained (last push {year})"
    if age <= 4:
        return 4.0, f"semi-active ({year})"
    return -2.0, f"stale ({year})"


def score_candidate(repo: dict[str, Any], oss_projects: set[str],
                    now_year: int = 2026) -> Optional[dict[str, Any]]:
    """Score one GitHub repo as a fuzzing candidate.

    Returns a result dict, or None if the repo is disqualified (wrong language,
    already OSS-Fuzzed, a binding/wrapper, or no parser surface).
    """
    name = repo.get("name", "") or ""
    desc = repo.get("description") or ""
    topics = [str(t).lower() for t in (repo.get("topics") or [])]
    lang = (repo.get("language") or "").lower()
    text = " ".join([name, desc, " ".join(topics)]).lower()

    # ── hard disqualifiers ──
    if lang not in ("c", "c++"):
        return None
    if is_oss_fuzz_covered(name, oss_projects):
        return None
    if name.endswith(("-sys", ".py", ".js")) or any(b in text for b in _BINDING_TOKENS):
        return None
    parser_hits = sorted({k for k in _PARSER_TOKENS if k in text})
    if not parser_hits:
        return None

    score = 0.0
    reasons: list[str] = []

    score += min(len(parser_hits) * 6, 24)
    reasons.append("parser surface: " + ", ".join(parser_hits[:4]))

    sec_hits = sorted({k for k in _UNTRUSTED_INPUT_TOKENS if k in text})
    if sec_hits:
        score += min(len(sec_hits) * 4, 16)
        reasons.append("untrusted input: " + ", ".join(sec_hits[:4]))

    has_decode = any(k in text for k in _DECODE_TOKENS)
    has_encode = any(k in text for k in _ENCODE_TOKENS)
    round_trip = has_decode and has_encode
    if round_trip:
        score += 20.0
        reasons.append("round-trip oracle applies (encode+decode) — OSS-Fuzz blind spot")

    stars = int(repo.get("stargazers_count", 0) or 0)
    s_pts, s_why = _star_score(stars)
    score += s_pts
    reasons.append(s_why)

    yr = _year_of(repo.get("pushed_at"))
    r_pts, r_why = _recency_score(yr, now_year)
    score += r_pts
    reasons.append(r_why)

    return {
        "name": name,
        "full_name": repo.get("full_name", name),
        "url": repo.get("html_url", ""),
        "language": repo.get("language", ""),
        "stars": stars,
        "last_push_year": yr,
        "description": desc[:160],
        "score": round(max(score, 0.0), 1),
        "round_trip": round_trip,
        "reasons": reasons,
    }


# ── Network (best-effort) ───────────────────────────────────────────────────

_GH_API = "https://api.github.com"
# Default searches: C/C++ parser & codec libraries, by topic and free text.
DEFAULT_QUERIES = (
    "language:C topic:parser",
    "language:C topic:file-format",
    "language:C topic:codec",
    "language:C++ topic:serialization",
    "language:C parser format in:name,description",
    "language:C decoder OR codec in:name,description",
    "language:C++ parser format in:name,description",
)


def _gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "nemesis-target-scout"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def fetch_oss_fuzz_projects(timeout: float = 20.0) -> set[str]:
    """Fetch the OSS-Fuzz project directory names (the exclusion set).

    Best-effort: on any failure, falls back to the bundled _KNOWN_FUZZED set so
    matching still excludes the obvious continuously-fuzzed targets.
    """
    import httpx
    url = f"{_GH_API}/repos/google/oss-fuzz/contents/projects"
    try:
        r = httpx.get(url, headers=_gh_headers(), timeout=timeout,
                      params={"per_page": "100"})
        r.raise_for_status()
        names = [e["name"] for e in r.json() if e.get("type") == "dir"]
        # The contents API paginates at 100; follow Link rel="next".
        page = 2
        while "rel=\"next\"" in r.headers.get("link", "") and page <= 20:
            r = httpx.get(url, headers=_gh_headers(), timeout=timeout,
                          params={"per_page": "100", "page": str(page)})
            r.raise_for_status()
            names += [e["name"] for e in r.json() if e.get("type") == "dir"]
            page += 1
        log.info("scout.oss_fuzz_projects", count=len(names))
        return normalize_oss_fuzz_set(names)
    except Exception as exc:  # noqa: BLE001 — best effort
        log.warning("scout.oss_fuzz_fetch_failed", error=str(exc),
                    note="falling back to bundled known-fuzzed set")
        return set(_KNOWN_FUZZED)


def search_github_candidates(queries=DEFAULT_QUERIES, per_query: int = 30,
                             timeout: float = 20.0) -> list[dict[str, Any]]:
    """Search GitHub for candidate repos. Returns raw repo dicts (deduped by id)."""
    import httpx
    seen: set[int] = set()
    out: list[dict[str, Any]] = []
    for q in queries:
        try:
            r = httpx.get(
                f"{_GH_API}/search/repositories",
                headers=_gh_headers(), timeout=timeout,
                params={"q": q, "sort": "updated", "order": "desc",
                        "per_page": str(min(per_query, 100))},
            )
            if r.status_code == 403:
                log.warning("scout.github_rate_limited", query=q,
                            hint="set GITHUB_TOKEN in .env to raise limits")
                continue
            r.raise_for_status()
            for repo in r.json().get("items", []):
                rid = repo.get("id")
                if rid in seen:
                    continue
                seen.add(rid)
                out.append(repo)
        except Exception as exc:  # noqa: BLE001
            log.warning("scout.search_failed", query=q, error=str(exc))
    log.info("scout.candidates_fetched", count=len(out), queries=len(queries))
    return out


def scout(queries=DEFAULT_QUERIES, top_n: int = 25, now_year: int = 2026,
          oss_projects: Optional[set[str]] = None,
          candidates: Optional[list[dict[str, Any]]] = None) -> list[dict[str, Any]]:
    """End-to-end: fetch exclusion set + candidates, score, rank, return top-N.

    `oss_projects` / `candidates` can be injected (e.g. for tests or to reuse a
    cached fetch); otherwise they are fetched from GitHub.
    """
    if oss_projects is None:
        oss_projects = fetch_oss_fuzz_projects()
    if candidates is None:
        candidates = search_github_candidates(queries)

    scored = []
    for repo in candidates:
        res = score_candidate(repo, oss_projects, now_year=now_year)
        if res is not None:
            scored.append(res)
    scored.sort(key=lambda c: c["score"], reverse=True)
    log.info("scout.scored", kept=len(scored), of=len(candidates))
    return scored[:top_n]


def render_report(results: list[dict[str, Any]]) -> str:
    """Render a ranked candidate list as markdown."""
    if not results:
        return "No candidates found (network failure or all filtered)."
    lines = [
        f"# Target Scout — {len(results)} candidates (un-fuzzed C/C++ parsers)",
        "",
        "| # | score | RT | ★ | last | candidate | why |",
        "|---|------:|----|---|------|-----------|-----|",
    ]
    for i, c in enumerate(results, 1):
        rt = "✓" if c["round_trip"] else " "
        why = "; ".join(c["reasons"][:3])
        lines.append(
            f"| {i} | {c['score']} | {rt} | {c['stars']} | {c['last_push_year'] or '?'} | "
            f"[{c['full_name']}]({c['url']}) | {why} |"
        )
    lines += ["", "## Suggested onboard (top 5)", ""]
    for c in results[:5]:
        slug = re.sub(r"[^a-z0-9]", "", c["name"].lower()) or "target"
        lines.append(
            f"- **{c['full_name']}** → "
            f"`nemesis onboard --source-root ~/{c['name']} --project-name {slug}`"
            + ("  _(enable round-trip oracle)_" if c["round_trip"] else "")
        )
    return "\n".join(lines)
