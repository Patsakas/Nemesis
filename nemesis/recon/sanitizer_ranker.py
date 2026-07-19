"""Fix 153 — LLM-driven sanitizer ranker.

Given a target function and its source, ranks the available sanitizer profiles
by likelihood of finding a bug. The pipeline's --auto-sanitizer flag picks the
top-K and runs each as a separate campaign.

Hard rules apply BEFORE the LLM call to avoid wasted ranking on unreachable
profiles (e.g. tsan when tsan_supported=false). The LLM only ranks the
remaining candidates.

Fallback: if LLM call fails or produces unparseable output, returns a safe
default that strongly favours `asan_ubsan` (the historical NEMESIS default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from nemesis.neural.json_extractor import extract_json

if TYPE_CHECKING:
    from nemesis.config import TargetConfig
    from nemesis.neural import LLMClient


# Sanitizer profiles the ranker can recommend. Order is the prompt presentation
# order; keys must match `_resolve_sanitizer_flags` profile names.
_PROFILES = ("asan_ubsan", "asan_ubsan_strict", "msan", "tsan")


@dataclass(frozen=True)
class SanitizerRanking:
    """Result of a ranker call."""
    scores: dict[str, float]   # profile → 0.0–1.0
    rationale: dict[str, str]  # profile → one-line reason from LLM (may be empty)
    source: str                # "llm" | "fallback" | "hard_rules_only"


def _scan_for_threading(source_snippet: str) -> bool:
    """Quick check: does the source mention threading primitives?"""
    tokens = ("pthread", "std::thread", "_Atomic", "atomic_", "GThread",
              "uv_thread_", "#pragma omp", "<thread>", "omp_set_")
    return any(t in source_snippet for t in tokens)


def _apply_hard_rules(
    scores: dict[str, float],
    target: "TargetConfig",
    source_snippet: str,
) -> dict[str, float]:
    """Zero out profiles that cannot run on this target regardless of LLM verdict."""
    out = dict(scores)
    if not getattr(target, "msan_supported", False):
        out["msan"] = 0.0
    tsan_supported = getattr(target, "tsan_supported", False)
    has_threading = _scan_for_threading(source_snippet)
    if not tsan_supported or not has_threading:
        out["tsan"] = 0.0
    return out


def _build_prompt(target_func: str, source_snippet: str) -> str:
    """LLM prompt for sanitizer ranking. Asks for strict JSON."""
    return (
        "You are a sanitizer-selection assistant for an AFL++ fuzzing pipeline.\n"
        "\n"
        f"Target function: `{target_func}`\n"
        "\n"
        "Source snippet:\n"
        "```c\n"
        f"{source_snippet[:6000]}\n"
        "```\n"
        "\n"
        "Available sanitizer profiles and what they catch:\n"
        "  - asan_ubsan        : ASAN + UBSan (default). Memory-safety bugs "
        "(buffer overflows, UAF, double-free, NULL deref) and crashing UB "
        "(signed overflow, shift overflow, pointer-overflow).\n"
        "  - asan_ubsan_strict : Above PLUS unsigned int overflow and "
        "implicit-conversion checks. Higher false-positive rate; pick when the "
        "function does heavy arithmetic on untrusted lengths.\n"
        "  - msan              : MemorySanitizer ONLY. Catches use-of-"
        "uninitialised-value reads. Pick when the function reads conditionally-"
        "initialised struct fields, partially-filled buffers, or has complex "
        "control flow that may skip initialisation.\n"
        "  - tsan              : ThreadSanitizer ONLY. Catches data races "
        "and lock-order issues. Only useful if the function (or a caller) is "
        "thread-safe and exposed to concurrent invocation.\n"
        "\n"
        "Task: assign a relevance score in [0.0, 1.0] to each profile based on "
        "how likely it is to surface a real bug in this function. Higher score "
        "= more likely. Multiple profiles may be high if multiple bug classes "
        "are plausible. Be honest — return 0.0 for irrelevant profiles, do not "
        "spread scores evenly. If unsure, prefer asan_ubsan.\n"
        "\n"
        "Output ONLY valid JSON in this exact shape:\n"
        "{\n"
        '  "asan_ubsan":        {"score": 0.0, "reason": "..."},\n'
        '  "asan_ubsan_strict": {"score": 0.0, "reason": "..."},\n'
        '  "msan":              {"score": 0.0, "reason": "..."},\n'
        '  "tsan":              {"score": 0.0, "reason": "..."}\n'
        "}\n"
    )


def _parse_response(text: str) -> tuple[dict[str, float], dict[str, str]]:
    """Parse LLM JSON response into score + rationale dicts. Tolerant to extras."""
    data = extract_json(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response not a JSON object")
    scores: dict[str, float] = {p: 0.0 for p in _PROFILES}
    rationale: dict[str, str] = {p: "" for p in _PROFILES}
    for prof in _PROFILES:
        entry = data.get(prof)
        if not isinstance(entry, dict):
            continue
        try:
            s = float(entry.get("score", 0.0))
        except (TypeError, ValueError):
            s = 0.0
        scores[prof] = max(0.0, min(1.0, s))
        reason = entry.get("reason", "")
        if isinstance(reason, str):
            rationale[prof] = reason[:200]
    return scores, rationale


def _fallback_ranking(reason: str) -> SanitizerRanking:
    """Safe default when LLM fails: strongly favour the historical default."""
    return SanitizerRanking(
        scores={"asan_ubsan": 1.0, "asan_ubsan_strict": 0.0, "msan": 0.0, "tsan": 0.0},
        rationale={p: (reason if p == "asan_ubsan" else "") for p in _PROFILES},
        source="fallback",
    )


def rank_sanitizers(
    target_func: str,
    source_snippet: str,
    target: "TargetConfig",
    llm_client: Optional["LLMClient"] = None,
    log=None,
) -> SanitizerRanking:
    """Return ranked sanitizer scores for this target.

    Hard rules zero-out unreachable profiles before the LLM call. If the LLM is
    unavailable or fails, returns a safe fallback strongly favouring asan_ubsan.
    """
    # If we have no LLM, fall back immediately — but still surface hard rules
    # via the rationale so the user knows asan_ubsan is the default.
    if llm_client is None:
        ranking = _fallback_ranking("no LLM client available")
        ranking = SanitizerRanking(
            scores=_apply_hard_rules(ranking.scores, target, source_snippet),
            rationale=ranking.rationale,
            source="hard_rules_only",
        )
        return ranking

    try:
        prompt = _build_prompt(target_func, source_snippet)
        response = llm_client.complete(
            prompt=prompt,
            system="You are a precise security-tooling assistant. Output JSON only.",
            stage="sanitizer_ranker",
            target_func=target_func,
        )
        raw_scores, rationale = _parse_response(response)
        gated_scores = _apply_hard_rules(raw_scores, target, source_snippet)
        # Augment rationale for any profile that was zeroed by hard rules so the
        # user sees WHY (not just that it's 0.0).
        for prof in _PROFILES:
            if raw_scores.get(prof, 0.0) > 0.0 and gated_scores[prof] == 0.0:
                rationale[prof] = (
                    f"hard-rule override: {prof} disabled "
                    f"(missing {prof}_supported flag or no threading detected). "
                    f"LLM had said: {rationale.get(prof, '')[:120]}"
                )
        return SanitizerRanking(
            scores=gated_scores, rationale=rationale, source="llm",
        )
    except Exception as exc:
        if log is not None:
            log.warning("sanitizer_ranker.llm_failed", error=str(exc)[:200])
        ranking = _fallback_ranking(f"LLM error: {type(exc).__name__}")
        ranking = SanitizerRanking(
            scores=_apply_hard_rules(ranking.scores, target, source_snippet),
            rationale=ranking.rationale,
            source="fallback",
        )
        return ranking


def pick_top_k(
    ranking: SanitizerRanking,
    k: int = 2,
    min_score: float = 0.3,
) -> list[str]:
    """Return up to k profiles sorted by score, dropping any below min_score.

    If the filter would leave the list empty (e.g. all hard-rules zeroed out),
    falls back to ['asan_ubsan'] as a safe single-pass default.
    """
    sorted_profiles = sorted(
        ranking.scores.items(), key=lambda kv: kv[1], reverse=True,
    )
    picked = [p for p, s in sorted_profiles if s >= min_score][:k]
    if not picked:
        return ["asan_ubsan"]
    return picked
