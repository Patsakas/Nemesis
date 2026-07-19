"""
Tests for Fix 153 — LLM-driven sanitizer ranker.

Covers hard-rule overrides, LLM-rank parsing, fallback on LLM failure,
top-K picking with min-score floor, and threading detection.
"""

from unittest.mock import MagicMock

import pytest

from nemesis.config import TargetConfig
from nemesis.recon.sanitizer_ranker import (
    SanitizerRanking,
    _apply_hard_rules,
    _scan_for_threading,
    pick_top_k,
    rank_sanitizers,
)


# ── Threading detection ─────────────────────────────────────


def test_threading_detection_pthread():
    assert _scan_for_threading("#include <pthread.h>\nvoid* w(void* a){}") is True


def test_threading_detection_atomic():
    assert _scan_for_threading("_Atomic int counter = 0;") is True


def test_threading_detection_omp():
    assert _scan_for_threading("#pragma omp parallel for") is True


def test_threading_detection_negative():
    assert _scan_for_threading("int parse(const char* s){return 0;}") is False


# ── Hard rules ──────────────────────────────────────────────


def test_hard_rule_msan_disabled_when_unsupported():
    target = TargetConfig(name="t", msan_supported=False, tsan_supported=False)
    scores = {"asan_ubsan": 0.9, "asan_ubsan_strict": 0.5, "msan": 0.8, "tsan": 0.7}
    out = _apply_hard_rules(scores, target, "no threading here")
    assert out["msan"] == 0.0


def test_hard_rule_tsan_disabled_when_unsupported():
    target = TargetConfig(name="t", msan_supported=True, tsan_supported=False)
    scores = {"asan_ubsan": 0.9, "asan_ubsan_strict": 0.0, "msan": 0.8, "tsan": 0.9}
    out = _apply_hard_rules(scores, target, "#include <pthread.h>")
    assert out["tsan"] == 0.0


def test_hard_rule_tsan_disabled_when_no_threading_in_source():
    target = TargetConfig(name="t", msan_supported=True, tsan_supported=True)
    scores = {"asan_ubsan": 0.9, "asan_ubsan_strict": 0.0, "msan": 0.0, "tsan": 0.9}
    out = _apply_hard_rules(scores, target, "int parse(const char* s){return 0;}")
    assert out["tsan"] == 0.0  # no pthread / atomic / omp tokens


def test_hard_rule_tsan_kept_when_supported_and_threaded():
    target = TargetConfig(name="t", tsan_supported=True)
    scores = {"asan_ubsan": 0.5, "asan_ubsan_strict": 0.0, "msan": 0.0, "tsan": 0.9}
    out = _apply_hard_rules(scores, target, "#include <pthread.h>\nvoid f(){}")
    assert out["tsan"] == 0.9


# ── pick_top_k ──────────────────────────────────────────────


def test_pick_top_k_default_two():
    r = SanitizerRanking(
        scores={"asan_ubsan": 0.9, "asan_ubsan_strict": 0.6, "msan": 0.8, "tsan": 0.0},
        rationale={}, source="llm",
    )
    picked = pick_top_k(r, k=2)
    assert picked == ["asan_ubsan", "msan"]


def test_pick_top_k_drops_below_min_score():
    r = SanitizerRanking(
        scores={"asan_ubsan": 0.9, "asan_ubsan_strict": 0.1, "msan": 0.0, "tsan": 0.0},
        rationale={}, source="llm",
    )
    picked = pick_top_k(r, k=4, min_score=0.3)
    assert picked == ["asan_ubsan"]  # only one passes the floor


def test_pick_top_k_falls_back_to_asan_when_all_zero():
    r = SanitizerRanking(
        scores={"asan_ubsan": 0.0, "asan_ubsan_strict": 0.0, "msan": 0.0, "tsan": 0.0},
        rationale={}, source="llm",
    )
    picked = pick_top_k(r, k=2)
    assert picked == ["asan_ubsan"]


def test_pick_top_k_one():
    r = SanitizerRanking(
        scores={"asan_ubsan": 0.9, "asan_ubsan_strict": 0.6, "msan": 0.8, "tsan": 0.0},
        rationale={}, source="llm",
    )
    assert pick_top_k(r, k=1) == ["asan_ubsan"]


# ── rank_sanitizers integration ─────────────────────────────


def test_rank_without_llm_returns_hard_rules_only():
    target = TargetConfig(name="t", msan_supported=False, tsan_supported=False)
    r = rank_sanitizers("foo", "void foo(){}", target, llm_client=None)
    assert r.source == "hard_rules_only"
    assert r.scores["asan_ubsan"] == 1.0
    assert r.scores["msan"] == 0.0
    assert r.scores["tsan"] == 0.0


def test_rank_without_llm_msan_supported_still_hard_rules_only():
    """No LLM → fallback. Even with msan_supported=True, no LLM signal to rank."""
    target = TargetConfig(name="t", msan_supported=True, tsan_supported=False)
    r = rank_sanitizers("foo", "void foo(){}", target, llm_client=None)
    assert r.source == "hard_rules_only"
    # Fallback always strongly favours asan_ubsan
    assert r.scores["asan_ubsan"] == 1.0


def test_rank_with_llm_parses_scores():
    target = TargetConfig(name="t", msan_supported=True, tsan_supported=False)
    fake_llm = MagicMock()
    fake_llm.complete.return_value = (
        '{'
        '"asan_ubsan":        {"score": 0.85, "reason": "memory parser"},'
        '"asan_ubsan_strict": {"score": 0.40, "reason": "size arithmetic"},'
        '"msan":              {"score": 0.55, "reason": "uninit struct fields"},'
        '"tsan":              {"score": 0.10, "reason": "single-threaded"}'
        '}'
    )
    r = rank_sanitizers("parse_data", "void parse(){}", target, llm_client=fake_llm)
    assert r.source == "llm"
    assert r.scores["asan_ubsan"] == 0.85
    assert r.scores["msan"] == 0.55
    assert r.scores["tsan"] == 0.0  # zeroed by hard rule (tsan_supported=False)
    assert "memory parser" in r.rationale["asan_ubsan"]


def test_rank_with_llm_clamps_invalid_scores():
    target = TargetConfig(name="t")
    fake_llm = MagicMock()
    fake_llm.complete.return_value = (
        '{"asan_ubsan": {"score": 2.5, "reason": "x"},'
        '"asan_ubsan_strict": {"score": -1, "reason": "y"},'
        '"msan": {"score": "junk", "reason": "z"},'
        '"tsan": {"score": 0.5, "reason": "w"}}'
    )
    r = rank_sanitizers("foo", "void foo(){}", target, llm_client=fake_llm)
    assert r.scores["asan_ubsan"] == 1.0       # clamped to 1.0
    assert r.scores["asan_ubsan_strict"] == 0.0  # clamped to 0.0
    assert r.scores["msan"] == 0.0             # non-numeric → 0.0


def test_rank_with_llm_failure_falls_back():
    target = TargetConfig(name="t")
    fake_llm = MagicMock()
    fake_llm.complete.side_effect = RuntimeError("rate limited")
    r = rank_sanitizers("foo", "void foo(){}", target, llm_client=fake_llm)
    assert r.source == "fallback"
    assert r.scores["asan_ubsan"] == 1.0


def test_rank_with_llm_unparseable_response_falls_back():
    target = TargetConfig(name="t")
    fake_llm = MagicMock()
    fake_llm.complete.return_value = "I cannot help with this request."
    r = rank_sanitizers("foo", "void foo(){}", target, llm_client=fake_llm)
    assert r.source == "fallback"


def test_rank_hard_rules_override_with_rationale_explanation():
    """When LLM gave high score for tsan but hard rule zeros it, rationale explains why."""
    target = TargetConfig(name="t", tsan_supported=False)
    fake_llm = MagicMock()
    fake_llm.complete.return_value = (
        '{"asan_ubsan": {"score": 0.9, "reason": "default"},'
        '"asan_ubsan_strict": {"score": 0.0, "reason": ""},'
        '"msan": {"score": 0.0, "reason": ""},'
        '"tsan": {"score": 0.95, "reason": "looks threaded"}}'
    )
    r = rank_sanitizers("foo", "#include <pthread.h>\nvoid foo(){}",
                        target, llm_client=fake_llm)
    assert r.scores["tsan"] == 0.0
    assert "hard-rule override" in r.rationale["tsan"]
