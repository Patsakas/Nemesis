"""
Tests for the canary filter in predicate synthesis.

Regression context (2026-05-13 libsndfile postmortem):
- LLM synthesised a predicate `bytes[4..7] all non-zero` for a WAV harness.
- Random byte sequences pass that ~98% of the time, so the random-only
  canary kept it.
- Real WAV files <16MB have byte 7 = 0 in the file-size field, so injecting
  the predicate filtered 100% of valid inputs → 0 coverage in fuzzing.

Fix: when no real seeds are provided, drop predicates entirely rather than
inject random-validated guesses. AFL still works without progress
predicates — just slower.
"""

from nemesis.recon.predicate_synthesis import (
    ProgressPredicate,
    canary_filter_predicates,
)


def _seed_from(bytes_in: bytes) -> bytes:
    return bytes_in


def test_canary_drops_all_when_no_real_seeds():
    """REGRESSION (libsndfile): random-only canary cannot distinguish
    format-aware from format-breaking predicates. When the corpus is
    empty, drop everything rather than gamble."""
    preds = [
        ProgressPredicate(
            name="size_field_nonzero",
            condition=("input_len >= 8 && input[4] != 0 && input[5] != 0 && "
                       "input[6] != 0 && input[7] != 0"),
            rationale="header size field present",
        ),
    ]
    out = canary_filter_predicates(preds, sample_seeds=[], min_pass_rate=0.01)
    assert out == [], (
        "without real seeds the canary cannot validate format-specific gates; "
        "they must all be dropped to avoid filtering valid inputs"
    )


def test_canary_keeps_predicate_when_real_seed_passes():
    """When a real seed satisfies the predicate, canary keeps it even if
    random-byte rate is low. The existing format-magic case (a predicate
    that targets a real file signature) stays alive."""
    # A real seed where byte 0 == 0x52 ('R')
    real_seed = b"RIFF\x24\x00\x00\x00WAVEfmt "
    preds = [
        ProgressPredicate(
            name="riff_magic",
            condition="input_len >= 4 && input[0] == 0x52",
            rationale="RIFF header magic byte",
        ),
    ]
    out = canary_filter_predicates(preds, sample_seeds=[real_seed], min_pass_rate=0.01)
    assert len(out) == 1, "predicate with a real-seed match must survive"
    assert out[0].name == "riff_magic"


def test_canary_drops_predicate_real_seeds_all_fail():
    """When real seeds exist and they ALL fail the predicate, drop it.
    This is the libsndfile case as if we'd had a corpus available: byte 7
    of file-size is always 0 for files < 16MB, so the predicate fails
    100% of real inputs."""
    real_seeds = [
        # Three valid WAV file headers, file sizes 36, 100, 1000 — all < 256
        # so bytes 5, 6, 7 are zero.
        b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00",
        b"RIFF\x64\x00\x00\x00WAVEfmt \x10\x00\x00\x00",
        b"RIFF\xe8\x03\x00\x00WAVEfmt \x10\x00\x00\x00",
    ]
    preds = [
        ProgressPredicate(
            name="size_field_all_nonzero",
            condition=("input_len >= 8 && input[4] != 0 && input[5] != 0 && "
                       "input[6] != 0 && input[7] != 0"),
            rationale="(buggy) requires every byte of the size field to be non-zero",
        ),
    ]
    out = canary_filter_predicates(preds, sample_seeds=real_seeds, min_pass_rate=0.01)
    assert out == [], (
        "predicate that fails for every real seed must be dropped — this is "
        "the case the random-only canary missed before the fix"
    )


def test_canary_empty_predicates_returns_empty():
    """Edge case: no predicates → returns empty list unchanged."""
    out = canary_filter_predicates([], sample_seeds=[], min_pass_rate=0.01)
    assert out == []


def test_canary_returns_list_type():
    """Always returns a list (downstream code calls len() and iterates)."""
    out = canary_filter_predicates([], sample_seeds=[b"data"], min_pass_rate=0.01)
    assert isinstance(out, list)
