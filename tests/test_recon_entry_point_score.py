"""
Tests for entry-point reachability scoring in recon.

Motivation (libnmea, 2026-07-22): the local-source scanner ranked

    int nmea_load_parsers();

as the #1 fuzz target — it mallocs and walks a pointer list, so it scored well
on every "looks dangerous" signal — while

    nmea_s *nmea_parse(char *sentence, size_t length, int check_checksum);

the canonical (buffer, length) entry point in the public header, ranked lower.
The architect then emitted a harness that compiled, linked and ran, and threw
the fuzz input away with `(void)buf; (void)len;` because the target accepted no
input. Onboard/harness/compile/launch all reported success while nothing was
being fuzzed.

The invariant these tests protect: dangerousness and reachability are different
questions, and a target must score on BOTH.
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.recon import IntrospectorParser


@pytest.fixture
def recon(tmp_path: Path) -> IntrospectorParser:
    cfg = NemesisConfig()
    cfg.target.source_root = str(tmp_path)
    return IntrospectorParser(cfg)


# ── _split_params ───────────────────────────────────────────


def test_no_params_is_empty_list(recon: IntrospectorParser):
    assert recon._split_params("nmea_load_parsers()") == []


def test_void_param_is_empty_list(recon: IntrospectorParser):
    assert recon._split_params("int foo(void)") == []


def test_params_are_split(recon: IntrospectorParser):
    params = recon._split_params("nmea_parse(char *sentence, size_t length, int check)")
    assert params == ["char *sentence", "size_t length", "int check"]


def test_function_pointer_param_does_not_split(recon: IntrospectorParser):
    """A callback param contains its own commas inside parens."""
    params = recon._split_params("foo(char *b, int (*cb)(int, int), size_t n)")
    assert params == ["char *b", "int (*cb)(int, int)", "size_t n"]


def test_unparseable_signature_returns_none(recon: IntrospectorParser):
    assert recon._split_params("not a signature") is None


# ── the libnmea case, end to end ────────────────────────────


def test_parse_outranks_loader(recon: IntrospectorParser):
    """The regression this whole change exists for."""
    loader = recon._entry_point_score("nmea_load_parsers()", "nmea_load_parsers")
    parser = recon._entry_point_score(
        "nmea_parse(char *sentence, size_t length, int check_checksum)", "nmea_parse"
    )
    assert parser > loader
    # And the gap must be wide enough to survive the other signals: the loader
    # scored ~16 on danger heuristics alone.
    assert parser - loader >= 20.0


# ── positive signals ────────────────────────────────────────


def test_buffer_plus_length_is_the_strongest_signal(recon: IntrospectorParser):
    assert recon._entry_point_score("f(const char *d, size_t n)", "f") == 8.0


def test_uint8_buffer_counts(recon: IntrospectorParser):
    assert recon._entry_point_score("f(uint8_t *data, size_t size)", "f") == 8.0


def test_buffer_without_length_scores_lower(recon: IntrospectorParser):
    assert recon._entry_point_score("f(char *s)", "f") == 4.0


def test_file_stream_is_a_weak_input_channel(recon: IntrospectorParser):
    assert recon._entry_point_score("f(FILE *fp)", "f") == 3.0


def test_consumer_verb_adds_bonus(recon: IntrospectorParser):
    plain = recon._entry_point_score("f(char *s, size_t n)", "f")
    named = recon._entry_point_score("decode(char *s, size_t n)", "decode")
    assert named - plain == 3.0


# ── negative signals ────────────────────────────────────────


def test_zero_arg_function_is_penalised(recon: IntrospectorParser):
    assert recon._entry_point_score("f()", "f") == -10.0


def test_lifecycle_verb_is_penalised(recon: IntrospectorParser):
    assert recon._entry_point_score("cleanup_ctx(ctx_t *c)", "cleanup_ctx") == -5.0


def test_struct_pointer_is_not_a_byte_buffer(recon: IntrospectorParser):
    """`nmea_s *data` carries no fuzzer bytes — only the caller can build it."""
    assert recon._entry_point_score("f(nmea_s *data)", "f") == 0.0


def test_zero_arg_penalty_is_not_exclusion(recon: IntrospectorParser):
    """A zero-arg function reading a global can still win on other evidence —
    the penalty must be finite, not -inf."""
    assert recon._entry_point_score("f()", "f") > -100.0


# ── signature extraction from source ────────────────────────


def test_signature_extracted_from_knr_definition(recon: IntrospectorParser):
    lines = ["nmea_s *", "nmea_parse(char *sentence, size_t length, int c)", "{"]
    assert recon._extract_signature(lines, 1).startswith("nmea_parse(char *sentence")


def test_signature_extraction_spans_wrapped_params(recon: IntrospectorParser):
    lines = ["foo(char *buf,", "    size_t len)", "{"]
    sig = recon._extract_signature(lines, 0)
    assert "size_t len" in sig
    assert recon._entry_point_score(sig, "foo") == 8.0


def test_missing_start_index_is_safe(recon: IntrospectorParser):
    assert recon._extract_signature(["whatever"], -1) == ""
    assert recon._entry_point_score("", "f") == 0.0
