"""Target Scout scoring (CVE-discovery candidate finder). Pure-function tests —
no network. Validates the OSS-Fuzz exclusion + the candidate ranking heuristics."""
from nemesis.recon.target_scout import (
    is_oss_fuzz_covered,
    normalize_oss_fuzz_set,
    render_report,
    score_candidate,
    scout,
)


def _repo(**kw):
    base = dict(name="x", full_name="o/x", description="", topics=[],
                language="C", stargazers_count=500, pushed_at="2025-06-01T00:00:00Z",
                html_url="http://x", id=1)
    base.update(kw)
    return base


OSS = normalize_oss_fuzz_set(["libpng", "expat", "cjson"])


def test_oss_fuzz_exclusion_matches_lib_variants():
    assert is_oss_fuzz_covered("libpng", OSS)
    assert is_oss_fuzz_covered("png", OSS)        # lib-stripped variant
    assert is_oss_fuzz_covered("cJSON", OSS)      # case/normalization
    assert not is_oss_fuzz_covered("libfoobar", OSS)


def test_known_fuzzed_excluded_even_without_fetch():
    # empty fetched set, but bundled _KNOWN_FUZZED still excludes the obvious ones
    assert is_oss_fuzz_covered("freetype", set())
    assert is_oss_fuzz_covered("openssl", set())


def test_disqualifiers_return_none():
    assert score_candidate(_repo(language="Python"), OSS) is None        # wrong lang
    assert score_candidate(_repo(name="libpng"), OSS) is None            # already fuzzed
    assert score_candidate(_repo(name="foo-sys"), OSS) is None           # rust binding
    assert score_candidate(_repo(description="python wrapper"), OSS) is None
    assert score_candidate(_repo(description="a math library"), OSS) is None  # no parser surface


def test_parser_library_scores_and_keeps():
    r = score_candidate(_repo(name="tinyflac", description="a small FLAC audio decoder"), OSS)
    assert r is not None
    assert r["score"] > 0
    assert any("parser surface" in x for x in r["reasons"])


def test_round_trip_codec_scores_higher_and_flagged():
    plain = score_candidate(_repo(name="foodec", description="a binary format decoder/parser"), OSS)
    rt = score_candidate(_repo(name="foocodec",
                               description="encode and decode the FOO binary format (parser)"), OSS)
    assert rt["round_trip"] is True
    assert plain["round_trip"] is False
    assert rt["score"] > plain["score"]


def test_star_sweet_spot_beats_extremes():
    mid = score_candidate(_repo(name="midparser", description="image format parser",
                                stargazers_count=800), OSS)
    huge = score_candidate(_repo(name="hugeparser", description="image format parser",
                                 stargazers_count=40000), OSS)
    assert mid["score"] > huge["score"]


def test_scout_orchestrator_ranks_and_filters_injected():
    candidates = [
        _repo(id=1, name="libpng", description="png parser"),                 # excluded
        _repo(id=2, name="weirdfmt", description="encode/decode WEIRD file format parser",
              stargazers_count=600, pushed_at="2025-01-01T00:00:00Z"),         # strong
        _repo(id=3, name="oldlib", description="legacy format reader",
              stargazers_count=20, pushed_at="2016-01-01T00:00:00Z"),          # weak
        _repo(id=4, name="pyfoo", description="python bindings parser"),       # excluded
    ]
    out = scout(oss_projects=OSS, candidates=candidates, top_n=10, now_year=2026)
    names = [c["name"] for c in out]
    assert "libpng" not in names and "pyfoo" not in names
    assert names[0] == "weirdfmt"                  # strongest ranked first
    assert "weirdfmt" in render_report(out)
