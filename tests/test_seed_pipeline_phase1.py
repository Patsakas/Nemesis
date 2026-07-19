"""Phase 1 seed-pipeline tests: feature flags, dictionary multi-byte tokens,
round-trip producer synthesis/run, and the SeedPipeline orchestrator gating.

Pure-Python coverage only — the actual library-linking compile and AFL run are
exercised in the WSL/Linux runtime, not here. The exec path of `run_producer`
is tested on POSIX with a shell stub and skipped on Windows.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from nemesis import feature_flags as ff
from nemesis.fuzzing import _combine_adjacent_char_cmps
from nemesis.recon import roundtrip_seedgen as rt

# ── feature flags ─────────────────────────────────────────────────────────

def test_new_flags_registered_and_default_enabled():
    for name in ("dict_extract", "roundtrip", "z3_seedgen", "seed_evolve"):
        assert name in ff._FEATURES
        assert ff.is_enabled(name) is True  # default-on (no env var set)


def test_flag_disable_via_env(monkeypatch):
    monkeypatch.setenv("NEMESIS_DISABLE_ROUNDTRIP", "1")
    assert ff.is_enabled("roundtrip") is False
    assert "roundtrip" in ff.disabled_features()
    # other flags untouched
    assert ff.is_enabled("z3_seedgen") is True


# ── dictionary: multi-byte magic stitching ────────────────────────────────

def test_combine_adjacent_chars_basic_gif():
    src = "if (buf[0] == 'G' && buf[1] == 'I' && buf[2] == 'F') return 1;"
    assert _combine_adjacent_char_cmps(src) == {"GIF"}


def test_combine_handles_two_separate_runs():
    src = "a[0]=='P'; a[1]=='K'; b[0]=='B'; b[1]=='M';"
    assert _combine_adjacent_char_cmps(src) == {"PK", "BM"}


def test_combine_skips_gaps_and_single_chars():
    # index 0 and 2 present but 1 missing → two singletons, no 2+ run
    src = "x[0]=='A'; x[2]=='C';"
    assert _combine_adjacent_char_cmps(src) == set()


def test_combine_ignores_far_indices():
    src = "p[100]=='Z'; p[101]=='Z';"
    assert _combine_adjacent_char_cmps(src, max_index=32) == set()


# ── round-trip: write-API extraction ──────────────────────────────────────

def test_extract_write_api_picks_encoders_only(tmp_path: Path):
    hdr = tmp_path / "foo.h"
    hdr.write_text(
        """
        int foo_decode(const char *in, int n);
        int foo_encode(const char *in, int n, char *out);
        void foo_read_header(FILE *f);
        size_t foo_compress(const void *src, size_t n, void *dst);
        void foo_free(void *p);
        """
    )
    decls = rt.extract_write_api(tmp_path, ["foo.h"])
    joined = " ".join(decls)
    assert "foo_encode" in joined
    assert "foo_compress" in joined
    # decoders / readers / frees excluded
    assert "foo_decode" not in joined
    assert "foo_read_header" not in joined
    assert "foo_free" not in joined


def test_extract_write_api_missing_header_is_safe(tmp_path: Path):
    assert rt.extract_write_api(tmp_path, ["nope.h"]) == []
    assert rt.extract_write_api(tmp_path, []) == []


# ── round-trip: producer source validation ────────────────────────────────

def test_validate_producer_accepts_reasonable_source():
    src = (
        '#include "png.h"\n'
        "int main(int argc, char **argv){ FILE*f=fopen(argv[1],\"wb\");"
        " srand(atoi(argv[2])); /* encode */ fclose(f); return 0; }"
    )
    ok, reason = rt._validate_producer(src)
    assert ok, reason


def test_validate_producer_rejects_no_main():
    ok, _ = rt._validate_producer('#include "x.h"\nvoid helper(void){}' * 5)
    assert not ok


def test_validate_producer_rejects_forbidden_call():
    src = (
        '#include "x.h"\n/* a sufficiently long producer body to clear the\n'
        '   minimum-length guard so the forbidden-call check is reached */\n'
        'int main(int c, char **argv){ FILE *f = fopen(argv[1], "wb");\n'
        '  system("rm -rf /"); fclose(f); return 0; }\n'
    )
    ok, reason = rt._validate_producer(src)
    assert not ok
    assert "forbidden" in reason


def test_strip_code_fences():
    assert rt._strip_code_fences("```c\nint main(){}\n```") == "int main(){}"
    assert rt._strip_code_fences("int main(){}") == "int main(){}"


def test_synthesize_returns_empty_without_api(monkeypatch):
    # No api_decls → must not call the LLM, returns "".
    class _Boom:
        def complete(self, *a, **k):
            raise AssertionError("LLM must not be called when api_decls is empty")

    out = rt.synthesize_producer_source(
        library_name="lib", target_func="f", format_name="bin",
        header_rels=[], api_decls=[], format_spec="", cve_records=[],
        client=_Boom(), log=None,
    )
    assert out == ""


# ── round-trip: producer run / seed collection ────────────────────────────

def test_run_producer_nonexistent_binary_returns_zero(tmp_path: Path):
    assert rt.run_producer(tmp_path / "nope", tmp_path / "out", n_seeds=3) == 0


@pytest.mark.skipif(os.name != "posix", reason="shell stub is POSIX-only")
def test_run_producer_collects_unique_seeds(tmp_path: Path):
    # Stub producer: writes the rng_seed (arg 2) as the file content → each
    # distinct seed yields a distinct file.
    stub = tmp_path / "producer.sh"
    stub.write_text('#!/bin/sh\nprintf "%s" "$2" > "$1"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    out = tmp_path / "seeds"
    n = rt.run_producer(stub, out, n_seeds=5)
    assert n == 5
    assert sum(1 for _ in out.iterdir()) == 5


@pytest.mark.skipif(os.name != "posix", reason="shell stub is POSIX-only")
def test_run_producer_dedups_identical_output(tmp_path: Path):
    stub = tmp_path / "producer.sh"
    stub.write_text('#!/bin/sh\nprintf "CONSTANT" > "$1"\n')  # ignores seed
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    out = tmp_path / "seeds"
    n = rt.run_producer(stub, out, n_seeds=10)
    assert n == 1  # all identical → deduped to one


# ── SeedPipeline orchestrator gating ──────────────────────────────────────

def test_seed_pipeline_all_disabled_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("NEMESIS_DISABLE_ROUNDTRIP", "1")
    monkeypatch.setenv("NEMESIS_DISABLE_Z3_SEEDGEN", "1")
    monkeypatch.setenv("NEMESIS_DISABLE_SEED_EVOLVE", "1")
    from nemesis.recon.seed_pipeline import SeedPipeline

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass

    sp = SeedPipeline(config=object(), symbolic=object(), llm_client=object(), log=_Log())
    added = sp.augment(harness=object(), seeds_dir=tmp_path, target_func="f")
    assert added == 0


def test_seed_pipeline_count_seeds(tmp_path):
    from nemesis.recon.seed_pipeline import SeedPipeline
    (tmp_path / "a").write_bytes(b"x")
    (tmp_path / "b").write_bytes(b"")  # empty — not counted
    (tmp_path / "c").write_bytes(b"yz")
    assert SeedPipeline._count_seeds(tmp_path) == 2
