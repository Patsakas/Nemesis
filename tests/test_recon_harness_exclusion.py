"""
Tests that recon never selects a fuzz harness as a fuzz target.

minmea ships a ClusterFuzzLite harness at `.clusterfuzzlite/fuzzer.c`, and the
scanner ranked its `LLVMFuzzerTestOneInput` as candidate #2 — a fuzzing
framework choosing a fuzz harness as its target. That is circular as well as
useless: the generated harness would wrap an existing harness, and coverage
credited to "the library" would include the other harness's setup.

Defence is layered on purpose, because any single layer is escapable:
  1. function name  (`LLVMFuzzer*` and friends) — holds wherever the file lives
  2. filename       (`fuzzer.c`, `*_fuzzer.c`, …)
  3. directory      (`fuzz/`, `fuzzing/`, `.clusterfuzzlite/`, `tests/`)
"""

from pathlib import Path

import pytest

from nemesis.config import NemesisConfig
from nemesis.recon import IntrospectorParser

# A body that trips the scanner's memory-op gate, so exclusion is the only
# reason a candidate would be missing.
HARNESS_BODY = """\
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
\tchar *copy = malloc(size + 1);
\tmemcpy(copy, data, size);
\tfree(copy);
\treturn 0;
}
"""

LIB_BODY = """\
#include <stdlib.h>
#include <string.h>

int lib_parse(const char *sentence, size_t length)
{
\tchar *copy = malloc(length + 1);
\tmemcpy(copy, sentence, length);
\tfree(copy);
\treturn 0;
}
"""


def _scan(root: Path) -> set[str]:
    cfg = NemesisConfig()
    cfg.target.source_root = str(root)
    return {t.func_name for t in IntrospectorParser(cfg)._scan_local_source()}


@pytest.fixture
def recon(tmp_path: Path) -> IntrospectorParser:
    cfg = NemesisConfig()
    cfg.target.source_root = str(tmp_path)
    return IntrospectorParser(cfg)


# ── layer 1: function name ──────────────────────────────────


@pytest.mark.parametrize("name", [
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "LLVMFuzzerCustomMutator",
    "FuzzerTestOneInput",
])
def test_harness_entry_points_rejected_by_name(recon: IntrospectorParser, name: str):
    assert recon._is_harness_function(name) is True


def test_library_function_not_rejected(recon: IntrospectorParser):
    assert recon._is_harness_function("nmea_parse") is False
    assert recon._is_harness_function("minmea_scan") is False


def test_name_check_survives_an_unexpected_location(tmp_path: Path):
    """Layer 1 must hold even when the harness sits in the library source dir
    under an innocuous filename — which is where our own generated harnesses
    land during a run."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "helpers.c").write_text(HARNESS_BODY)
    (src / "lib.c").write_text(LIB_BODY)

    names = _scan(tmp_path)
    assert "lib_parse" in names
    assert "LLVMFuzzerTestOneInput" not in names


# ── layer 2 + 3: filename and directory ─────────────────────


@pytest.mark.parametrize("rel", [
    ".clusterfuzzlite/fuzzer.c",     # minmea, the case that started this
    "fuzz/harness.c",
    "fuzzing/broker/packet.c",       # mosquitto-style upstream fuzz tree
    "oss-fuzz/target.c",
    "tests/test_parse.c",
    "src/thing_fuzzer.c",
])
def test_harness_locations_are_excluded(tmp_path: Path, rel: str):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    # Deliberately a *library-looking* function, so only the path/filename can
    # be what excludes it.
    path.write_text(LIB_BODY)
    (tmp_path / "real.c").write_text(LIB_BODY.replace("lib_parse", "real_parse"))

    names = _scan(tmp_path)
    assert "real_parse" in names, "the real library function must survive"
    assert "lib_parse" not in names, f"{rel} should have been excluded"


def test_ordinary_source_still_scanned(tmp_path: Path):
    """Guard against the exclusions being too broad."""
    for rel in ["src/parser.c", "lib/decode.c", "src/modules/gnss.c"]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(LIB_BODY.replace("lib_parse", "f_" + Path(rel).stem))

    names = _scan(tmp_path)
    assert {"f_parser", "f_decode", "f_gnss"} <= names
