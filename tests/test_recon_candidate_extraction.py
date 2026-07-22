"""
Tests for candidate extraction in recon: which functions become fuzz targets.

Scoring is irrelevant for a function that never enters the candidate set, and
that is exactly how the libnmea failure happened. Two independent defects:

  * `_find_enclosing_function` walked back 50 lines while
    `_find_function_start_line` walked back 100. A gate-matching line more than
    50 lines below its signature yielded a valid start index and a None name,
    and `_scan_local_source` drops candidates with no name. Every function
    longer than ~50 lines was invisible — including `nmea_parse`, the canonical
    (buffer, length) entry point.

  * `^(\\w+)\\s*\\(` matches `free(data);` as readily as a definition, so call
    sites were promoted to fuzz targets. `printf` and `free` were ranked.

These are silent: the pipeline reports success either way. The tests below are
the guard that they cannot come back quietly.
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


def _long_function(body_lines: int) -> list[str]:
    """K&R definition whose interesting line sits `body_lines` below the signature."""
    lines = ["nmea_s *", "nmea_parse(char *sentence, size_t length, int check)", "{"]
    lines += [f"\tint pad{i} = {i};" for i in range(body_lines)]
    lines += ["\tparser->errors++;", "\treturn NULL;", "}"]
    return lines


# ── visibility: long functions ──────────────────────────────


@pytest.mark.parametrize("body", [10, 60, 200])
def test_long_function_stays_visible(recon: IntrospectorParser, body: int):
    """The 50-line window made anything past it nameless. libnmea's real gap
    was 54 lines; 200 guards against a merely-bigger fixed window."""
    lines = _long_function(body)
    idx = len(lines) - 3          # the `parser->errors++;` line
    assert recon._find_enclosing_function(lines, idx) == "nmea_parse"


def test_name_and_start_line_never_disagree(recon: IntrospectorParser):
    """The original bug was precisely a disagreement: valid start, None name."""
    lines = _long_function(80)
    idx = len(lines) - 3
    start = recon._find_function_start_line(lines, idx)
    name = recon._find_enclosing_function(lines, idx)
    assert start >= 0
    assert name is not None
    assert lines[start].startswith(name)


def test_walk_stops_at_previous_function_end(recon: IntrospectorParser):
    """A line that belongs to no function must not be attributed to the
    function above it — the column-0 `}` is the boundary."""
    lines = [
        "static void",
        "helper(char *p, size_t n)",
        "{",
        "\treturn;",
        "}",
        "",
        "int global_thing = 1;   /* not inside any function */",
    ]
    assert recon._find_enclosing_function(lines, 6) is None


# ── candidate correctness: call sites are not definitions ───


@pytest.mark.parametrize(
    "call",
    [
        "free(data);",
        "printf(\"%s\\n\", s);",
        "memcpy(dst, src, n);",
    ],
)
def test_call_site_is_not_a_definition(recon: IntrospectorParser, call: str):
    lines = ["void", "real_func(char *s, size_t n)", "{", f"\t{call}", "}"]
    assert recon._is_function_definition(lines, 3) is False


def test_call_site_resolves_to_its_enclosing_function(recon: IntrospectorParser):
    """`free` used to be reported as the target here; it must be `real_func`."""
    lines = ["void", "real_func(char *s, size_t n)", "{", "\tfree(s);", "}"]
    assert recon._find_enclosing_function(lines, 3) == "real_func"


def test_prototype_is_not_a_definition(recon: IntrospectorParser):
    """A declaration ends in `;` and has no body."""
    assert recon._is_function_definition(["int nmea_load_parsers();"], 0) is False


def test_knr_definition_is_a_definition(recon: IntrospectorParser):
    lines = ["nmea_s *", "nmea_parse(char *s, size_t n, int c)", "{"]
    assert recon._is_function_definition(lines, 1) is True


def test_same_line_brace_definition(recon: IntrospectorParser):
    assert recon._is_function_definition(["foo(int a) {"], 0) is True


def test_wrapped_params_definition(recon: IntrospectorParser):
    lines = ["foo(char *buf,", "    size_t len)", "{"]
    assert recon._is_function_definition(lines, 0) is True


def test_control_flow_keyword_is_never_a_function(recon: IntrospectorParser):
    lines = ["void", "f(char *s)", "{", "\tif (s) {", "\t\tfree(s);", "\t}", "}"]
    assert recon._find_enclosing_function(lines, 4) == "f"


# ── the libnmea regression fixture, end to end ──────────────


LIBNMEA_PARSER_C = """\
#include <string.h>

int
nmea_load_parsers()
{
\tint i;
\tchar *files[255];
\tnmea_parser_module_s *parser;

\tparser = malloc(sizeof(nmea_parser_module_s));
\tparser->next = NULL + 1;
\treturn 0;
}
"""

LIBNMEA_NMEA_C_TEMPLATE = """\
#include <string.h>

nmea_s *
nmea_parse(char *sentence, size_t length, int check_checksum)
{
%s
\tparser->errors++;
\treturn parser->parser.data;
}
"""


def test_libnmea_shape_ranks_parse_above_loader(tmp_path: Path):
    """The original failure, reproduced from source: a zero-argument loader that
    mallocs and walks pointers must not outrank the (buffer, length) parser
    whose body puts its first interesting line >50 lines down."""
    src = tmp_path / "src" / "nmea"
    src.mkdir(parents=True)
    (src / "parser.c").write_text(LIBNMEA_PARSER_C)
    padding = "\n".join(f"\tint pad{i} = {i};" for i in range(60))
    (src / "nmea.c").write_text(LIBNMEA_NMEA_C_TEMPLATE % padding)

    cfg = NemesisConfig()
    cfg.target.source_root = str(tmp_path)
    targets = IntrospectorParser(cfg)._scan_local_source()
    by_name = {t.func_name: t.priority_score for t in targets}

    assert "nmea_parse" in by_name, "the parser entry point must be a candidate at all"
    assert "nmea_load_parsers" in by_name
    assert by_name["nmea_parse"] > by_name["nmea_load_parsers"]


def test_no_libc_names_leak_into_candidates(tmp_path: Path):
    """`printf` / `free` / `malloc` are call sites, never fuzz targets."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text(
        "void\n"
        "consume(char *buf, size_t len)\n"
        "{\n"
        "\tchar *p = malloc(len + 1);\n"
        "\tmemcpy(p, buf, len);\n"
        "\tprintf(\"%s\", p);\n"
        "\tfree(p);\n"
        "}\n"
    )
    cfg = NemesisConfig()
    cfg.target.source_root = str(tmp_path)
    names = {t.func_name for t in IntrospectorParser(cfg)._scan_local_source()}

    assert "consume" in names
    assert names.isdisjoint({"printf", "free", "malloc", "memcpy"})
