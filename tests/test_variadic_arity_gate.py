"""
Tests for the variadic-arity preflight gate.

The pipeline generated a minmea harness that looped fourteen literal format
strings through a fixed list of six pointers. minmea_scan consumes one pointer
per format character (';' and '_' excepted), so formats needing up to twenty
arguments read past the end of the argument list and dereferenced whatever was
there — undefined behaviour in the harness, making every crash it could produce
a false positive.

Model choice does not close this. Three samples each on the same prompt:
mistral-small-4 (the configured architect) 0/3 sound, gpt-oss-120b 2/3,
glm-5.2 3/3. Better models lower the rate; only a check removes the class,
which is why this runs before the build rather than after a crash.
"""

import pytest

from nemesis.symbolic.variadic_arity import (
    check,
    find_declaration,
    required_args,
    target_is_variadic,
)

PROLOGUE = """\
#include "minmea.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        char *buf = (char *)__AFL_FUZZ_TESTCASE_BUF;
"""
EPILOGUE = """
    }
    return 0;
}
"""


def harness(body: str) -> str:
    return PROLOGUE + body + EPILOGUE


# ── detecting a variadic target ─────────────────────────────


def test_variadic_declaration_detected():
    assert target_is_variadic(
        "bool minmea_scan(const char *sentence, const char *format, ...);")


def test_fixed_arity_declaration_not_variadic():
    assert not target_is_variadic(
        "nmea_s *nmea_parse(char *sentence, size_t length, int check);")


def test_function_pointer_param_does_not_confuse_detection():
    assert not target_is_variadic("int f(int (*cb)(int, ...), int n);")


def test_declaration_found_in_header_first():
    sources = {
        "src/minmea.c": "bool minmea_scan(const char *s, const char *f, ...) {",
        "minmea.h": "bool minmea_scan(const char *s, const char *f, ...);",
    }
    assert find_declaration(sources, "minmea_scan").endswith("...);")


# ── required_args ───────────────────────────────────────────


def test_minmea_style_counts_every_char():
    assert required_args("tTfd") == 4


def test_semicolon_and_underscore_consume_nothing():
    """`;` switches to optional mode, `_` skips a field."""
    assert required_args("t;Tf_d") == 4


def test_printf_style_counts_conversions():
    assert required_args("%s = %d\\n") == 2


def test_printf_percent_escape_is_not_an_argument():
    assert required_args("100%% of %s") == 1


# ── the four cases named for this gate ──────────────────────


def test_literal_format_correct_is_accepted():
    code = harness('minmea_scan(buf, "tTfd", &a, &b, &c, &d);')
    assert check(code, "minmea_scan") == []


def test_literal_format_mismatch_is_rejected():
    """The shape of the real bug: more directives than pointers."""
    code = harness('minmea_scan(buf, "tciiiiiiiiiiiiifff", &a, &b, &c, &d, &e, &f);')
    findings = check(code, "minmea_scan")
    assert len(findings) == 1
    assert findings[0].reason == "arity_mismatch"
    assert "18" in findings[0].detail and "6 passed" in findings[0].detail


def test_constant_propagated_format_correct_is_accepted():
    """gpt-oss-120b named its format; that is fine and must not be rejected."""
    code = harness('const char *fmt = "cifT_Ds_t;_c";\n'
                   "minmea_scan(buf, fmt, &a, &b, &c, &d, &e, &f, &g, &h);")
    assert check(code, "minmea_scan") == []


def test_unknown_format_source_is_rejected():
    """An array element cannot be checked, and one fixed argument list cannot
    match every format in the array — this is what the pipeline produced."""
    code = harness(
        'const char *formats[] = {"t", "tT", "tciiiiiiiiiiiiifff"};\n'
        "for (int i = 0; i < 3; i++)\n"
        "    minmea_scan(buf, formats[i], &a, &b, &c, &d, &e, &f);")
    findings = check(code, "minmea_scan")
    assert len(findings) == 1
    assert findings[0].reason == "format_not_resolvable"


# ── the real generated harness ──────────────────────────────


def test_the_actual_rejected_harness(tmp_path):
    """Verbatim shape of benchmarks/minmea_harness_generation/invalid/."""
    code = harness(
        'const char *formats[] = {\n'
        '    "t", "tT", "tTf", "tTf;f", "tcfdfd",\n'
        '    "tciiiiiiiiiiiiifff", "tiii;iiifiiifiiifiiif"\n'
        "};\n"
        "for (size_t i = 0; i < 7; i++) {\n"
        "    minmea_scan(buf, formats[i], &output.type, &output.time,\n"
        "                &output.fval, &output.cval, &output.ival, &output.dval);\n"
        "}")
    findings = check(code, "minmea_scan")
    assert findings, "the harness that shipped must not pass this gate"
    assert findings[0].reason == "format_not_resolvable"


# ── guards against over-rejection ───────────────────────────


def test_extra_arguments_are_allowed():
    """Passing more than the format needs is wasteful, not undefined."""
    assert check(harness('minmea_scan(buf, "tT", &a, &b, &c, &d);'),
                 "minmea_scan") == []


def test_prototype_is_not_treated_as_a_call():
    code = "bool minmea_scan(const char *s, const char *f, ...);\n" + harness(
        'minmea_scan(buf, "tT", &a, &b);')
    assert check(code, "minmea_scan") == []


def test_unrelated_calls_are_ignored():
    code = harness('printf("%s %d\\n", s, n);\nminmea_scan(buf, "t", &a);')
    assert check(code, "minmea_scan") == []


def test_reassigned_format_variable_is_not_resolvable():
    """Two different values means the binding cannot be resolved statically."""
    code = harness('const char *fmt = "tT";\n'
                   'const char *fmt = "tciiiiiiiiiiiiifff";\n'
                   "minmea_scan(buf, fmt, &a, &b);")
    findings = check(code, "minmea_scan")
    assert findings and findings[0].reason == "format_not_resolvable"


def test_multiple_calls_each_reported():
    code = harness('minmea_scan(buf, "tTfd", &a, &b, &c, &d);\n'
                   'minmea_scan(buf, "tTfd", &a, &b);')
    findings = check(code, "minmea_scan")
    assert len(findings) == 1
    assert findings[0].call_index == 2


@pytest.mark.parametrize("fmt,args,sound", [
    ("t", 1, True), ("t", 0, False),
    ("tT", 2, True), ("tT", 1, False),
    (";;;", 0, True),
])
def test_arity_boundaries(fmt: str, args: int, sound: bool):
    ptrs = ", ".join(["&a"] * args)
    call = f'minmea_scan(buf, "{fmt}"' + (f", {ptrs}" if ptrs else "") + ");"
    assert bool(check(harness(call), "minmea_scan") == []) is sound
