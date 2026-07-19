"""Progress predicates are injected at the very top of the __AFL_LOOP body,
where the harness's own variables do not exist yet. Anything the model called
the input has to be rewritten to the AFL macros, and whatever cannot be
resolved has to be dropped — otherwise the builder gets a harness that will
not compile.

Regression: a real cjson run emitted `len >= 4 && memchr(input, ':', len)`.
`input` was rewritten but `len` was not, so the harness failed with
"use of undeclared identifier 'len'" and the iteration was wasted.
"""
import re

from nemesis.recon.predicate_synthesis import ProgressPredicate, inject_predicates

HARNESS = """#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        const unsigned char *src = __AFL_FUZZ_TESTCASE_BUF;
        char *buf = (char *)malloc(len + 1);
        if (!buf) continue;
        memcpy(buf, src, len); buf[len] = 0;
        target_parse(buf);
        free(buf);
    }
    return 0;
}
"""

# The predicate block sits above this line, so anything it references must
# already be in scope there.
_DECL = "size_t len = __AFL_FUZZ_TESTCASE_LEN;"


def _injected_conditions(source: str) -> list[str]:
    return re.findall(r"if \(!\((.+?)\)\) continue;", source)


def _block_before_declaration(source: str) -> str:
    return source.split(_DECL)[0]


def test_bare_len_is_rewritten_to_the_afl_macro():
    """The exact condition that broke the cjson run."""
    p = ProgressPredicate(name="has_colon",
                          condition="len >= 4 && memchr(input, ':', len) != NULL",
                          rationale="key/value separator")
    out = inject_predicates(HARNESS, [p], "target_parse")
    conds = _injected_conditions(out)

    assert conds, "the predicate should have been injected"
    assert "__AFL_FUZZ_TESTCASE_LEN" in conds[0]
    assert "__AFL_FUZZ_TESTCASE_BUF" in conds[0]
    # no bare identifier survives above the declaration
    assert not re.search(r"\blen\b", _block_before_declaration(out))
    assert not re.search(r"\binput\b", _block_before_declaration(out))


def test_other_common_aliases_are_rewritten():
    p = ProgressPredicate(name="has_brace",
                          condition="size >= 2 && memchr(data, '{', size) != NULL",
                          rationale="object start")
    out = inject_predicates(HARNESS, [p], "target_parse")
    before = _block_before_declaration(out)
    assert not re.search(r"\bsize\b(?!_t)", before)
    assert not re.search(r"\bdata\b", before)
    assert "__AFL_FUZZ_TESTCASE_LEN" in before and "__AFL_FUZZ_TESTCASE_BUF" in before


def test_predicate_with_unresolvable_identifier_is_dropped():
    """A name that is not the input and not a known helper cannot compile here."""
    good = ProgressPredicate(name="ok", condition="len > 4", rationale="")
    bad = ProgressPredicate(name="bad", condition="parser_depth > 3 && len > 4", rationale="")
    out = inject_predicates(HARNESS, [good, bad], "target_parse")

    assert "parser_depth" not in out
    assert len(_injected_conditions(out)) == 1


def test_source_is_untouched_when_every_predicate_is_dropped():
    bad = ProgressPredicate(name="bad", condition="some_state == 1", rationale="")
    assert inject_predicates(HARNESS, [bad], "target_parse") == HARNESS


def test_injection_is_idempotent():
    p = ProgressPredicate(name="has_colon", condition="len >= 4", rationale="")
    once = inject_predicates(HARNESS, [p], "target_parse")
    twice = inject_predicates(once, [p], "target_parse")
    assert once == twice
