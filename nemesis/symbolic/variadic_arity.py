"""Static check: does the harness call a variadic target with matching arity?

A variadic callee reads its extra arguments with `va_arg`, once per directive
in its format string. Pass fewer than the format demands and the callee reads
whatever happens to sit in the varargs area and dereferences it. That is
undefined behaviour in the *harness*, so every crash it produces is a false
positive — the kind a maintainer rejects on sight, and rightly.

The pipeline generated exactly that for minmea. `minmea_scan(sentence, format,
...)` consumes one pointer per format character (`;` and `_` excepted), and the
harness looped fourteen literal formats — some needing twenty arguments —
through a fixed list of six pointers:

    const char *formats[] = { "t", "tT", "tciiiiiiiiiiiiifff", ... };
    for (i = 0; i < 14; i++)
        minmea_scan(buf, formats[i], &a, &b, &c, &d, &e, &f);

Model choice does not fix this. Over 3 samples each on the same prompt:
mistral-small-4 (the configured architect) 0/3 sound, gpt-oss-120b 2/3,
glm-5.2 3/3. A better model lowers the rate; only a check removes the class.

Two rules, both language-agnostic about the *contents* of the format:

  1. the format argument must be statically resolvable — a literal, or a
     single-assignment `const char *f = "...";`. An array element or a
     parameter cannot be checked, and a fixed argument list cannot match a
     varying format anyway. That rule alone catches the observed bug.

  2. once resolved, the count of argument-consuming directives must not exceed
     the number of variadic arguments passed. printf-style formats are counted
     by conversion specifier; anything else is counted conservatively as one
     argument per character outside `no_arg_chars`.

Rule 2 can over-reject a mini-language where most characters consume nothing.
That is the deliberate direction: a rejected harness is regenerated, an
accepted-but-unsound one silently poisons every result downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Characters that carry no argument in the mini-languages we have met. minmea:
# ';' switches remaining fields to optional, '_' skips a field.
DEFAULT_NO_ARG_CHARS = ";_ "

_CONST_FMT_RE = re.compile(
    r'(?:const\s+)?char\s*(?:\*|\[\s*\])\s*(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*;')
_PRINTF_CONV_RE = re.compile(r"%[-+ #0]*[\d*]*(?:\.[\d*]+)?(?:hh|h|ll|l|j|z|t|L)?"
                             r"([diouxXeEfgGaAcspn%])")


@dataclass(frozen=True)
class ArityFinding:
    call_index: int
    reason: str
    detail: str

    def __str__(self) -> str:
        return f"variadic call #{self.call_index}: {self.reason} — {self.detail}"


def target_is_variadic(declaration: str) -> bool:
    """True if a C declaration ends its parameter list with `...`."""
    start = declaration.find("(")
    if start < 0:
        return False
    depth, end = 0, -1
    for i in range(start, len(declaration)):
        if declaration[i] == "(":
            depth += 1
        elif declaration[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return False
    return declaration[start + 1:end].rstrip().endswith("...")


def find_declaration(sources: dict[str, str], func: str) -> str | None:
    """Locate `func`'s declaration in {path: text}, preferring headers."""
    pattern = re.compile(rf"[\w\s\*]+\b{re.escape(func)}\s*\([^;{{]*[;{{]", re.S)
    for path in sorted(sources, key=lambda p: (not p.endswith(".h"), p)):
        m = pattern.search(sources[path])
        if m:
            return " ".join(m.group(0).split())
    return None


def _split_args(inner: str) -> list[str]:
    """Top-level comma split that respects strings, chars and nesting."""
    parts: list[str] = []
    depth, buf, i, n = 0, "", 0, len(inner)
    while i < n:
        ch = inner[i]
        if ch in ('"', "'"):
            quote = ch
            buf += ch
            i += 1
            while i < n:
                buf += inner[i]
                if inner[i] == "\\":
                    i += 2
                    continue
                if inner[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
        i += 1
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _resolvable_formats(code: str) -> dict[str, str]:
    """Single-assignment `const char *f = "...";` bindings.

    Names assigned more than once with different values are dropped: they are
    not statically resolvable, which is the whole point of the check.
    """
    seen: dict[str, str] = {}
    conflicting: set[str] = set()
    for m in _CONST_FMT_RE.finditer(code):
        name, value = m.group(1), m.group(2)
        if name in seen and seen[name] != value:
            conflicting.add(name)
        seen[name] = value
    return {k: v for k, v in seen.items() if k not in conflicting}


def required_args(fmt: str, no_arg_chars: str = DEFAULT_NO_ARG_CHARS) -> int:
    """How many variadic arguments a resolved format demands."""
    if "%" in fmt:
        return sum(1 for m in _PRINTF_CONV_RE.finditer(fmt) if m.group(1) != "%")
    return sum(1 for ch in fmt if ch not in no_arg_chars)


def check(code: str, func: str, format_arg_index: int = 1,
          no_arg_chars: str = DEFAULT_NO_ARG_CHARS) -> list[ArityFinding]:
    """Findings for every call to `func` in `code`. Empty list means sound.

    `format_arg_index` is the zero-based position of the format parameter,
    counting only the named ones — 1 for `f(sentence, format, ...)`.
    """
    consts = _resolvable_formats(code)
    findings: list[ArityFinding] = []
    call_index = 0

    for m in re.finditer(rf"\b{re.escape(func)}\s*\(", code):
        # A declaration or prototype is not a call.
        preceding = code[max(0, m.start() - 60):m.start()]
        if re.search(r"\b(bool|void|int|extern|static|inline)\s*\*?\s*$", preceding):
            continue

        depth, end, i = 0, -1, m.end() - 1
        while i < len(code):
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end < 0:
            continue

        args = _split_args(code[m.end():end])
        if len(args) <= format_arg_index:
            continue
        call_index += 1

        fmt_expr = args[format_arg_index]
        passed = len(args) - (format_arg_index + 1)

        literal = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', fmt_expr)
        if literal:
            fmt = literal.group(1)
        elif fmt_expr in consts:
            fmt = consts[fmt_expr]
        else:
            findings.append(ArityFinding(
                call_index, "format_not_resolvable",
                f"format argument `{fmt_expr[:40]}` is not a literal or a "
                f"single-assignment constant, so its arity cannot be checked; "
                f"{passed} variadic argument(s) passed"))
            continue

        needed = required_args(fmt, no_arg_chars)
        if needed > passed:
            findings.append(ArityFinding(
                call_index, "arity_mismatch",
                f'format "{fmt}" needs {needed} variadic argument(s), '
                f"{passed} passed"))
    return findings


REGENERATION_HINT = (
    "The target function is variadic: it reads one argument per directive in "
    "its format string. Use a single literal format string and pass exactly "
    "one correctly-typed pointer per directive. Do NOT loop a fixed argument "
    "list over an array of different format strings — the argument count "
    "cannot match every format, and the callee will read past the arguments "
    "you passed, which is undefined behaviour in the harness rather than a bug "
    "in the library."
)
