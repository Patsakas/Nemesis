"""Validation-gate extractor.

Scans a C/C++ library source tree for public-API "limit relaxation" setters —
the functions that lift compile-time validation gates blocking fuzzing reach.

Background:
  Most parsers reject malformed input early via per-field validation
  (`if (image_width > USER_WIDTH_MAX) error()`). Direct fuzz harnesses inherit
  the default limits, so adversarial inputs bounce off the validator and never
  reach the deeper code where bugs typically live. Public APIs almost always
  expose setters that let callers raise these caps:
      png_set_user_limits(...), png_set_chunk_malloc_max(...)
      TIFFSetField(..., TIFFTAG_USERLIMIT, ...)
      xmlCtxtSetMaxAmplification(...)
      ...
  An LLM generating a harness *might* discover these by reading source, but
  that is unreliable. This module extracts them deterministically and feeds
  them into the architect prompt as a structured <validation_gates> block —
  the LLM can then emit the calls without having to deduce them.

Heuristics:
  We grep .c/.h files for function definitions whose names contain idiomatic
  keywords (`set_user`, `set_*_max`, `set_*_limit`, `set_*_min`, `set_options`,
  `set_*_threshold`, `set_*_cache`). We extract the prototype and return one
  ValidationGate per match.

  False positives are tolerable: an extra setter in the prompt costs ~80 chars
  and the LLM ignores irrelevant ones. False negatives (missed setters) are
  the real risk — that's why the keyword set is intentionally broad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ValidationGate:
    setter_name: str
    prototype: str  # full single-line C prototype, e.g. "void png_set_user_limits(png_structrp, png_uint_32, png_uint_32);"
    source_file: str  # repo-relative path where the definition lives


# Function-name idioms that almost always denote a permissive-limit setter.
# Order doesn't matter; any match qualifies.
_KEYWORD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"_set_user(_|$)"),
    re.compile(r"_set_(\w*_)?(max|limit|min|threshold|cache|options?|flags?)(_|$)"),
    re.compile(r"_set_(chunk|memory|alloc|buffer|read|write)_"),
)

# Skip names that look like format-specific chunk/tag setters rather than
# limit-relaxation. These are libpng/libtiff conventions; harmless if a
# library uses lowercase tag names — we only filter UPPER- or mixed-case
# 4-character chunk suffixes which are PNG-specific.
_PNG_CHUNK_SUFFIXES = re.compile(
    r"_set_("
    r"oFFs|pHYs|cHRM|gAMA|sBIT|sRGB|tIME|tRNS|iCCP|pCAL|sCAL|sPLT|hIST|"
    r"bKGD|PLTE|IHDR|IDAT|IEND|tEXt|zTXt|iTXt|fcTL|acTL|fdAT|"
    r"unknown_chunks?|read_user_chunk_fn|read_status_fn|write_status_fn|"
    r"progressive_read_fn|user_transform_info"
    r")\b"
)

# Definition signature: optional macro prefix, return type, optional calling-
# convention macro (PNGAPI / TIFFAPI / __cdecl / FAR / PNG_FUNCTION etc.),
# function name, args, opening brace. Args may span multiple lines.
# We require the opening brace so we only match definitions, not declarations.
_DEF_RE = re.compile(
    r"""
    (?:^|\n)                              # line start
    (?:[A-Z][A-Z0-9_]*\s*\([^)]*\)\s*)?   # optional PNG_EXPORT(48, ...) macro wrap
    (?P<rettype>(?:void|int|long|short|char|size_t|ssize_t|[a-z_]+_t|
                 (?:unsigned\s+)?(?:int|long|short|char)|
                 [A-Z][A-Za-z0-9_]*))     # return type (incl. typedefs like png_uint_32)
    [\ \t]+
    (?:[A-Z][A-Z0-9_]*[\ \t\n]+)?         # optional calling-convention macro (PNGAPI, TIFFAPI, FAR)
    (?P<name>[a-z_][a-z0-9_]+)            # function name (lowercase + underscores)
    [\ \t]*\(
    (?P<args>[^;{)]*(?:\([^)]*\)[^;{)]*)*) # args, allowing nested parens for fn-ptr params
    \)[\s\n]*\{                            # opening brace = it's a definition
    """,
    re.VERBOSE,
)

_SKIP_DIR_SEGMENTS = frozenset(
    {"test", "tests", "build", "build_debug", "build_fuzz", "build_ubsan",
     "build_coverage", ".git", "contrib", "examples", "docs", "doc", "man",
     "fuzz", "fuzzers", ".github", "scripts", "tools"}
)


def _name_is_validation_setter(name: str) -> bool:
    if _PNG_CHUNK_SUFFIXES.search(name):
        return False
    return any(p.search(name) for p in _KEYWORD_PATTERNS)


def _normalize_args(args: str) -> str:
    return re.sub(r"\s+", " ", args).strip()


def extract_validation_gates(source_root: Path) -> list[ValidationGate]:
    """Return up to ~30 candidate limit-relaxation setters in source_root.

    Caller is expected to render the result as a <validation_gates> block in
    the harness-generation prompt.
    """
    if not source_root.exists() or not source_root.is_dir():
        return []

    seen_names: set[str] = set()
    gates: list[ValidationGate] = []

    for path in source_root.rglob("*.c"):
        if any(seg in _SKIP_DIR_SEGMENTS for seg in path.parts):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue

        for m in _DEF_RE.finditer(text):
            name = m.group("name")
            if name in seen_names:
                continue
            if not _name_is_validation_setter(name):
                continue
            args = _normalize_args(m.group("args"))
            rettype = m.group("rettype").strip()
            prototype = f"{rettype} {name}({args});"
            seen_names.add(name)
            try:
                rel = str(path.relative_to(source_root))
            except ValueError:
                rel = path.name
            gates.append(ValidationGate(name, prototype, rel))

            if len(gates) >= 30:
                return gates

    return gates


# Subset of gates that are SAFE to auto-inject into a harness with maximum
# values. Setters that install callbacks (`_fn`/`_callback`), or that toggle
# features via enum codes (`_set_option`), or that have non-numeric params,
# are excluded — passing 0x7FFFFFFF to those would corrupt the parser state.
_INJECT_NAME_RE = re.compile(
    r"_set_("
    r"user_(limits?|width|height|max|min|threshold)|"
    r"\w*_(max|min|limit|threshold|cache)|"
    r"chunk_malloc_max|chunk_cache_max"
    r")\b"
)
_NUMERIC_TYPE_RE = re.compile(
    r"\b(?:"
    r"u?int(?:8|16|32|64)_t|size_t|ssize_t|"
    r"(?:unsigned\s+)?(?:int|long|short|char)|"
    r"[a-z_]+_(?:uint|int|alloc_size|size)_(?:8|16|32|64|t)|"
    r"png_uint_32|png_int_32|png_uint_16|png_byte|png_alloc_size_t"
    r")\b"
)


def _setter_is_injectable(g: ValidationGate) -> bool:
    """True iff calling this setter with max-permissive ints is safe."""
    if not _INJECT_NAME_RE.search(g.setter_name):
        return False
    # Drop any setter whose prototype mentions a function-pointer parameter.
    if "(*" in g.prototype or "_fn" in g.prototype.split("(", 1)[1].split(")", 1)[0]:
        return False
    return True


def _extract_arg_types(prototype: str) -> list[str]:
    """Extract param-type tokens from a prototype's argument list."""
    inner = prototype.split("(", 1)[1].rsplit(")", 1)[0]
    if not inner.strip() or inner.strip() == "void":
        return []
    args: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in inner:
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            cur.append(ch)
    if cur:
        args.append("".join(cur).strip())
    return args


# Anchor: factory call followed by the conventional null-check early-out.
# We anchor AFTER the null-check (not before the first parse call) because
# (a) the parse-call regex was prone to matching destroy/cleanup helpers
# inside error branches, and (b) limit-relaxing setters only mutate context
# fields, so they're safe to call as early as the context exists.
_FACTORY_AND_NULLCHECK_RE = re.compile(
    r"""
    (?P<lead>[\ \t]*)
    (?P<type>[A-Za-z_][A-Za-z0-9_]*p)\s+
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*
    [a-z_][a-z0-9_]*_(?:create|init|alloc)\w*\s*\([^;]*?\)\s*;
    \s*\n
    [\ \t]*if\s*\(\s*!\s*(?P=var)\s*\)\s*
    (?:continue\s*;|return\b[^;]*;|\{[^}]*\})
    """,
    re.VERBOSE,
)


def _strip_comments(source: str) -> str:
    """Remove /* */ and // comments so presence checks don't match a setter
    name that only appears in a comment. Good enough for C harness sources;
    string literals are left intact (a setter name in a string is implausible)."""
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)
    return source


def inject_setter_calls(source: str, gates: list[ValidationGate]) -> str:
    """Auto-insert calls to limit-relaxing setters into a harness.

    Anchors on the first `<type> <var> = *_create_/init_/alloc_(...);` line
    followed by an `if (!var) continue/return/{...}` null-check, and inserts
    setter calls on the line *after* the null check. Idempotent — any setter
    name already CALLED in the source is skipped (comments don't count).

    Returns the source unchanged on any pattern miss.
    """
    injectable = [g for g in gates if _setter_is_injectable(g)]
    if not injectable:
        return source

    fm = _FACTORY_AND_NULLCHECK_RE.search(source)
    if not fm:
        return source
    var_name = fm.group("var")
    indent = fm.group("lead")
    insert_at = fm.end()

    # Presence check ignores comments: a setter merely named in a comment must
    # not suppress its injection (found via the harness-autonomy experiment).
    code_only = _strip_comments(source)
    setter_lines: list[str] = []
    for g in injectable:
        if re.search(rf"\b{re.escape(g.setter_name)}\s*\(", code_only):
            continue
        types = _extract_arg_types(g.prototype)
        if len(types) < 2:
            continue
        if not re.search(r"\bp\b|\bptr\b|\brp\b|_struct\w*\b", types[0]):
            continue
        rest_ok = all(_NUMERIC_TYPE_RE.search(t) for t in types[1:])
        if not rest_ok:
            continue
        call_args = [var_name] + ["0x7FFFFFFFU"] * (len(types) - 1)
        setter_lines.append(f"{indent}{g.setter_name}({', '.join(call_args)});")

    if not setter_lines:
        return source

    block = (
        f"\n{indent}/* nemesis: validation-gate relaxation (auto-injected) */\n"
        + "\n".join(setter_lines) + "\n"
    )
    return source[:insert_at] + block + source[insert_at:]


def render_validation_gates_block(gates: list[ValidationGate]) -> str:
    """Format gates as an XML block ready to drop into the architect prompt.

    The phrasing is intentionally directive ("MUST", "MANDATORY") — earlier
    "SHOULD" wording was ignored by the architect in favour of the per-target
    harness_template's explicit C skeleton. The block is rendered with an
    EXPLICIT INSERTION POINT instruction so the LLM knows where in its
    template body to place the setter calls.
    """
    if not gates:
        return ""
    lines = [
        "<validation_gates>",
        "  MANDATORY HARNESS CONSTRUCTION RULE:",
        "  After every call that constructs a parser/decoder context",
        "  (e.g. *_create_*, *_init, *_alloc) and BEFORE any *_read_* /",
        "  *_decode_* / setjmp() invocation, your harness MUST emit ONE",
        "  call to EACH setter listed below, passing the most permissive",
        "  value its parameter type allows:",
        "      png_uint_32 / uint32_t / int      → 0x7FFFFFFF",
        "      png_alloc_size_t / size_t         → 0   (often means \"no cap\")",
        "      function-pointer / opaque pointer → SKIP this setter",
        "  Skipping these calls keeps default validation limits active and",
        "  prevents fuzzing from reaching deep parser code. Treat this as",
        "  hard a requirement as the existing CRITICAL RULES section.",
        "",
        "  Setters extracted from this library (use ALL relevant ones):",
    ]
    for g in gates:
        lines.append(f"    <setter file=\"{g.source_file}\">{g.prototype}</setter>")
    lines.append("</validation_gates>")
    return "\n".join(lines)
