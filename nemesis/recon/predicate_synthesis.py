"""Locus-style progress-predicate synthesis (Tier 1 #2, 2026-05-07).

Background
----------
For narrow-trigger bugs like CVE-2023-4863 (libwebp Huffman table
overflow), vanilla coverage-guided AFL cannot reach the trigger because
the path requires passing through 10+ bit-level validation gates.
Random byte mutations cannot keep the input syntactically valid long
enough to reach the vulnerable code.

Locus (arxiv 2508.21302) showed that injecting LLM-synthesised
"progress predicates" — boolean expressions that fire only when a seed
advances toward the buggy state — gives AFL extra coverage edges that
reward seeds making genuine progress, while early-terminating off-path
seeds. On Magma the technique gave vanilla AFL++ a 15.3× speedup
(directed-fuzzer-only headlines of 41.6× are aggregate; do not oversell).

NEMESIS port
------------
1.  `synthesize_predicates()` builds a prompt with target_func + the
    harness source + the format_spec + the bug_history (recent CVEs)
    and asks the LLM for 3-5 progress predicates as plain C boolean
    expressions plus a one-line rationale per predicate.

2.  `inject_predicates()` rewrites the harness to insert
        if (!(<expr>)) continue;
    immediately before the first call to `target_func` inside the
    `__AFL_LOOP` body. `continue` (NOT `exit(0)`) is mandatory in
    persistent mode — `exit(0)` kills the fork-server child and forces
    a slow respawn, halving exec rate.

3.  Each predicate gets its own `if (...)` line so AFL's edge bitmap
    gives a distinct coverage edge per predicate. Seeds that pass more
    predicates are scored higher; off-path seeds short-circuit at the
    first failed predicate.

Generality
----------
No per-library code. The LLM gets the library name, the harness source,
the format spec (synthesised at onboard time), the bug history (fetched
from NVD), and the target function — all already in NEMESIS pipeline
state. Output is plain C expressions; injection is a pure string
rewrite anchored on the target_func call site.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nemesis.neural import LLMClient


@dataclass
class ProgressPredicate:
    name: str           # short identifier, e.g. "vp8l_signature_byte"
    condition: str      # C boolean expression, e.g. "input_len >= 21 && input[20] == 0x2F"
    rationale: str      # one-line "why this is on-path to the bug"


_SYSTEM_PROMPT = """\
You synthesise Locus-style progress predicates for AFL++ fuzz harnesses
targeting narrow-trigger bug rediscovery.

A progress predicate is a plain C boolean expression that evaluates true
when the current input is structurally on the path to a known bug. It is
NOT a trigger check — it is an INTERMEDIATE waypoint. Multiple predicates
form a progressive ladder: each one harder to satisfy than the last.

Each predicate must be:
  * a single C boolean expression (no semicolons, no statements, no calls
    to library functions — bytewise inspection of the AFL input buffer
    only)
  * referencing only variables that are visible at the call site of the
    target function in the provided harness source
  * cheap to evaluate (low single-digit microseconds at most)
  * progress-oriented: phrased so seeds that satisfy it are closer to
    the bug than seeds that don't

Examples for libpng harnesses targeting an IHDR-time integer overflow:
  - input_len >= 8 && memcmp(input, "\\x89PNG\\r\\n\\x1a\\n", 8) == 0
  - input_len >= 24 && memcmp(input + 12, "IHDR", 4) == 0
  - input_len >= 32 && (input[24] | input[25] | input[26] | input[27]) != 0

Output STRICT JSON:
  {"predicates": [
     {"name": "<snake_case>", "condition": "<C boolean expr>", "rationale": "<1 line>"},
     ...
  ]}

Constraints:
  * 3 to 5 predicates, ordered from easiest to hardest.
  * No predicate may reject all known PoC seeds — keep them PROGRESS,
    not TRIGGER.
  * Variables and types must match the harness source verbatim. If the
    harness aliases `__AFL_FUZZ_TESTCASE_BUF` to `input`, use `input`.
  * No predicate may invoke library code. ONLY buffer/length reads,
    `memcmp` on string literals, bit shifts and arithmetic.

OUTPUT ONLY THE JSON OBJECT. NO MARKDOWN FENCES. NO PROSE BEFORE OR AFTER.
"""


def _build_user_prompt(
    library_name: str,
    target_func: str,
    harness_source: str,
    cve_records: list[dict],
    format_spec: str,
) -> str:
    lines: list[str] = [
        f"Library: {library_name}",
        f"Target function: {target_func}",
        "",
        "Harness source (predicates must reference variables in scope at the",
        "target call site):",
        "```c",
        harness_source[:6000],
        "```",
        "",
    ]
    if format_spec:
        lines += [
            "Format reference (use this to identify which bytes carry the",
            "encoding decisions on the path to the bug):",
            "```",
            format_spec[:3000],
            "```",
            "",
        ]
    if cve_records:
        lines += [
            "Recent CVEs against this library — use these to identify the",
            "specific code surface and trigger conditions to bias toward:",
            "",
        ]
        for rec in cve_records:
            lines.append(f"  {rec.get('id', '?')}: {rec.get('description', '')[:400]}")
        lines.append("")
    lines += [
        f"Now emit 3-5 progress predicates leading to `{target_func}`.",
    ]
    return "\n".join(lines)


def _extract_predicates(raw_response: str) -> list[ProgressPredicate]:
    if not raw_response:
        return []
    text = raw_response.strip()

    if text.startswith("```"):
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    obj = None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                return []
    if not isinstance(obj, dict):
        return []

    raw_list = obj.get("predicates", [])
    if not isinstance(raw_list, list):
        return []

    out: list[ProgressPredicate] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        cond = str(entry.get("condition", "")).strip()
        rat = str(entry.get("rationale", "")).strip()
        if not cond:
            continue
        # Sanity: reject obvious dangerous content
        if ";" in cond or "{" in cond or "}" in cond:
            continue
        if "exit(" in cond or "abort(" in cond or "system(" in cond:
            continue
        # Bound size — predicates should be tight
        if len(cond) > 400:
            continue
        if not name:
            name = f"pred_{len(out)}"
        out.append(ProgressPredicate(name=name, condition=cond, rationale=rat))

    return out


def synthesize_predicates(
    library_name: str,
    target_func: str,
    harness_source: str,
    cve_records: list[dict],
    format_spec: str,
    client: LLMClient,
    log: logging.Logger | None = None,
    max_predicates: int = 5,
) -> list[ProgressPredicate]:
    """Ask the LLM for 3-5 progress predicates leading to `target_func`.

    Returns [] on any error — caller writes the harness without
    predicate gates and falls back to vanilla coverage-guided fuzzing.
    """
    from nemesis.neural import ModelRole

    if not target_func or "(" in target_func:
        if log:
            log.warning("predicate_synthesis.bad_target_func", target=target_func)
        return []

    prompt = _build_user_prompt(
        library_name=library_name,
        target_func=target_func,
        harness_source=harness_source,
        cve_records=cve_records,
        format_spec=format_spec,
    )

    try:
        response = client.complete(
            prompt=prompt,
            system=_SYSTEM_PROMPT,
            stage="predicate_synthesis",
            target_func=target_func,
            role=ModelRole.ARCHITECT,
        )
    except Exception as exc:
        if log:
            log.warning("predicate_synthesis.llm_failed", error=str(exc))
        return []

    preds = _extract_predicates(response or "")
    if log:
        log.info(
            "predicate_synthesis.parsed",
            count=len(preds),
            names=[p.name for p in preds[:max_predicates]],
        )
    return preds[:max_predicates]


# ──────────────────────────────────────────────────────────────────────
# Injection
# ──────────────────────────────────────────────────────────────────────

# Sentinel used to skip re-injection on a re-write. inject_predicates is
# idempotent — calling it twice on the same source is a no-op.
_NEMESIS_PREDICATES_SENTINEL = "/* nemesis: progress predicates (Locus-style)"


_AFL_LEN = "((size_t)__AFL_FUZZ_TESTCASE_LEN)"
_AFL_BUF = "((const uint8_t *)__AFL_FUZZ_TESTCASE_BUF)"

# Names models reach for when they mean "the fuzz input" or "its length".
# The predicates are injected at the very top of the __AFL_LOOP body, where the
# harness's own aliases do not exist yet, so every one of these has to be
# rewritten to the macros — which are the only things reliably in scope there.
_INPUT_ALIASES: dict[str, str] = {
    "input_len": _AFL_LEN, "input_size": _AFL_LEN, "data_len": _AFL_LEN,
    "data_size": _AFL_LEN, "buf_len": _AFL_LEN, "buffer_len": _AFL_LEN,
    "size": _AFL_LEN, "length": _AFL_LEN, "len": _AFL_LEN, "n": _AFL_LEN,
    "input": _AFL_BUF, "data": _AFL_BUF, "buf": _AFL_BUF,
    "buffer": _AFL_BUF, "bytes": _AFL_BUF, "ptr": _AFL_BUF,
}
# Longest first so `input_len` is consumed before `input`; one pass, so a
# replacement can never be re-matched by a later alias.
_ALIAS_RE = re.compile(
    r"\b(" + "|".join(sorted(_INPUT_ALIASES, key=len, reverse=True)) + r")\b"
)

# Everything a condition may legitimately mention once aliases are rewritten.
_ALLOWED_IDENTIFIERS = frozenset({
    "__AFL_FUZZ_TESTCASE_LEN", "__AFL_FUZZ_TESTCASE_BUF",
    "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int", "unsigned", "char", "const", "void", "sizeof", "NULL",
    "memchr", "memcmp", "memmem", "strncmp", "strncasecmp", "strchr", "strstr",
})
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _rewrite_condition(cond: str) -> str:
    """Map whatever the model called the input onto the AFL macros."""
    return _ALIAS_RE.sub(lambda m: _INPUT_ALIASES[m.group(1)], cond)


def _unresolved_identifiers(cond: str) -> set[str]:
    """Identifiers that would not compile at the top of the loop body."""
    return {t for t in _IDENT_RE.findall(cond) if t not in _ALLOWED_IDENTIFIERS}


def inject_predicates(
    harness_source: str,
    predicates: list[ProgressPredicate],
    target_func: str,
    log: logging.Logger | None = None,
) -> str:
    """Insert `if (!(cond)) continue;` gates as early as possible inside
    the `__AFL_LOOP` body — RIGHT AFTER the input/input_len reads, before
    any heavy per-iteration setup (malloc/init/etc).

    Why this matters for throughput
    -------------------------------
    Earlier versions anchored the gates immediately before the
    `target_func(...)` call. That is correct for "did we reach the
    target", but if the harness body allocates a large buffer (lz4
    template mallocs 1 MiB per iter) BEFORE the call, every rejected
    seed pays the malloc cost. With 95% predicate-rejection rate, the
    pipeline does 20× more allocation than needed. Moving gates to the
    top of the loop body turns rejection into a one-branch `continue`.

    Anchor strategy (in order):
      1. The line ending with `__AFL_FUZZ_TESTCASE_LEN` — after this
         line both `input` and `input_len` are in scope. Insertion
         goes immediately after.
      2. (Fallback) The first call site of `target_func`.

    Idempotent: re-injection is a no-op if the sentinel is already
    present. Returns source unchanged when neither anchor matches.
    """
    if not predicates:
        return harness_source
    if _NEMESIS_PREDICATES_SENTINEL in harness_source:
        return harness_source

    # 1) Preferred anchor: IMMEDIATELY inside the `__AFL_LOOP` body, before
    # any heavy setup (malloc / memcpy / aliases). Why this matters:
    #
    #   * Per-iteration cost. Putting predicates above malloc means every
    #     rejected seed pays only the cheap branch; no allocator pressure.
    #   * Variable scope. Earlier versions anchored after the harness's
    #     `input` and `input_len` aliases, but Fix-139 heap-copy renames
    #     them to `_nfx_buf` / `_nfx_len`, leaving the LLM-emitted
    #     predicates referencing names that no longer exist. Anchoring at
    #     the top of the loop and rewriting `input`/`input_len` to the
    #     two `__AFL_FUZZ_TESTCASE_*` macros sidesteps the whole issue —
    #     the macros are always in scope inside __AFL_LOOP.
    insert_at = -1
    indent = ""
    loop_re = re.compile(
        r"(?:while\s*\(\s*)?__AFL_LOOP\s*\([^)]*\)\s*\)?\s*\{",
    )
    lm = loop_re.search(harness_source)
    if lm:
        # Inject right after the `__AFL_LOOP(...) {` opening brace.
        insert_at = lm.end()
        # Inherit indentation from the next non-empty line.
        nl = harness_source.find("\n", insert_at)
        if nl != -1:
            tail = harness_source[insert_at + 1:]
            ind_m = re.match(r"[ \t]*", tail)
            indent = ind_m.group(0) if ind_m else "    "
            insert_at = nl + 1  # write a fresh line below the brace
        else:
            indent = "    "

    # 2) Fallback: anchor on the target_func call site (legacy behaviour).
    if insert_at < 0:
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(target_func)}\s*\(")
        tm = pattern.search(harness_source)
        if not tm:
            if log:
                log.warning("predicate_synthesis.no_anchor_found",
                            target=target_func)
            return harness_source
        insert_at = harness_source.rfind("\n", 0, tm.start()) + 1
        indent_match = re.match(r"[ \t]*", harness_source[insert_at:tm.start()])
        indent = indent_match.group(0) if indent_match else ""

    # Rewrite `input` / `input_len` references to the AFL macros so the
    # predicates compile regardless of how the harness aliased the buffer
    # (Fix 139 heap-copy renames it to _nfx_buf, some harnesses don't alias
    # at all, etc.). Word-boundary regex avoids touching `__AFL_FUZZ_TESTCASE_LEN`
    # or other tokens that happen to contain "input".
    block_lines = [
        f"{indent}{_NEMESIS_PREDICATES_SENTINEL} for `{target_func}` */",
    ]
    kept = 0
    for p in predicates:
        cond = _rewrite_condition(p.condition)
        unresolved = _unresolved_identifiers(cond)
        if unresolved:
            # Emitting this would not compile: at the top of the loop body the
            # only things in scope are the two AFL macros. Drop the predicate
            # rather than hand the builder a broken harness.
            if log:
                log.warning("predicate_synthesis.dropped_unresolved",
                            name=p.name, identifiers=sorted(unresolved))
            continue
        comment = p.rationale.replace("*/", "* /")[:160] if p.rationale else p.name
        block_lines.append(f"{indent}/* {p.name}: {comment} */")
        block_lines.append(f"{indent}if (!({cond})) continue;")
        kept += 1

    if not kept:
        return harness_source

    block_lines.append(
        f"{indent}/* nemesis: end progress predicates */"
    )
    block = "\n".join(block_lines) + "\n"

    return harness_source[:insert_at] + block + harness_source[insert_at:]


def render_predicates_block(predicates: list[ProgressPredicate]) -> str:
    """Format predicates as an XML log block (debug-friendly).

    Used by callers that want to record the synthesised set in run logs
    even when injection is skipped.
    """
    if not predicates:
        return ""
    lines = ["<progress_predicates>"]
    for p in predicates:
        lines.append(f"  <pred name=\"{p.name}\">")
        lines.append(f"    <cond>{p.condition}</cond>")
        if p.rationale:
            lines.append(f"    <why>{p.rationale}</why>")
        lines.append("  </pred>")
    lines.append("</progress_predicates>")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# Canary validation (Fix C, 2026-05-07)
# ──────────────────────────────────────────────────────────────────────
#
# Background: in the lz4 run, Mistral synthesised a predicate set whose
# first gate was `memcmp(input, "\\x00\\x00\\x00\\x00", 4) == 0` (i.e. it
# misidentified raw lz4 blocks as lz4 frames). The independent pass rate
# of that predicate against any non-trivial seed is ~1 in 4.3 billion;
# combined with the rest of the chain it was effectively a wall.
#
# Symptom: AFL exec stays high (because almost everything `continue`s
# out before calling the target API), bitmap stays at zero, no crashes.
# The synthesis stage emits beautiful-looking predicates that
# pathologically reject every seed.
#
# Fix: before injecting, evaluate each predicate against a sample of
# real seeds for the format. Drop any predicate whose pass rate is
# below `min_pass_rate` (default 1%). Then drop predicates from the
# tail of the surviving chain until at least one seed passes the full
# AND-chain.

_C_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _decode_c_string(literal: str) -> bytes | None:
    """Decode a C-quoted string into bytes. Handles \\xHH, \\n, \\t, \\\\."""
    try:
        return literal.encode("latin1").decode("unicode_escape").encode("latin1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None


def _translate_predicate_to_python(c_cond: str) -> str | None:
    """Best-effort translation of a C boolean expression to Python.

    Supported syntax (covers everything our predicate_synthesis prompt
    asks the LLM to emit):
      * `input_len OP N` and `N OP input_len` with OP in `>= > <= < == !=`
      * `input[K]` (byte indexing)
      * arithmetic + bitwise: `&`, `|`, `^`, `<<`, `>>`, `+`, `-`, `*`
      * comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`
      * boolean: `&&` → `and`, `||` → `or`, leading `!` → `not `
      * `memcmp(input, "lit", N) == 0` (offset 0 only — most common)
      * `memcmp(input + K, "lit", N) == 0` (constant offset)

    Anything outside this grammar returns None — caller treats as
    "untranslatable; accept without canary".
    """
    if not c_cond:
        return None
    if any(t in c_cond for t in (";", "{", "}")):
        return None
    # Reject any function call that is NOT memcmp. (input_len isn't a call
    # — it's only here defensively for grammars where parens follow it.)
    for fn in re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", c_cond):
        if fn != "memcmp" and fn != "input_len":
            return None

    py = c_cond

    def _memcmp_repl(m: re.Match) -> str:
        ptr_expr = m.group(1).strip()
        literal = m.group(2)
        try:
            length = int(m.group(3))
        except ValueError:
            return m.group(0)  # leave unchanged; will fail eval and be skipped
        if ptr_expr == "input":
            offset = 0
        else:
            mo = re.match(r"input\s*\+\s*(\d+)\s*$", ptr_expr)
            if not mo:
                return m.group(0)
            offset = int(mo.group(1))
        decoded = _decode_c_string(literal)
        if decoded is None or len(decoded) < length:
            return m.group(0)
        slice_bytes = decoded[:length]
        return f"input[{offset}:{offset + length}] == {slice_bytes!r}"

    py = re.sub(
        r'memcmp\(\s*([^,]+?)\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*(\d+)\s*\)\s*==\s*0',
        _memcmp_repl,
        py,
    )

    # Translate boolean operators. Order matters — `!=` must NOT be touched.
    py = py.replace("&&", " and ").replace("||", " or ")
    # Leading `!` (negation) when followed by `(` — already covered by parens;
    # standalone `!x` becomes `not x`. Be careful not to break `!=`.
    py = re.sub(r"!\s*\(", "not (", py)
    py = re.sub(r"!(?!=)\s*([A-Za-z_])", r"not \1", py)

    return py


import ast as _ast

# Whitelist of AST node types a translated predicate may contain. Anything else
# (Call, Attribute, Lambda, comprehensions, …) is rejected — `{"__builtins__":{}}`
# alone does NOT stop `().__class__.__bases__…` sandbox escapes, so we validate
# the expression structurally before evaluating it.
_PRED_ALLOWED_NODES: tuple = (
    _ast.Expression, _ast.BoolOp, _ast.And, _ast.Or,
    _ast.UnaryOp, _ast.Not, _ast.UAdd, _ast.USub, _ast.Invert,
    _ast.BinOp, _ast.Add, _ast.Sub, _ast.Mult, _ast.Div, _ast.Mod,
    _ast.FloorDiv, _ast.Pow, _ast.LShift, _ast.RShift,
    _ast.BitOr, _ast.BitXor, _ast.BitAnd,
    _ast.Compare, _ast.Eq, _ast.NotEq, _ast.Lt, _ast.LtE, _ast.Gt, _ast.GtE,
    _ast.Subscript, _ast.Slice, _ast.Name, _ast.Load,
    _ast.Constant, _ast.Tuple, _ast.List,
)
_PRED_ALLOWED_NAMES = {"input", "input_len"}


def _predicate_expr_is_safe(py_expr: str) -> bool:
    """True if py_expr is a pure boolean/arithmetic predicate over input/input_len."""
    try:
        tree = _ast.parse(py_expr, mode="eval")
    except (SyntaxError, ValueError):
        return False
    for node in _ast.walk(tree):
        if not isinstance(node, _PRED_ALLOWED_NODES):
            return False
        if isinstance(node, _ast.Name) and node.id not in _PRED_ALLOWED_NAMES:
            return False
    return True


def _evaluate_predicate(py_expr: str, seed: bytes) -> bool | None:
    """Evaluate a translated predicate against `seed`. Returns None on error.

    The expression is structurally validated (AST whitelist) before eval, so a
    malicious/garbled predicate from the LLM cannot execute arbitrary code.
    """
    if not _predicate_expr_is_safe(py_expr):
        return None
    try:
        return bool(eval(  # noqa: S307 — AST-validated, restricted namespace
            compile(py_expr, "<predicate>", "eval"),
            {"__builtins__": {}},
            {"input": seed, "input_len": len(seed)},
        ))
    except Exception:
        return None


def _generate_random_canary_seeds(
    n: int = 200,
    min_size: int = 1,
    max_size: int = 256,
    rng_seed: int = 0xCAFEBABE,
) -> list[bytes]:
    """Generate `n` pseudo-random byte sequences for predicate stress-testing.

    These complement the real-seed corpus and serve a different purpose:
    they are uniform random bytes so any predicate that can ONLY be
    satisfied by a specific format magic / header structure will be
    rejected by all of them. That's expected and not grounds for
    dropping the predicate. What random seeds DO catch is logical
    *contradictions* between predicates — when no input could possibly
    satisfy the AND-chain (e.g. predicate A: `byte[0] == 0xF0`, predicate
    B: `byte[0] != 0xF0`). Real seeds may not cover this if the corpus
    is empty or all from the same family.
    """
    import random as _r
    rng = _r.Random(rng_seed)
    seeds: list[bytes] = []
    for _ in range(n):
        size = rng.randint(min_size, max_size)
        seeds.append(bytes(rng.randint(0, 255) for _ in range(size)))
    return seeds


def canary_filter_predicates(
    predicates: list[ProgressPredicate],
    sample_seeds: list[bytes],
    min_pass_rate: float = 0.01,
    log: logging.Logger | None = None,
) -> list[ProgressPredicate]:
    """Drop predicates with catastrophic pass rate against `sample_seeds`.

    Two-stage filter:
      1. Per-predicate independent pass rate — drop any predicate whose
         pass rate is below `min_pass_rate`. These are predicates that
         model the wrong format.
      2. AND-chain pass rate — once per-predicate survivors are known,
         iteratively drop the LAST predicate while no seed passes the
         full chain. The early predicates are usually correct (header
         framing); the deep ones are where LLMs hallucinate.

    The function ALWAYS appends 200 pseudo-random byte sequences to
    `sample_seeds` to stress-test for logical contradictions. Real
    seeds catch wrong-format-model predicates; random seeds catch
    contradictory predicates (e.g. lz4 had `nibble != 15 && nibble == 15`
    spread across two predicates that no input could satisfy).
    """
    if not predicates:
        return predicates

    # Always include random seeds — they catch contradictions even when
    # the corpus is empty (lz4 / libwebp early in the project lifecycle).
    random_seeds = _generate_random_canary_seeds(n=200)
    real_seeds = list(sample_seeds)
    combined = real_seeds + random_seeds

    # Conservative gate (2026-05-13 libsndfile postmortem): when there
    # are NO real seeds, random-only canary cannot reliably distinguish
    # "good format-aware predicate" from "bad format-breaking predicate".
    # Example: a predicate `bytes[4..7] all non-zero` passes ~98% of
    # random byte sequences (so canary keeps it) but FAILS for any real
    # WAV file under 16MB (where byte 7 of the file-size field is zero
    # in little-endian encoding). Injecting it gates the entire fuzzing
    # loop against valid inputs → 0 coverage, 0 crashes.
    #
    # When real_seeds is empty: drop the whole predicate set rather
    # than risk format-breaking gates. AFL still works without progress
    # predicates — just slower. This is far better than a working
    # pipeline that silently produces no coverage on every target whose
    # corpus directory hasn't been populated yet.
    if not real_seeds:
        if log:
            log.warning(
                "predicate.canary_no_real_seeds_skip_inject",
                count=len(predicates),
                names=[p.name for p in predicates],
                note=("no real seeds available — random-only canary cannot "
                      "validate format-specific predicates; dropping all to "
                      "avoid filtering format-correct inputs at the gate"),
            )
        return []

    # Per-predicate pass rate — keep predicate if EITHER real-seed rate
    # OR combined-seed rate clears the threshold. Real-only success is
    # legitimate (format-magic predicate), so we don't punish it for
    # 0% on random.
    def _rate_for(py_expr: str, seeds: list[bytes]) -> tuple[int, int]:
        passes = evaluated = 0
        for seed in seeds:
            v = _evaluate_predicate(py_expr, seed)
            if v is None:
                continue
            evaluated += 1
            if v:
                passes += 1
        return passes, evaluated

    survivors: list[ProgressPredicate] = []
    per_predicate_rand_rates: list[float] = []  # Phase B heuristic
    for p in predicates:
        py = _translate_predicate_to_python(p.condition)
        if py is None:
            survivors.append(p)
            per_predicate_rand_rates.append(-1.0)  # untranslatable marker
            if log:
                log.info("predicate.canary_skip_untranslatable", name=p.name)
            continue

        real_pass, real_eval = _rate_for(py, real_seeds)
        rand_pass, rand_eval = _rate_for(py, random_seeds)
        real_rate = real_pass / real_eval if real_eval else None
        rand_rate = rand_pass / rand_eval if rand_eval else 0.0
        per_predicate_rand_rates.append(rand_rate)

        # Decision: real-seed evidence trumps random when available.
        # Old logic was `real OR random`, which kept predicates that all
        # real seeds reject as long as random passed them. That hid the
        # libsndfile `bytes[4..7] all non-zero` bug — random bytes pass
        # at ~98%, real WAV headers fail at 100%, but OR-keep kept it.
        #
        # New logic:
        #   - real_rate available  → trust it exclusively
        #   - real_rate unavailable → random fallback (predicate didn't
        #     evaluate on any real seed, treat as no-signal)
        if real_rate is not None:
            keep = real_rate >= min_pass_rate
        else:
            keep = rand_rate >= min_pass_rate
        if keep:
            survivors.append(p)
            if log:
                log.info("predicate.canary_pass",
                         name=p.name,
                         real_rate=(round(real_rate, 3) if real_rate is not None else "n/a"),
                         random_rate=round(rand_rate, 3))
        else:
            if log:
                log.warning("predicate.canary_dropped_low_rate",
                            name=p.name,
                            real_rate=(round(real_rate, 4) if real_rate is not None else "n/a"),
                            random_rate=round(rand_rate, 4),
                            min=min_pass_rate)

    # Phase B "keep top-3 tight predicates" heuristic was REMOVED
    # (2026-05-08 audit). It rescued predicates the canary correctly
    # killed (cJSON `has_trailing_newline` was elevated even though the
    # CVE-2023-53154 PoC has no trailing newline by definition). The
    # heuristic prioritised "bug-targeting-tight" over "satisfiable by
    # any input we have" without real-seed evidence, so it pushed
    # format-validity gates back into the chain whenever random
    # couldn't satisfy them — which is exactly when they were
    # format-magic predicates we WANTED to drop. Trust the canary; if
    # a predicate is satisfied by neither real seeds nor random, it
    # stays dropped.

    if not survivors:
        return survivors

    # AND-chain check: ANY seed (real OR random) must pass the full chain.
    # Random seeds catch contradictions; real seeds keep format-magic chains
    # alive when the random sample wouldn't satisfy them naturally.
    def _chain_passes(chain: list[ProgressPredicate], seeds: list[bytes]) -> int:
        py_chain = [_translate_predicate_to_python(q.condition) for q in chain]
        count = 0
        for seed in seeds:
            ok = True
            for t in py_chain:
                if t is None:
                    continue
                v = _evaluate_predicate(t, seed)
                if v is None or not v:
                    ok = False
                    break
            if ok:
                count += 1
        return count

    # AND-chain check on combined real+random seeds. Random catches
    # contradictions; real seeds keep format-magic chains alive when
    # the random sample wouldn't satisfy them naturally.
    while len(survivors) > 1 and _chain_passes(survivors, combined) == 0:
        dropped = survivors.pop()
        if log:
            log.warning("predicate.canary_chain_tail_dropped",
                        name=dropped.name, remaining=len(survivors))

    # Last-resort: even one-predicate chain unsatisfiable → drop all.
    if survivors and _chain_passes(survivors, combined) == 0:
        if log:
            log.warning("predicate.canary_chain_unsatisfiable",
                        kept=[p.name for p in survivors])
        return []

    return survivors


def load_canary_seeds(
    seeds_dirs: list[Path],
    max_seeds: int = 50,
    max_seed_bytes: int = 65536,
    log: logging.Logger | None = None,
) -> list[bytes]:
    """Read up to `max_seeds` non-empty seed files from the given dirs.

    Searches dirs in order; stops once `max_seeds` are accumulated.
    Files larger than `max_seed_bytes` are read truncated (predicates
    only inspect the head bytes anyway).
    """
    out: list[bytes] = []
    seen_hashes: set[int] = set()
    for d in seeds_dirs:
        if len(out) >= max_seeds:
            break
        if not d.is_dir():
            continue
        for entry in sorted(d.iterdir()):
            if len(out) >= max_seeds:
                break
            if not entry.is_file():
                continue
            try:
                data = entry.read_bytes()
            except OSError:
                continue
            if not data:
                continue
            data = data[:max_seed_bytes]
            h = hash(data)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            out.append(data)
    if log:
        log.info("predicate.canary_seeds_loaded",
                 count=len(out),
                 dirs=[str(d) for d in seeds_dirs if d.is_dir()])
    return out
