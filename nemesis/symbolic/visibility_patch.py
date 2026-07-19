"""Visibility-only patch: strip `static` from a function's definition so an
external harness can link against it.

Why this is honest
------------------
The `static` keyword in C is a *visibility-only* attribute — it controls
whether the symbol is emitted with internal or external linkage. Removing
it does NOT change:

  - Control flow inside the function
  - Inlining decisions in -O0/-O1 builds (no `static inline` is targeted)
  - Memory layout, alignment, or struct definitions
  - Any runtime semantics

The compiled assembly of the function body is byte-identical patched vs
unpatched (modulo the symbol-name table entry that `static` would suppress).

This means: if a fuzzer finds an input that crashes the patched build via a
direct call to the now-public function, the SAME input crashes the
unpatched library when reached through the natural public API. NEMESIS
already has the verification step (`_verify_crash_standalone` rebuilds
against the clean `debug_build_dir` which is rooted in `source_root` —
the pristine, untouched copy).

Honest backtest convention
--------------------------
We apply this patch ONLY to `work_root` (the rsync'd copy used for the
fuzz build). `source_root` stays pristine, the debug build is unpatched,
and every crash must reproduce there before being counted as a CVE
rediscovery.

Usage
-----
```yaml
pinned_funcs:
  - func_name: build_node
    file_path: lib/xmlparse.c
    auto_expose: true
```

`expose_static(file_path, func_name)` returns True if the patch was
applied. Idempotent — re-running on an already-patched file is a no-op.
"""

from __future__ import annotations

import re
from pathlib import Path

# Sentinel comment we leave in place to make each patch idempotent and
# auditable (a reviewer can grep for this and find every exposure). We
# embed the function name so the same file can host exposures for
# multiple pinned functions without re-triggering the "already patched"
# guard.
_SENTINEL_FMT = (
    "/* nemesis: visibility patch (static stripped for fuzz harness on `{f}`) */"
)


def _sentinel_for(func_name: str) -> str:
    return _SENTINEL_FMT.format(f=func_name)


def expose_static(file_path: Path, func_name: str) -> tuple[bool, str]:
    """Strip `static` from the definition of `func_name` in `file_path`.

    Returns (changed, message). `changed` is True if a `static` keyword
    was removed. `message` is a one-line human-readable summary suitable
    for logging.

    The function locates the definition by matching:
      `^static <return-type-tokens>\\s+func_name\\s*\\(`
    spanning at most 3 lines (libxml2/expat split across lines for the
    XMLPUBFUN macro pattern).

    No change is made if:
      - the function does not exist in the file
      - the function exists but is not declared `static`
      - the file contains the sentinel comment (already patched)
    """
    if not file_path.exists():
        return False, f"file not found: {file_path}"
    try:
        text = file_path.read_text(errors="replace")
    except OSError as exc:
        return False, f"read failed: {exc}"
    sentinel = _sentinel_for(func_name)
    if sentinel in text:
        return False, f"already patched ({func_name})"

    # Match `static <type chunk> <funcname>(` where the type chunk may
    # span multiple lines (libxml2/expat split `static void` from the
    # function name onto separate lines for readability).
    #
    # ^[ \t]* — leading indentation on the line that starts with `static`
    # static\s+ — the keyword + at least one whitespace char (incl. \n)
    # ([\w\*\s]+?) — the return type chunk (non-greedy), can span newlines
    # \b<name>\s*\( — the function name and opening paren of arg list
    pattern = re.compile(
        r"^([ \t]*)static\s+([\w\*\s]+?)\b"
        + re.escape(func_name)
        + r"\s*\(",
        re.MULTILINE,
    )

    new_parts: list[str] = []
    pos = 0
    n_replaced = 0
    for m in pattern.finditer(text):
        indent = m.group(1)
        type_part = m.group(2).strip()  # collapse to single line
        new_parts.append(text[pos : m.start()])
        new_parts.append(
            f"{sentinel}\n{indent}{type_part} {func_name}("
        )
        pos = m.end()
        n_replaced += 1
    if n_replaced == 0:
        return False, (
            f"`static {func_name}` declaration/definition not found "
            f"in {file_path.name}"
        )
    new_parts.append(text[pos:])
    new_text = "".join(new_parts)
    file_path.write_text(new_text)
    return True, (
        f"exposed `{func_name}` in {file_path.name} "
        f"({n_replaced} site{'s' if n_replaced > 1 else ''})"
    )
