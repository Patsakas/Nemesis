"""Caller-graph traversal: walk UP from a pinned function to find the public
API gateway. Honest assist for the architect — gives it the information a
human researcher would gather (`grep`, read code), not the answer.

For an `indirect_reach` pin like `xmlSnprintfElementContent` (libxml2 valid.c
internal helper), this module:
  1. greps for callers across the source tree
  2. walks UP one level at a time (BFS)
  3. stops at the first caller whose name appears in any of the public headers
     listed in `harness_includes` — that's the gateway
  4. extracts the gateway's signature + Doxygen-style doc comment
  5. returns a structured `<reach_path>` block ready for the architect prompt

Failure modes (returns empty path):
  - no callers found within MAX_DEPTH levels
  - no caller is declared in a public header (target may be truly internal)
  - source tree too large to grep within timeout

The output deliberately does NOT contain CVE descriptions, trigger geometry,
or "bug class" tags — only static facts derivable by `grep` and reading the
code. This keeps backtests honest.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

MAX_DEPTH = 5  # levels of caller traversal
MAX_CALLERS_PER_LEVEL = 8  # cap to keep grep cheap
GREP_TIMEOUT_S = 10


@dataclass
class CallerHop:
    """A function that calls (directly or transitively) the pinned function."""
    func_name: str
    file_path: str  # relative to source_root, e.g. "valid.c"
    line: int  # line of the call site (where this function calls down the chain)
    depth: int  # 1 = direct caller of pinned, 2 = caller of a depth-1 hop, ...
    is_public: bool  # function declared in any public header
    signature: str = ""  # full C declaration (one line)
    doc_comment: str = ""  # Doxygen block above the function definition


@dataclass
class ReachPath:
    """All callers (UP to MAX_DEPTH levels) of the pinned function, with the
    public-API gateway flagged. Same-depth hops are SIBLINGS (independent
    callers), not a chain — the architect sees both and picks one."""
    pinned: str
    hops: list[CallerHop] = field(default_factory=list)
    gateway: Optional[CallerHop] = None  # first public caller encountered

    def render_block(self) -> str:
        """Format as <reach_path> block for the architect prompt."""
        if not self.hops:
            return ""
        # Group by depth so the architect sees siblings vs. transitive callers
        by_depth: dict[int, list[CallerHop]] = {}
        for h in self.hops:
            by_depth.setdefault(h.depth, []).append(h)
        lines = ["<reach_path>"]
        lines.append(f"Pinned target: {self.pinned}")
        lines.append("")
        lines.append(
            "Static call-graph traversal (grep-based) found the following "
            "functions that ultimately reach the pinned target. Functions at "
            "the SAME depth are independent siblings (different code paths), "
            "not a chain. The harness must invoke ONE public-API entry point."
        )
        for d in sorted(by_depth.keys()):
            lines.append("")
            lines.append(f"  depth {d} (callers transitively reaching pinned):")
            for h in by_depth[d]:
                tag = " [PUBLIC API]" if h.is_public else " [internal]"
                lines.append(
                    f"    - {h.func_name}  ({h.file_path}:{h.line}){tag}"
                )
        if self.gateway:
            lines.append("")
            lines.append(
                f"Recommended harness entry point: {self.gateway.func_name} "
                "(first public-API caller found)"
            )
            if self.gateway.signature:
                lines.append("")
                lines.append(f"Signature:\n  {self.gateway.signature}")
            if self.gateway.doc_comment:
                lines.append("")
                lines.append("Documentation (from header / source comment):")
                for c_line in self.gateway.doc_comment.splitlines():
                    lines.append(f"  {c_line}")
        else:
            lines.append("")
            lines.append(
                "NOTE: no public-API caller found within "
                f"{MAX_DEPTH} levels — the pinned function may be truly internal. "
                "Inspect the callers above, pick the closest one whose signature "
                "is callable from a fuzz harness, and consider what input shape "
                "is required to make it execute the pinned function's body."
            )
        lines.append("</reach_path>")
        return "\n".join(lines)


def _public_func_set(public_headers: list[Path]) -> set[str]:
    """Names of functions declared in any of the public headers.

    libxml2-class headers split a declaration across two lines:
      `XMLPUBFUN xmlDocPtr XMLCALL`
      `\\t\\txmlReadMemory(const char *buffer, ...);`

    We collapse whitespace (newlines + tabs become single spaces) before
    matching so the function name and arg list are on the same line. Then
    we match `<typespec> <name>(<args>);` — the trailing `;` is what
    distinguishes a declaration from a function-pointer typedef body or
    an inline definition.
    """
    funcs: set[str] = set()
    for hdr in public_headers:
        if not hdr.exists():
            continue
        try:
            text = hdr.read_text(errors="replace")
        except OSError:
            continue
        # Strip C/C++ comments first so they don't introduce noise
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        text = re.sub(r"//[^\n]*", " ", text)
        # Collapse all whitespace runs to a single space
        flat = re.sub(r"\s+", " ", text)
        # Match: tokens... NAME ( args ) ;
        # Skip typedefs (which look like `typedef RET (*NAME)(args);`)
        for m in re.finditer(
            r"(?:^|[^\w])([A-Za-z_]\w+)\s*\(([^;{}]*?)\)\s*;",
            flat,
        ):
            name = m.group(1)
            # Filter false positives:
            #  - language keywords + common storage-class words
            #  - all-caps names (almost always macros: LIBXML_ATTR_FORMAT,
            #    XMLCALL_DEPRECATED, ...)
            #  - typedef'd function pointer (caught by `(*NAME)` shape — the
            #    paren is BEFORE the name, so our regex captures the type, not
            #    the typedef name). Adding an explicit guard.
            if name in {
                "if", "while", "for", "switch", "return", "sizeof", "typeof",
                "static", "extern", "inline", "const", "void", "struct",
                "union", "enum", "typedef", "case", "default", "do",
            }:
                continue
            if name.isupper():
                continue
            funcs.add(name)
    return funcs


def _grep_callers(
    func_name: str, source_root: Path, skip_files: set[str],
) -> list[tuple[str, int, str]]:
    """Return [(rel_file, line, content), ...] for sites calling func_name.

    Excludes the function's own definition file (which contains the function
    signature, not a callsite) and test/build dirs.
    """
    try:
        result = subprocess.run(
            [
                "grep", "-rn", "--include=*.c",
                f"{func_name}(", str(source_root),
            ],
            capture_output=True, text=True, timeout=GREP_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    out: list[tuple[str, int, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        gfile, gline_s, content = parts
        rel = Path(gfile).resolve().relative_to(source_root.resolve()) \
            if Path(gfile).is_absolute() else Path(gfile)
        rel_str = str(rel)
        # We DO NOT skip the pinned file here — callers in the same file
        # (like xmlValidateOneCdataElement calling xmlSnprintfElementContent
        # both inside valid.c) are exactly the path we want. The function's
        # own definition line is filtered later via `visited` because its
        # enclosing function is itself.
        rel_parts = set(Path(rel_str).parts)
        if rel_parts & {
            "test", "tests", "examples", "python", "contrib",
            ".git", "build", "build_debug", "build_fuzz",
            "build_ubsan", "build_coverage", "fuzz",
        }:
            continue
        # Some libraries (libxml2, libtiff) put test code at the source root
        # rather than under tests/ — filter by filename prefix.
        basename = Path(rel_str).name
        if any(basename.startswith(p) for p in (
            "test", "runtest", "runsuite", "runxmlconf", "fuzz_",
        )):
            continue
        _ = skip_files  # kept for backwards-compat signature
        # Skip the function's own definition (line containing return type + name)
        # The grep already matches "name(" — the def line also matches. We can
        # only exclude it heuristically: if the line ends with "{" or is just
        # a signature like "name(args) {", skip it.
        stripped = content.strip()
        if (stripped.startswith(func_name + "(")
                or stripped.startswith("static")
                and func_name + "(" in stripped):
            # candidate definition (not call); accept only if there's `;` later
            # — but easier to just skip when it ends with `{` or `,`
            if stripped.endswith("{") or stripped.endswith(","):
                continue
        try:
            gline = int(gline_s)
        except ValueError:
            continue
        out.append((rel_str, gline, content))
    return out


# Detect the enclosing function for a given file:line. We walk UP from
# call_line looking for the first line that starts AT COLUMN 0 with a C
# identifier followed by `(`. Inside a function body, every line is indented,
# so this heuristic is robust for normal C codebases (libxml2, libpng,
# libtiff, brotli, ...). Lines starting with `static`, `extern`, `inline`,
# `const` are storage-class prefixes — the actual function name is on the
# next column-0 line.
_KEYWORDS_PREFIX = {
    "static", "extern", "inline", "const", "void", "struct", "union",
    "enum", "typedef", "register", "volatile", "auto",
}


def _enclosing_func(
    file_path: Path, call_line: int,
) -> Optional[tuple[str, int, str]]:
    """Return (func_name, def_line, signature) for the function containing call_line.

    The heuristic: starting at `call_line` and walking UP, find the first
    line that begins at column 0 (no leading whitespace) and matches
    `^[A-Za-z_]\\w*\\s*\\(`. Skip storage-class prefix lines (`static`,
    `extern`, ...) and skip macro-only attribute lines (e.g. an
    all-uppercase identifier).
    """
    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    idx = min(call_line - 1, len(lines) - 1)
    for i in range(idx, max(idx - 800, -1), -1):
        ln = lines[i]
        if not ln or ln[0] in (" ", "\t"):
            continue  # indented → inside a body
        # Try to parse: optional storage-class prefix + name (
        m = re.match(
            r"^(?:(static|extern|inline|const)\s+)?"
            r"(?:[A-Za-z_][\w\*\s]*?\s+)?"
            r"([A-Za-z_]\w+)\s*\(",
            ln,
        )
        if not m:
            continue
        name = m.group(2)
        # Reject storage-class only lines and keywords
        if name in _KEYWORDS_PREFIX:
            continue
        if name in {"if", "while", "for", "switch", "sizeof", "return",
                    "do", "case"}:
            continue
        if name.isupper():
            # `LIBXML_ATTR_FORMAT(3,0)` — attribute macro line, the real
            # function name follows. Keep walking down? No, we're walking
            # UP. The macro is BEFORE the name in source order, so when
            # walking UP we encounter the name FIRST and then the macro.
            # If we hit an all-caps name first, it means the call is
            # inside an attribute macro line (impossible for a normal C
            # call); keep walking.
            continue
        # Build the signature: gather lines from the storage-class prefix
        # (if any, on a previous line) through the `)` closing paren.
        sig_lines: list[str] = []
        # Look one line up for prefix tokens
        if i > 0 and lines[i - 1].strip() and lines[i - 1][0] not in (" ", "\t"):
            prev = lines[i - 1].strip()
            if any(prev == k or prev.startswith(k + " ") for k in
                   ("static", "extern", "inline", "static inline",
                    "extern inline")):
                sig_lines.append(prev)
        sig_lines.append(ln.rstrip())
        # Continue gathering until we close the param list
        j = i + 1
        depth = ln.count("(") - ln.count(")")
        while depth > 0 and j < len(lines) and j - i < 12:
            sig_lines.append(lines[j].rstrip())
            depth += lines[j].count("(") - lines[j].count(")")
            j += 1
        sig = " ".join(s.strip() for s in sig_lines if s.strip())
        return name, i + 1, sig
    return None


def _extract_doc_comment(file_path: Path, def_line: int) -> str:
    """Pull the Doxygen-style /** ... */ block immediately above def_line."""
    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if def_line - 2 < 0:
        return ""
    # Walk UP through blank lines first
    i = def_line - 2
    while i >= 0 and not lines[i].strip():
        i -= 1
    if i < 0 or "*/" not in lines[i]:
        return ""
    # Found end of comment; walk up to find /**
    end = i
    while i >= 0 and "/**" not in lines[i] and "/*" not in lines[i]:
        i -= 1
    if i < 0:
        return ""
    # Collect comment lines, strip leading * and whitespace
    body: list[str] = []
    for cl in lines[i:end + 1]:
        cl = cl.strip()
        cl = re.sub(r"^/\*\*?", "", cl)
        cl = re.sub(r"\*/$", "", cl)
        cl = cl.lstrip("* ").rstrip()
        if cl:
            body.append(cl)
    return "\n".join(body[:25])  # cap at 25 lines


def build_reach_path(
    pinned_func: str,
    pinned_file: str,
    source_root: Path,
    public_headers: list[Path],
) -> ReachPath:
    """BFS up the caller graph until we hit a function declared in a public header.

    Args:
        pinned_func: e.g. "xmlSnprintfElementContent"
        pinned_file: e.g. "valid.c" — the file containing the pinned definition
        source_root: project root path
        public_headers: list of paths to public header files

    Returns:
        ReachPath with hops[] populated. `gateway` is the first public hop, if any.
    """
    public_funcs = _public_func_set(public_headers)
    skip_files: set[str] = {Path(pinned_file).name} if pinned_file else set()

    path = ReachPath(pinned=pinned_func)
    visited: set[str] = {pinned_func}
    frontier = [pinned_func]

    for depth in range(1, MAX_DEPTH + 1):
        next_frontier: list[str] = []
        for callee in frontier[:MAX_CALLERS_PER_LEVEL]:
            for rel_file, line, _content in _grep_callers(
                callee, source_root, skip_files,
            ):
                abs_file = source_root / rel_file
                enc = _enclosing_func(abs_file, line)
                if not enc:
                    continue
                fn_name, def_line, sig = enc
                if fn_name in visited:
                    continue
                visited.add(fn_name)
                is_public = fn_name in public_funcs
                # Try to find the doc comment in the .c file first; if absent,
                # fall back to scanning each public header for it.
                doc = _extract_doc_comment(abs_file, def_line)
                if not doc and is_public:
                    for hdr in public_headers:
                        if not hdr.exists():
                            continue
                        try:
                            ht = hdr.read_text(errors="replace").splitlines()
                        except OSError:
                            continue
                        for hi, hl in enumerate(ht):
                            if re.search(
                                rf"\b{re.escape(fn_name)}\s*\(",
                                hl,
                            ):
                                doc = _extract_doc_comment(hdr, hi + 1)
                                if doc:
                                    break
                        if doc:
                            break
                hop = CallerHop(
                    func_name=fn_name,
                    file_path=rel_file,
                    line=line,
                    depth=depth,
                    is_public=is_public,
                    signature=sig.strip(),
                    doc_comment=doc,
                )
                path.hops.append(hop)
                if is_public and path.gateway is None:
                    path.gateway = hop
                    # Don't return immediately — keep gathering siblings at
                    # the same depth so the architect sees alternatives.
                next_frontier.append(fn_name)
                if len(path.hops) >= 16:  # absolute cap
                    return path
        # Stop expanding further depths once we have a gateway: deeper hops
        # are usually too generic to help (e.g. main()).
        if path.gateway is not None:
            return path
        if not next_frontier:
            break
        frontier = next_frontier
    return path
