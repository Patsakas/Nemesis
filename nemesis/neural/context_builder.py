"""
Budget-aware codebase context builder for the Architect model's 1M context window.

Builds a prioritized <codebase_context> XML string that fits within a configurable
token budget. Sections are added in priority order and dropped when the budget
is exhausted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.recon.validation_gates import (
    extract_validation_gates,
    render_validation_gates_block,
)

# Directories to skip when scanning source trees
_SKIP_DIRS = {"build", "build_fuzz", "build_debug", "build_ubsan", ".git", "__pycache__"}


class ContextBuilder:
    """Build budget-aware codebase context for the Architect's 1M window."""

    DEFAULT_BUDGET = 800_000  # tokens (~4 chars/token for C code)
    CHARS_PER_TOKEN = 4       # conservative estimate for C source
    _SAFETY_MARGIN = 0.10     # reserve 10% of context_window for system prompt + framing

    def __init__(
        self,
        config: NemesisConfig,
        budget_tokens: int = 0,
        oracle: object | None = None,
        context_window: int = 0,
        max_output_tokens: int = 0,
    ) -> None:
        self.config = config
        self.log = get_logger("context_builder")
        self._budget_tokens = budget_tokens or self.DEFAULT_BUDGET

        # Auto-cap: if model context_window is known, ensure budget fits
        if context_window > 0:
            margin = int(context_window * self._SAFETY_MARGIN)
            safe_input = context_window - max_output_tokens - margin
            if safe_input > 0 and self._budget_tokens > safe_input:
                self.log.info(
                    "budget.auto_capped",
                    configured=self._budget_tokens,
                    capped_to=safe_input,
                    context_window=context_window,
                    max_output=max_output_tokens,
                    margin=margin,
                )
                self._budget_tokens = safe_input

        self._budget_chars = self._budget_tokens * self.CHARS_PER_TOKEN
        self._used_chars = 0
        self._oracle = oracle

    def build(self, target: "CoverageTarget", context: "AnalysisContext") -> str:
        """Return a <codebase_context>...</codebase_context> XML string.

        Sections are added in priority order; each section is skipped
        if it would exceed the remaining character budget.
        """
        self._used_chars = 0
        sections: list[str] = []

        source_root = Path(self.config.target.source_root)

        # 0. Validation-gate setters (cheap, high-leverage). Lifting per-field
        # validation limits is a near-universal prerequisite for reaching deep
        # parser code from a fuzz harness; static extraction is more reliable
        # than asking the LLM to discover the setters from headers.
        vg = self._build_validation_gates(source_root)
        if vg:
            sections.append(vg)

        # 1. Public headers from harness_includes
        hdr = self._build_headers_section(source_root)
        if hdr:
            sections.append(hdr)

        # 2. Target function's source file (full)
        tgt = self._build_target_source(source_root, target)
        if tgt:
            sections.append(tgt)

        # 3. Call-chain source files
        cc = self._build_call_chain_sources(source_root, context)
        if cc:
            sections.append(cc)

        # 4. Test suite examples
        ts = self._build_test_suite(source_root, target)
        if ts:
            sections.append(ts)

        # 5. Existing OSS-Fuzz harnesses
        eh = self._build_existing_harnesses(source_root)
        if eh:
            sections.append(eh)

        # 6. Oracle-ranked source files (FAISS)
        if self._oracle is not None:
            orc = self._build_oracle_ranked_sources(target, context)
            if orc:
                sections.append(orc)

        # 7. Repository tree (cheap, always fits)
        tree = self._build_repo_tree(source_root)
        if tree:
            sections.append(tree)

        if not sections:
            return ""

        body = "\n\n".join(sections)
        self.log.info(
            "context.built",
            func=target.func_name,
            sections=len(sections),
            chars=self._used_chars,
            budget_pct=round(self._used_chars / self._budget_chars * 100, 1),
        )
        return f"<codebase_context>\n{body}\n</codebase_context>"

    # ── Private section builders ──────────────────────────────

    def _add_if_budget(self, text: str) -> str:
        """Return text if it fits within remaining budget, else empty string."""
        if self._used_chars + len(text) > self._budget_chars:
            return ""
        self._used_chars += len(text)
        return text

    def _read_file_safe(self, path: Path, max_chars: int = 0) -> str:
        """Read file content, returning empty on any error."""
        try:
            content = path.read_text(errors="replace")
            if max_chars and len(content) > max_chars:
                content = content[:max_chars] + "\n// ... truncated ..."
            return content
        except (OSError, UnicodeDecodeError):
            return ""

    def _build_validation_gates(self, source_root: Path) -> str:
        """Static-extract permissive-limit setters and render as XML block.

        Cached on `self` because the result depends only on source_root and
        we may be called many times during a single pipeline run.
        """
        cached = getattr(self, "_vg_cache", None)
        if cached is None or cached[0] != source_root:
            try:
                gates = extract_validation_gates(source_root)
            except Exception as exc:
                self.log.warning("validation_gates.extract_failed", error=str(exc))
                gates = []
            self._vg_cache = (source_root, gates)
        else:
            gates = cached[1]

        if not gates:
            return ""
        block = render_validation_gates_block(gates)
        block = self._add_if_budget(block)
        if block:
            self.log.info("validation_gates.injected", count=len(gates))
        return block

    def _build_headers_section(self, source_root: Path) -> str:
        """Read all files from harness_includes config."""
        includes = self.config.target.harness_includes
        if not includes:
            return ""

        parts: list[str] = []
        for inc in includes:
            # inc may be like "archive.h" or "libarchive/archive.h"
            candidates = [
                source_root / inc,
                source_root / self.config.target.source_subdir / inc if self.config.target.source_subdir else None,
                source_root / self.config.target.include_subdir / inc if self.config.target.include_subdir else None,
            ]
            # Also try rglob for bare filenames
            found = None
            for c in candidates:
                if c and c.exists():
                    found = c
                    break
            if not found:
                matches = list(source_root.rglob(Path(inc).name))
                if matches:
                    found = matches[0]

            if found:
                content = self._read_file_safe(found)
                if content:
                    rel = str(found.relative_to(source_root))
                    part = f'<source_file path="{rel}" role="public_header">\n{content}\n</source_file>'
                    part = self._add_if_budget(part)
                    if part:
                        parts.append(part)

        return "\n".join(parts) if parts else ""

    def _build_target_source(self, source_root: Path, target: "CoverageTarget") -> str:
        """Full content of the file containing the target function."""
        if not target.file_path:
            return ""

        fpath = source_root / target.file_path
        if not fpath.exists():
            # Try rglob for the filename
            matches = list(source_root.rglob(Path(target.file_path).name))
            if matches:
                fpath = matches[0]
            else:
                return ""

        content = self._read_file_safe(fpath)
        if not content:
            return ""

        rel = str(fpath.relative_to(source_root))
        text = f'<source_file path="{rel}" role="target_source">\n{content}\n</source_file>'
        return self._add_if_budget(text)

    def _build_call_chain_sources(
        self, source_root: Path, context: "AnalysisContext"
    ) -> str:
        """Files from context.call_chain entries."""
        if not context.call_chain or not context.call_chain.chain:
            return ""

        parts: list[str] = []
        seen_files: set[str] = set()

        for func_name in context.call_chain.chain:
            # Try to find the file for this function from source_snippets
            snippet = context.source_snippets.get(func_name, "")
            if snippet and len(snippet) > 50:
                text = f'<call_chain_function name="{func_name}">\n{snippet}\n</call_chain_function>'
                text = self._add_if_budget(text)
                if text:
                    parts.append(text)

        return "\n".join(parts) if parts else ""

    @staticmethod
    def _extract_format_keywords(func_name: str, file_path: str) -> list[str]:
        """Extract format keywords from function name and file path.

        Used to find relevant test files that exercise the same format/API,
        even when test files don't reference the internal function directly.
        e.g. pax_attribute in archive_read_support_format_tar.c → ["pax", "tar"]
             xar_read_header in archive_read_support_format_xar.c → ["xar"]
             parse_file in archive_read_support_format_mtree.c → ["mtree"]
        """
        import re
        keywords: list[str] = []

        # Extract from file path: archive_read_support_format_tar.c → "tar"
        basename = Path(file_path).stem if file_path else ""
        m = re.search(r"(?:format|filter)_([a-z0-9]+)", basename, re.IGNORECASE)
        if m:
            keywords.append(m.group(1).lower())

        # Extract from function name: split by _ and take meaningful tokens
        # Skip very generic tokens
        _GENERIC = {"read", "write", "support", "format", "filter", "header",
                     "data", "open", "close", "new", "free", "set", "get",
                     "archive", "entry", "file", "parse", "create", "init"}
        for token in func_name.lower().split("_"):
            if len(token) >= 3 and token not in _GENERIC:
                keywords.append(token)

        # Deduplicate preserving order
        seen: set[str] = set()
        result: list[str] = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                result.append(kw)
        return result

    def _build_test_suite(self, source_root: Path, target: "CoverageTarget") -> str:
        """Find .c test files relevant to the target function.

        Fix 101 (FUDGE/UTopia-inspired): search in source_subdir/test/ too,
        and match by format keywords — not just exact function name.
        This gives the LLM real API usage examples for correct init/cleanup.
        """
        # Build search dirs: include source_subdir/test/ (e.g. libarchive/test/)
        test_dirs: list[Path] = [source_root / "test", source_root / "tests"]
        src_sub = self.config.target.source_subdir
        if src_sub:
            test_dirs.insert(0, source_root / src_sub / "test")
            test_dirs.insert(1, source_root / src_sub / "tests")

        # Extract format keywords for broader matching
        fmt_keywords = self._extract_format_keywords(
            target.func_name, target.file_path or ""
        )

        # Also check config format_aliases (e.g. tar→pax means "pax" tests relevant for tar)
        seeds_cfg = getattr(self.config, "seeds", None)
        if seeds_cfg:
            aliases = getattr(seeds_cfg, "format_aliases", {}) or {}
            expanded: list[str] = []
            for kw in fmt_keywords:
                expanded.append(kw)
                # Reverse lookup: if tar→pax, and kw=pax, also add tar
                for src, dst in aliases.items():
                    if dst == kw and src not in expanded:
                        expanded.append(src)
                    if src == kw and dst not in expanded:
                        expanded.append(dst)
            fmt_keywords = expanded

        self.log.debug(
            "test_suite.search",
            func=target.func_name,
            keywords=fmt_keywords,
            dirs=[str(d) for d in test_dirs if d.exists()],
        )

        # Score test files: prioritize read/format tests with keyword matches.
        # Scoring:
        #   +10 exact function name in filename
        #   +5  per keyword matched in filename (cumulative)
        #   +3  "read" in filename (we're building read harnesses)
        #   +2  "format" in filename (format-specific tests)
        #   +1  function name found in file content (weakest signal)
        scored: list[tuple[int, Path]] = []

        for tdir in test_dirs:
            if not tdir.exists():
                continue
            for cfile in sorted(tdir.rglob("*.c")):
                if any(skip in cfile.parts for skip in _SKIP_DIRS):
                    continue
                fname_lower = cfile.name.lower()
                score = 0

                # Exact function name in filename → highest priority
                if target.func_name.lower() in fname_lower:
                    score += 10

                # Each keyword match in filename → cumulative bonus
                for kw in fmt_keywords:
                    if kw in fname_lower:
                        score += 5

                # Bonus for read/format test files (most relevant for fuzzing)
                if "read" in fname_lower:
                    score += 3
                if "format" in fname_lower:
                    score += 2

                # If no filename match, check content for function name
                if score == 0:
                    try:
                        content = cfile.read_text(errors="replace")
                    except OSError:
                        continue
                    if target.func_name in content:
                        score += 1

                if score > 0:
                    scored.append((score, cfile))

        # Sort by score descending, take top 5
        scored.sort(key=lambda x: -x[0])

        parts: list[str] = []
        for _score, cfile in scored[:5]:
            try:
                content = cfile.read_text(errors="replace")
            except OSError:
                continue
            try:
                rel = str(cfile.relative_to(source_root))
            except ValueError:
                rel = cfile.name
            # Limit test files to 12K chars each
            if len(content) > 12000:
                content = content[:12000] + "\n// ... truncated ..."
            text = f'<test_file path="{rel}">\n{content}\n</test_file>'
            text = self._add_if_budget(text)
            if text:
                parts.append(text)

        if parts:
            header = (
                "<!-- These are REAL unit tests from the library developers.\n"
                "     Study them for the CORRECT API initialization, call sequence, "
                "and cleanup pattern.\n"
                "     Base your harness on these proven patterns. -->"
            )
            return (
                f"<test_suite_examples>\n{header}\n"
                f"{''.join(parts)}\n</test_suite_examples>"
            )
        return ""

    def _build_existing_harnesses(self, source_root: Path) -> str:
        """Find existing OSS-Fuzz harnesses in contrib/ or fuzz/ directories."""
        fuzz_dirs = [source_root / "contrib", source_root / "fuzz", source_root / "fuzzing"]
        parts: list[str] = []

        for fdir in fuzz_dirs:
            if not fdir.exists():
                continue
            for pattern in ["*fuzz*.c", "*fuzz*.cc", "*fuzz*.cpp"]:
                for fpath in sorted(fdir.rglob(pattern)):
                    content = self._read_file_safe(fpath, max_chars=6000)
                    if content:
                        rel = str(fpath.relative_to(source_root))
                        text = f'<existing_harness path="{rel}">\n{content}\n</existing_harness>'
                        text = self._add_if_budget(text)
                        if text:
                            parts.append(text)
                    if len(parts) >= 5:
                        break
            if len(parts) >= 5:
                break

        return "\n".join(parts) if parts else ""

    def _build_oracle_ranked_sources(
        self, target: "CoverageTarget", context: "AnalysisContext"
    ) -> str:
        """Use FAISS oracle to rank remaining relevant source files."""
        if not hasattr(self._oracle, "query") or not self._oracle.is_built():
            return ""

        first_snippet = next(iter(context.source_snippets.values()), "")
        query = f"{target.func_name}\n{first_snippet[:300]}"

        try:
            oracle_result = self._oracle.query(query, k=12)
            if oracle_result:
                return self._add_if_budget(oracle_result)
        except Exception as exc:
            self.log.debug("oracle.query_failed", error=str(exc))

        return ""

    def _build_repo_tree(self, source_root: Path) -> str:
        """Directory listing with file sizes."""
        lines: list[str] = []
        try:
            for root, dirs, files in os.walk(source_root):
                # Skip build/hidden dirs
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
                rel_root = os.path.relpath(root, source_root)
                depth = rel_root.count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                indent = "  " * depth
                dir_name = os.path.basename(root)
                lines.append(f"{indent}{dir_name}/")
                for f in sorted(files)[:30]:  # max 30 files per dir
                    fpath = Path(root) / f
                    try:
                        size = fpath.stat().st_size
                    except OSError:
                        size = 0
                    size_str = f"{size // 1024}K" if size >= 1024 else f"{size}B"
                    lines.append(f"{indent}  {f} ({size_str})")
                if len(files) > 30:
                    lines.append(f"{indent}  ... and {len(files) - 30} more files")
        except OSError:
            return ""

        if not lines:
            return ""

        tree_text = "\n".join(lines)
        text = f"<repo_tree>\n{tree_text}\n</repo_tree>"
        return self._add_if_budget(text)
