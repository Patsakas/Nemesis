"""
NEMESIS Codebase Oracle — RAG-based source context injection.

Architecture adapted from OverHAuL:
  - libclang AST for accurate function/type extraction
  - FAISS IndexFlatL2 + IndexIDMap for ANN search
  - NVIDIA NIM nv-embedqa-e5-v5 instead of OpenAI (free tier, 1024-dim)
  - Persistent cache in workspace/oracle/ (fingerprint-based invalidation)

Additional vs OverHAuL:
  - Type extraction (struct/typedef/enum from headers)
  - Persistent cache — no rebuild between runs unless source changes
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from nemesis.logging import get_logger

log = get_logger("oracle")


@dataclass
class CodeChunk:
    kind: str       # "function" | "type"
    name: str       # identifier (e.g. "lha_read_file_header_3")
    file_path: str  # relative path from source_root
    line: int       # start line
    content: str    # truncated code (max 4000 chars)
    signature: str  # function type spelling or CursorKind name


class CodebaseOracle:
    """
    RAG oracle over a C library source tree.

    Usage:
        oracle = CodebaseOracle(library_name, source_root, workspace_dir, nvidia_api_key)
        oracle.build()                   # first run: ~3-4 min; subsequent: ~0.5s (cache)
        snippet = oracle.query("lha_read_file_header_3 lha header parsing", k=8)
        # Returns <codebase_oracle>...</codebase_oracle> XML block
    """

    BATCH_SIZE = 50          # NVIDIA NIM max batch size
    MAX_CONTENT_CHARS = 4000  # same as OverHAuL
    EMBED_MODEL = "nvidia/nv-embedqa-e5-v5"
    EMBED_DIM = 1024

    def __init__(
        self,
        library_name: str,
        source_root: str | Path,
        workspace_dir: str | Path,
        nvidia_api_key: str,
        model: str = EMBED_MODEL,
    ) -> None:
        self._library_name = library_name
        self._source_root = Path(source_root)
        self._cache_dir = Path(workspace_dir) / "oracle"
        self._api_key = nvidia_api_key
        self._model = model

        self._index = None   # faiss.IndexIDMap — loaded lazily
        self._chunks: list[CodeChunk] = []

    # ── Public API ───────────────────────────────────────────────────────────

    def build(self, force: bool = False) -> None:
        """Build (or load from cache) the FAISS index over source_root."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        if not force and self._is_cache_fresh():
            log.info("oracle.cache_hit", library=self._library_name)
            self._load()
            return

        log.info("oracle.building", library=self._library_name, source_root=str(self._source_root))
        chunks = self._extract_chunks(self._source_root)
        if not chunks:
            log.warning("oracle.no_chunks", library=self._library_name)
            return

        log.info("oracle.embedding", chunks=len(chunks))
        texts = [f"{c.name}\n{c.content}" for c in chunks]
        embeddings = self._embed_batch(texts, input_type="passage")

        import faiss
        import numpy as np

        embeddings = np.ascontiguousarray(embeddings, dtype=np.float32)
        dim = embeddings.shape[1]
        base_index = faiss.IndexFlatL2(dim)
        self._index = faiss.IndexIDMap(base_index)
        ids = np.arange(len(chunks), dtype=np.int64)
        self._index.add_with_ids(embeddings, ids)
        self._chunks = chunks

        self._save()
        log.info("oracle.built", library=self._library_name, chunks=len(chunks))

    def query(self, query_text: str, k: int = 8) -> str:
        """
        Semantic search over the source index.

        Returns an XML block ready for injection into LLM prompts:
            <codebase_oracle>
            // path/to/file.c:42 [function]
            static int foo(...) { ... }

            ---

            // include/foo.h:10 [type]
            typedef struct { ... } FooBar;
            </codebase_oracle>

        Returns empty string if oracle not built or no results.
        """
        if not self.is_built():
            return ""

        import numpy as np

        q_emb = self._embed_batch([query_text], input_type="query")
        q_emb = np.ascontiguousarray(q_emb, dtype=np.float32)
        _, ids = self._index.search(q_emb.reshape(1, -1), k)
        results = [self._chunks[i] for i in ids[0] if 0 <= i < len(self._chunks)]

        if not results:
            return ""

        parts = [f"// {c.file_path}:{c.line} [{c.kind}]\n{c.content}" for c in results]
        body = "\n\n---\n\n".join(parts)
        return f"<codebase_oracle>\n{body}\n</codebase_oracle>"

    def is_built(self) -> bool:
        """True if the FAISS index is loaded and ready."""
        return self._index is not None and len(self._chunks) > 0

    def find_callers(self, func_name: str, k: int = 5) -> list[CodeChunk]:
        """Find functions that call func_name (Fix E: call graph escalation).

        Scans stored code chunks for references to func_name.
        Returns up to k caller CodeChunks ranked by call frequency
        (how many times func_name appears in each chunk).

        Used when a target is unreachable directly (deep in call graph) —
        the pipeline escalates to fuzz a higher-level caller instead.
        """
        if not self.is_built():
            return []

        import re as _re

        # Build a regex that matches bare calls: func_name( or func_name followed by space/NL/(
        call_pat = _re.compile(
            r"\b" + _re.escape(func_name) + r"\s*\(",
        )

        hits: list[tuple[int, CodeChunk]] = []
        for chunk in self._chunks:
            if chunk.kind != "function":
                continue
            if chunk.name == func_name:
                continue  # skip the function itself
            count = len(call_pat.findall(chunk.content))
            if count > 0:
                hits.append((count, chunk))

        # Sort by call frequency descending (most calls first)
        hits.sort(key=lambda x: x[0], reverse=True)
        result = [chunk for _, chunk in hits[:k]]
        if not result:
            log.info("find_callers.raw_fallback", func=func_name)
            result = self._find_callers_raw(func_name, k=k)
        return result

    def _find_callers_raw(self, func_name: str, k: int = 5) -> list[CodeChunk]:
        """Fallback caller search: scan raw .c files when chunk-based search misses.

        Chunks are truncated at MAX_CONTENT_CHARS (4000), so calls deep in large
        functions (e.g. header_pax ~6000 chars calling pax_attribute) are missed.
        This method reads full source files and finds enclosing functions.
        """
        import re as _re

        call_pat = _re.compile(r"\b" + _re.escape(func_name) + r"\s*\(")
        # Regex to find C function definitions (start of line, optional static, returns type, name, params, open brace)
        func_def_pat = _re.compile(
            r"^(?:static\s+)?[\w\s\*]+\b(\w+)\s*\([^)]*\)\s*\{",
            _re.MULTILINE,
        )
        # C keywords that the func_def_pat might false-match
        _C_KEYWORDS = frozenset({
            "if", "else", "while", "for", "do", "switch", "case", "return",
            "sizeof", "typeof", "goto", "break", "continue", "default",
        })

        hits: list[tuple[int, CodeChunk]] = []
        for fp in sorted(self._source_root.rglob("*.c")):
            # Skip build directories
            if any(part in self._SKIP_FP_DIRS for part in fp.parts):
                continue
            try:
                source = fp.read_text(errors="replace")
            except OSError:
                continue

            # Quick check: does this file even mention the function?
            if func_name not in source:
                continue

            lines = source.splitlines(keepends=True)

            # Find all function definitions and their line ranges
            func_ranges: list[tuple[str, int, int]] = []  # (name, start_line_0, end_line_0)
            for m in func_def_pat.finditer(source):
                fn_name = m.group(1)
                if fn_name in _C_KEYWORDS:
                    continue
                start_offset = m.start()
                start_line = source[:start_offset].count("\n")
                # Find matching closing brace by counting braces
                depth = 0
                end_line = start_line
                for i in range(start_line, len(lines)):
                    for ch in lines[i]:
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                end_line = i
                                break
                    if depth == 0 and end_line > start_line:
                        break
                func_ranges.append((fn_name, start_line, end_line))

            # For each function range, check if it calls func_name
            rel_path = str(fp.relative_to(self._source_root))
            for fn_name, start, end in func_ranges:
                if fn_name == func_name:
                    continue  # skip the function itself
                body = "".join(lines[start : end + 1])
                count = len(call_pat.findall(body))
                if count > 0:
                    # Build a snippet around the call site (up to MAX_CONTENT_CHARS)
                    snippet = body[: self.MAX_CONTENT_CHARS]
                    hits.append((
                        count,
                        CodeChunk(
                            kind="function",
                            name=fn_name,
                            file_path=rel_path,
                            line=start + 1,
                            content=snippet,
                            signature="",
                        ),
                    ))

        hits.sort(key=lambda x: x[0], reverse=True)
        if hits:
            log.info("find_callers.raw_found", func=func_name,
                     callers=[h[1].name for h in hits[:k]])
        return [chunk for _, chunk in hits[:k]]

    # ── Extraction ───────────────────────────────────────────────────────────

    def _extract_chunks(self, source_root: Path) -> list[CodeChunk]:
        """Walk source tree and extract function + type chunks via libclang."""
        chunks: list[CodeChunk] = []
        c_files = list(source_root.rglob("*.c"))
        h_files = list(source_root.rglob("*.h"))

        for fp in c_files:
            try:
                chunks.extend(self._extract_functions(str(fp)))
            except Exception as exc:
                log.debug("oracle.parse_error", file=str(fp), error=str(exc))

        for fp in h_files:
            try:
                chunks.extend(self._extract_functions(str(fp)))
                chunks.extend(self._extract_types(str(fp)))
            except Exception as exc:
                log.debug("oracle.parse_error", file=str(fp), error=str(exc))

        return chunks

    def _extract_functions(self, filepath: str) -> list[CodeChunk]:
        """Extract FUNCTION_DECL definitions via libclang (OverHAuL approach)."""
        import clang.cindex as cindex

        index = cindex.Index.create()
        tu = index.parse(filepath)
        chunks: list[CodeChunk] = []

        try:
            source_lines = Path(filepath).read_text(errors="replace").splitlines(keepends=True)
        except OSError:
            return chunks

        for node in tu.cursor.walk_preorder():
            if node.kind != cindex.CursorKind.FUNCTION_DECL:
                continue
            if not node.is_definition():
                continue
            if not node.extent.start.file:
                continue
            # Only chunks from THIS file (not transitively included)
            if str(node.extent.start.file.name) != filepath:
                continue

            start = node.extent.start.line - 1
            end = node.extent.end.line
            code = "".join(source_lines[start:end])

            if not code.strip():
                continue
            code = code[: self.MAX_CONTENT_CHARS]

            chunks.append(
                CodeChunk(
                    kind="function",
                    name=node.spelling,
                    file_path=str(Path(filepath).relative_to(self._source_root)),
                    line=node.extent.start.line,
                    content=code,
                    signature=node.type.spelling,
                )
            )

        return chunks

    def _extract_types(self, filepath: str) -> list[CodeChunk]:
        """Extract struct/typedef/enum definitions from header files (NEMESIS addition)."""
        import clang.cindex as cindex

        if not filepath.endswith(".h"):
            return []

        index = cindex.Index.create()
        tu = index.parse(filepath)
        chunks: list[CodeChunk] = []

        TYPE_KINDS = {
            cindex.CursorKind.STRUCT_DECL,
            cindex.CursorKind.TYPEDEF_DECL,
            cindex.CursorKind.ENUM_DECL,
        }

        try:
            source_lines = Path(filepath).read_text(errors="replace").splitlines(keepends=True)
        except OSError:
            return chunks

        for node in tu.cursor.walk_preorder():
            if node.kind not in TYPE_KINDS:
                continue
            if not node.is_definition():
                continue
            if not node.extent.start.file:
                continue
            # Skip transitively included types
            if str(node.extent.start.file.name) != filepath:
                continue

            start = node.extent.start.line - 1
            end = node.extent.end.line
            code = "".join(source_lines[start:end])

            if not code.strip():
                continue
            code = code[: self.MAX_CONTENT_CHARS]

            name = node.spelling or node.displayname
            chunks.append(
                CodeChunk(
                    kind="type",
                    name=name,
                    file_path=str(Path(filepath).relative_to(self._source_root)),
                    line=node.extent.start.line,
                    content=code,
                    signature=node.kind.name,
                )
            )

        return chunks

    # ── Embedding ────────────────────────────────────────────────────────────

    def _embed_batch(self, texts: list[str], input_type: str = "passage"):
        """Call NVIDIA NIM embeddings API in batches of BATCH_SIZE."""
        import numpy as np
        from openai import OpenAI

        client = OpenAI(
            api_key=self._api_key,
            base_url="https://integrate.api.nvidia.com/v1",
        )

        all_embs: list[list[float]] = []
        for i in range(0, len(texts), self.BATCH_SIZE):
            batch = texts[i : i + self.BATCH_SIZE]
            resp = client.embeddings.create(
                input=batch,
                model=self._model,
                encoding_format="float",
                extra_body={"input_type": input_type, "truncate": "END"},
            )
            all_embs.extend([d.embedding for d in resp.data])

        return np.array(all_embs, dtype=np.float32)

    # ── Cache ────────────────────────────────────────────────────────────────

    def _faiss_path(self) -> Path:
        return self._cache_dir / f"{self._library_name}.faiss"

    def _json_path(self) -> Path:
        return self._cache_dir / f"{self._library_name}.json"

    def _fingerprint_path(self) -> Path:
        return self._cache_dir / f"{self._library_name}.fingerprint"

    # Directories to exclude from fingerprint (build artifacts invalidate cache spuriously)
    _SKIP_FP_DIRS = {"build", "build_debug", "build_fuzz", "build_ubsan", ".git", "__pycache__"}

    def _source_fingerprint(self) -> str:
        """SHA256 of all .c/.h file mtimes+sizes in source_root.

        Excludes build directories — generated headers (config.h, tiffconf.h etc.)
        are recreated on every library build and would otherwise invalidate the cache
        on every run.
        """
        h = hashlib.sha256()
        for fp in sorted(self._source_root.rglob("*.[ch]")):
            # Skip files inside build directories
            if any(part in self._SKIP_FP_DIRS for part in fp.parts):
                continue
            try:
                st = fp.stat()
                h.update(f"{fp}:{st.st_mtime}:{st.st_size}\n".encode())
            except OSError:
                pass
        return h.hexdigest()

    def _is_cache_fresh(self) -> bool:
        """Return True if all cache files exist and fingerprint matches current source."""
        for p in (self._faiss_path(), self._json_path(), self._fingerprint_path()):
            if not p.exists():
                return False
        try:
            stored = self._fingerprint_path().read_text().strip()
            return stored == self._source_fingerprint()
        except OSError:
            return False

    def _save(self) -> None:
        """Persist FAISS index, chunk metadata, and source fingerprint."""
        import faiss

        faiss.write_index(self._index, str(self._faiss_path()))
        self._json_path().write_text(
            json.dumps([asdict(c) for c in self._chunks], ensure_ascii=False, indent=2)
        )
        self._fingerprint_path().write_text(self._source_fingerprint())
        log.debug("oracle.saved", library=self._library_name, path=str(self._cache_dir))

    def _load(self) -> None:
        """Load FAISS index and chunk metadata from cache."""
        import faiss

        self._index = faiss.read_index(str(self._faiss_path()))
        raw = json.loads(self._json_path().read_text())
        self._chunks = [CodeChunk(**c) for c in raw]
        log.debug("oracle.loaded", library=self._library_name, chunks=len(self._chunks))
