"""
NEMESIS Stage 1 — Recon (Static Analysis).

Identifies low-coverage functions via OSS-Fuzz Introspector,
traces their call chains, and extracts source context for LLM analysis.
"""

from __future__ import annotations

import re
from pathlib import Path

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import (
    AnalysisContext,
    Blocker,
    BlockerType,
    CallChain,
    CoverageTarget,
)
from nemesis.recon.git_history import GitHistoryIndex


def find_sibling_functions(func_name: str, source_root: Path) -> list[str]:
    """Find functions with similar names that may need the same fix.

    Heuristics (variant patterns common in C codebases):
    - _text_w() <-> _text_nl() (wide/narrow variants)
    - _read() <-> _write() (direction variants)
    - _v1() <-> _v2() (version variants)
    - Same prefix, different suffix

    Standalone utility — not wired into the pipeline. Use via:
        nemesis variant-check --func archive_acl_from_text_w --source ~/libarchive_clean

    Args:
        func_name: Name of the function to find siblings for.
        source_root: Root directory of the source tree to scan.

    Returns:
        List of candidate sibling function names.
    """
    # Extract common prefixes by splitting on known variant suffixes
    _VARIANT_SUFFIXES = [
        "_w", "_nl", "_l", "_a",
        "_read", "_write",
        "_v1", "_v2", "_v3",
        "_32", "_64",
        "_new", "_old",
        "_be", "_le",
    ]

    prefix = func_name
    matched_suffix = ""
    for suffix in sorted(_VARIANT_SUFFIXES, key=len, reverse=True):
        if func_name.endswith(suffix):
            prefix = func_name[: -len(suffix)]
            matched_suffix = suffix
            break

    if not prefix or len(prefix) < 4:
        return []

    # Scan source files for functions sharing the prefix
    candidates: set[str] = set()
    func_pattern = re.compile(
        rf"\b({re.escape(prefix)}[A-Za-z0-9_]*)\s*\(", re.MULTILINE
    )

    for src_file in source_root.rglob("*.[ch]"):
        try:
            content = src_file.read_text(errors="replace")
        except OSError:
            continue
        for m in func_pattern.finditer(content):
            name = m.group(1)
            if name != func_name and name not in candidates:
                candidates.add(name)

    # Sort by similarity to original (same-suffix variants first)
    def _sort_key(name: str) -> tuple[int, str]:
        # Prefer names that share a variant suffix pattern
        for s in _VARIANT_SUFFIXES:
            if name.endswith(s) and matched_suffix and s != matched_suffix:
                return (0, name)
        return (1, name)

    return sorted(candidates, key=_sort_key)


class ReconStage:
    """Stage 1 orchestrator — runs all recon sub-modules."""

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("recon")
        self.introspector = IntrospectorParser(config)
        self.tracer = CallChainTracer(config)
        self.extractor = ContextExtractor(config)

    def run(self) -> list[CoverageTarget]:
        """
        Execute the full recon stage.

        Returns ranked list of low-coverage target functions.
        """
        self.log.info("recon.start", project=self.config.target.oss_fuzz_project)
        targets = self.introspector.fetch_and_parse()
        self.log.info("recon.targets_found", count=len(targets))
        return targets

    def extract_context(self, target: CoverageTarget) -> AnalysisContext:
        """Extract full analysis context for a given target."""
        chain = self.tracer.trace(target)
        context = self.extractor.extract(chain)
        return context


class IntrospectorParser:
    """
    Parses OSS-Fuzz Introspector data to find 0%-coverage functions.

    Data source: https://introspector.oss-fuzz.com/api
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("recon.introspector")
        self.api_url = config.introspector.api_url
        self.threshold = config.introspector.coverage_threshold_pct
        self._git_index: GitHistoryIndex | None = None

    @property
    def git_history(self) -> GitHistoryIndex:
        """Lazily-built git index, shared across every scored candidate.

        Built once per parser instance: the index is one `git log` pass, and
        scoring runs over hundreds of functions that mostly live in a handful
        of files.
        """
        if self._git_index is None:
            scoring = self.config.recon_scoring
            if not scoring.git_history_enabled:
                self._git_index = GitHistoryIndex()  # empty → scores 0.0
            else:
                self._git_index = GitHistoryIndex.build(
                    self.config.target.source_root,
                    months=scoring.git_history_months,
                )
        return self._git_index

    def _git_history_bonus(self, rel_path: str) -> float:
        """Ranking bonus from churn + past fixes for the file a candidate is in."""
        scoring = self.config.recon_scoring
        if not scoring.git_history_enabled:
            return 0.0
        return self.git_history.score_bonus(
            rel_path,
            recency_bonus=scoring.git_recency_bonus,
            fix_bonus=scoring.git_fix_bonus,
            fix_bonus_cap=scoring.git_fix_bonus_cap,
        )

    def fetch_and_parse(self) -> list[CoverageTarget]:
        """
        Fetch function coverage data from OSS-Fuzz Introspector API
        and return functions below the coverage threshold.

        API endpoint: {api_url}/all-functions?project={project}
        Falls back to local source scan if the API is unavailable.
        """
        project = self.config.target.oss_fuzz_project
        self.log.info("fetch.start", project=project, api=self.api_url)

        # Try the Introspector API first
        targets = []
        try:
            targets = self._fetch_from_api()
            self.log.info("fetch.api_success", count=len(targets))
        except Exception as e:
            self.log.warning("fetch.api_failed", error=str(e))

        # Fall back to local source scan
        if not targets:
            self.log.info("fetch.fallback_local_scan")
            targets = self._scan_local_source()

        # Rank by priority score
        targets.sort(key=lambda t: t.priority_score, reverse=True)

        # Prepend pinned functions at the front (they bypass heuristic scoring)
        pinned = self._inject_pinned()
        if pinned:
            # Fix 125: sort pinned by priority so direct_internal (105) come first
            pinned.sort(key=lambda t: t.priority_score, reverse=True)
            pinned_names = {t.func_name for t in pinned}
            targets = pinned + [t for t in targets if t.func_name not in pinned_names]
            self.log.info("pinned.injected", count=len(pinned))

        return targets

    def _fetch_endpoint(self, endpoint: str, project: str,
                        extra_params: dict[str, str] | None = None) -> list[dict]:
        """Reusable HTTP call to any Introspector API endpoint.

        Args:
            endpoint: API path without leading slash (e.g. "all-functions").
            project: OSS-Fuzz project name.
            extra_params: Additional query parameters beyond project.

        Returns:
            List of function dicts (empty on any error).
        """
        import httpx

        url = f"{self.api_url}/{endpoint}"
        params: dict[str, str] = {"project": project}
        if extra_params:
            params.update(extra_params)

        try:
            resp = httpx.get(url, params=params, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.log.warning("fetch.endpoint_error", endpoint=endpoint, error=str(e))
            return []

        # Handle error responses: {"result":"error","msg":"..."} or extended_msgs
        if isinstance(data, dict) and data.get("result") == "error":
            msg = data.get("msg", "") or data.get("extended_msgs", "")
            self.log.warning("fetch.endpoint_error", endpoint=endpoint, error=str(msg))
            return []

        # Different endpoints use different keys for the function list
        funcs = data.get("functions", data.get("targets", []))
        if isinstance(funcs, list):
            self.log.info("fetch.endpoint_ok", endpoint=endpoint, count=len(funcs))
            return funcs

        self.log.warning("fetch.endpoint_error", endpoint=endpoint, error="unexpected format")
        return []

    def _parse_functions(self, raw_funcs: list[dict], seen: set[str]) -> list[CoverageTarget]:
        """Parse and score a list of raw function dicts from any Introspector endpoint.

        Args:
            raw_funcs: Function dicts from the API.
            seen: Shared set of already-seen function names (for cross-endpoint dedup).

        Returns:
            New CoverageTarget objects (not already in seen).
        """
        import fnmatch

        project = self.config.target.oss_fuzz_project
        threshold = self.config.introspector.coverage_threshold_pct
        exclude_dirs = set(self.config.introspector.exclude_dirs)
        exclude_files = self.config.introspector.exclude_files
        src_prefix = f"/src/{project}/"

        targets: list[CoverageTarget] = []

        for func in raw_funcs:
            name = func.get("function_name", "")
            if not name or name in seen:
                continue

            cov_pct = float(func.get("runtime_coverage_percent", 0))
            if cov_pct >= threshold:
                continue

            # Normalize file path
            full_path = func.get("function_filename", "")
            if full_path.startswith(src_prefix):
                rel_path = full_path[len(src_prefix):]
            else:
                marker = f"/{project}/"
                idx = full_path.find(marker)
                rel_path = full_path[idx + len(marker):] if idx != -1 else full_path

            # Apply directory and file exclusions
            path_parts = set(Path(rel_path).parts[:-1])
            if path_parts & exclude_dirs:
                continue
            if any(fnmatch.fnmatch(Path(rel_path).name, pat) for pat in exclude_files):
                continue
            if self._is_harness_function(name):
                continue

            line_begin = int(func.get("source_line_begin", 0))
            line_end = int(func.get("source_line_end", line_begin))
            complexity = int(func.get("accummulated_complexity", 0))
            signature = func.get("function_signature", "")

            # Scoring
            score = 0.0
            score += min(complexity * 0.02, 15.0)
            if cov_pct < 5.0:
                score += 1.5
            elif cov_pct <= 30.0:
                score += 4.0
            else:
                score += max(0.0, (threshold - cov_pct) / max(threshold - 30.0, 1) * 2.0)
            has_memops = any(
                kw in signature for kw in ["char *", "uint8", "void *", "size_t"]
            )
            has_ptr_arith = "*" in signature
            if has_memops:
                score += 2.0
            if any(s in name for s in ("Free", "Init", "Clear", "Reset", "Destroy")):
                score -= 4.0

            # Config-driven scoring bonuses/penalties
            fname = Path(rel_path).name
            scoring = self.config.recon_scoring

            for pattern, bonus in scoring.bonus_patterns.items():
                if re.match(re.escape(pattern), fname):
                    score += bonus
                    break

            # Accumulate ALL matching substring bonuses (was: first-match `break`,
            # which made the score depend on YAML key order when >1 pattern hit).
            for pattern, bonus in scoring.bonus_func_patterns.items():
                if re.search(re.escape(pattern), name):
                    score += bonus

            rel_parts_list = Path(rel_path).parts
            if rel_parts_list and rel_parts_list[0] in scoring.penalty_dirs:
                score -= 6.0

            if fname in scoring.penalty_files:
                score -= 8.0

            if fname in scoring.low_value_files:
                score -= scoring.low_value_files[fname]

            for suffix in scoring.penalty_funcs:
                if name.endswith(suffix) or f"{suffix}_" in name:
                    score -= 10.0
                    break

            score += self._vuln_pattern_score(signature, [])
            score += self._entry_point_score(signature, name)
            score += self._git_history_bonus(rel_path)

            is_static = self._is_static_function(name, rel_path)
            if is_static:
                self.log.debug("fetch.static_function", func=name, file=rel_path)

            seen.add(name)
            targets.append(CoverageTarget(
                func_name=name,
                file_path=rel_path,
                line=line_begin,
                coverage_pct=cov_pct,
                has_memory_ops=has_memops,
                has_pointer_arith=has_ptr_arith,
                complexity=line_end - line_begin,
                priority_score=max(score, 0.0),
                is_static=is_static,
            ))

        return targets

    def _fetch_from_api(self) -> list[CoverageTarget]:
        """Fetch low-coverage functions from OSS-Fuzz Introspector API.

        Uses a cascade of endpoints in priority order:
        1. far-reach-but-low-coverage — deep reachability + low coverage (best signal)
        2. easy-params-far-reach — simple params + far reach (easy harnesses)
        3. optimal-targets — Google's curated list
        4. all-functions — full list (current behavior)

        Shared seen set deduplicates across endpoints.
        """
        project = self.config.target.oss_fuzz_project
        cascade = [
            "far-reach-but-low-coverage",
            "easy-params-far-reach",
            "optimal-targets",
            "all-functions",
        ]

        seen: set[str] = set()
        all_targets: list[CoverageTarget] = []

        for endpoint in cascade:
            raw = self._fetch_endpoint(endpoint, project)
            if not raw:
                continue
            new_targets = self._parse_functions(raw, seen)
            self.log.info(
                "fetch.cascade_step",
                endpoint=endpoint,
                new=len(new_targets),
                total=len(all_targets) + len(new_targets),
            )
            all_targets.extend(new_targets)

        if not all_targets:
            raise ValueError("All Introspector API endpoints returned empty results")

        self.log.info(
            "fetch.api_parsed",
            endpoints_tried=len(cascade),
            total_targets=len(all_targets),
        )

        # Enrichment: existing harnesses + per-function headers
        if self.config.introspector.enable_enrichment:
            self._enrich_with_existing_harnesses(project, all_targets)
            self._enrich_with_headers(project, all_targets)

        return all_targets

    def _enrich_with_existing_harnesses(self, project: str,
                                        targets: list[CoverageTarget]) -> None:
        """Mark targets that already have OSS-Fuzz harnesses.

        Endpoint: GET /api/harness-source-and-executable?project={project}
        """
        import httpx

        url = f"{self.api_url}/harness-source-and-executable"
        try:
            resp = httpx.get(url, params={"project": project}, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.log.debug("enrich.harnesses_error", error=str(e))
            return

        # Build a set of fuzzed function names from harness data
        harness_pairs = data.get("pairs", [])
        if not isinstance(harness_pairs, list):
            return

        # Map function names to harness source paths
        harness_map: dict[str, str] = {}
        for pair in harness_pairs:
            source = pair.get("source", "")
            funcs = pair.get("functions_reached", [])
            if isinstance(funcs, list):
                for fn in funcs:
                    if isinstance(fn, str) and fn not in harness_map:
                        harness_map[fn] = source

        matched = 0
        for t in targets:
            if t.func_name in harness_map:
                t.existing_harness_path = harness_map[t.func_name]
                matched += 1

        self.log.info("enrich.harnesses_done", matched=matched, total=len(targets))

    def _enrich_with_headers(self, project: str, targets: list[CoverageTarget]) -> None:
        """Fetch needed headers for top-N targets (by score).

        Endpoint: GET /api/get-header-files-needed-for-function?project={project}&function={func}
        Rate-limited to enrichment_batch_size.
        """
        import httpx

        batch_size = self.config.introspector.enrichment_batch_size
        # Sort by priority_score descending, take top N
        sorted_targets = sorted(targets, key=lambda t: t.priority_score, reverse=True)
        top_targets = sorted_targets[:batch_size]

        enriched = 0
        for t in top_targets:
            url = f"{self.api_url}/get-header-files-needed-for-function"
            try:
                resp = httpx.get(
                    url,
                    params={"project": project, "function": t.func_name},
                    timeout=15.0,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                continue

            headers = data.get("headers", [])
            if isinstance(headers, list) and headers:
                t.needed_headers = [h for h in headers if isinstance(h, str)]
                enriched += 1

        self.log.info("enrich.headers_done", enriched=enriched, batch_size=batch_size)

    def _is_static_function(self, func_name: str, rel_path: str) -> bool:
        """
        Return True if func_name has static linkage in its source file.

        Static functions are not exported symbols — a harness in a separate
        translation unit cannot call them by name.  Filtering them out at
        Stage 1 prevents the 'call to undeclared function' compile errors that
        would otherwise waste 3 LLM API calls + a full library build.
        """
        source_root = Path(self.config.target.source_root)
        src_file = source_root / rel_path
        if not src_file.exists():
            return False  # can't determine → keep it (conservative)
        try:
            content = src_file.read_text(errors="replace")
        except OSError:
            return False

        # Match a function *definition* (not forward declaration) that starts
        # with the static keyword, anywhere before the function name.
        # Examples that must match:
        #   static int read_symlink_stored(struct archive *a, ...)
        #   static lha_read_file_header_3(struct lha_stream *s)
        # Examples that must NOT match:
        #   static int result = foo(...);   ← not a definition
        # Strategy: look for 'static' on the same line as 'func_name(' where
        # the line does NOT end with ';' (i.e. it's a definition, not a call).
        pattern = re.compile(
            r'^\s*static\b[^;{]*\b' + re.escape(func_name) + r'\s*\(',
            re.MULTILINE,
        )
        return bool(pattern.search(content))

    def _inject_pinned(self) -> list[CoverageTarget]:
        """Convert pinned_funcs config entries to CoverageTarget objects."""
        result = []
        for pf in self.config.target.pinned_funcs:
            # Fix 125: direct_internal targets get higher priority (selected first by max_targets)
            # Fix 156: explicit priority_score override takes precedence over both defaults.
            if pf.priority_score > 0:
                _score = pf.priority_score
            else:
                _score = 105.0 if pf.direct_internal else 100.0
            result.append(CoverageTarget(
                func_name=pf.func_name,
                file_path=pf.file_path,
                line=pf.line,
                coverage_pct=0.0,
                has_memory_ops=pf.has_memory_ops,
                has_pointer_arith=pf.has_pointer_arith,
                priority_score=_score,
                harness_hint=pf.harness_hint,
                force_no_blocker=pf.force_no_blocker,
                indirect_reach=pf.indirect_reach,
                direct_internal=pf.direct_internal,  # Fix 123
                differential_oracle=pf.differential_oracle,  # Fix 135
                differential_reference=pf.differential_reference,  # Fix 148
                threaded_oracle=pf.threaded_oracle,  # Fix 150
                output_invariants=pf.output_invariants,  # Fix 136
                needed_headers=pf.needed_headers,  # Fix 134
            ))
            self.log.info("pinned.target", func=pf.func_name, file=pf.file_path)
        return result

    def _scan_local_source(self) -> list[CoverageTarget]:
        """
        Fallback: scan local source for functions matching
        vulnerability patterns (pointer arith, memory ops).
        """
        source_root = Path(self.config.target.source_root)
        targets = []

        if not source_root.exists():
            self.log.warning("source_root.missing", path=str(source_root))
            return targets

        import fnmatch
        exclude_files = self.config.introspector.exclude_files
        exclude_dirs = set(self.config.introspector.exclude_dirs)

        # Scan C files for functions with vulnerability patterns
        for c_file in source_root.rglob("*.c"):
            # Skip excluded filenames
            if any(fnmatch.fnmatch(c_file.name, pat) for pat in exclude_files):
                self.log.debug("scan.excluded_file", file=c_file.name)
                continue

            # Skip excluded directory components (e.g. test/, contrib/)
            rel_parts = set(c_file.relative_to(source_root).parts[:-1])
            if rel_parts & exclude_dirs:
                continue

            rel_path = str(c_file.relative_to(source_root))
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue

                has_ptr_arith = "->" in line and "+" in line
                has_memops = any(
                    op in line
                    for op in ["malloc(", "memcpy(", "memmove(", "realloc(", "free("]
                )

                if not (has_ptr_arith or has_memops):
                    continue

                func_name = self._find_enclosing_function(lines, i - 1)
                if (
                    not func_name
                    or self._is_harness_function(func_name)
                    or self._is_duplicate(targets, func_name)
                ):
                    continue

                # Base score
                score = 0.0
                if has_ptr_arith:
                    score += 5.0
                if has_memops:
                    score += 3.0

                # Complexity bonus: count control-flow keywords in surrounding
                # 100-line window — more branches = more interesting
                window_start = max(0, i - 50)
                window_end = min(len(lines), i + 50)
                window = lines[window_start:window_end]
                cf_count = sum(
                    1 for ln in window
                    if any(kw in ln for kw in ["if (", "if(", "for (", "for(", "while (", "while(", "switch (", "switch("])
                )
                score += min(cf_count * 0.5, 5.0)  # cap bonus at 5.0

                # Function body length proxy: lines from function start to match
                func_start_idx = self._find_function_start_line(lines, i - 1)
                body_depth = (i - 1) - func_start_idx if func_start_idx >= 0 else 0
                score += min(body_depth * 0.1, 3.0)  # cap at 3.0

                # Vulnerability pattern bonus: dangerous constructs score higher
                score += self._vuln_pattern_score(line, window)

                # Entry-point reachability: can fuzzer bytes even get in here?
                # Everything above scores how dangerous the code looks; this
                # scores whether we can drive it at all. See _entry_point_score.
                score += self._entry_point_score(
                    self._extract_signature(lines, func_start_idx), func_name
                )

                # Config-driven scoring bonuses/penalties
                fname = Path(rel_path).name
                scoring = self.config.recon_scoring

                for pattern, bonus in scoring.bonus_patterns.items():
                    if re.match(re.escape(pattern), fname):
                        score += bonus
                        break

                # Bonus func patterns: function name substring → score bonus.
                # Accumulate all matches (was first-match `break` → order-dependent).
                for pattern, bonus in scoring.bonus_func_patterns.items():
                    if re.search(re.escape(pattern), func_name):
                        score += bonus

                rel_parts = Path(rel_path).parts
                if rel_parts and rel_parts[0] in scoring.penalty_dirs:
                    score -= 6.0
                if fname in scoring.penalty_files:
                    score -= 8.0
                if fname in scoring.low_value_files:
                    score -= scoring.low_value_files[fname]

                # Penalty: "Free" / "Init" / "Alloc" wrappers are usually trivial
                if any(s in func_name for s in ("Free", "Init", "Clear", "Reset", "Destroy")):
                    score -= 4.0

                # Churn + past-fix history for the file (see recon/git_history.py)
                score += self._git_history_bonus(rel_path)

                targets.append(CoverageTarget(
                    func_name=func_name,
                    file_path=rel_path,
                    line=i,
                    coverage_pct=0.0,
                    has_memory_ops=has_memops,
                    has_pointer_arith=has_ptr_arith,
                    priority_score=score,
                ))

        self.log.info("scan.complete", targets_found=len(targets))
        return targets

    def _vuln_pattern_score(self, line: str, window: list[str]) -> float:
        """
        Score a source line for dangerous vulnerability patterns.

        Distinguishes genuinely risky constructs (user-controlled sizes,
        accumulative realloc loops, shift-based allocations) from safe ones
        (sizeof-bounded copies, fixed-size structs).

        Returns a bonus score (0.0 – 12.0) to add on top of the base score.
        """
        bonus = 0.0

        # --- memcpy / memmove with variable size (not sizeof) ---
        # memcpy(dst, src, var) but NOT memcpy(dst, src, sizeof(...))
        if re.search(r"mem(?:cpy|move)\s*\(", line):
            if "sizeof(" not in line:
                bonus += 6.0   # unchecked variable-size copy
            # extra: destination is pointer + offset  e.g. memcpy(buf + off, src, n)
            if re.search(r"mem(?:cpy|move)\s*\(\s*\w+\s*\+", line):
                bonus += 3.0

        # --- malloc / realloc with size arithmetic (a + b, a * b, a << b) ---
        if re.search(r"(?:malloc|realloc)\s*\([^)]*[\+\*<<][^)]*\)", line):
            bonus += 5.0

        # --- realloc inside a loop (accumulative buffer growth) ---
        if "realloc(" in line:
            loop_kws = ("for (", "for(", "while (", "while(")
            if any(kw in ln for ln in window for kw in loop_kws):
                bonus += 4.0

        # --- left-shift on a size/count variable (e.g. window_size << bits) ---
        if re.search(r"\w+(?:size|len|count|cnt|sz)\s*<<\s*\w+", line, re.IGNORECASE):
            bonus += 5.0
        if re.search(r"<<\s*\([^)]*(?:compression|info|flag|header)\b", line, re.IGNORECASE):
            bonus += 4.0

        # --- integer cast that could truncate (e.g. (uint16_t)(a + b)) ---
        if re.search(r"\(\s*(?:u?int(?:8|16|32)_t|unsigned\s+(?:short|char))\s*\)\s*\(", line):
            bonus += 3.0

        # --- safe patterns: penalise to avoid false positives ---
        if "sizeof(" in line and "memcpy(" in line:
            bonus -= 4.0   # sizeof-bounded copy is almost always safe

        return max(bonus, 0.0)

    # ── entry-point reachability ────────────────────────────

    # A function can only be fuzzed through parameters that carry bytes we
    # control. These are the byte-buffer element types; `struct foo *` and
    # `FILE *` are deliberately NOT here (handled separately / not at all).
    _BUFFER_TYPES = ("char", "uint8_t", "int8_t", "byte", "void", "uchar")
    # Scalar types that plausibly carry a length alongside a buffer.
    _LENGTH_TYPES = ("size_t", "ssize_t", "int", "unsigned", "long", "uint32_t",
                     "uint64_t", "uint16_t")
    _LENGTH_NAMES = ("len", "length", "size", "sz", "count", "n", "nbytes", "num")
    # Lifecycle verbs: these run before/after parsing and take their data from
    # the environment (getenv, a directory listing, a global registry), not from
    # the caller — so they are near-useless as fuzz entry points.
    _LIFECYCLE_VERBS = ("load", "unload", "init", "register", "unregister",
                        "create", "destroy", "cleanup", "alloc", "free", "open",
                        "close", "setup", "teardown", "new", "delete")
    # Verbs that consume caller-supplied bytes.
    _CONSUMER_VERBS = ("parse", "decode", "read", "validate", "process",
                       "consume", "deserial", "unpack", "extract", "scan",
                       "load_from", "from_buffer", "from_string")

    def _split_params(self, signature: str) -> list[str] | None:
        """Return the parameter list of a C signature, or None if unparseable.

        An empty list means the function genuinely takes no arguments —
        `f()` and `f(void)` both yield [].
        """
        start = signature.find("(")
        if start < 0:
            return None
        depth = 0
        end = -1
        for i in range(start, len(signature)):
            if signature[i] == "(":
                depth += 1
            elif signature[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end < 0:
            return None
        inner = signature[start + 1:end].strip()
        if not inner or inner == "void":
            return []
        # Split on top-level commas only (function-pointer params nest parens).
        params, depth, buf = [], 0, ""
        for ch in inner:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            if ch == "," and depth == 0:
                params.append(buf.strip())
                buf = ""
            else:
                buf += ch
        if buf.strip():
            params.append(buf.strip())
        return params

    def _entry_point_score(self, signature: str, func_name: str) -> float:
        """
        Score how plausibly this function can be driven by fuzzer bytes.

        The rest of the scoring measures how *dangerous* a function looks
        (pointer arithmetic, malloc/memcpy, branch density). Nothing measured
        whether the function can receive attacker-controlled input at all, and
        those two are not the same question. libnmea made the gap concrete: a
        loader whose whole signature is

            int nmea_load_parsers();

        ranked #1 because it mallocs and walks a pointer list, while

            nmea_s *nmea_parse(char *sentence, size_t length, int check);

        — the canonical (buffer, length) entry point sitting in the public
        header — ranked lower. The generated harness was correct for the
        function it was given; it just discarded the fuzz input, because there
        was nowhere to put it. Every pipeline stage reported success while
        fuzzing nothing.

        A zero-argument function is penalised, not excluded: it can still be a
        valid target when it reads a global the harness sets up, but it should
        have to outrank real entry points on other evidence to get there.
        """
        score = 0.0
        params = self._split_params(signature)

        if params is not None:
            has_buffer = has_length = has_stream = False
            for p in params:
                low = p.lower()
                if "*" in low and any(t in low for t in self._BUFFER_TYPES):
                    has_buffer = True
                elif "file" in low and "*" in low:
                    has_stream = True
                elif "*" not in low and (
                    any(t in low for t in self._LENGTH_TYPES)
                    or any(re.search(rf"\b{n}\b", low) for n in self._LENGTH_NAMES)
                ):
                    has_length = True

            if has_buffer and has_length:
                score += 8.0      # canonical fuzz entry point
            elif has_buffer:
                score += 4.0
            elif has_stream:
                score += 3.0
            elif not params:
                # No parameters at all — nothing for the harness to feed.
                score -= 10.0

        low_name = func_name.lower()
        if any(v in low_name for v in self._LIFECYCLE_VERBS):
            score -= 5.0
        if any(v in low_name for v in self._CONSUMER_VERBS):
            score += 3.0
        return score

    def _extract_signature(self, lines: list[str], start_idx: int) -> str:
        """Join a K&R-style definition from its name line until the params close.

        `_find_function_start_line` points at the line holding `name(...`, with
        the return type on the line above, so the parameter list starts there
        but may wrap across several lines.
        """
        if start_idx < 0 or start_idx >= len(lines):
            return ""
        buf = ""
        for ln in lines[start_idx:start_idx + 10]:
            buf += " " + ln.strip()
            if ")" in buf and buf.count("(") <= buf.count(")"):
                break
        return buf.strip()

    # Everything up to the first `(`: a leading identifier followed by any mix
    # of identifiers, whitespace and `*` (i.e. a return type and qualifiers).
    _FUNC_HEAD_RE = re.compile(r"^([A-Za-z_][\w\s\*]*?)\(")
    _NOT_FUNC_NAMES = ("if", "for", "while", "switch", "return", "sizeof", "do",
                       "else", "case", "goto")

    def _definition_name(self, line: str) -> str | None:
        """Name of the function whose definition this line opens, or None.

        The previous pattern was `^(\\w+)\\s*\\(`, which requires the line to
        *begin* with the function name — true only for K&R layout:

            nmea_s *
            nmea_parse(char *sentence, size_t length, int check)

        Every other C project on earth writes the return type on the same line:

            bool minmea_parse_rmc(struct minmea_sentence_rmc *frame, ...)
            static int hex2int(char c)

        and matched nothing, so `_find_enclosing_function` returned None for
        every line and `_scan_local_source` produced *zero* candidates. libnmea
        only worked because it happens to use K&R. Since the local scan is the
        sole target source for any project not in OSS-Fuzz, this silently
        emptied the pipeline for exactly the projects it exists to serve.
        """
        head_m = self._FUNC_HEAD_RE.match(line.strip())
        if not head_m:
            return None
        head = head_m.group(1)
        if "=" in head or ";" in head:
            return None            # an expression or initialiser, not a header
        tokens = re.findall(r"[A-Za-z_]\w*", head)
        if not tokens:
            return None
        if tokens[0] in self._NOT_FUNC_NAMES:
            return None            # `return foo(`, `if (`, `case x(` …
        name = tokens[-1]
        return None if name in self._NOT_FUNC_NAMES else name

    def _is_function_definition(self, lines: list[str], idx: int) -> bool:
        """True if lines[idx] opens a definition rather than a call statement.

        `free(data);` and `nmea_parse(char *s, size_t n)` both match
        name-then-paren. Only a definition is followed by a body, so require the
        parameter list to close and a brace to follow. Without this the scanner
        happily reports `printf` and `free` as fuzz targets, because it picked
        them up from call sites.
        """
        buf = ""
        for j in range(idx, min(idx + 8, len(lines))):
            s = lines[j].strip()
            buf += " " + s
            if buf.count("(") > buf.count(")"):
                continue          # parameter list still open (wrapped params)
            if s.endswith(";"):
                return False      # a call statement, or a prototype
            if s.endswith("{"):
                return True
            for k in range(j + 1, min(j + 3, len(lines))):
                nxt = lines[k].strip()
                if not nxt:
                    continue
                return nxt.startswith("{")
            return False
        return False

    def _find_function_start_line(self, lines: list[str], idx: int) -> int:
        """Return the 0-based line index where the enclosing function definition starts.

        The backward walk stops at a column-0 `}` — that is the end of the
        *previous* function, so continuing past it would attribute this line to
        a function it does not belong to. This bound is what makes an unlimited
        lookback safe, and an unlimited lookback is what this needs: libnmea's
        `nmea_parse` body puts its first interesting line 54 lines below the
        signature, and the old fixed 50-line window returned no name at all, so
        the canonical `(buffer, length)` entry point was dropped before scoring.
        """
        for i in range(idx, -1, -1):
            raw = lines[i]
            if i < idx and raw.startswith("}"):
                return -1
            if (
                self._definition_name(raw) is not None
                and self._is_function_definition(lines, i)
            ):
                return i
        return -1

    def _find_enclosing_function(self, lines: list[str], idx: int) -> str | None:
        """Name of the function containing lines[idx], or None.

        Derived from `_find_function_start_line` so the two can never disagree:
        when they used different lookback windows, a long function yielded a
        valid start index and a None name, and the candidate was silently
        discarded.
        """
        start = self._find_function_start_line(lines, idx)
        if start < 0:
            return None
        return self._definition_name(lines[start])

    def _is_duplicate(self, targets: list[CoverageTarget], name: str) -> bool:
        return any(t.func_name == name for t in targets)

    # libFuzzer entry points, and the names AFL/OSS-Fuzz harnesses conventionally
    # use. A harness is the thing we generate, never the thing we target.
    _HARNESS_FUNCS = frozenset({
        "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize", "LLVMFuzzerCustomMutator",
        "LLVMFuzzerCustomCrossOver", "FuzzerTestOneInput", "fuzz_one", "fuzz_target",
    })

    def _is_harness_function(self, name: str) -> bool:
        """True for functions that are themselves fuzz harnesses.

        minmea ships a ClusterFuzzLite harness, and recon ranked its
        `LLVMFuzzerTestOneInput` as target #2 — a fuzzing framework selecting a
        fuzz harness as its fuzz target. Beyond being useless, it is circular:
        the generated harness would wrap an existing harness, and the coverage
        attributed to "the library" would partly be the other harness's own
        setup code.

        Name-level, so it holds regardless of where the file lives or what it
        is called; the path/filename exclusions are the second line of defence.
        """
        return name in self._HARNESS_FUNCS or name.startswith("LLVMFuzzer")


class CallChainTracer:
    """
    Traces call chains from target functions to entry points.

    Uses grep/cscope to find callers, and scans for blockers
    (#ifdef, runtime checks) along the path.
    """

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("recon.tracer")

    def trace(self, target: CoverageTarget) -> CallChain:
        """
        Trace the call chain for a target function.

        Returns the chain with any blockers found along the path.
        """
        self.log.info("trace.start", func=target.func_name)

        source_root = Path(self.config.target.source_root)
        chain = self._find_callers(target.func_name, source_root)
        blockers = self._find_blockers(chain, source_root)

        # Also include known blockers from config
        for kb in self.config.known_blockers:
            blockers.append(Blocker(
                condition=kb.condition,
                file_path=kb.file,
                line=kb.line or 0,
                blocker_type=BlockerType(kb.type),
                bypass_strategy=kb.description,
            ))

        return CallChain(
            entry_point=chain[0] if chain else "unknown",
            chain=chain,
            blockers=blockers,
            target=target,
            depth=len(chain),
        )

    def _find_callers(self, func: str, root: Path) -> list[str]:
        """
        Find caller chain using grep.

        TODO: replace with cscope -d -L2 or ctags for accuracy.
        """
        import subprocess

        callers = [func]
        current = func

        for _ in range(10):  # max depth
            try:
                result = subprocess.run(
                    [
                        "grep", "-rn", f"{current}(",
                        str(root / self.config.target.source_subdir)
                        if self.config.target.source_subdir else str(root),
                    ],
                    capture_output=True, text=True, timeout=10,
                )
                # Parse callers from grep output
                for line in result.stdout.splitlines():
                    # Skip the function definition itself
                    if f"{current}(" in line and "static" not in line.split(current)[0]:
                        # Extract calling function name (heuristic)
                        parts = line.split(":")
                        if len(parts) >= 3:
                            caller = self._extract_caller_from_line(parts[2])
                            if caller and caller != current and caller not in callers:
                                callers.insert(0, caller)
                                current = caller
                                break
                else:
                    break  # No more callers found
            except (subprocess.TimeoutExpired, FileNotFoundError):
                break

        self.log.info("trace.complete", func=func, depth=len(callers), chain=callers)
        return callers

    def _extract_caller_from_line(self, line: str) -> str | None:
        """Extract function name from a line of code (heuristic)."""
        import re
        # Look for function call pattern before our target
        m = re.search(r"(\w+)\s*\(", line.strip())
        if m and m.group(1) not in ("if", "for", "while", "switch", "return", "sizeof"):
            return m.group(1)
        return None

    def _find_blockers(self, chain: list[str], root: Path) -> list[Blocker]:
        """
        Scan source files for compile-time guards and runtime checks
        near the functions in the call chain.
        """
        blockers = []
        import subprocess

        for func in chain:
            try:
                result = subprocess.run(
                    [
                        "grep", "-n", "-B5", f"{func}(",
                        str(root / self.config.target.source_subdir)
                        if self.config.target.source_subdir else str(root),
                    ],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if "#if" in line or "#ifdef" in line:
                        parts = line.split(":")
                        if len(parts) >= 3:
                            blockers.append(Blocker(
                                condition=parts[2].strip(),
                                file_path=parts[0],
                                line=int(parts[1]) if parts[1].isdigit() else 0,
                                blocker_type=BlockerType.MACRO,
                            ))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return blockers


class ContextExtractor:
    """Extracts source code context for LLM analysis."""

    CONTEXT_LINES = 150  # lines before/after target to extract

    def __init__(self, config: NemesisConfig) -> None:
        self.config = config
        self.log = get_logger("recon.context")
        self._git_index: GitHistoryIndex | None = None

    @property
    def git_history(self) -> GitHistoryIndex:
        """Lazily-built git index (see IntrospectorParser.git_history)."""
        if self._git_index is None:
            scoring = self.config.recon_scoring
            if not scoring.git_history_enabled:
                self._git_index = GitHistoryIndex()
            else:
                self._git_index = GitHistoryIndex.build(
                    self.config.target.source_root,
                    months=scoring.git_history_months,
                )
        return self._git_index

    def extract(self, chain: CallChain) -> AnalysisContext:
        """Extract full source context for a call chain."""
        source_root = Path(self.config.target.source_root)
        snippets: dict[str, str] = {}

        target = chain.target
        target_file = source_root / target.file_path

        if target_file.exists():
            try:
                lines = target_file.read_text(errors="replace").splitlines()
                start = max(0, target.line - self.CONTEXT_LINES)
                end = min(len(lines), target.line + self.CONTEXT_LINES)
                snippets[target.func_name] = "\n".join(lines[start:end])
            except OSError:
                pass

        # Extract context for each function in the chain
        for func in chain.chain:
            if func == target.func_name:
                continue
            snippet = self._extract_function_body(func, source_root)
            if snippet:
                snippets[func] = snippet

        # Extract macro environment
        macro_env = self._extract_macros(target_file)

        # Past fixes to this file are a direct hint about what goes wrong here —
        # "previously fixed an OOB read in the chunk loop" tells the analysis
        # where to look far more cheaply than re-deriving it from the source.
        git_lines = self.git_history.context_lines(target.file_path)
        if git_lines:
            self.log.debug(
                "context.git_history", func=target.func_name, lines=len(git_lines),
            )

        return AnalysisContext(
            target=target,
            call_chain=chain,
            source_snippets=snippets,
            macro_env=macro_env,
            build_config=self.config.target.build.configure,
            git_history=git_lines,
        )

    def _extract_function_body(self, func: str, root: Path) -> str | None:
        """Extract a function body from source files."""
        import subprocess
        try:
            result = subprocess.run(
                [
                    "grep", "-rn", "-A30", f"^{func}(",
                    str(root / self.config.target.source_subdir)
                    if self.config.target.source_subdir else str(root),
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                return result.stdout[:2000]  # cap at 2000 chars
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _extract_macros(self, file_path: Path) -> dict[str, str]:
        """Extract #define macros from a file."""
        macros: dict[str, str] = {}
        if not file_path.exists():
            return macros

        try:
            for line in file_path.read_text(errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("#define "):
                    parts = stripped[8:].split(None, 1)
                    if len(parts) == 2:
                        macros[parts[0]] = parts[1]
                    elif len(parts) == 1:
                        macros[parts[0]] = ""
        except OSError:
            pass

        return macros
