"""
NEMESIS Stage 1 — Recon (Static Analysis).

Identifies low-coverage functions via OSS-Fuzz Introspector,
traces their call chains, and extracts source context for LLM analysis.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger
from nemesis.models import (
    AnalysisContext,
    Blocker,
    BlockerType,
    CallChain,
    CoverageTarget,
)


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
                if not func_name or self._is_duplicate(targets, func_name):
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

    def _find_function_start_line(self, lines: list[str], idx: int) -> int:
        """Return the 0-based line index where the enclosing function definition starts."""
        func_pattern = re.compile(r"^(\w+)\s*\(")
        for i in range(idx, max(idx - 100, 0), -1):
            line = lines[i].strip()
            m = func_pattern.match(line)
            if m and m.group(1) not in ("if", "for", "while", "switch", "return"):
                return i
        return -1

    def _find_enclosing_function(self, lines: list[str], idx: int) -> Optional[str]:
        """Look backwards from idx to find the function name."""
        import re
        func_pattern = re.compile(r"^(\w+)\s*\(")

        for i in range(idx, max(idx - 50, 0), -1):
            line = lines[i].strip()
            m = func_pattern.match(line)
            if m and m.group(1) not in ("if", "for", "while", "switch", "return"):
                return m.group(1)
        return None

    def _is_duplicate(self, targets: list[CoverageTarget], name: str) -> bool:
        return any(t.func_name == name for t in targets)


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

    def _extract_caller_from_line(self, line: str) -> Optional[str]:
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

        return AnalysisContext(
            target=target,
            call_chain=chain,
            source_snippets=snippets,
            macro_env=macro_env,
            build_config=self.config.target.build.configure,
        )

    def _extract_function_body(self, func: str, root: Path) -> Optional[str]:
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
