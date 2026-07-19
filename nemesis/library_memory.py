"""
NEMESIS — Cross-run library memory.

Stores per-library learned priors: which harness API patterns compile reliably,
which types need which headers, which patterns are forbidden.

Data is persisted as JSON in workspace/library_memory/{library_name}.json.
Counts (not ratios) are stored so statistics remain valid across incremental updates.

Score of a pattern: success_rate * log1p(total_seen)
  → patterns with high success but low N are less trusted than high-N patterns.
  → prevents early over-fitting to lucky first runs.

Usage (in pipeline):
    mem = LibraryMemory(config)
    mem.record_harness_outcome("TIFFReadScanline", compiled=True, reached=True)
    snippet = mem.build_prompt_snippet()
    # → inject into LLM system prompt as <library_memory>...</library_memory>
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

from nemesis.logging import get_logger


class LibraryMemory:
    """Per-library learned priors, persisted across runs."""

    def __init__(self, library_name: str, workspace_dir: str | Path) -> None:
        self.library_name = library_name
        self.log = get_logger("library_memory")
        self._path = Path(workspace_dir) / "library_memory" / f"{library_name}.json"
        self._data: dict = self._load()

    # ── Persistence ────────────────────────────────────────

    def _load(self) -> dict:
        """Load existing memory or return empty structure."""
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                self.log.warning("library_memory.load_failed", lib=self.library_name, error=str(e))
        return {
            "harness_patterns": {},   # api_call_prefix → {compile_success, compile_total, reach_success, reach_total}
            "type_fixes": {},         # C type → {header, confirmed, count}
            "forbidden_patterns": [], # list of strings that reliably cause harness failure
            "planner_hints": {},      # func_name → {hint, compile_success, compile_total, reach_success, reach_total}
        }

    def save(self) -> None:
        """Persist memory to disk atomically.

        Write to a temp file then os.replace() so an interrupt mid-write can't
        truncate the JSON — a corrupt file makes _load() silently reset ALL
        learned priors to empty (data loss across runs).
        """
        import os as _os
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(f".json.tmp.{_os.getpid()}")
        try:
            tmp.write_text(json.dumps(self._data, indent=2))
            _os.replace(tmp, self._path)
        except OSError as e:
            self.log.warning("library_memory.save_failed", lib=self.library_name, error=str(e))
            try:
                tmp.unlink()
            except OSError:
                pass
            return
        self.log.debug("library_memory.saved", lib=self.library_name, path=str(self._path))

    # ── Recording outcomes ──────────────────────────────────

    def record_harness_outcome(
        self,
        harness_code: str,
        compiled: bool,
        function_reached: bool,
    ) -> None:
        """Extract API call patterns from harness and record compile/reach outcome.

        Patterns are extracted as the first token of each function call that
        looks like a library API (contains the library name or common prefix).
        """
        patterns = self._extract_api_patterns(harness_code)
        for pat in patterns:
            entry = self._data["harness_patterns"].setdefault(pat, {
                "compile_success": 0, "compile_total": 0,
                "reach_success": 0, "reach_total": 0,
            })
            entry["compile_total"] += 1
            if compiled:
                entry["compile_success"] += 1
            entry["reach_total"] += 1
            if function_reached:
                entry["reach_success"] += 1

        self.save()

    def record_type_fix(self, c_type: str, header: str) -> None:
        """Record that c_type was fixed by including header."""
        entry = self._data["type_fixes"].setdefault(c_type, {
            "header": header, "confirmed": True, "count": 0,
        })
        entry["count"] += 1
        entry["header"] = header  # update to most recent
        self.save()

    def record_forbidden_pattern(self, pattern: str) -> None:
        """Record an API pattern that reliably causes harness failure."""
        if pattern not in self._data["forbidden_patterns"]:
            self._data["forbidden_patterns"].append(pattern)
            self.save()

    def record_planner_hint(
        self,
        func_name: str,
        hint: str,
        compiled: bool,
        reached: bool,
    ) -> None:
        """Record a planner-generated hint and its outcome after fuzzing."""
        hints = self._data.setdefault("planner_hints", {})
        entry = hints.setdefault(func_name, {
            "hint": hint,
            "compile_success": 0, "compile_total": 0,
            "reach_success": 0, "reach_total": 0,
        })
        # Update hint text to latest (may improve over iterations)
        if hint:
            entry["hint"] = hint
        entry["compile_total"] += 1
        if compiled:
            entry["compile_success"] += 1
        entry["reach_total"] += 1
        if reached:
            entry["reach_success"] += 1
        self.save()

    def get_planner_hint(self, func_name: str) -> str:
        """Return a cached planner hint if it has >=50% compile rate.

        Returns empty string if no hint cached or hint has poor compile rate.
        """
        hints = self._data.get("planner_hints", {})
        entry = hints.get(func_name)
        if not entry or not entry.get("hint"):
            return ""
        total = entry.get("compile_total", 0)
        if total == 0:
            # Never tested — return it (first run)
            return entry["hint"]
        compile_rate = entry.get("compile_success", 0) / total
        if compile_rate >= 0.5:
            return entry["hint"]
        self.log.debug(
            "planner_hint.low_compile_rate",
            func=func_name,
            rate=round(compile_rate, 2),
        )
        return ""

    # ── Querying ────────────────────────────────────────────

    def top_patterns(self, n: int = 5, min_seen: int = 2) -> list[dict]:
        """Return top-N harness patterns by trusted compile score.

        Score = (compile_success / compile_total) * log1p(compile_total)
        Patterns with < min_seen observations are excluded.
        """
        results = []
        for pat, entry in self._data["harness_patterns"].items():
            total = entry.get("compile_total", 0)
            if total < min_seen:
                continue
            success = entry.get("compile_success", 0)
            rate = success / total
            score = rate * math.log1p(total)
            results.append({
                "pattern": pat,
                "compile_rate": round(rate, 2),
                "reach_rate": round(
                    entry.get("reach_success", 0) / max(entry.get("reach_total", 1), 1), 2
                ),
                "n": total,
                "score": round(score, 3),
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:n]

    def build_prompt_snippet(self) -> str:
        """Build a <library_memory> XML block for injection into LLM system prompts.

        Only includes patterns with sufficient evidence (min_seen=2).
        Returns empty string if no useful priors exist yet.
        """
        top = self.top_patterns(n=5, min_seen=2)
        type_fixes = {
            t: v["header"] for t, v in self._data["type_fixes"].items()
            if v.get("count", 0) >= 1
        }
        forbidden = self._data.get("forbidden_patterns", [])

        if not top and not type_fixes and not forbidden:
            return ""

        lines = ["<library_memory>"]
        lines.append(f"Learned priors for {self.library_name} (from past runs):")

        if top:
            lines.append("\nHigh-success harness API patterns (sorted by evidence strength):")
            for p in top:
                lines.append(
                    f"  {p['pattern']}  "
                    f"[compile={p['compile_rate']*100:.0f}%, "
                    f"reach={p['reach_rate']*100:.0f}%, "
                    f"n={p['n']}]"
                )

        if type_fixes:
            lines.append("\nRequired headers for library-specific types:")
            for c_type, header in type_fixes.items():
                lines.append(f"  {c_type}  →  #include <{header}>")

        if forbidden:
            lines.append("\nFORBIDDEN patterns (reliably cause harness failure):")
            for pat in forbidden:
                lines.append(f"  {pat}")

        lines.append("</library_memory>")
        return "\n".join(lines)

    # ── Internal helpers ────────────────────────────────────

    def _extract_api_patterns(self, harness_code: str) -> list[str]:
        """Extract short API call prefixes from harness source.

        Looks for function calls of the form lib_prefix_*(...) that appear
        more than once (avoids noise from standard C functions).
        """
        # Match function-call-like identifiers: word chars followed by (
        calls = re.findall(r'\b([A-Za-z_]\w{4,})\s*\(', harness_code)

        # Exclude C standard lib and AFL macros
        _exclude = {
            "main", "while", "if", "for", "sizeof", "return", "malloc", "free",
            "memcpy", "memset", "printf", "fprintf", "fread", "fwrite",
            "__AFL_LOOP", "__AFL_FUZZ_INIT", "__AFL_INIT",
        }
        freq: dict[str, int] = {}
        for c in calls:
            if c not in _exclude:
                freq[c] = freq.get(c, 0) + 1

        # Keep patterns that appear at least twice (not one-off calls)
        return [k for k, v in freq.items() if v >= 2]
