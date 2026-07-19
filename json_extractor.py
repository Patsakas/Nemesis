"""
NEMESIS - Robust JSON Extractor for LLM Responses
==================================================
Handles Claude responses containing markdown fences, explanatory text,
and mixed content around JSON blocks.

Install: Copy to ~/nemesis/nemesis/neural/json_extractor.py
"""

import json
import re
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def extract_json(text: str) -> Optional[dict[str, Any]]:
    """
    Extract JSON dict from LLM response text.

    Strategy (ordered by reliability):
      1. Find ```json ... ``` fenced code blocks via regex
      2. Find ``` ... ``` generic code blocks containing JSON
      3. Find first balanced { ... } in raw text
      4. Try json.loads on stripped text directly

    Returns None if no valid JSON found.
    """
    if not text or not text.strip():
        return None

    # --- Strategy 1 & 2: Extract from fenced code blocks ---
    # Use a compiled pattern with escaped backticks
    fence_pattern = re.compile(
        r"```(?:json)?\s*\n(.*?)\n\s*```",
        re.DOTALL,
    )
    for match in fence_pattern.finditer(text):
        candidate = match.group(1).strip()
        result = _try_parse(candidate, "fence_block")
        if result is not None:
            return result

    # --- Strategy 3: Find first balanced { ... } ---
    result = _extract_balanced_braces(text)
    if result is not None:
        return result

    # --- Strategy 4: Raw text parse ---
    result = _try_parse(text.strip(), "raw_text")
    if result is not None:
        return result

    logger.warning("json_extract.failed: no valid JSON found in LLM response")
    return None


def _try_parse(candidate: str, source: str) -> Optional[dict[str, Any]]:
    """Attempt JSON parse, return dict or None."""
    try:
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            logger.debug("json_extract.success", source=source)
            return obj
        # If it parsed but is not a dict (e.g. a list), wrap or skip
        if isinstance(obj, list) and len(obj) == 1 and isinstance(obj[0], dict):
            return obj[0]
        logger.debug("json_extract.skip: parsed but not a dict", source=source)
        return None
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_balanced_braces(text: str) -> Optional[dict[str, Any]]:
    """
    Find the first top-level balanced { ... } in text and parse it.
    Handles nested braces and strings with escaped quotes.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape_next:
            escape_next = False
            continue

        if ch == "\\":
            escape_next = True
            continue

        if ch == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                result = _try_parse(candidate, "balanced_braces")
                if result is not None:
                    return result
                # If this block failed, try finding next {
                next_start = text.find("{", i + 1)
                if next_start != -1:
                    return _extract_balanced_braces(text[next_start:])
                return None

    return None


# ----- Self-test -----
if __name__ == "__main__":
    # Test 1: JSON in ```json fence
    test1 = """Looking at the code, I can see the vulnerability...

Here is my analysis:

```json
{"vulnerability_type": "null_ptr_deref", "cwe": "CWE-476", "severity": "medium"}
```

This is a classic NULL pointer dereference."""

    r1 = extract_json(test1)
    assert r1 is not None, "Test 1 failed"
    assert r1["cwe"] == "CWE-476", f"Test 1 wrong value: {r1}"
    print(f"Test 1 PASS: {r1}")

    # Test 2: JSON in generic ``` fence
    test2 = """Analysis complete.

```
{"blockers": ["__STDC_ISO_10646__"], "patch_type": "preprocessor"}
```
"""
    r2 = extract_json(test2)
    assert r2 is not None, "Test 2 failed"
    assert "blockers" in r2, f"Test 2 wrong keys: {r2}"
    print(f"Test 2 PASS: {r2}")

    # Test 3: Raw JSON without fences
    test3 = '{"harness_code": "int main() { return 0; }", "format": "c"}'
    r3 = extract_json(test3)
    assert r3 is not None, "Test 3 failed"
    print(f"Test 3 PASS: {r3}")

    # Test 4: JSON buried in text (no fences)
    test4 = 'The result is {"status": "ok", "count": 42} as expected.'
    r4 = extract_json(test4)
    assert r4 is not None, "Test 4 failed"
    assert r4["count"] == 42, f"Test 4 wrong value: {r4}"
    print(f"Test 4 PASS: {r4}")

    # Test 5: No JSON at all
    test5 = "This response contains no JSON whatsoever."
    r5 = extract_json(test5)
    assert r5 is None, "Test 5 should return None"
    print("Test 5 PASS: None (correct)")

    # Test 6: Nested JSON
    test6 = """```json
{"analysis": {"root_cause": "missing null check", "loc": {"file": "foo.c", "line": 42}}, "cwe": "CWE-476"}
```"""
    r6 = extract_json(test6)
    assert r6 is not None and r6["cwe"] == "CWE-476", "Test 6 failed"
    print(f"Test 6 PASS: {r6}")

    # Test 7: Multiple code blocks - should pick first valid JSON
    test7 = """Here's the patch:
```c
if (ptr == NULL) return -1;
```

And the analysis:
```json
{"patch_applied": true, "confidence": 0.95}
```
"""
    r7 = extract_json(test7)
    assert r7 is not None and r7["patch_applied"] is True, "Test 7 failed"
    print(f"Test 7 PASS: {r7}")

    print("\n--- All 7 tests PASSED ---")