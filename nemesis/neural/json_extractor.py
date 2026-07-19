"""
NEMESIS - Robust JSON Extractor for LLM Responses v2
=====================================================
Handles the specific issue where LLM outputs JSON with literal
backslash-n sequences outside of string values in arrays like seed_commands.

Install: Copy this file to ~/nemesis/nemesis/neural/json_extractor.py
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def extract_json(text: str) -> dict[str, Any] | None:
    if not text or not text.strip():
        return None

    # Strategy 1: fenced code blocks
    fence_pattern = re.compile(
        r"```(?:json)?\s*\n(.*?)\n\s*```",
        re.DOTALL,
    )
    for match in fence_pattern.finditer(text):
        candidate = match.group(1).strip()
        result = _try_parse(candidate, "fence_block")
        if result is not None:
            return result

    # Strategy 2: balanced braces
    result = _extract_balanced_braces(text)
    if result is not None:
        return result

    # Strategy 3: raw text
    result = _try_parse(text.strip(), "raw_text")
    if result is not None:
        return result

    logger.warning("json_extract.failed: no valid JSON found in LLM response")
    return None


def _try_parse(candidate: str, source: str) -> dict[str, Any] | None:
    # Attempt 1: direct parse
    obj = _safe_loads(candidate)
    if isinstance(obj, dict):
        return obj

    # Attempt 2: clean and parse
    cleaned = _clean_json(candidate)
    obj = _safe_loads(cleaned)
    if isinstance(obj, dict):
        return obj

    # Attempt 3: aggressive clean
    aggressive = _aggressive_clean(candidate)
    obj = _safe_loads(aggressive)
    if isinstance(obj, dict):
        return obj

    return None


def _safe_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    # strict=False permits raw control chars (newlines/tabs) INSIDE strings —
    # the single most common reason c_code fails to parse. Trying it here, before
    # the destructive _clean_json/_aggressive_clean passes run, preserves the C
    # source verbatim instead of risking a desynced-state-machine mangle.
    try:
        return json.loads(text, strict=False)
    except (json.JSONDecodeError, ValueError):
        return None


def _clean_json(text: str) -> str:
    """Remove literal backslash-n outside JSON strings."""
    result = []
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            # Inside a JSON string: preserve everything including escapes
            if c == '\\' and i + 1 < n:
                result.append(c)
                result.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            result.append(c)
            i += 1
        else:
            # Outside a JSON string
            if c == '"':
                in_str = True
                result.append(c)
                i += 1
            elif c == '\\' and i + 1 < n and text[i + 1] == 'n':
                # Literal \n outside string -> space
                result.append(' ')
                i += 2
            elif c == '\\' and i + 1 < n and text[i + 1] == '"':
                # Literal \" outside string -> "
                result.append('"')
                i += 2
            elif c == '\\' and i + 1 < n and text[i + 1] == '\\':
                # Literal \\ outside string -> skip
                result.append(' ')
                i += 2
            else:
                result.append(c)
                i += 1
    return ''.join(result)


def _aggressive_clean(text: str) -> str:
    """More aggressive cleaning for badly formatted LLM JSON."""
    # First apply normal clean
    text = _clean_json(text)

    # Remove any remaining standalone backslashes outside strings
    # by doing another pass
    result = []
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == '\\' and i + 1 < n:
                result.append(c)
                result.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            result.append(c)
            i += 1
        else:
            if c == '"':
                in_str = True
                result.append(c)
                i += 1
            elif c == '\\':
                # Any remaining backslash outside string -> skip it
                i += 1
            else:
                result.append(c)
                i += 1
    return ''.join(result)


def _extract_balanced_braces(text: str) -> dict[str, Any] | None:
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
                candidate = text[start: i + 1]
                result = _try_parse(candidate, "balanced_braces")
                if result is not None:
                    return result
                next_start = text.find("{", i + 1)
                if next_start != -1:
                    return _extract_balanced_braces(text[next_start:])
                return None

    return None


# ----- Self-test -----
if __name__ == "__main__":
    # Test 1: JSON in ```json fence
    test1 = '''Looking at the code...

```json
{"vulnerability_type": "null_ptr_deref", "cwe": "CWE-476", "severity": "medium"}
```

Explanation here.'''
    assert extract_json(test1) is not None, "Test 1 failed"
    print("Test 1 PASS")

    # Test 2: JSON with literal \n outside strings (the LLM bug)
    test2 = '''Here is the analysis:

```json
{
  "target_func": "test",
  "c_code": "int main() {\\nreturn 0;\\n}",
  "seed_commands": [\\n    "echo hello",\\n    "echo world"\\n  ],
  "flags": "-g"
}
```'''
    r2 = extract_json(test2)
    assert r2 is not None, "Test 2 failed"
    assert r2["target_func"] == "test", f"Test 2 wrong: {r2}"
    assert len(r2["seed_commands"]) == 2, f"Test 2 seeds: {r2['seed_commands']}"
    print("Test 2 PASS (literal \\n outside strings)")

    # Test 3: JSON with escaped quotes outside strings
    test3 = '''```json
{
  "name": "test",
  "cmds": [\\n    \\"echo foo\\",\\n    \\"echo bar\\"\\n  ]
}
```'''
    r3 = extract_json(test3)
    assert r3 is not None, "Test 3 failed"
    print("Test 3 PASS (escaped quotes outside strings)")

    # Test 4: Clean JSON (no issues)
    test4 = '{"a": 1, "b": "hello"}'
    assert extract_json(test4) is not None, "Test 4 failed"
    print("Test 4 PASS")

    # Test 5: No JSON
    test5 = "No JSON here at all."
    assert extract_json(test5) is None, "Test 5 failed"
    print("Test 5 PASS")

    print("\n--- All tests PASSED ---")
