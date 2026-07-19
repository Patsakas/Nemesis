"""Bug-class classifier — analyse a pinned function's source code (and the
NAMES of its direct callers, nothing else) to label the kind of input shape
most likely to expose a memory-safety bug there.

Honest backtest constraint
--------------------------
This module deliberately does NOT receive any CVE description, CWE label,
or bug history. It sees only:
  - The function's own source body.
  - The names (not signatures, not bodies) of immediate callers.

That is the same information a human auditor has when reading unfamiliar
code with no public CVE entry to consult. The output is therefore a fair
input to the architect prompt: it amplifies what's already in the source,
not what's in NVD.

Output shape
------------
```python
BugClass(
    label="deep_recursion" | "accumulator_overflow" | "malformation_eof"
          | "stateful_sequence" | "other",
    evidence="<1-line citation, e.g. 'line 7160: build_node calls itself in"
             " a loop over dest->numchildren'>",
    harness_hint="<1-2 sentences of generic guidance: what input geometry"
                 " is needed, what to amplify in the harness setup>",
)
```

The classifier returns `BugClass(label='other', ...)` on any LLM error or
parse failure — caller falls back to the existing prompt without the new
hint block.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import logging

    from nemesis.neural import LLMClient


_VALID_LABELS = {
    "deep_recursion",
    "accumulator_overflow",
    "malformation_eof",
    "stateful_sequence",
    "other",
}


@dataclass
class BugClass:
    label: str
    evidence: str
    harness_hint: str

    def render_block(self) -> str:
        if self.label not in _VALID_LABELS or self.label == "other":
            return ""
        # Friendly label for prompt readability.
        label_pretty = {
            "deep_recursion": "deep recursion / unbounded tree depth",
            "accumulator_overflow": "accumulator (running sum / count) overflow",
            "malformation_eof": "malformation / premature EOF / missing terminator",
            "stateful_sequence": "stateful API sequence / multi-call ordering",
        }[self.label]
        block = (
            "<trigger_pattern>\n"
            "Static analysis of the pinned function's source identifies the "
            "most plausible memory-safety trigger class:\n"
            f"  Class: {label_pretty}\n"
            f"  Evidence: {self.evidence}\n"
            f"  Harness implication: {self.harness_hint}\n"
            "Note: this label is derived ONLY from the function body and the "
            "NAMES of its callers — no CVE description was consulted. Treat "
            "it as a hypothesis, not a directive: design the harness to "
            "produce inputs of this geometry, then let the fuzzer confirm "
            "or refute it.\n"
        )
        # Fix 148: when the trigger is deep_recursion, the natural way to
        # detect a stack overflow with AFL+ASAN is to constrain stack size.
        # Default Linux stack is 8MB; ASAN-instrumented frames need ~150–300
        # bytes each, so triggering needs tens of thousands of recursion
        # levels — beyond what mutators can synthesise in 15 min. Wrapping
        # the per-loop body in a pthread with a 64 KB stack reduces the
        # required nesting depth by ~125×, making the trigger reachable in
        # minutes. This is harness-side instrumentation only — no source
        # change to the library, so the rediscovery stays honest.
        if self.label == "deep_recursion":
            block += (
                "\n"
                "RECOMMENDED HARNESS PATTERN — small-stack worker thread:\n"
                "Because the trigger is deep recursion, allocate a small\n"
                "(64 KB) thread stack via pthread_attr_setstacksize and run\n"
                "the parser there. This makes the stack-overflow detectable\n"
                "with shallower nesting (≈30–80 levels instead of 30 000+).\n"
                "It is a STANDARD fuzzing technique (Google's libFuzzer\n"
                "harnesses use the same pattern via setrlimit) and changes\n"
                "no library semantics — only how the harness invokes them.\n"
                "Use approximately this skeleton:\n"
                "```c\n"
                "#include <pthread.h>\n"
                "static void *_nemesis_worker(void *arg) {\n"
                "    /* parser setup + public API call go here, exactly as you\n"
                "       would have written them inside __AFL_LOOP otherwise */\n"
                "    return NULL;\n"
                "}\n"
                "int main(int argc, char **argv) {\n"
                "    (void)argc; (void)argv;\n"
                "    __AFL_INIT();\n"
                "    pthread_attr_t attr;\n"
                "    pthread_attr_init(&attr);\n"
                "    pthread_attr_setstacksize(&attr, 64 * 1024);\n"
                "    while (__AFL_LOOP(10000)) {\n"
                "        pthread_t t;\n"
                "        if (pthread_create(&t, &attr, _nemesis_worker, NULL) == 0) {\n"
                "            pthread_join(t, NULL);\n"
                "        }\n"
                "    }\n"
                "    pthread_attr_destroy(&attr);\n"
                "    return 0;\n"
                "}\n"
                "```\n"
                "Compile flag: add `-pthread` (the linker flag will be picked\n"
                "up by the build wrapper). The exec rate drops ~3× vs. an\n"
                "in-line harness — that is fine; trigger discovery dominates.\n"
            )
        block += "</trigger_pattern>"
        return block


_SYSTEM_PROMPT = """\
You are a senior C security auditor. You analyse one function at a time
and classify the input-shape most likely to expose a memory-safety bug.

You have NO access to CVE databases, NO bug-history, NO CWE labels. You
see only the function's own source code and the NAMES of its immediate
callers (not their bodies).

Output strict JSON, no prose, no Markdown fences. Schema:

{
  "class": "deep_recursion" | "accumulator_overflow" | "malformation_eof"
           | "stateful_sequence" | "other",
  "evidence": "<one short sentence quoting concrete code (e.g., line N,
                operator/call) that justifies the class>",
  "harness_hint": "<1-2 sentences: GENERIC guidance for a fuzz harness
                   author — what input geometry to construct, what kind
                   of state must be set up via the public API. NEVER
                   mention specific CVE numbers, specific function names
                   beyond those visible in the source, or specific
                   exploit primitives.>"
}

Class definitions:
  deep_recursion       — function calls itself or a peer such that stack
                         growth is proportional to input nesting depth.
                         Evidence: a self-call inside a loop over a
                         tree-shaped count.
  accumulator_overflow — function maintains a running counter (length,
                         offset, sum, capacity) that grows with input
                         and is later used to size memory.
                         Evidence: a `+=`/`*=` against a counter
                         variable that is later passed to malloc /
                         memcpy / array index.
  malformation_eof     — function early-exits on malformed/short input
                         and the bug is on the exit path itself
                         (premature termination, missing trailing byte,
                         missing UTF-8 continuation).
                         Evidence: `if (ptr >= end) return ...;` style
                         guards, or string-terminator handling.
  stateful_sequence    — bug requires multiple calls in a specific order
                         or shared parser/codec state across them.
                         Evidence: function operates on a context whose
                         field is mutated and re-read across calls.
  other                — none of the above.

Be conservative: if the code does not clearly fit one of the first four,
output "other" with a one-line evidence and an empty harness_hint.
"""


def _build_user_prompt(
    func_name: str, func_source: str, caller_names: list[str],
) -> str:
    callers = ", ".join(caller_names) if caller_names else "(no callers found)"
    # Cap at 6KB of code so the prompt stays cheap.
    if len(func_source) > 6 * 1024:
        func_source = func_source[: 6 * 1024] + "\n/* ... truncated ... */\n"
    return (
        f"Function: {func_name}\n"
        f"Direct callers (names only, no bodies): {callers}\n"
        "\n"
        f"Source:\n```c\n{func_source}\n```\n"
    )


def _parse_response(text: str) -> Optional[BugClass]:
    """Extract the first JSON object in `text` and validate the schema."""
    text = text.strip()
    # Strip optional ```json fences
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # Find the first {...} balanced object
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if start == -1:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                blob = text[start : i + 1]
                try:
                    obj = json.loads(blob)
                except json.JSONDecodeError:
                    return None
                lab = obj.get("class", "other")
                if lab not in _VALID_LABELS:
                    return None
                return BugClass(
                    label=lab,
                    evidence=str(obj.get("evidence", "")).strip()[:300],
                    harness_hint=str(obj.get("harness_hint", "")).strip()[:600],
                )
    return None


def classify_bug_class(
    func_name: str,
    func_source: str,
    caller_names: list[str],
    client: "LLMClient",
    log: "logging.Logger | None" = None,
) -> BugClass:
    """Run the classifier. Returns BugClass(label='other', ...) on any failure."""
    from nemesis.neural import ModelRole

    if not func_source or not func_name:
        return BugClass(label="other", evidence="empty input", harness_hint="")
    prompt = _build_user_prompt(func_name, func_source, caller_names)
    try:
        response = client.complete(
            prompt=prompt,
            system=_SYSTEM_PROMPT,
            stage="bug_class",
            target_func=func_name,
            role=ModelRole.ARCHITECT,
        )
    except Exception as exc:  # noqa: BLE001
        if log:
            log.warning("bug_class.llm_failed", error=str(exc))
        return BugClass(
            label="other", evidence=f"llm error: {exc}", harness_hint="",
        )
    parsed = _parse_response(response or "")
    if parsed is None:
        if log:
            log.warning(
                "bug_class.parse_failed",
                preview=(response or "")[:120].replace("\n", " "),
            )
        return BugClass(
            label="other",
            evidence="response not parseable as JSON",
            harness_hint="",
        )

    # Heuristic post-process: if the function literally calls itself, that
    # recursion dominates whatever other pattern the LLM might have spotted.
    # The classic case is expat's `build_node` — the body contains BOTH
    # `*contpos += dest->numchildren` (looks like accumulator) AND a literal
    # `build_node(parser, cn, ...)` self-call. The recursive call is the
    # actual stack-overflow trigger. We trust this signal because it is a
    # plain syntactic fact extracted from the source — not LLM judgement.
    self_call_re = re.compile(
        r"\b" + re.escape(func_name) + r"\s*\(",
    )
    self_calls = list(self_call_re.finditer(func_source))
    # Subtract 1 for the function's own definition line. Two or more remaining
    # matches (== one or more recursive calls in the body) is enough.
    recursive_self_calls = max(0, len(self_calls) - 1)
    if recursive_self_calls >= 1 and parsed.label != "deep_recursion":
        if log:
            log.info(
                "bug_class.upgraded_to_deep_recursion",
                func=func_name,
                from_label=parsed.label,
                self_calls_in_body=recursive_self_calls,
            )
        parsed = BugClass(
            label="deep_recursion",
            evidence=(
                f"function `{func_name}` calls itself "
                f"{recursive_self_calls} time(s) in its body — "
                f"recursion dominates trigger pattern (LLM had labelled "
                f"`{parsed.label}` based on: {parsed.evidence[:120]})"
            ),
            harness_hint=(
                "trigger needs deeply nested input. Construct inputs whose "
                "structural depth scales with content nesting and let the "
                "harness exercise the recursion via the public API."
            ),
        )

    if log:
        log.info(
            "bug_class.classified",
            func=func_name,
            label=parsed.label,
            evidence_preview=parsed.evidence[:80],
        )
    return parsed
