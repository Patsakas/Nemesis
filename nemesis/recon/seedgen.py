"""SeedMind-style LLM-driven seed generator (Tier 2 #3, 2026-05-07).

Background
----------
SeedMind (arxiv 2411.18143) found that asking an LLM to emit a Python
*generator script* — rather than raw byte sequences — bypasses the
model's well-known reluctance to produce binary blobs and lets a
single ~$0.50 LLM call seed thousands of valid corpus files. Coverage
gains over the OSS-Fuzz default corpus reached 39-44% on hard targets.

NEMESIS port
------------
1.  `synthesize_generator_script()` asks the architect LLM to write a
    Python script with the contract

        python script.py <out_path> <rng_seed>

    The script writes one binary seed to `<out_path>` whose
    structure is biased by the rng_seed argument. The prompt requires
    the LLM to honour the rng_seed so we can vary the produced corpus
    across many invocations — without that, the NEMESIS sha256 LLM
    cache would return one identical script for the run, and the 1000
    invocations would emit 1000 byte-identical seeds.

2.  `produce_seeds()` invokes the script N times in a temp dir with
    distinct rng_seeds, copies non-empty unique outputs into the AFL
    `-i` directory, and returns the count of seeds produced.

3.  The existing `_prevalidate_seeds()` and `_minimize_seeds()` stages
    in fuzzing/__init__.py then drop crashers and corpus duplicates,
    so the LLM script does not need to be perfect — only diverse.

Generality
----------
No per-library logic. The LLM gets the library name + format_spec
(synthesised at onboard time) + cve_records (NVD) + the target func +
harness source — same context bundle used by mutator_synthesis and
predicate_synthesis. Output is plain Python so it runs in any subprocess.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nemesis.neural import LLMClient


_SYSTEM_PROMPT = """\
You write a Python 3 script that generates ONE binary seed file for an
AFL++ fuzzing harness, biased by a runtime random-seed argument.

Contract — your script will be invoked as:

    python script.py <out_path> <rng_seed>

* `out_path` is a filesystem path; you write the seed bytes there.
* `rng_seed` is an integer (parse with int(sys.argv[2])). Pass it to
  `random.seed(...)` at startup. THIS IS MANDATORY — the harness will
  invoke your script hundreds of times with different rng_seeds, and
  if you do not seed the RNG, every invocation will emit the same
  bytes and the call wave will be wasted.

* Produce a structurally valid input that passes the parser's early
  validation (magic bytes, header dimensions, chunk framing) but
  varies in the bytes that carry encoding decisions (length fields,
  type tags, count fields, payload).
* If the format has CRC fields, compute them — a malformed CRC will
  short-circuit the parser before any of your varied bytes matter.
* Bias your variation toward the fields named in the recent CVE
  descriptions and the Mutator strategy section of the format spec.
* Produce some "extreme but plausible" inputs (length fields near
  INT_MAX, deeply-nested containers, Huffman-table sizes near the
  type limit) — those drive coverage into the deep parser code.
* Cap the seed at 16 KiB unless the format truly requires larger
  inputs. Smaller seeds keep AFL exec rate high.

Output STRICT JSON with one field:

    {"script": "<full Python source as one string with literal \\n line breaks>"}

The script's source MUST:
* Begin with `import sys, random`. You may ONLY import from this
  list: {allowed_imports}. No third-party packages.
* End with the file write — no global side effects on import beyond
  function/constant definitions.
* Be self-contained — no relative imports, no environment lookups
  beyond `sys.argv`.
* Avoid network I/O, file reads, subprocess, eval, exec.

OUTPUT ONLY THE JSON OBJECT. NO MARKDOWN FENCES. NO PROSE BEFORE OR AFTER.
"""


def _build_user_prompt(
    library_name: str,
    target_func: str,
    harness_source: str,
    cve_records: list[dict],
    format_spec: str,
) -> str:
    parts: list[str] = [
        f"Library: {library_name}",
        f"Target function: {target_func or '(no pin)'}",
        "",
        "Harness source (informational — your script writes seeds the "
        "harness will consume via __AFL_FUZZ_TESTCASE_BUF):",
        "```c",
        harness_source[:5000] if harness_source
        else "(no harness — produce a generic seed for the format)",
        "```",
        "",
    ]
    if format_spec:
        parts += [
            "Format spec — your seed must be parseable through the early "
            "framing then vary the structurally meaningful fields:",
            "```",
            format_spec[:3500],
            "```",
            "",
        ]
    if cve_records:
        parts += [
            "Recent CVEs against this library — bias your generated bytes "
            "toward the fields and code paths these triggers exercise:",
            "",
        ]
        for rec in cve_records:
            parts.append(f"  {rec.get('id', '?')}: {rec.get('description', '')[:400]}")
        parts.append("")
    parts.append(
        f"Now emit the Python generator script for {library_name}."
    )
    return "\n".join(parts)


def _extract_script(raw_response: str) -> str:
    """Pull the `script` field out of the LLM's JSON envelope."""
    if not raw_response:
        return ""
    text = raw_response.strip()
    if text.startswith("```"):
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    obj = None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                return ""
    if not isinstance(obj, dict):
        return ""
    script = obj.get("script", "")
    if not isinstance(script, str):
        return ""
    return script.strip()


# Conservative blacklist for static rejection. We do NOT pretend this is
# a real sandbox — these are LLM-emitted scripts that we run in a
# subprocess inside our own tempdir; treat them as trusted but verify
# they don't exfiltrate or escape obvious bounds. Hard sandboxing
# (seccomp, namespaces, …) is a Tier-3 follow-up.
_FORBIDDEN_PATTERNS = (
    r"\bsubprocess\b",
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\bsocket\b",
    r"\bhttp\.client\b",
    r"\burllib\b",
    r"\brequests\b",
    r"\beval\(",
    r"\bexec\(",
    r"\b__import__\b",
    # NOTE: open() in write mode is REQUIRED — the script's contract is
    # to write a seed to sys.argv[1]. We rely on subprocess cwd
    # confinement (tempdir) for path containment instead.
)


import ast

# Modules a generator script may import. Anything else (os, subprocess, socket,
# ctypes, importlib, …) is rejected at the AST level — far harder to bypass than
# the regex blacklist (which `getattr(os, "sys"+"tem")` or `__import__` evade).
_SCRIPT_ALLOWED_IMPORTS = {
    "struct", "random", "sys", "math", "binascii", "array",
    "io", "string", "itertools", "base64",
    # Pure data transforms — no filesystem, network or process surface.
    # `json` matters for JSON parsers, `zlib` for the many container formats
    # that embed deflate streams, `hashlib` for the checksums they carry.
    "json", "zlib", "hashlib",
}
_SCRIPT_FORBIDDEN_CALLS = {
    "eval", "exec", "__import__", "compile",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
}


def _render_system_prompt() -> str:
    """Fill the allowed-import list in from the whitelist, so the prompt can
    never promise something the sandbox will then reject. A plain replace —
    the prompt contains literal JSON braces, so str.format is out."""
    return _SYSTEM_PROMPT.replace(
        "{allowed_imports}", ", ".join(sorted(_SCRIPT_ALLOWED_IMPORTS))
    )


def _script_ast_is_safe(script: str) -> tuple[bool, str]:
    """Structurally validate a generator script: only whitelisted imports, no
    dunder-attribute access (blocks ``().__class__.__bases__`` escapes), no
    eval/exec/getattr-style calls. Defence-in-depth over the regex blacklist."""
    try:
        tree = ast.parse(script)
    except (SyntaxError, ValueError) as exc:
        return False, f"unparseable script: {exc}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in _SCRIPT_ALLOWED_IMPORTS:
                    return False, f"import not allowed: {a.name}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in _SCRIPT_ALLOWED_IMPORTS:
                return False, f"import-from not allowed: {node.module}"
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                return False, f"dunder attribute access: {node.attr}"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _SCRIPT_FORBIDDEN_CALLS:
                return False, f"forbidden call: {node.func.id}"
    return True, ""


def _seedgen_child_env() -> dict[str, str]:
    """Minimal environment for running a generator script — strips the parent's
    secrets (LLM API keys etc.) so a malicious script can't read/exfiltrate them."""
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
            "LANG", "LC_ALL", "PYTHONPATH", "HOME")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _validate_script(script: str) -> tuple[bool, str]:
    if len(script) < 80:
        return False, f"script too short ({len(script)} chars)"
    if "sys.argv" not in script:
        return False, "script does not consume sys.argv (rng_seed missing)"
    if "random.seed" not in script and "random.Random(" not in script:
        return False, "script does not seed RNG — would produce identical output every call"
    for pat in _FORBIDDEN_PATTERNS:
        if re.search(pat, script):
            return False, f"forbidden pattern matched: {pat}"
    ok, reason = _script_ast_is_safe(script)
    if not ok:
        return False, reason
    return True, ""


def _smoke_test_script(script: str, log: logging.Logger | None = None) -> tuple[bool, str]:
    """Invoke the script once with a known seed and verify it produces output.

    Catches runtime bugs the static validator can't see (e.g. an LLM that
    packs a 28-bit dim into a 16-bit struct field — fails with struct.error
    on every invocation, all 200 produce_seeds attempts wasted).

    Returns (ok, reason). Soft test: a single timeout or random crash is
    not enough to reject; we only reject when the script reliably fails.
    """
    with tempfile.TemporaryDirectory(prefix="nemesis_seedgen_smoke_") as workdir:
        wp = Path(workdir)
        script_path = wp / "gen.py"
        script_path.write_text(script, encoding="utf-8")
        out_path = wp / "out.bin"
        # Try TWO different seeds — covers more code paths in the script
        # and lets us distinguish "script is broken" from "this one seed
        # hits an unlucky branch".
        produced = 0
        last_stderr = ""
        for seed in (0xC0DEBABE, 0xDEADBEEF):
            try:
                proc = subprocess.run(
                    [sys.executable, str(script_path),
                     str(out_path), str(seed)],
                    capture_output=True, timeout=10, cwd=str(wp),
                    env=_seedgen_child_env(),
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                last_stderr = f"timeout/spawn: {exc}"
                continue
            if proc.returncode != 0:
                last_stderr = (proc.stderr or b"").decode(
                    "utf-8", errors="replace")[-400:]
                continue
            try:
                if out_path.is_file() and out_path.stat().st_size > 0:
                    produced += 1
            except OSError:
                pass
            # Reset for next attempt
            import contextlib
            with contextlib.suppress(OSError):
                out_path.unlink()
    if produced == 0:
        return False, f"smoke test: 0/2 invocations produced output. last stderr: {last_stderr}"
    return True, ""


def synthesize_generator_script(
    library_name: str,
    target_func: str,
    harness_source: str,
    cve_records: list[dict],
    format_spec: str,
    client: LLMClient,
    log: logging.Logger | None = None,
) -> str:
    """Ask the LLM for a Python generator script. Returns "" on any failure."""
    from nemesis.neural import ModelRole

    prompt = _build_user_prompt(
        library_name=library_name,
        target_func=target_func,
        harness_source=harness_source,
        cve_records=cve_records,
        format_spec=format_spec,
    )
    try:
        response = client.complete(
            prompt=prompt,
            system=_render_system_prompt(),
            stage="seedgen.synth",
            target_func=target_func or library_name,
            role=ModelRole.ARCHITECT,
        )
    except Exception as exc:
        if log:
            log.warning("seedgen.llm_failed", error=str(exc))
        return ""

    script = _extract_script(response or "")
    ok, reason = _validate_script(script)
    if not ok:
        if log:
            log.warning("seedgen.script_rejected", reason=reason,
                        excerpt=script[:300])
        return ""

    # Smoke test — catches runtime bugs the static validator misses
    # (e.g. struct.pack overflow, division by zero on certain seeds,
    # missing imports). Without this, an LLM math error costs 200×
    # subprocess invocations producing nothing.
    smoke_ok, smoke_reason = _smoke_test_script(script, log=log)
    if not smoke_ok:
        if log:
            log.warning("seedgen.smoke_failed",
                        reason=smoke_reason, excerpt=script[:300])
        return ""

    if log:
        log.info("seedgen.script_synthesised", length=len(script))
    return script


def produce_seeds(
    script_source: str,
    out_dir: Path,
    n_seeds: int = 200,
    rng_seed_base: int = 0xC0DE_BABE,
    per_seed_timeout_s: float = 5.0,
    max_seed_bytes: int = 65536,
    log: logging.Logger | None = None,
) -> int:
    """Run the generator script N times and copy unique non-empty seeds.

    Returns the number of distinct seeds written into out_dir. The
    caller is expected to feed out_dir into AFL's `-i` flag (or merge
    it with an existing seeds dir).
    """
    if not script_source:
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    next_index = 0
    attempted = 0
    failures = 0

    with tempfile.TemporaryDirectory(prefix="nemesis_seedgen_") as workdir:
        workdir_p = Path(workdir)
        script_path = workdir_p / "gen.py"
        script_path.write_text(script_source, encoding="utf-8")

        seed_buf_dir = workdir_p / "out"
        seed_buf_dir.mkdir()

        for i in range(n_seeds):
            attempted += 1
            rng_seed = rng_seed_base + i * 1009  # spread across RNG state space
            buf_path = seed_buf_dir / f"raw_{i:04d}.bin"
            try:
                proc = subprocess.run(
                    [sys.executable, str(script_path), str(buf_path), str(rng_seed)],
                    capture_output=True,
                    timeout=per_seed_timeout_s,
                    cwd=str(workdir_p),
                    env=_seedgen_child_env(),
                )
            except (subprocess.TimeoutExpired, OSError):
                failures += 1
                continue
            if proc.returncode != 0:
                failures += 1
                continue
            if not buf_path.is_file():
                failures += 1
                continue
            try:
                data = buf_path.read_bytes()
            except OSError:
                failures += 1
                continue
            if not data or len(data) > max_seed_bytes:
                continue

            digest = hashlib.sha256(data).hexdigest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)

            dest = out_dir / f"seedgen_{next_index:04d}_{digest[:12]}.bin"
            try:
                shutil.copyfile(buf_path, dest)
                next_index += 1
            except OSError:
                pass

    if log:
        log.info(
            "seedgen.produced",
            attempted=attempted,
            unique=next_index,
            failures=failures,
        )
    return next_index
