"""LLM-driven AFL custom-mutator adapter synthesis.

Background
----------
The PNG benchmark (CVE-2018-13785) was rediscovered by NEMESIS in 9 seconds —
critically because we had a hand-written PNG mutator adapter that knows about
chunked layout, CRC32 armour, and "interesting" IHDR width values.

Three other narrow-trigger benchmarks (libwebp Huffman, libtiff custom-tag,
lz4 literal-length) failed to reach the CVE because vanilla AFL byte-flips
cannot synthesise the specific structural patterns required.

Hand-writing one adapter per library does not scale. This module asks the
architect LLM to synthesise an adapter from:
  - The format-agnostic mutator scaffold contract (mutator_scaffold.h)
  - The PNG adapter as a few-shot example
  - Format hints derived from the YAML target config (magic_bytes, public API)
  - The pinned target function source (highlights what fields/lengths matter)

Pipeline contract
-----------------
`synthesize_and_compile_adapter(config, llm_client, log)` returns a path to a
compiled `.so` ready to be set as `AFL_CUSTOM_MUTATOR_LIBRARY`, or `None` on
any failure (synthesis returns invalid C, compile fails, smoke test fails).

`smoke_test_adapter(so_path, sample_seed)` verifies the adapter's `afl_custom_init`
and `afl_custom_fuzz` symbols exist and that one mutation round produces output
of plausible size — a cheap guard against the LLM returning a trivially broken
.so that would freeze AFL.

The fall-back behaviour is the existing one (no custom mutator → vanilla AFL),
so a synthesis failure never regresses the pipeline.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

SCAFFOLD_REL = Path("nemesis/templates/mutator/mutator_scaffold.h")
BITSTREAM_REL = Path("nemesis/templates/mutator/mutator_bitstream.h")
PNG_REF_REL = Path("nemesis/templates/mutator/adapters/png.c")
ADAPTER_DIR_REL = Path("nemesis/templates/mutator/adapters")


_SYNTH_SYSTEM = """\
You are a fuzzing engineer who designs AFL++ custom-mutator adapters for
structured binary file formats. You write C99 code that compiles cleanly with
`clang -shared -fPIC -O2`, depends only on libc, and integrates with the
NEMESIS mutator scaffold (header included).

FUZZING-EFFICIENCY RULES (non-negotiable):
1. Mutations must be CHEAP. Each call to `nm_adapter_apply_targeted` should
   modify at most 64 bytes — never write hundreds or thousands of bytes in
   a single mutation. AFL needs ~10000 executions per second; a mutation
   that grows the buffer by 65535 bytes drops the throughput by 1000×
   and the fuzzer never converges.
2. Never write a `for (i=0; i<N; i++) buf[off+i] = 0xFF;` loop with
   N >= 256. Cap any inner-loop write at 32 bytes. AFL's havoc step will
   compound short runs across iterations to organically reach longer
   sequences when those produce coverage gains.
3. When a spec mentions "trigger requires sums to reach 4 GiB" or similar,
   that does NOT mean YOUR mutation has to write 4 GiB. Write a few
   short 0xFF runs and trust AFL+cmplog to amplify when productive.
4. Keep parsing bounded: any while loop in `nm_adapter_parse` must have
   an explicit max-iteration cap (e.g. NM_MAX_CHUNKS) and explicit
   off+N <= size guards.

OUTPUT FORMAT:
Your output is ONLY a single self-contained .c file — no markdown, no
explanation, no triple-backtick fences. Begin with the scaffold include and
end with the closing brace of the last hook function.
"""


_SYNTH_USER_TEMPLATE = """\
Generate a custom mutator adapter for the **{library}** library, format
**{format_name}**.

Hooks to implement (signatures fixed by the scaffold):
  static int  nm_adapter_has_signature(const uint8_t *buf, size_t size);
  static int  nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out);
  static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk);
  static int  nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size,
                                        nm_chunk_t *chunks, int n,
                                        uint32_t *rng);

Format hints (from YAML target config):
{format_hints}

Pinned target function:
  {target_func} at {target_file}

Bug class hint: {bug_class_hint}

{format_spec_block}

{bug_history_block}

{bit_cursor_block}

REQUIREMENTS
1. Begin with `#include "../mutator_scaffold.h"` (header path is fixed —
   the file lives at `adapters/<library>.c`, the scaffold one directory up).
   For bit-packed formats (VP8L Huffman, deflate, FLAC, JPEG arithmetic,
   ...) ALSO `#include "../mutator_bitstream.h"` and use its bit-cursor
   helpers in `nm_adapter_apply_targeted` to mutate at sub-byte
   granularity. Byte-aligned formats (PNG/RIFF/TIFF/LZ4) ignore it.
2. Implement EXACTLY the four `static` hooks above. Do NOT define
   `afl_custom_init`, `afl_custom_fuzz`, or `afl_custom_deinit` — those live
   in the scaffold.
3. `nm_adapter_apply_targeted` must mutate the structurally-meaningful fields
   for this format with edge values that exercise the bug class above.
   Examples (analogous to PNG width=0x55555555 for CVE-2018-13785):
     • Length/size fields: 0, 1, INT_MAX, UINT_MAX, UINT_MAX-1,
       0xFFFFFFFF/N for N in {{2,3,4,6,8}} (math-derived overflow values)
     • Type/tag/opcode bytes: full enumeration of the codec's defined values,
       plus 0xFF, 0x00, and one byte past the highest valid token
     • Encoded-length prefixes (tokens that themselves encode a length): try
       both minimum and maximum encodings of the same logical length
4. `nm_adapter_fix_integrity` recomputes whatever checksum the format uses
   AFTER the mutation. PNG uses CRC32-zlib. Use the helpers in the scaffold
   (`nm_crc32_init`, `nm_crc32`) where applicable. If the format has no
   per-chunk checksum, leave the function as a no-op (return immediately).
5. `nm_adapter_parse` walks the structure into `nm_chunk_t` entries. Set
   `data_off`, `data_len`, and (when present) `integrity_off` /
   `integrity_len`. `kind` is an adapter-defined tag for downstream hooks.
6. Use the byte-order helpers from the scaffold — do NOT include any
   library-specific headers and do NOT hand-roll your own shift/mask reads.
   Available for every width: `nm_read_be16`/`nm_read_le16`,
   `nm_read_be32`/`nm_read_le32`, `nm_read_be64`/`nm_read_le64` and the
   matching `nm_write_*`. Pick the width that matches the field (wavpack
   block fields are 16-bit LE; bigtiff offsets are 64-bit). Do NOT redefine
   `nm_chunk_t`, `NM_MAX_CHUNKS`, or any other scaffold type/macro — they are
   already declared by the `#include` and a redefinition is a hard compile
   error ("typedef redefinition with different types"). Use them as-is.
7. Cap any internal loop or chunk count to defensive maxima (e.g. 16 MiB
   per chunk, 64 chunks total) so a malformed input does not livelock.
8. The file must compile cleanly under `-Wall -Wextra` — no implicit
   declarations, no unused parameters without `(void)x;`.

Reference adapter (PNG, hand-written, has been validated):

<scaffold_h path="../mutator_scaffold.h">
{scaffold_h}
</scaffold_h>

<png_reference path="adapters/png.c">
{png_reference}
</png_reference>

Output: the complete .c file for `adapters/{library_lower}.c`, NO markdown.
"""


@dataclass
class _SynthInputs:
    library: str
    library_lower: str
    format_name: str
    format_hints: str
    target_func: str
    target_file: str
    bug_class_hint: str


def _strip_code_fences(text: str) -> str:
    """LLMs occasionally return ```c ... ``` despite instructions. Strip safely."""
    text = text.strip()
    fence = re.match(r"^```(?:c|cpp)?\s*\n(.*)\n```\s*$", text, re.DOTALL)
    if fence:
        return fence.group(1)
    # Also handle un-closed leading fence
    if text.startswith("```"):
        first_nl = text.find("\n")
        if first_nl >= 0:
            text = text[first_nl + 1 :]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _build_format_hints(config) -> tuple[str, str, str]:
    """Return (format_name, hints_block, bug_class_hint).

    Walks the YAML target config and renders structural data the LLM needs:
      - Magic bytes (used by has_signature)
      - Public API function names that hit the parser (parse/decode entry points)
      - Bug-class hint derived from pinned-func metadata (memory ops / pointer arith
        flags) when explicit metadata is missing.
    """
    target = config.target
    fuzzing = config.fuzzing  # noqa: F841 (reserved for future use)

    magic = getattr(target, "magic_bytes", {}) or {}
    format_name = next(iter(magic), "binary")

    lines: list[str] = []
    if magic:
        lines.append("Magic byte signatures (decode-time hints):")
        for fmt_label, patterns in magic.items():
            for p in patterns:
                lines.append(f"  - format={fmt_label!r} prefix={p!r}")

    bonus = getattr(target, "recon_scoring", None)
    if bonus and getattr(bonus, "bonus_func_patterns", None):
        lines.append("Public API substrings worth inspecting:")
        for pat in list(bonus.bonus_func_patterns)[:15]:
            lines.append(f"  - {pat}")

    pinned = list(getattr(target, "pinned_funcs", []) or [])
    bug_class = "integer overflow in size/length computation"  # default heuristic
    if pinned:
        pf = pinned[0]
        # Fix 148: detect recursion by reading the pinned function's source
        # and checking for a self-call in its body. This is the same signal
        # the bug_class classifier uses; doing it here keeps the mutator
        # synthesis prompt independent of the neural pipeline cache.
        is_recursive = False
        try:
            import os
            import re as _re_rec
            from pathlib import Path as _Path_rec
            src_root = _Path_rec(
                os.path.expandvars(target.source_root)
            ).expanduser()
            file_rel = pf.file_path
            if file_rel:
                fp = src_root / file_rel
                if fp.exists():
                    text = fp.read_text(errors="replace")
                    self_call_re = _re_rec.compile(
                        r"\b" + _re_rec.escape(pf.func_name) + r"\s*\(",
                    )
                    n = len(self_call_re.findall(text))
                    # >=3 occurrences = forward decl + definition line +
                    # at least one recursive call in body. Conservative.
                    is_recursive = n >= 3
        except Exception:
            is_recursive = False

        if is_recursive:
            bug_class = (
                "DEEP RECURSION / unbounded tree depth — "
                f"`{pf.func_name}` calls itself in its body. The "
                "trigger is an input whose structural NESTING DEPTH "
                "exceeds the stack budget. Vanilla AFL byte-flips and "
                "single-character inserts grow depth by ONE per "
                "mutation; that is too slow. The mutator MUST include "
                "an explicit depth-doubling operator: scan the input "
                "for the format's nesting tokens (parentheses for SGML/"
                "DTD content models, square brackets for JSON arrays, "
                "curly braces for objects, opening/closing tags for "
                "XML elements, ...) and INSERT one or two extra wrapper "
                "levels around an existing nested group on every call. "
                "After N invocations the depth grows like 2^N rather "
                "than N+1, so deeply-nested inputs that overflow stacks "
                "become reachable in minutes instead of hours."
            )
        elif getattr(pf, "has_pointer_arith", False) and getattr(pf, "has_memory_ops", False):
            bug_class = "integer overflow that propagates into a memcpy/memmove size"
        elif getattr(pf, "has_pointer_arith", False):
            bug_class = "out-of-bounds read/write driven by attacker-controlled offsets"

    return format_name, "\n".join(lines) if lines else "  (no structured hints)", bug_class


def _read_text(path: Path) -> str:
    return path.read_text(errors="replace")


def synthesize_adapter_source(
    config,
    llm_client,
    log,
    nemesis_root: Path,
) -> tuple[str, _SynthInputs] | None:
    """Ask the architect LLM to synthesise an adapter .c source.

    Returns (source_text, inputs) on success, or None on failure
    (no LLM provider available, empty response, source missing the required
    hooks, etc.). All failures are non-fatal — caller falls back to vanilla AFL.
    """
    scaffold_path = nemesis_root / SCAFFOLD_REL
    png_ref_path = nemesis_root / PNG_REF_REL
    if not scaffold_path.exists() or not png_ref_path.exists():
        log.warning("mutator_synthesis.template_missing", scaffold=str(scaffold_path), png_ref=str(png_ref_path))
        return None

    scaffold_h = _read_text(scaffold_path)
    png_reference = _read_text(png_ref_path)

    library = config.target.name or "unknown"
    # `removeprefix` strips the literal "lib" only (Python 3.9+); plain
    # `lstrip("lib")` would also delete any leading l/i/b chars from names like
    # "lz4" → "z4" — exactly the bug we hit on the first synthesis pass.
    _lower = library.lower()
    library_lower = _lower.removeprefix("lib") or _lower
    format_name, format_hints, bug_class_hint = _build_format_hints(config)

    pinned = list(getattr(config.target, "pinned_funcs", []) or [])
    if pinned:
        pf = pinned[0]
        target_func = pf.func_name
        target_file = pf.file_path
    else:
        target_func = "(no pinned function — generic adapter)"
        target_file = ""

    # Format-spec injection: pull a compact spec recap for the library
    # (lz4 token-stream, VP8L code lengths, PNG chunked-CRC, TIFF IFD).
    # The first synthesis iteration produced shape-correct adapters but
    # mutated bytes at structurally-meaningless offsets; the spec block
    # tells the LLM which bytes carry the encoding decisions for the
    # bug class.
    from nemesis.feature_flags import is_enabled as _fflag
    from nemesis.recon.format_specs import get_format_spec
    targets_dir = nemesis_root / "config" / "targets"
    if _fflag("format_spec"):
        format_spec = get_format_spec(library, targets_dir=targets_dir)
    else:
        format_spec = ""
        log.info("mutator_synthesis.format_spec_disabled")
    if format_spec:
        format_spec_block = (
            "<format_spec>\n"
            "Format reference (use this to choose which bytes to mutate "
            "in `nm_adapter_apply_targeted` and how to walk the structure "
            "in `nm_adapter_parse`):\n\n"
            f"{format_spec}\n"
            "</format_spec>"
        )
    else:
        format_spec_block = (
            "<format_spec>\n"
            "(No bundled spec for this library. Recall the format from your "
            "training data and use it to choose structurally-meaningful "
            "mutation targets — DO NOT mutate at fixed byte offsets like "
            "data_off+4; mutate at offsets that carry encoding decisions.)\n"
            "</format_spec>"
        )

    # Bug-history injection (Tier 1 #1, 2026-05-07): pull recent CVE
    # descriptions from NVD so the LLM biases mutations toward fields and
    # code paths that have been historically buggy. CPE-filtered to the
    # library's own product, so third-party CVEs that merely mention the
    # name don't pollute the prompt.
    from nemesis.feature_flags import is_enabled
    from nemesis.recon import cve_context as _cc

    if is_enabled("bug_history"):
        cve_records = _cc.get_or_fetch(
            library_name=library,
            targets_dir=targets_dir,
            max_cves=3,
            log=log,
        )
        bug_history_block = _cc.format_bug_history_block(cve_records)
    else:
        bug_history_block = ""
        log.info("mutator_synthesis.bug_history_disabled")
    if not bug_history_block:
        bug_history_block = (
            "<bug_history>\n"
            "(No CVE history available — NVD lookup failed or library has "
            "no public CVEs. Rely on the format spec and your own knowledge "
            "of common parser bug patterns.)\n"
            "</bug_history>"
        )

    # Tier 2 #4 (2026-05-07): bit-cursor scaffold for bit-packed formats.
    # The bitstream header is gated by `bit_cursor` so A/B comparisons can
    # measure its contribution. When disabled we still send a brief mention
    # in the prompt so the LLM doesn't go and reinvent its own bit cursor.
    bitstream_path = nemesis_root / BITSTREAM_REL
    if _fflag("bit_cursor") and bitstream_path.exists():
        bitstream_h = _read_text(bitstream_path)
        bit_cursor_block = (
            "<bit_cursor_helper path=\"../mutator_bitstream.h\">\n"
            "Bit-packed formats (VP8L, deflate, FLAC, ...) MUST use this "
            "header for sub-byte mutation. Include alongside the scaffold:\n"
            "    #include \"../mutator_bitstream.h\"\n\n"
            f"{bitstream_h}\n"
            "</bit_cursor_helper>"
        )
    else:
        bit_cursor_block = (
            "<bit_cursor_helper>\n"
            "(disabled — adapter must use byte-aligned mutations only)\n"
            "</bit_cursor_helper>"
        )

    prompt = _SYNTH_USER_TEMPLATE.format(
        library=library,
        library_lower=library_lower,
        format_name=format_name,
        format_hints=format_hints,
        target_func=target_func,
        target_file=target_file,
        bug_class_hint=bug_class_hint,
        format_spec_block=format_spec_block,
        bug_history_block=bug_history_block,
        bit_cursor_block=bit_cursor_block,
        scaffold_h=scaffold_h,
        png_reference=png_reference,
    )

    try:
        # Mutator synthesis routed to ARCHITECT (mistral-small-4-119b)
        # rather than DEFAULT. Reasons:
        #   - Format-aware mutator code needs nuanced understanding of
        #     bit-cursor patterns, format-spec details, and bug_history
        #     hints. Larger context window helps.
        #   - DEFAULT (groq/llama-3.3-70b) was raising 400 errors every
        #     run because the JSON-output enforcement at the provider
        #     level conflicts with this stage's plain-C output contract.
        #     ARCHITECT path (NVIDIA NIM) doesn't enforce response_format.
        from nemesis.neural import ModelRole
        response = llm_client.complete(
            prompt=prompt,
            system=_SYNTH_SYSTEM,
            stage="mutator_synthesis",
            target_func=target_func,
            role=ModelRole.ARCHITECT,
        )
    except Exception as exc:
        log.warning("mutator_synthesis.llm_call_failed", error=str(exc))
        return None

    source = _strip_code_fences(response or "")
    if not source:
        log.warning("mutator_synthesis.empty_response")
        return None

    # Sanity-check: the four hooks must be defined.
    required = (
        "nm_adapter_has_signature",
        "nm_adapter_parse",
        "nm_adapter_fix_integrity",
        "nm_adapter_apply_targeted",
    )
    missing = [h for h in required if f"{h}(" not in source]
    if missing:
        log.warning("mutator_synthesis.hooks_missing", missing=missing)
        return None

    inputs = _SynthInputs(
        library=library,
        library_lower=library_lower,
        format_name=format_name,
        format_hints=format_hints,
        target_func=target_func,
        target_file=target_file,
        bug_class_hint=bug_class_hint,
    )
    log.info(
        "mutator_synthesis.generated",
        library=library,
        format=format_name,
        chars=len(source),
    )
    return source, inputs


def compile_adapter(source_path: Path, so_path: Path, log) -> bool:
    """clang -shared -fPIC -O2 — same flags the pipeline uses for the
    hand-written PNG mutator. Plain `clang`, NOT `afl-clang-fast` (the .so
    is loaded by afl-fuzz itself, not by the target — instrumenting it
    abort()s on missing __afl_area_ptr at custom-mutator-load time).
    """
    # Fix 149 (2026-05-10): -Wall surfaces silent issues earlier (the bare
    # default level still hard-errors on implicit function declarations on
    # modern clang, which is exactly the snprintf trap we kept hitting; the
    # extra warnings just give better stderr context). NOT -Werror — we
    # don't want unused-variable warnings to fail an otherwise-correct .so.
    cmd = ["clang", "-shared", "-fPIC", "-O2", "-Wall", "-o", str(so_path), str(source_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("mutator_synthesis.compile_error", error=str(exc))
        return False
    if result.returncode != 0:
        log.warning(
            "mutator_synthesis.compile_failed",
            stderr=result.stderr[-400:],
        )
        return False
    log.info("mutator_synthesis.compile_ok", so=str(so_path), bytes=so_path.stat().st_size if so_path.exists() else 0)
    return True


def smoke_test_adapter(so_path: Path, log) -> bool:
    """Cheap dlopen-style sanity check: the .so must define the AFL custom-
    mutator hooks. Without these afl-fuzz prints the famous
    "undefined symbol: afl_custom_init" abort and our 15-min fuzz budget is
    burnt before a single test case is mutated.
    """
    try:
        result = subprocess.run(
            ["nm", "-D", str(so_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("mutator_synthesis.smoke_error", error=str(exc))
        return False
    if result.returncode != 0:
        return False
    needed = ("afl_custom_init", "afl_custom_fuzz", "afl_custom_deinit")
    missing = [s for s in needed if s not in result.stdout]
    if missing:
        log.warning("mutator_synthesis.smoke_symbols_missing", missing=missing)
        return False
    log.info("mutator_synthesis.smoke_ok", so=str(so_path))
    return True


def synthesize_and_compile_adapter(
    config,
    llm_client,
    log,
    nemesis_root: Path,
) -> Path | None:
    """Top-level entry: synthesise + compile + smoke-test. Returns path to
    the compiled .c source on success (set as `custom_mutator_source` in
    config.fuzzing), or None on any failure.
    """
    if not getattr(config.target, "magic_bytes", None):
        # No structured format → vanilla AFL is already the right choice.
        log.debug("mutator_synthesis.skipped_no_magic_bytes")
        return None

    out = synthesize_adapter_source(config, llm_client, log, nemesis_root)
    if out is None:
        return None
    source, inputs = out

    adapter_dir = nemesis_root / ADAPTER_DIR_REL
    adapter_dir.mkdir(parents=True, exist_ok=True)
    src_path = adapter_dir / f"{inputs.library_lower}_synth.c"
    so_path = adapter_dir / f"{inputs.library_lower}_synth.so"

    src_path.write_text(source)

    if not compile_adapter(src_path, so_path, log):
        # Keep the source for inspection but don't activate it.
        return None
    if not smoke_test_adapter(so_path, log):
        return None
    return src_path
