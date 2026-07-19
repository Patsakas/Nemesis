"""Auto-synthesize a per-library format-spec snippet during onboarding.

Background
----------
The first generation of `format_specs.py` shipped four hardcoded entries
(libpng, libtiff, lz4, libwebp). That violates the project rule that all
library-specific knowledge belongs in config, not code, and prevents
NEMESIS from generalising to a new library without a code edit.

This module replaces that hardcoding with an LLM-synthesised snippet
generated once at onboarding time and cached at
`config/targets/<lib>/format_spec.txt`. At fuzz time,
`format_specs.get_format_spec()` reads the cache file first and falls
back to the legacy `_SPECS` dict only when no cached entry exists (so
already-validated libraries keep working without re-onboarding).

Design choices
--------------
* The synthesiser is shown the existing PNG entry as a STYLE TEMPLATE,
  not as content. The LLM must produce an analogous structure (file
  layout / vulnerable surface / mutator strategy) for the new library.
* Bug-class hints with specific CVE numbers are deliberately EXCLUDED.
  Those come from a separate bug_history block fetched from NVD at fuzz
  time (Tier 1 #1 in the integration plan). This keeps the format_spec
  purely descriptive — one snippet per library, reusable across CVEs.
* Sample seed bytes (first 256 bytes hex) are included when available;
  they help the LLM ground its description in the actual on-wire layout.
* The synthesiser reuses the ONBOARDER role so it shares the model
  configuration, cost accounting, and cache scheme of the existing
  onboard step.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid circular import at runtime
    from nemesis.neural import LLMClient


_STYLE_TEMPLATE_PNG = """\
PNG file format (informally: "chunked, CRC-armoured")

File layout:
  signature: \\x89 P N G \\r \\n \\x1A \\n   (8 bytes, fixed)
  followed by chunks:
    chunk ::= <4-byte BE length>
              <4-byte type tag (ASCII, e.g. "IHDR" "IDAT" "IEND")>
              <length bytes of data>
              <4-byte BE CRC32 over (type + data)>

The first chunk MUST be IHDR (13 bytes of data):
  width            (4 bytes BE)
  height           (4 bytes BE)
  bit_depth        (1 byte)
  color_type       (1 byte: 0/2/3/4/6 for gray/rgb/palette/gray+a/rgba)
  compression_type (1 byte, must be 0)
  filter_type      (1 byte, must be 0)
  interlace_type   (1 byte: 0 = none, 1 = Adam7)

Mutator strategy:
  - keep signature + IHDR framing intact
  - target IHDR width/height with overflow-prone values
  - flip color_type, bit_depth, interlace bytes through their valid
    enumeration plus a few invalid edges
  - DO recompute the IHDR CRC32 after each mutation — the chunk-length
    check only fires after the chunk is accepted, which requires CRC
    validity

PER-MUTATION COST: keep each mutation tiny — at most ~16 bytes of write.
AFL's havoc/cmplog will compose larger runs across iterations.
"""


_SYSTEM_PROMPT = """\
You are a fuzzing engineer producing a compact format-spec snippet for a C
library. The snippet will be injected into a sibling LLM's prompt for
synthesising an AFL custom mutator, so it must describe the format
concretely enough that the mutator can decide WHICH bytes carry encoding
decisions and WHICH ones are framing.

Output STRICT JSON with one field:

  {"format_spec": "<plain-text spec, 30-80 lines, with literal \\n line breaks>"}

The "format_spec" value MUST contain:
  1. Top-level file/wire layout (header bytes, chunks, sections, with
     concrete byte counts and types).
  2. The structurally meaningful fields (length prefixes, type tags,
     count fields, tile/dimension fields, etc.). Be explicit about
     byte/bit boundaries when the format is bit-packed.
  3. A "Mutator strategy" section with concrete byte-level targeting
     hints (which fields to flip, which structural invariants the
     mutator must preserve, whether per-chunk checksums must be
     recomputed).
  4. A final line: "PER-MUTATION COST: keep each mutation tiny — at
     most ~16 bytes of write. AFL's havoc/cmplog will compose larger
     runs across iterations."

The "format_spec" value MUST NOT contain:
  - CVE numbers or CVE-specific bug-class hints. (CVE knowledge is
    injected separately at fuzz time.)
  - C, Python, or other source code (descriptive prose only).
  - History, marketing, or generic prose unrelated to byte layout.

If you do not know the format from training data, return
  {"format_spec": "UNKNOWN: <one-line reason>"}
and nothing else. Do not invent fields.

OUTPUT ONLY THE JSON OBJECT. NO MARKDOWN FENCES. NO PROSE BEFORE OR AFTER.
"""


def _build_user_prompt(
    library_name: str,
    headers_content: str,
    sample_seed_hex: str = "",
) -> str:
    parts: list[str] = [
        f"Library: {library_name}",
        "",
        "Reference style example (PNG) — produce the same SHAPE for the target library:",
        "",
        _STYLE_TEMPLATE_PNG,
        "",
        f"Now write the analogous format-spec snippet for `{library_name}`.",
        "",
        "Public API headers (truncated to 8 KB):",
        headers_content[:8000],
    ]
    if sample_seed_hex:
        parts += [
            "",
            f"Sample input file (first {len(sample_seed_hex) // 2} bytes, hex):",
            sample_seed_hex,
        ]
    return "\n".join(parts)


def _extract_format_spec(raw_response: str) -> str:
    """Pull the `format_spec` field out of the LLM's JSON envelope.

    Tolerates: surrounding markdown fences, leading prose, trailing prose,
    and the occasional self-corrective JSON-error envelope Mistral-medium
    emits when its training nudges it toward JSON despite plain-text
    instructions.
    """
    import json
    import re as _re

    if not raw_response:
        return ""
    text = raw_response.strip()

    # Strip ```json ... ``` fences if present
    if text.startswith("```"):
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    # Try direct JSON parse first
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # Greedy extract of the outermost {...} block
        m = _re.search(r"\{.*\}", text, _re.DOTALL)
        if not m:
            return ""
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return ""

    if not isinstance(obj, dict):
        return ""
    spec = obj.get("format_spec", "")
    if not isinstance(spec, str):
        return ""
    return spec.strip()


def _validate(text: str) -> tuple[bool, str]:
    """Return (ok, reason). Reject obvious garbage; warn-but-accept otherwise."""
    if not text or len(text) < 200:
        return False, f"too short ({len(text)} chars)"
    if text.lower().startswith("unknown:"):
        return False, "LLM signalled UNKNOWN format"
    return True, ""


def synthesize_format_spec(
    library_name: str,
    headers_content: str,
    client: LLMClient,
    sample_seed_path: Path | None = None,
    log=None,
) -> str:
    """Synthesise a format-spec snippet for `library_name`.

    Returns the snippet on success, or "" when synthesis failed (caller
    should treat empty as "no spec available" and fall through to the
    LLM's training-data recall in mutator_synthesis).
    """
    sample_hex = ""
    if sample_seed_path is not None and sample_seed_path.is_file():
        try:
            data = sample_seed_path.read_bytes()[:256]
            sample_hex = data.hex()
        except OSError as exc:
            if log:
                log.warning(
                    "format_spec.sample_read_failed", path=str(sample_seed_path), error=str(exc)
                )

    prompt = _build_user_prompt(library_name, headers_content, sample_hex)

    try:
        from nemesis.models import ModelRole  # local import to avoid cycles
    except ImportError:
        from nemesis.neural import ModelRole  # type: ignore

    try:
        response = client.complete(
            prompt=prompt,
            system=_SYSTEM_PROMPT,
            stage="onboard.format_spec",
            target_func=library_name,
            role=ModelRole.ONBOARDER,
        )
    except Exception as exc:
        if log:
            log.warning("format_spec.llm_failed", error=str(exc))
        return ""

    text = _extract_format_spec(response or "")
    ok, reason = _validate(text)
    if not ok:
        if log:
            log.warning("format_spec.rejected", reason=reason, excerpt=text[:200])
        return ""

    if log:
        log.info("format_spec.synthesised", library=library_name, length=len(text))
    return text


def cache_path_for(library_name: str, targets_dir: Path) -> Path:
    """Resolve the on-disk cache path for a library's format spec."""
    return targets_dir / library_name / "format_spec.txt"


def write_cached(library_name: str, spec_text: str, targets_dir: Path) -> Path:
    """Persist `spec_text` under `<targets_dir>/<library_name>/format_spec.txt`."""
    out_path = cache_path_for(library_name, targets_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(spec_text, encoding="utf-8")
    return out_path


def read_cached(library_name: str, targets_dir: Path) -> str:
    """Return the cached snippet for `library_name`, or "" when absent."""
    p = cache_path_for(library_name, targets_dir)
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
