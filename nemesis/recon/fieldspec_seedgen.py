"""Structured field-spec seed generation (robust alternative to freeform scripts).

Why
---
The SeedMind-style `seedgen` asks the LLM for a *freeform Python generator
script*. That is powerful but fragile: the model sometimes packs a 28-bit value
into a 16-bit struct field, forgets to seed the RNG, or imports a missing
module — every such bug wastes the whole produce wave (hence seedgen's smoke
test). This module trades expressiveness for reliability: the LLM emits a
declarative JSON *field spec* (a list of typed fields), and a small, total,
deterministic interpreter here turns it into bytes. There is no LLM-authored
code to crash — the worst a bad spec can do is produce a slightly-off seed,
which AFL tolerates.

Used as a FALLBACK: when the freeform script is rejected or smoke-fails,
`seedgen` asks for a field spec instead. The interpreter is pure and fully
unit-tested; the LLM call mirrors the existing seedgen synthesis path.

Field spec grammar (JSON: {"fields": [ ... ]})
----------------------------------------------
  {"kind": "const", "hex": "504b0304"}                  literal magic bytes
  {"kind": "int", "size": 4, "endian": "le",
       "min": 0, "max": 1000}                            random int in [min,max]
  {"kind": "int", "size": 2, "endian": "be",
       "values": [0, 1, 65535]}                          pick one of values
  {"kind": "bytes", "name": "payload",
       "min": 0, "max": 64, "fill": "random"}            payload region
  {"kind": "len", "size": 4, "endian": "le",
       "of": "payload", "adjust": 0}                     length of a named region
"""

from __future__ import annotations

import json
import random
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging

    from nemesis.neural import LLMClient


def _as_int(v, default: int = 0) -> int:
    try:
        if isinstance(v, str):
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        return int(v)
    except (TypeError, ValueError):
        return default


def _pack_int(value: int, size: int, endian: str) -> bytes:
    size = max(1, min(8, int(size)))
    order = "big" if str(endian).lower().startswith("b") else "little"
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, order)


def build_from_fieldspec(fields: list[dict], rng: random.Random) -> bytes:
    """Deterministically render a field list into bytes. Total — never raises.

    Unknown field kinds are skipped. `len` fields are resolved in a second pass
    against the byte length of the region produced by the named `bytes` field.
    """
    out = bytearray()
    region_len: dict[str, int] = {}
    # (offset_in_out, size, endian, of_name, adjust)
    len_patches: list[tuple[int, int, str, str, int]] = []

    for f in fields or []:
        if not isinstance(f, dict):
            continue
        kind = str(f.get("kind", "")).lower()
        if kind == "const":
            hexs = re.sub(r"[^0-9a-fA-F]", "", str(f.get("hex", "")))
            if len(hexs) % 2:
                hexs = hexs[:-1]
            try:
                out += bytes.fromhex(hexs)
            except ValueError:
                pass
        elif kind == "int":
            size = _as_int(f.get("size", 1), 1)
            endian = f.get("endian", "le")
            values = f.get("values")
            if isinstance(values, list) and values:
                val = _as_int(rng.choice(values))
            else:
                lo, hi = _as_int(f.get("min", 0)), _as_int(f.get("max", 255))
                if hi < lo:
                    lo, hi = hi, lo
                val = rng.randint(lo, hi)
            out += _pack_int(val, size, endian)
        elif kind == "bytes":
            lo, hi = _as_int(f.get("min", 0)), _as_int(f.get("max", 32))
            if hi < lo:
                lo, hi = hi, lo
            hi = min(hi, 1 << 16)  # keep seeds small
            n = rng.randint(lo, hi)
            fill = str(f.get("fill", "random")).lower()
            if fill == "zero":
                chunk = bytes(n)
            elif fill == "ascii":
                chunk = bytes(rng.randint(0x20, 0x7e) for _ in range(n))
            else:
                chunk = bytes(rng.randrange(256) for _ in range(n))
            name = f.get("name")
            if name:
                region_len[str(name)] = n
            out += chunk
        elif kind == "len":
            size = _as_int(f.get("size", 4), 4)
            endian = f.get("endian", "le")
            of = str(f.get("of", ""))
            adjust = _as_int(f.get("adjust", 0))
            len_patches.append((len(out), size, str(endian), of, adjust))
            out += bytes(size)  # placeholder, patched below
        # unknown kind → skip

    for off, size, endian, of, adjust in len_patches:
        length = region_len.get(of, 0) + adjust
        out[off:off + size] = _pack_int(max(0, length), size, endian)

    return bytes(out)


def validate_fieldspec(spec: dict) -> tuple[bool, str]:
    if not isinstance(spec, dict):
        return False, "spec is not an object"
    fields = spec.get("fields")
    if not isinstance(fields, list) or not fields:
        return False, "spec.fields missing or empty"
    valid_kinds = {"const", "int", "bytes", "len"}
    if not any(str(f.get("kind", "")).lower() in valid_kinds
               for f in fields if isinstance(f, dict)):
        return False, "no recognised field kinds"
    return True, ""


def _extract_json(raw: str) -> dict:
    text = (raw or "").strip()
    if text.startswith("```"):
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1:]
        if text.endswith("```"):
            text = text[:-3]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return {}
    return {}


_SYSTEM = """\
You emit a JSON field specification describing the byte layout of ONE valid
input file for a parser fuzzing harness. A deterministic interpreter renders it
to bytes — you write NO code, only the spec.

Output STRICT JSON: {"fields": [ ... ]} with field objects:
  {"kind":"const","hex":"504b0304"}                 literal magic / fixed bytes
  {"kind":"int","size":N,"endian":"le|be","min":a,"max":b}   varied integer
  {"kind":"int","size":N,"endian":"le|be","values":[...]}    integer from a set
  {"kind":"bytes","name":"payload","min":a,"max":b,"fill":"random|zero|ascii"}
  {"kind":"len","size":N,"endian":"le|be","of":"payload","adjust":0}

Rules:
* Begin with the format's magic bytes as a const field.
* Order fields in true file order; a `len` must precede the `bytes` region it
  measures only if the format puts the length first (most do) — the interpreter
  back-patches either way.
* Bias int ranges toward edge values that exercise deep decoder paths.
* OUTPUT ONLY THE JSON OBJECT. No markdown, no prose.
"""


def synthesize_fieldspec(
    library_name: str,
    target_func: str,
    format_spec: str,
    cve_records: list[dict],
    client: LLMClient,
    log: logging.Logger | None = None,
) -> dict:
    """Ask the LLM for a field spec. Returns {} on any failure."""
    from nemesis.neural import ModelRole

    parts = [f"Library: {library_name}", f"Target decoder: {target_func or '(none)'}"]
    if format_spec:
        parts += ["", "Format spec (drive the field layout from this):", "```",
                  format_spec[:3000], "```"]
    if cve_records:
        parts += ["", "Recent CVEs — bias fields toward these triggers:"]
        parts += [f"  {r.get('id','?')}: {r.get('description','')[:240]}" for r in cve_records[:3]]
    parts += ["", f"Emit the JSON field spec for one valid {library_name} input."]
    prompt = "\n".join(parts)

    try:
        resp = client.complete(
            prompt=prompt, system=_SYSTEM, stage="fieldspec.synth",
            target_func=target_func or library_name, role=ModelRole.ARCHITECT,
        )
    except Exception as exc:  # noqa: BLE001
        if log:
            log.warning("fieldspec.llm_failed", error=str(exc))
        return {}
    spec = _extract_json(resp or "")
    ok, reason = validate_fieldspec(spec)
    if not ok:
        if log:
            log.warning("fieldspec.rejected", reason=reason)
        return {}
    if log:
        log.info("fieldspec.synthesised", fields=len(spec.get("fields", [])))
    return spec


def produce_seeds_from_spec(
    spec: dict,
    out_dir,
    n_seeds: int = 100,
    rng_seed_base: int = 0xF1E1D5,
    log: logging.Logger | None = None,
) -> int:
    """Render `n_seeds` unique seeds from a validated spec into out_dir."""
    import hashlib
    from pathlib import Path

    out_dir = Path(out_dir)
    fields = spec.get("fields", []) if isinstance(spec, dict) else []
    if not fields:
        return 0
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    written = 0
    for i in range(n_seeds):
        rng = random.Random(rng_seed_base + i * 7919)
        data = build_from_fieldspec(fields, rng)
        if not data:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        try:
            (out_dir / f"fieldspec_{written:04d}_{digest[:12]}.bin").write_bytes(data)
            written += 1
        except OSError:
            pass
    if log:
        log.info("fieldspec.produced", unique=written, requested=n_seeds)
    return written
