"""Z3-assisted ("light concolic") seed synthesis.

Background
----------
Some CVEs hide behind a narrow numeric gate that byte-level mutation rarely
hits in a 15-minute budget:

  * a magic field that must equal an exact constant
    (libtiff CVE-2022-22844: a custom-tag DE word == 0x0200);
  * a size computed by multiplying two attacker-controlled fields that must
    *overflow* 32 bits so an undersized buffer is allocated
    (libtiff CVE-2022-3970: width*height raster sizing).

AFL's RedQueen/CMPLOG already auto-solves simple `== CONST` comparisons, so the
real differentiator of a constraint solver is the *arithmetic* case: finding a
(width, height) pair that looks plausible yet wraps `width*height*bpp` past
2^32 into a small allocation. That is a textbook SMT problem.

What this module does
---------------------
1. `extract_constraints()` greps the pinned function body for equality /
   relational comparisons against integer constants.
2. `detect_mul_overflow_pairs()` finds `a * b` products that feed an allocation
   or size variable.
3. Z3 solves each interesting constraint for a concrete value (the overflow
   case is solved jointly for the two operands), respecting the bit-width of
   the InputSpec parameter the variable maps to.
4. `build_seeds()` writes the solved values into a *copy of a real seed* at the
   exact byte offsets the harness InputSpec assigns to those parameters — so
   the rest of the input stays structurally valid and only the gated field is
   driven to its trigger value.

Honest scope
------------
This only reaches constraints whose variable NAME matches an InputSpec
parameter (offset-known). Deep parser-internal fields the harness does not
model are out of reach without full taint/symbolic execution — those still
rely on CMPLOG + the round-trip/mutator stages. The arithmetic-overflow seeds
are the unique contribution here; plain `== CONST` placement merely guarantees
the constant lands at the right offset, which the dictionary cannot.

All failures are non-fatal: missing z3, no InputSpec, no mappable constraint →
0 seeds, caller falls back to the other sources.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from nemesis.models import PathConstraint

if TYPE_CHECKING:
    import logging
    from nemesis.models import HarnessSpec, InputParam, InputSpec


_INT = r"(0x[0-9a-fA-F]+|\d+)"
_EQ_RE = re.compile(rf"\b([A-Za-z_]\w*)\s*(==|!=|>=|<=|>|<)\s*{_INT}\b")
# `dst = a * b` or `malloc(a * b)` / `_TIFFmalloc(w * h * 4)` etc.
_MUL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)")
_ALLOC_HINT = ("malloc", "alloc", "calloc", "realloc", "size", "len", "count", "n_", "_n")


def _parse_int(tok: str) -> Optional[int]:
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except ValueError:
        return None


def slice_function_body(source: str, func_name: str) -> str:
    """Best-effort extraction of a function body by brace matching.

    Returns the whole source if the function definition cannot be located —
    constraint extraction is still useful file-wide, just noisier.
    """
    if not func_name:
        return source
    # Find `func_name(` not preceded by a member/'.'/'->' access.
    for m in re.finditer(re.escape(func_name) + r"\s*\(", source):
        # Walk forward to the opening brace of the body (skip the proto args).
        i = source.find(")", m.end() - 1)
        if i == -1:
            continue
        j = source.find("{", i)
        if j == -1 or (";" in source[i:j]):  # a prototype/declaration, not a def
            continue
        depth = 0
        for k in range(j, min(len(source), j + 200_000)):
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return source[j:k + 1]
    return source


def extract_constraints(func_source: str) -> list[PathConstraint]:
    """Extract equality/relational comparisons against integer constants."""
    out: list[PathConstraint] = []
    seen: set[tuple[str, str, str]] = set()
    for m in _EQ_RE.finditer(func_source or ""):
        var, op, val = m.group(1), m.group(2), m.group(3)
        if _parse_int(val) is None:
            continue
        key = (var, op, val)
        if key in seen:
            continue
        seen.add(key)
        out.append(PathConstraint(variable=var, operator=op, value=val, source="ast"))
    return out


def detect_mul_overflow_pairs(func_source: str) -> list[tuple[str, str]]:
    """Find `a * b` products that plausibly feed an allocation/size.

    Conservative: only returns a pair when an allocation/size hint appears on
    the same source line (keeps the false-positive rate low so we don't waste
    seeds solving overflows for unrelated arithmetic).
    """
    pairs: list[tuple[str, str]] = []
    seen: set[frozenset] = set()
    for line in (func_source or "").splitlines():
        low = line.lower()
        if not any(h in low for h in _ALLOC_HINT):
            continue
        for m in _MUL_RE.finditer(line):
            a, b = m.group(1), m.group(2)
            if a == b:
                continue
            key = frozenset((a, b))
            if key in seen:
                continue
            seen.add(key)
            pairs.append((a, b))
    return pairs


def solve_mul_overflow(
    bits_a: int = 32,
    bits_b: int = 32,
    bpp: int = 1,
    small_alloc_max: int = 4096,
) -> Optional[tuple[int, int]]:
    """Find (a, b), each >= 2, whose 32-bit product wraps to a small value.

    Models the classic under-allocation overflow: the logical size
    `a*b*bpp` exceeds 2^32 (so the real data is huge) but the truncated
    32-bit allocation size is < small_alloc_max (so the buffer is tiny). The
    decoder then writes huge data into the tiny buffer. Returns None if z3 is
    unavailable or the model is unsat.
    """
    try:
        from z3 import BitVec, BitVecVal, Solver, ZeroExt, UGT, ULT, sat
    except Exception:  # noqa: BLE001 — z3 optional
        return None

    a = BitVec("a", 32)
    b = BitVec("b", 32)
    s = Solver()
    # plausible-looking, non-trivial operands, each bounded by its field width
    s.add(UGT(a, 1), UGT(b, 1))
    if bits_a < 32:
        s.add(ULT(a, 1 << bits_a))
    if bits_b < 32:
        s.add(ULT(b, 1 << bits_b))
    # 64-bit true product to detect overflow without wrapping in the model
    a64, b64, bpp64 = ZeroExt(32, a), ZeroExt(32, b), BitVecVal(bpp, 64)
    true_size = a64 * b64 * bpp64
    s.add(UGT(true_size, BitVecVal(0xFFFFFFFF, 64)))          # logically huge
    wrapped = (a * b * BitVecVal(bpp, 32))                    # 32-bit truncation
    s.add(ULT(wrapped, BitVecVal(small_alloc_max, 32)))      # allocates tiny
    if s.check() != sat:
        return None
    mdl = s.model()
    return int(mdl[a].as_long()), int(mdl[b].as_long())


def solve_constraint_value(con: PathConstraint, bits: int) -> Optional[int]:
    """Solve a single comparison for a concrete in-range value of `bits` width."""
    target = _parse_int(con.value)
    if target is None:
        return None
    op = con.operator
    mask = (1 << bits) - 1
    if op == "==":
        v = target
    elif op == "!=":
        v = (target + 1) & mask
    elif op in (">", ">="):
        v = target + (1 if op == ">" else 0)
    elif op in ("<", "<="):
        v = target - (1 if op == "<" else 0)
    else:
        return None
    if v < 0 or v > mask:
        return None
    return v


def place_value(buf: bytearray, param: "InputParam", value: int, big_endian: bool = False) -> bool:
    """Write `value` into buf at the parameter's offset, sized by param.size."""
    size = max(1, min(4, int(getattr(param, "size", 1) or 1)))
    off = int(getattr(param, "offset", 0) or 0)
    if off < 0 or off + size > len(buf):
        return False
    order = "big" if big_endian else "little"
    try:
        buf[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, order)
    except (OverflowError, ValueError):
        return False
    return True


def _param_by_name(spec: "InputSpec", name: str) -> Optional["InputParam"]:
    for p in getattr(spec, "params", []) or []:
        if p.name and p.name.lower() == name.lower():
            return p
    return None


def build_seeds(
    base: bytes,
    spec: "InputSpec",
    constraints: list[PathConstraint],
    overflow_pairs: list[tuple[str, str]],
    log: "logging.Logger | None" = None,
) -> list[bytes]:
    """Produce seed variants by placing solved values at InputSpec offsets."""
    seeds: list[bytes] = []
    min_size = int(getattr(spec, "min_size", 1) or 1)
    base_buf = bytearray(base) if base else bytearray(max(min_size, 64))

    # 1) Magic-constant / relational placement (exact-offset guarantee).
    for con in constraints:
        p = _param_by_name(spec, con.variable)
        if p is None:
            continue
        bits = 8 * max(1, min(4, int(getattr(p, "size", 1) or 1)))
        v = solve_constraint_value(con, bits)
        if v is None:
            continue
        for be in (False, True) if bits > 8 else (False,):
            buf = bytearray(base_buf)
            if place_value(buf, p, v, big_endian=be):
                seeds.append(bytes(buf))

    # 2) Arithmetic-overflow placement (the unique Z3 contribution).
    for a_name, b_name in overflow_pairs:
        pa, pb = _param_by_name(spec, a_name), _param_by_name(spec, b_name)
        if pa is None or pb is None:
            continue
        bits_a = 8 * max(1, min(4, int(getattr(pa, "size", 1) or 1)))
        bits_b = 8 * max(1, min(4, int(getattr(pb, "size", 1) or 1)))
        # Try common bytes-per-element multipliers (RGBA=4, RGB-ish=3, 16bpp=2,
        # raw=1) — narrow fields only overflow once a channel multiplier is
        # applied, which is exactly the raster-sizing CVE pattern.
        sol = None
        for _bpp in (4, 3, 2, 1):
            sol = solve_mul_overflow(bits_a, bits_b, bpp=_bpp)
            if sol is not None:
                break
        if sol is None:
            continue
        va, vb = sol
        for be in (False, True):
            buf = bytearray(base_buf)
            ok_a = place_value(buf, pa, va, big_endian=be)
            ok_b = place_value(buf, pb, vb, big_endian=be)
            if ok_a and ok_b:
                seeds.append(bytes(buf))
        if log:
            log.info("z3.overflow_solved", a=a_name, b=b_name, va=va, vb=vb)

    # de-dup while preserving order
    uniq: list[bytes] = []
    seen: set[bytes] = set()
    for s in seeds:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _pick_base_seed(seeds_dir: Path, max_bytes: int) -> bytes:
    """Use the smallest existing valid seed as the structural base, else b''."""
    try:
        cands = [f for f in seeds_dir.iterdir()
                 if f.is_file() and 0 < f.stat().st_size <= max_bytes]
    except OSError:
        return b""
    if not cands:
        return b""
    cands.sort(key=lambda f: f.stat().st_size)
    try:
        return cands[0].read_bytes()
    except OSError:
        return b""


def synthesize_seeds(
    *,
    config,
    seeds_dir: Path,
    harness: "HarnessSpec",
    target_func: str = "",
    nemesis_root: Optional[Path] = None,
    log: "logging.Logger",
) -> int:
    """Top-level entry for the SeedPipeline Z3 stage. Returns seeds written."""
    spec = getattr(harness, "input_spec", None)
    if spec is None or not getattr(spec, "params", None):
        log.info("z3.no_input_spec")
        return 0

    target = config.target
    pinned = list(getattr(target, "pinned_funcs", []) or [])
    if not pinned:
        log.info("z3.no_pinned_func")
        return 0
    pf = pinned[0]
    func_name = pf.func_name or target_func

    source_root = Path(os.path.expandvars(os.path.expanduser(str(target.source_root))))
    src_path = source_root / pf.file_path if getattr(pf, "file_path", "") else None
    if not src_path or not src_path.is_file():
        log.info("z3.source_not_found", file=str(src_path))
        return 0
    try:
        full = src_path.read_text(errors="replace")
    except OSError:
        return 0

    body = slice_function_body(full, func_name)
    constraints = extract_constraints(body)
    overflow_pairs = detect_mul_overflow_pairs(body)
    if not constraints and not overflow_pairs:
        log.info("z3.no_constraints")
        return 0

    base = _pick_base_seed(seeds_dir, int(getattr(spec, "max_size", 1 << 18) or (1 << 18)))
    seeds = build_seeds(base, spec, constraints, overflow_pairs, log=log)
    if not seeds:
        log.info("z3.no_mappable_constraints",
                 constraints=len(constraints), overflow_pairs=len(overflow_pairs))
        return 0

    seeds_dir.mkdir(parents=True, exist_ok=True)
    import hashlib
    written = 0
    for s in seeds:
        digest = hashlib.sha256(s).hexdigest()[:12]
        dest = seeds_dir / f"z3_{written:03d}_{digest}.bin"
        try:
            dest.write_bytes(s)
            written += 1
        except OSError:
            pass
    log.info("z3.seeds_written", count=written,
             constraints=len(constraints), overflow_pairs=len(overflow_pairs))
    return written
