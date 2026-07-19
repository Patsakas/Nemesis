"""Phase 2: Z3-assisted seed synthesis.

z3 is a hard dependency of NEMESIS (symbolic stage), so the solver paths are
tested for real here rather than mocked.
"""

from __future__ import annotations

from types import SimpleNamespace

from nemesis.models import InputParam, InputSpec
from nemesis.recon import z3_seedgen as z

# ── constraint extraction ─────────────────────────────────────────────────

def test_extract_constraints_eq_and_relational():
    src = "if (tag == 0x0200) {} if (count >= 16) {} if (n != 3) {}"
    cons = z.extract_constraints(src)
    got = {(c.variable, c.operator, c.value) for c in cons}
    assert ("tag", "==", "0x0200") in got
    assert ("count", ">=", "16") in got
    assert ("n", "!=", "3") in got


def test_detect_mul_overflow_pairs_only_on_alloc_lines():
    src = (
        "int area = width * height;\n"            # no alloc hint → ignored
        "buf = malloc(w * h * 4);\n"              # alloc hint → captured
    )
    pairs = z.detect_mul_overflow_pairs(src)
    assert ("w", "h") in [tuple(p) for p in pairs]
    assert ("width", "height") not in [tuple(p) for p in pairs]


def test_slice_function_body_extracts_only_body():
    src = (
        "void other(){ int x == 99; }\n"
        "int target(int a){ if (a == 0x0200) return 1; return 0; }\n"
    )
    body = z.slice_function_body(src, "target")
    assert "0x0200" in body
    assert "99" not in body  # other()'s body excluded


# ── Z3 overflow solver (real) ─────────────────────────────────────────────

def test_solve_mul_overflow_produces_real_overflow():
    sol = z.solve_mul_overflow(bpp=4)
    assert sol is not None
    a, b = sol
    assert a >= 2 and b >= 2
    # logical size overflows 32 bits ...
    assert a * b * 4 > 0xFFFFFFFF
    # ... but the 32-bit-truncated allocation is tiny
    assert ((a * b * 4) & 0xFFFFFFFF) < 4096


def test_solve_constraint_value_operators():
    assert z.solve_constraint_value(_con("x", "==", "0x10"), 16) == 0x10
    assert z.solve_constraint_value(_con("x", ">", "5"), 16) == 6
    assert z.solve_constraint_value(_con("x", ">=", "5"), 16) == 5
    assert z.solve_constraint_value(_con("x", "<", "5"), 16) == 4
    # out of range for the bit width → None
    assert z.solve_constraint_value(_con("x", "==", "0x1FF"), 8) is None


# ── byte placement ────────────────────────────────────────────────────────

def test_place_value_little_and_big_endian():
    buf = bytearray(8)
    p = InputParam(name="tag", offset=2, size=2, type="uint16")
    assert z.place_value(buf, p, 0x0200, big_endian=False)
    assert bytes(buf[2:4]) == b"\x00\x02"
    buf2 = bytearray(8)
    assert z.place_value(buf2, p, 0x0200, big_endian=True)
    assert bytes(buf2[2:4]) == b"\x02\x00"


def test_place_value_out_of_bounds_rejected():
    buf = bytearray(2)
    p = InputParam(name="x", offset=4, size=4, type="uint32")
    assert z.place_value(buf, p, 1, big_endian=False) is False


# ── build_seeds integration ───────────────────────────────────────────────

def test_build_seeds_places_constant_at_offset():
    spec = InputSpec(params=[InputParam(name="tag", offset=0, size=2, type="uint16")],
                     min_size=16)
    cons = z.extract_constraints("if (tag == 0x0200) {}")
    seeds = z.build_seeds(b"\x00" * 16, spec, cons, [])
    assert seeds
    # at least one seed carries 0x0200 at offset 0 (LE or BE)
    assert any(s[0:2] in (b"\x00\x02", b"\x02\x00") for s in seeds)


def test_build_seeds_overflow_pair():
    spec = InputSpec(
        params=[
            InputParam(name="w", offset=0, size=2, type="uint16"),
            InputParam(name="h", offset=2, size=2, type="uint16"),
        ],
        min_size=16,
    )
    seeds = z.build_seeds(b"\x00" * 16, spec, [], [("w", "h")])
    assert seeds  # solver found w,h and placed them


# ── top-level synthesize_seeds ────────────────────────────────────────────

def test_synthesize_seeds_end_to_end(tmp_path):
    # source file with an overflow-feeding multiplication on the two params
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "dec.c").write_text(
        "int decode(int w, int h){ char *buf = malloc(w * h * 4); return !!buf; }"
    )
    spec = InputSpec(
        params=[
            InputParam(name="w", offset=0, size=2, type="uint16"),
            InputParam(name="h", offset=2, size=2, type="uint16"),
        ],
        min_size=16,
    )
    harness = SimpleNamespace(input_spec=spec)
    target = SimpleNamespace(
        source_root=str(src_dir),
        pinned_funcs=[SimpleNamespace(func_name="decode", file_path="dec.c")],
    )
    config = SimpleNamespace(target=target)
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass

    n = z.synthesize_seeds(config=config, seeds_dir=seeds_dir, harness=harness,
                           target_func="decode", log=_Log())
    assert n > 0
    assert sum(1 for f in seeds_dir.iterdir() if f.name.startswith("z3_")) == n


def test_synthesize_seeds_no_input_spec_returns_zero(tmp_path):
    harness = SimpleNamespace(input_spec=None)
    config = SimpleNamespace(target=SimpleNamespace(source_root=str(tmp_path), pinned_funcs=[]))

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass

    assert z.synthesize_seeds(config=config, seeds_dir=tmp_path, harness=harness, log=_Log()) == 0


# ── helper ────────────────────────────────────────────────────────────────

def _con(var, op, val):
    from nemesis.models import PathConstraint
    return PathConstraint(variable=var, operator=op, value=val, source="ast")
