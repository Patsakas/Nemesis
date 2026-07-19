"""
NEMESIS Fix 122 — Target-aware seed synthesis from harness InputSpec.

Generates ~25 deterministic seed files per target by combining:
- Parameter boundary values (min, max, midpoint, 0, edge)
- Data fill patterns (zeros, 0xFF, ascending, LCG random, repeat, mixed)
- Size variants (min, max, powers of 2, interesting_sizes)

No LLM calls needed — the InputSpec extracted alongside the harness
provides all the information about how fuzz input bytes map to
library parameters.
"""

from __future__ import annotations

import struct
from pathlib import Path

from nemesis.models import InputParam, InputSpec


class SeedSynthesizer:
    """Deterministic seed generator from harness input layout."""

    # Data fill patterns for the payload region
    _PATTERNS: list[tuple[str, bytes | None]] = [
        ("zeros", b"\x00"),
        ("ones", b"\xff"),
        ("ascending", None),  # special: range(256) repeated
        ("lcg", None),        # special: LCG pseudo-random
        ("repeat4", b"\xDE\xAD\xBE\xEF"),
        ("mixed", b"\x00\xff\x41\x0a\x0d\x20"),
    ]

    # Text skeleton patterns for data_type="text"
    _TEXT_SKELETONS: list[tuple[str, bytes]] = [
        ("xml", b"<root/>"),
        ("json", b"{}"),
        ("csv", b"a,b,c\n1,2,3\n"),
    ]

    @classmethod
    def generate(cls, spec: InputSpec, seeds_dir: Path) -> int:
        """Generate targeted seeds from InputSpec into seeds_dir.

        Returns the number of seeds written.
        """
        seeds_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        # Phase 1: Compute interesting param value sets
        param_value_sets = cls._param_boundary_values(spec.params)

        # Phase 2: Compute interesting sizes
        sizes = cls._interesting_sizes(spec)

        # Phase 3: Compute data patterns
        data_patterns = cls._data_patterns(spec)

        # Phase 4: Combination — param combos × data patterns × sizes
        # Cap param combos at 3 representative ones
        param_combos = cls._select_param_combos(param_value_sets, spec.params, max_combos=3)

        # Cap data patterns at 3
        data_sel = data_patterns[:3]

        # Cap sizes at 3 representative ones
        size_sel = cls._select_sizes(sizes, max_sizes=3)

        # Fix 126: use actual bytes for dedup (hash() is non-deterministic across sessions)
        written_hashes: set[bytes] = set()

        for pi, (pname, param_bytes) in enumerate(param_combos):
            for di, (dname, dfill) in enumerate(data_sel):
                for si, size in enumerate(size_sel):
                    seed = cls._build_seed(spec, param_bytes, dfill, size)
                    if seed in written_hashes:
                        continue
                    written_hashes.add(seed)
                    fname = f"synth_{pname}_{dname}_{size}.bin"
                    (seeds_dir / fname).write_bytes(seed)
                    count += 1

        # Phase 5: Extra boundary seeds — one per param at each boundary value
        for param in spec.params:
            for val_name, val_bytes in cls._single_param_seeds(param):
                seed = cls._build_seed_single_param(spec, param, val_bytes, spec.min_size)
                # Dedup on the raw bytes (same set as Phase 4). The old code put
                # hash(seed) — an int — into a set of bytes, so it never matched
                # Phase-4 entries and re-emitted duplicate boundary seeds (and
                # hash() is non-deterministic across sessions anyway).
                if seed in written_hashes:
                    continue
                written_hashes.add(seed)
                fname = f"synth_param_{param.name}_{val_name}.bin"
                (seeds_dir / fname).write_bytes(seed)
                count += 1

        return count

    @classmethod
    def _param_boundary_values(cls, params: list[InputParam]) -> dict[str, list[tuple[str, int]]]:
        """For each param, compute interesting values (pre-transform domain)."""
        result: dict[str, list[tuple[str, int]]] = {}
        for p in params:
            type_max = cls._type_max(p.type, p.size)
            values: list[tuple[str, int]] = [
                ("zero", 0),
                ("max", type_max),
                ("mid", type_max // 2),
            ]
            if type_max > 1:
                values.append(("near_max", type_max - 1))
            if p.range and len(p.range) >= 2:
                # Add values that map to range endpoints via transform
                values.append(("rmin", p.range[0]))
                values.append(("rmax", p.range[1]))
            if p.enum_values:
                for ev in p.enum_values[:3]:
                    values.append((f"enum{ev}", ev))
            result[p.name] = values
        return result

    @classmethod
    def _interesting_sizes(cls, spec: InputSpec) -> list[int]:
        """Compute interesting total seed sizes."""
        # Minimum usable size must fit all params + at least 1 data byte
        floor = max(spec.min_size, spec.data_offset + 1)
        ceiling = min(spec.max_size, 65536)
        sizes: set[int] = set()
        sizes.add(floor)
        sizes.add(ceiling)
        # Powers of 2 within range
        p = 1
        while p <= spec.max_size:
            if p >= floor:
                sizes.add(p)
            # Also ±1 around powers of 2
            if p - 1 >= floor:
                sizes.add(p - 1)
            if p + 1 <= spec.max_size and p + 1 >= floor:
                sizes.add(p + 1)
            p *= 2
        # User-specified interesting sizes
        for s in spec.interesting_sizes:
            if floor <= s <= spec.max_size:
                sizes.add(s)
        return sorted(sizes)

    @classmethod
    def _data_patterns(cls, spec: InputSpec) -> list[tuple[str, bytes]]:
        """Generate data fill patterns based on data_type."""
        patterns: list[tuple[str, bytes]] = []
        if spec.data_type == "text":
            for name, skeleton in cls._TEXT_SKELETONS:
                patterns.append((name, skeleton))
        # Always include binary patterns
        for name, fill in cls._PATTERNS:
            if fill is not None:
                patterns.append((name, fill))
            elif name == "ascending":
                patterns.append(("ascending", bytes(range(256))))
            elif name == "lcg":
                # LCG: x = (x * 1103515245 + 12345) & 0x7fffffff
                lcg_data = bytearray(256)
                x = 42
                for i in range(256):
                    x = (x * 1103515245 + 12345) & 0x7FFFFFFF
                    lcg_data[i] = x & 0xFF
                patterns.append(("lcg", bytes(lcg_data)))
        return patterns

    @classmethod
    def _select_param_combos(
        cls,
        value_sets: dict[str, list[tuple[str, int]]],
        params: list[InputParam],
        max_combos: int = 3,
    ) -> list[tuple[str, dict[str, int]]]:
        """Select representative param value combinations.

        Returns list of (combo_name, {param_name: raw_value}).
        """
        if not params:
            return [("default", {})]

        combos: list[tuple[str, dict[str, int]]] = []

        # Combo 1: All zeros
        combos.append(("allzero", {p.name: 0 for p in params}))

        # Combo 2: All at midpoint
        mid_vals = {}
        for p in params:
            type_max = cls._type_max(p.type, p.size)
            mid_vals[p.name] = type_max // 2
        combos.append(("allmid", mid_vals))

        # Combo 3: All at max
        max_vals = {}
        for p in params:
            type_max = cls._type_max(p.type, p.size)
            max_vals[p.name] = type_max
        combos.append(("allmax", max_vals))

        # Convert to packed bytes
        result: list[tuple[str, dict[str, int]]] = []
        for name, vals in combos[:max_combos]:
            result.append((name, vals))
        return result

    @classmethod
    def _select_sizes(cls, sizes: list[int], max_sizes: int = 3) -> list[int]:
        """Pick representative sizes: smallest, largest, and one in between."""
        if len(sizes) <= max_sizes:
            return sizes
        result = [sizes[0], sizes[-1]]
        mid_idx = len(sizes) // 2
        result.insert(1, sizes[mid_idx])
        return result[:max_sizes]

    @classmethod
    def _build_seed(
        cls,
        spec: InputSpec,
        param_values: dict[str, int],
        data_fill: bytes,
        total_size: int,
    ) -> bytes:
        """Build a complete seed buffer."""
        buf = bytearray(total_size)

        # Pack param bytes at their offsets
        for p in spec.params:
            val = param_values.get(p.name, 0)
            cls._pack_param(buf, p, val)

        # Fill data region
        data_start = spec.data_offset
        if data_start < total_size:
            data_len = total_size - data_start
            fill = data_fill * ((data_len // len(data_fill)) + 1) if data_fill else b"\x00" * data_len
            buf[data_start:total_size] = fill[:data_len]

        # Overlay magic bytes
        if spec.magic_bytes:
            offset = spec.magic_bytes.get("offset", 0)
            hex_val = spec.magic_bytes.get("value", "")
            if hex_val:
                try:
                    magic = bytes.fromhex(hex_val)
                    end = min(offset + len(magic), total_size)
                    buf[offset:end] = magic[:end - offset]
                except ValueError:
                    pass

        return bytes(buf)

    @classmethod
    def _build_seed_single_param(
        cls,
        spec: InputSpec,
        param: InputParam,
        value: int,
        total_size: int,
    ) -> bytes:
        """Build a seed with one param set to a specific value, others zeroed."""
        size = max(total_size, spec.data_offset + 1)
        buf = bytearray(size)
        cls._pack_param(buf, param, value)
        return bytes(buf)

    @classmethod
    def _single_param_seeds(cls, param: InputParam) -> list[tuple[str, int]]:
        """Generate boundary values for a single param."""
        type_max = cls._type_max(param.type, param.size)
        values: list[tuple[str, int]] = [
            ("zero", 0),
            ("max", type_max),
            ("mid", type_max // 2),
        ]
        if type_max > 1:
            values.append(("near_max", type_max - 1))
            values.append(("one", 1))
        return values

    @classmethod
    def _pack_param(cls, buf: bytearray, param: InputParam, value: int) -> None:
        """Pack a value into the buffer at the param's offset."""
        if param.offset + param.size > len(buf):
            return  # buffer too small for this param
        fmt = cls._struct_fmt(param.type, param.size)
        # Clamp value to fit
        type_max = cls._type_max(param.type, param.size)
        if param.type == "int32":
            value = max(-(type_max + 1), min(type_max, value))
        else:
            value = max(0, min(type_max, value))
        try:
            struct.pack_into(fmt, buf, param.offset, value)
        except struct.error:
            pass

    @staticmethod
    def _type_max(type_name: str, size: int) -> int:
        """Max value for a parameter type."""
        if type_name == "int32":
            return 0x7FFFFFFF
        return (1 << (size * 8)) - 1

    @staticmethod
    def _struct_fmt(type_name: str, size: int) -> str:
        """struct format character for a param type."""
        if type_name == "int32":
            return "<i"
        fmts = {1: "<B", 2: "<H", 4: "<I"}
        return fmts.get(size, "<B")
