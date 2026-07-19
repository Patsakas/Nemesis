"""Phase 3 #6: structured field-spec seed interpreter (deterministic core)."""

from __future__ import annotations

import random

from nemesis.recon import fieldspec_seedgen as fs


def test_const_field_emits_magic():
    out = fs.build_from_fieldspec([{"kind": "const", "hex": "504b0304"}], random.Random(0))
    assert out == b"PK\x03\x04"


def test_int_field_endianness_and_range():
    out_le = fs.build_from_fieldspec(
        [{"kind": "int", "size": 2, "endian": "le", "values": [0x0200]}], random.Random(0))
    assert out_le == b"\x00\x02"
    out_be = fs.build_from_fieldspec(
        [{"kind": "int", "size": 2, "endian": "be", "values": [0x0200]}], random.Random(0))
    assert out_be == b"\x02\x00"


def test_int_range_respected():
    for seed in range(20):
        out = fs.build_from_fieldspec(
            [{"kind": "int", "size": 1, "min": 5, "max": 9}], random.Random(seed))
        assert 5 <= out[0] <= 9


def test_bytes_fill_modes():
    z = fs.build_from_fieldspec(
        [{"kind": "bytes", "min": 4, "max": 4, "fill": "zero"}], random.Random(1))
    assert z == b"\x00\x00\x00\x00"
    a = fs.build_from_fieldspec(
        [{"kind": "bytes", "min": 8, "max": 8, "fill": "ascii"}], random.Random(1))
    assert len(a) == 8 and all(0x20 <= c <= 0x7e for c in a)


def test_len_field_backpatches_region_length():
    fields = [
        {"kind": "len", "size": 4, "endian": "le", "of": "payload"},
        {"kind": "bytes", "name": "payload", "min": 10, "max": 10, "fill": "zero"},
    ]
    out = fs.build_from_fieldspec(fields, random.Random(0))
    # first 4 bytes = little-endian length of the 10-byte payload
    assert out[:4] == (10).to_bytes(4, "little")
    assert len(out) == 14


def test_len_adjust():
    fields = [
        {"kind": "len", "size": 2, "endian": "be", "of": "p", "adjust": 2},
        {"kind": "bytes", "name": "p", "min": 3, "max": 3, "fill": "zero"},
    ]
    out = fs.build_from_fieldspec(fields, random.Random(0))
    assert out[:2] == (5).to_bytes(2, "big")  # 3 + adjust 2


def test_build_is_deterministic():
    fields = [{"kind": "int", "size": 4, "min": 0, "max": 10000},
              {"kind": "bytes", "min": 0, "max": 32}]
    a = fs.build_from_fieldspec(fields, random.Random(123))
    b = fs.build_from_fieldspec(fields, random.Random(123))
    assert a == b


def test_unknown_kind_skipped_not_fatal():
    out = fs.build_from_fieldspec(
        [{"kind": "const", "hex": "ab"}, {"kind": "bogus"}, {"kind": "const", "hex": "cd"}],
        random.Random(0))
    assert out == b"\xab\xcd"


def test_validate_fieldspec():
    assert fs.validate_fieldspec({"fields": [{"kind": "const", "hex": "00"}]})[0]
    assert not fs.validate_fieldspec({})[0]
    assert not fs.validate_fieldspec({"fields": []})[0]
    assert not fs.validate_fieldspec({"fields": [{"kind": "nope"}]})[0]


def test_extract_json_handles_fences():
    assert fs._extract_json('```json\n{"fields": []}\n```') == {"fields": []}
    assert fs._extract_json('{"fields": [1]}') == {"fields": [1]}


def test_produce_seeds_writes_unique(tmp_path):
    spec = {"fields": [
        {"kind": "const", "hex": "474946"},  # GIF
        {"kind": "int", "size": 2, "min": 0, "max": 65535},
        {"kind": "bytes", "min": 0, "max": 32},
    ]}
    n = fs.produce_seeds_from_spec(spec, tmp_path, n_seeds=30)
    assert n > 0
    files = list(tmp_path.glob("fieldspec_*.bin"))
    assert len(files) == n
    assert all(f.read_bytes()[:3] == b"GIF" for f in files)


def test_produce_seeds_empty_spec(tmp_path):
    assert fs.produce_seeds_from_spec({"fields": []}, tmp_path, n_seeds=10) == 0
