"""Neural fragility fixes (audit Batch 1):
- _extract_best_code_block picks the real harness, not the first prose fence.
- json_extractor parses c_code with raw newlines without mangling it.
"""
from nemesis.neural import _extract_best_code_block
from nemesis.neural.json_extractor import extract_json


def test_best_code_block_skips_leading_prose_fence():
    resp = (
        "Here's what was wrong:\n\n"
        "```c\n// just the broken line\nfopn(f);\n```\n\n"
        "And here is the corrected harness:\n\n"
        "```c\n#include <cJSON.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)"
        "{ return 0; }\nint main(){return 0;}\n```\n"
    )
    best = _extract_best_code_block(resp)
    assert "LLVMFuzzerTestOneInput" in best
    assert "just the broken line" not in best


def test_best_code_block_none_when_no_fence():
    assert _extract_best_code_block("no code here") is None


def test_best_code_block_single():
    resp = "```c\n#include <x.h>\nint main(){}\n```"
    assert "#include" in _extract_best_code_block(resp)


def test_json_extractor_preserves_c_code_with_raw_newlines():
    # c_code with REAL newlines inside the string (not escaped) — strict=False
    # must parse it and keep the source intact.
    raw = '{"target_func": "f", "c_code": "int main() {\n  return 0;\n}"}'
    out = extract_json(raw)
    assert out is not None
    assert out["target_func"] == "f"
    assert "return 0;" in out["c_code"]


def test_json_extractor_preserves_backslash_escapes_in_c_code():
    # printf with \n escape inside a properly-quoted JSON string must survive.
    raw = '{"c_code": "printf(\\"hi\\\\n\\");"}'
    out = extract_json(raw)
    assert out is not None
    assert "printf(" in out["c_code"]
