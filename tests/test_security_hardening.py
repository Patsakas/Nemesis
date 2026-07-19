"""Security hardening (audit Batch 1): the two dynamic-execution vectors that
run LLM-generated content — predicate eval and seedgen scripts — are validated
structurally (AST whitelist), and seedgen children get a secret-free env."""
from nemesis.recon.predicate_synthesis import _evaluate_predicate, _predicate_expr_is_safe
from nemesis.recon.seedgen import _script_ast_is_safe, _seedgen_child_env


# ── predicate eval ──────────────────────────────────────────
def test_predicate_allows_real_predicates():
    assert _predicate_expr_is_safe("input[0] == 0x47 and input_len > 4")
    assert _predicate_expr_is_safe("(input[0] & 0x80) != 0")


def test_predicate_rejects_sandbox_escape():
    assert not _predicate_expr_is_safe("().__class__.__bases__[0]")
    assert not _predicate_expr_is_safe("open('x')")
    assert not _predicate_expr_is_safe("__import__('os')")


def test_predicate_rejects_unknown_names():
    assert not _predicate_expr_is_safe("os.system('id')")
    assert not _predicate_expr_is_safe("secret == 1")


def test_evaluate_predicate_safe_eval_still_works():
    assert _evaluate_predicate("input[0] == 0x47", b"GIF") is True
    assert _evaluate_predicate("input[0] == 0x99", b"GIF") is False
    # malicious expr → None (rejected, not executed)
    assert _evaluate_predicate("().__class__.__bases__[0]", b"x") is None


# ── seedgen script validation ───────────────────────────────
def test_seedgen_accepts_normal_generator():
    good = (
        "import struct, random, sys\n"
        "random.seed(int(sys.argv[2]))\n"
        "open(sys.argv[1], 'wb').write(struct.pack('<I', random.randint(0, 9)))\n"
    )
    ok, _ = _script_ast_is_safe(good)
    assert ok


def test_seedgen_rejects_dangerous_scripts():
    for bad in (
        "import os\nos.system('id')",
        "x = __import__('os').system('id')",
        "().__class__.__bases__[0].__subclasses__()",
        "import sys\ngetattr(sys, 'modules')",
        "import socket",
    ):
        ok, reason = _script_ast_is_safe(bad)
        assert not ok, f"should reject: {bad}"


def test_seedgen_child_env_strips_secrets(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "sekret")
    monkeypatch.setenv("NVIDIA_API_KEY", "sekret2")
    env = _seedgen_child_env()
    assert "GROQ_API_KEY" not in env
    assert "NVIDIA_API_KEY" not in env
    assert env.get("PYTHONDONTWRITEBYTECODE") == "1"
