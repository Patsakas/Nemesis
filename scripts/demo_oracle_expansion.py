"""
End-to-end demo of the Targeted Oracle Expansion (Fix 148-152).

Builds a realistic expat-flavoured target config exercising every new oracle
mode and prints:
  1. What the harness-generation prompt actually looks like with the new blocks
  2. What the cross-config validation gates report on misconfigured combos
  3. What the onboard auto-detect would emit for a self-contained threaded lib

Run with:  python scripts/demo_oracle_expansion.py
"""

import io
import sys
import tempfile
from pathlib import Path

# Force UTF-8 output so unicode arrows / em-dashes render on Windows cp1252 consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# Ensure the local nemesis package wins over any installed copy
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nemesis.config import NemesisConfig, PinnedFunc, TargetConfig
from nemesis.models import (
    AnalysisContext,
    CallChain,
    CoverageTarget,
    CWE,
    VulnerabilityAnalysis,
)
from nemesis.neural import PromptBuilder
from nemesis.onboard import (
    _format_oracle_hints_comment,
    _probe_oracle_candidates,
)
from nemesis.recon.oracle_validation import validate_oracle_config


# ── Section banner helpers ──────────────────────────────────


def banner(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


# ── Demo 1: real prompt with all new oracle blocks active ───


def demo_prompt_with_all_modes() -> None:
    banner("DEMO 1 — harness prompt for storeRawNames with all oracle modes active")

    target = CoverageTarget(
        func_name="storeRawNames",
        file_path="lib/xmlparse.c",
        line=4827,
        coverage_pct=18.0,
        has_memory_ops=True,
        has_pointer_arith=True,
        # Fix 135 round-trip oracle (legacy)
        differential_oracle=True,
        # Fix 148 — cross-impl differential against libxml2 strict mode
        differential_reference="xmlReadMemory",
        # Fix 150 — multi-threaded harness for race detection (unrealistic for
        # expat itself but useful to see all blocks render together)
        threaded_oracle=True,
        # Fix 136 — output invariants
        output_invariants=[
            "out_len <= XML_MAX_RAW_NAME_BYTES",
            "ptr_diff(end, start) >= 0",
        ],
    )

    analysis = VulnerabilityAnalysis(
        vulnerability_type="buffer logic divergence in entity name storage",
        cwe=CWE.OUT_OF_BOUNDS_WRITE,
        root_cause="Raw name accumulator may write past tag scratch buffer",
        attack_vector="Crafted entity declaration with overlapping namespace prefix",
        confidence=0.55,
        has_blocker=False,
        blocker_description="none",
    )

    ctx = AnalysisContext(
        target=target,
        call_chain=CallChain(
            entry_point="LLVMFuzzerTestOneInput",
            chain=["LLVMFuzzerTestOneInput", "XML_Parse",
                   "doContent", "storeRawNames"],
            target=target,
            depth=3,
        ),
        source_snippets={
            "lib/xmlparse.c::storeRawNames": (
                "static int storeRawNames(XML_Parser parser) {\n"
                "  TAG *tag = parser->m_tagStack;\n"
                "  /* ... ~50 lines of name copy logic ... */\n"
                "}\n"
            ),
        },
    )

    prompt = PromptBuilder.build_harness_prompt(analysis, ctx)

    # Extract just the new oracle blocks for readability — full prompt is huge
    for block_tag in ("differential_oracle", "differential_reference",
                      "threaded_oracle", "output_invariants"):
        start_marker = f"<{block_tag}>"
        end_marker = f"</{block_tag}>"
        if start_marker in prompt:
            i = prompt.index(start_marker)
            j = prompt.index(end_marker) + len(end_marker)
            print()
            print(prompt[i:j])
        else:
            print(f"\n!! {block_tag} block NOT emitted")

    print()
    print(f"[total prompt length: {len(prompt)} chars]")


# ── Demo 2: validation gate warnings on misconfigured targets ──


def demo_validation_gates_misconfig() -> None:
    banner("DEMO 2 — cross-config validation warnings")

    cases = [
        ("TSan profile but ZERO threaded_oracle pinned_funcs",
         NemesisConfig(target=TargetConfig(
             name="bad_tsan", sanitizer_profile="tsan", tsan_supported=True,
             pinned_funcs=[
                 PinnedFunc(func_name="parse", file_path="x.c", line=1),
             ],
         ))),
        ("threaded_oracle pin under default ASAN profile",
         NemesisConfig(target=TargetConfig(
             name="bad_threaded", sanitizer_profile="asan_ubsan",
             pinned_funcs=[
                 PinnedFunc(func_name="ssl_use", file_path="ssl.c", line=10,
                            threaded_oracle=True),
                 PinnedFunc(func_name="cipher_op", file_path="ssl.c", line=42,
                            threaded_oracle=True),
             ],
         ))),
        ("Properly configured expat differential test",
         NemesisConfig(target=TargetConfig(
             name="good_expat", sanitizer_profile="asan_ubsan",
             pinned_funcs=[
                 PinnedFunc(func_name="storeRawNames", file_path="lib/xmlparse.c",
                            line=4827, differential_reference="xmlReadMemory"),
             ],
         ))),
    ]

    for label, cfg in cases:
        print(f"\n[case] {label}")
        warnings = validate_oracle_config(cfg)
        if not warnings:
            print("  (clean — no oracle.config warnings)")
            continue
        for w in warnings:
            print(f"  WARN [{w.key}]")
            print(f"    message: {w.message}")
            print(f"    suggest: {w.suggestion}")


# ── Demo 3: onboard auto-detection on simulated source trees ──


def demo_onboard_oracle_hints() -> None:
    banner("DEMO 3 — onboard oracle-candidacy probe (simulated source trees)")

    cases = [
        ("self-contained single-threaded XML lib (expat-like)",
         {"src/parser.c": "int parse(const char* s) { return 0; }\n"},
         "-lm"),
        ("threaded codec lib with heavy deps (libssh2-like)",
         {"src/session.c": "#include <pthread.h>\nvoid mt(void) {}\n",
          "src/io.c": "#include <pthread.h>\n"},
         "-lz -lssl -lcrypto -lpthread"),
        ("self-contained threaded lib (our perfect MSan+TSan target)",
         {"src/mt_alloc.c": "#include <stdatomic.h>\n_Atomic int n=0;\n",
          "src/work.c": "#include <pthread.h>\n"},
         ""),
    ]

    for label, files, link_libs in cases:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, content in files.items():
                f = root / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(content)
            hints = _probe_oracle_candidates(root, link_libs)
            print(f"\n[lib] {label}")
            print(f"  link_libs: {link_libs or '(none)'}")
            print(_format_oracle_hints_comment(hints))


if __name__ == "__main__":
    demo_prompt_with_all_modes()
    demo_validation_gates_misconfig()
    demo_onboard_oracle_hints()
    print()
    print("=" * 78)
    print("  All three demos complete.")
    print("=" * 78)
