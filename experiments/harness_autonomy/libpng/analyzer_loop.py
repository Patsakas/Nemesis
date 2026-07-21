#!/usr/bin/env python3
"""End-to-end analyzer-loop test: does NEMESIS's OWN static analyzer localize the
libpng width-limit guard from RAW source — no CVE text, no saved harness, no
target-specific hint — and does the symbolic layer then produce the bypass?

Two things are measured:
  (1) extract_validation_gates(raw libpng) finds png_set_user_limits by itself.
  (2) inject_setter_calls(naive harness) deterministically turns Arm A into Arm B
      with NO LLM at all (the pure-symbolic end of the loop).

Usage: analyzer_loop.py <libpng-source-root>
"""
import sys, pathlib
REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from nemesis.recon.validation_gates import (          # noqa: E402
    extract_validation_gates, render_validation_gates_block,
    inject_setter_calls, _setter_is_injectable,
)

src = pathlib.Path(sys.argv[1])
print(f"source_root = {src}  (exists={src.is_dir()})\n")

gates = extract_validation_gates(src)
print(f"=== (1) STATIC EXTRACTION — {len(gates)} validation-gate setters found ===")
for g in gates:
    inj = "  [INJECTABLE]" if _setter_is_injectable(g) else ""
    print(f"  {g.setter_name:32s} {g.source_file}{inj}")

names = {g.setter_name for g in gates}
target = "png_set_user_limits"
print(f"\n>>> analyzer found '{target}' UNAIDED: {target in names}")
print(f">>> and it is classified injectable: "
      f"{any(_setter_is_injectable(g) and g.setter_name==target for g in gates)}")

# (2) Pure-symbolic bypass: feed the NAIVE harness, get the reachable one, no LLM.
naive = (REPO / "benchmarks" / "harness_reasoning" / "libpng" / "arm_a_naive.c").read_text()
injected = inject_setter_calls(naive, gates)
added = injected != naive
print(f"\n=== (2) PURE-SYMBOLIC INJECTION into the naive harness (no LLM) ===")
print(f">>> harness modified: {added}")
if added:
    # show the auto-inserted block
    for line in injected.splitlines():
        if "nemesis:" in line or "png_set_user_limits" in line or "_max(" in line.lower():
            print("   +", line.strip())
