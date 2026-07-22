"""Harness generation + validation benchmark: one variable, the architect model.

Separate from the end-to-end run on purpose. The full pipeline answers "can
NEMESIS produce a useful result"; this answers "how reliably does this architect
model produce a *sound* harness", and mixing them makes neither interpretable.

Held fixed across every sample and every model:
  target, recon output, analysis context, prompt, harness schema, preflight
  gate, repair budget (1), repair prompt.

Varied: `architect_model` only.

Recon and analysis run once and are reused, so a slow or flaky recon cannot
leak into the model comparison.

Reported:
  first_pass_valid_rate  generated soundly with no repair — measures the model
  eventual_soundness     final_passed / samples         — measures the product
  repair_success_rate    DIAGNOSTIC ONLY. Its denominator is the number of
                         first-pass failures, so at n=10 a "66%" is 2 of 3.
                         Do not rank models on it.
  mean_generation_latency, mean_attempts_to_valid, timeout_rate
  failure_category_distribution — *what kind* of reasoning fails, which is
                                  more actionable than a bare failure rate

Every report carries `evaluation_valid`. A degraded endpoint inflates latency,
truncates samples and reshuffles which generations survive, so results gathered
through one are not comparable with results gathered through a healthy one.
Marking the run invalid is the only thing that stops the numbers being quoted
later without that context.

Modes:
  screening   n=10, repair budget 1 — find bad models cheaply
  evaluation  n=30, repair budget 2 — numbers for a case study

usage: generation_benchmark.py <target.yaml> <out.json>
                               [screening|evaluation] [model,model,...]
"""
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from nemesis.config import load_config
from nemesis.models import AnalysisContext
from nemesis.neural import NeuralStage
from nemesis.recon import ReconStage
from nemesis.symbolic import SymbolicStage

CATEGORIES = [
    ("variadic_arity", ("variadic call", "arity_mismatch", "format_not_resolvable")),
    ("missing_target_call", ("not called in harness",)),
    ("missing_afl_macros", ("__AFL_LOOP", "__AFL_FUZZ_TESTCASE_BUF")),
    ("syntax_error", ("unbalanced braces",)),
    ("missing_main", ("no main() function",)),
    ("unsafe_io_pattern", ("pipe() used without",)),
]


def categorise(reasons: list[str]) -> list[str]:
    hits = []
    for reason in reasons:
        for name, needles in CATEGORIES:
            if any(n in reason for n in needles):
                hits.append(name)
                break
        else:
            if "target function is variadic" not in reason:  # the hint, not a reason
                hits.append("other")
    return sorted(set(hits))


MODES = {
    "screening": {"n": 10, "repair_budget": 1},
    "evaluation": {"n": 30, "repair_budget": 2},
}

# Above this share of samples lost to provider errors, the batch says nothing
# about the model and the report says so rather than publishing the numbers.
MAX_INFRA_LOSS = 0.20


def main() -> None:
    target_yaml, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "screening"
    if mode not in MODES:
        sys.exit(f"mode must be one of {sorted(MODES)}")
    n = MODES[mode]["n"]
    repair_budget = MODES[mode]["repair_budget"]
    base_cfg = load_config(target_path=target_yaml)
    models = (sys.argv[4].split(",") if len(sys.argv) > 4
              else [base_cfg.llm.architect.model])
    print(f"mode={mode} n={n} repair_budget={repair_budget}")

    cfg = load_config(target_path=target_yaml)
    symbolic = SymbolicStage(cfg)

    # ── fixed inputs, computed once ─────────────────────────
    targets = ReconStage(cfg).run()
    if not targets:
        sys.exit("recon produced no targets")
    target = targets[0]
    print(f"target: {target.func_name} ({target.file_path})")

    # Built the same way the pipeline builds it (nemesis/pipeline.py), and
    # once — a re-analysed context per sample would vary the prompt and make
    # the model the wrong variable to blame for the difference.
    context = AnalysisContext(target=target, call_chain=target)
    analysis = NeuralStage(cfg).analyze(context)
    declaration = symbolic._target_declaration(target.func_name)
    print(f"declaration: {declaration}")

    results = {}
    for model in models:
        print(f"\n=== {model} ===")
        cfg.llm.architect.model = model
        neural_m = NeuralStage(cfg)
        samples = []
        for i in range(n):
            t0 = time.time()
            row = {"sample": i, "model": model}
            try:
                harness = neural_m.generate_harness_strategy_a(analysis, context)
                row["latency_s"] = round(time.time() - t0, 1)
            except Exception as exc:
                row.update(latency_s=round(time.time() - t0, 1), infra_failure=True,
                           error=f"{type(exc).__name__}: {str(exc)[:80]}")
                samples.append(row)
                print(f"  {i}: INFRA {row['error'][:50]}")
                continue

            ok, reasons = symbolic._preflight_harness(
                harness.c_code, target.func_name, target_declaration=declaration)
            row.update(first_pass_passed=ok, attempts=1,
                       first_pass_categories=categorise(reasons))

            code, attempts = harness.c_code, 1
            if not ok:
                row["repair_attempted"] = True
                for _ in range(repair_budget):
                    repaired = neural_m.repair_harness(
                        code, "\n".join(reasons), target.func_name)
                    if not repaired:
                        row["repair_produced_code"] = False
                        break
                    code, attempts = repaired, attempts + 1
                    ok, reasons = symbolic._preflight_harness(
                        code, target.func_name, target_declaration=declaration)
                    if ok:
                        break
                row["final_categories"] = categorise(reasons)
            row.update(final_passed=ok, attempts=attempts)
            samples.append(row)
            print(f"  {i}: first={row.get('first_pass_passed')} "
                  f"final={row.get('final_passed')} {row['latency_s']}s "
                  f"{row.get('first_pass_categories') or ''}")

        valid = [s for s in samples if not s.get("infra_failure")]
        repaired_n = [s for s in valid if s.get("repair_attempted")]
        cats: Counter = Counter()
        for s in valid:
            cats.update(s.get("first_pass_categories") or [])

        results[model] = {
            "samples": len(samples),
            "usable_samples": len(valid),
            "timeout_rate": round(1 - len(valid) / len(samples), 3) if samples else None,
            "first_pass_valid_rate": (
                round(sum(1 for s in valid if s["first_pass_passed"]) / len(valid), 3)
                if valid else None),
            # Diagnostic only — denominator is the first-pass failures, so at
            # screening sizes this is a handful of samples, not an estimate.
            "repair_success_rate_diagnostic": (
                round(sum(1 for s in repaired_n if s.get("final_passed")) / len(repaired_n), 3)
                if repaired_n else None),
            "repair_denominator": len(repaired_n),
            "eventual_soundness": (
                round(sum(1 for s in valid if s.get("final_passed")) / len(valid), 3)
                if valid else None),
            "mean_generation_latency_s": (
                round(statistics.mean(s["latency_s"] for s in valid), 1) if valid else None),
            "mean_attempts_to_valid": (
                round(statistics.mean(s["attempts"] for s in valid if s.get("final_passed")), 2)
                if any(s.get("final_passed") for s in valid) else None),
            "failure_category_distribution": dict(cats),
            "records": samples,
        }

    worst_loss = max((r["timeout_rate"] or 0.0) for r in results.values())
    valid = worst_loss <= MAX_INFRA_LOSS
    report = {
        "evaluation_valid": valid,
        "invalid_reason": (None if valid else
                           f"infra_timeout_rate_above_threshold "
                           f"({worst_loss:.0%} > {MAX_INFRA_LOSS:.0%})"),
        "reading_note": (
            "repair_success_rate_diagnostic is not a ranking metric — check "
            "repair_denominator before quoting it. Rank on first_pass_valid_rate "
            "(the model) and eventual_soundness (the product)."),
        "protocol": {
            "mode": mode,
            "held_fixed": ["target", "recon output", "analysis context", "prompt",
                           "harness schema", "preflight gate",
                           f"repair budget ({repair_budget})", "repair prompt"],
            "varied": "architect_model",
            "target": target.func_name,
            "declaration": declaration,
            "samples_per_model": n,
        },
        "models": results,
    }
    out_path.write_text(json.dumps(report, indent=2))

    if not valid:
        print(f"\n*** EVALUATION INVALID: {report['invalid_reason']} ***")
        print("    latency and soundness numbers below are not comparable.")
    print(f"\n{'model':<40}{'1st':>7}{'final':>7}{'lat':>7}{'t/o':>6}  repair(diag)")
    for model, r in results.items():
        rep = (f"{r['repair_success_rate_diagnostic']} "
               f"(n={r['repair_denominator']})"
               if r["repair_denominator"] else "-")
        print(f"{model:<40}{str(r['first_pass_valid_rate']):>7}"
              f"{str(r['eventual_soundness']):>7}"
              f"{str(r['mean_generation_latency_s']):>7}"
              f"{str(r['timeout_rate']):>6}  {rep}")
    print(f"\nwritten: {out_path}")


if __name__ == "__main__":
    main()
