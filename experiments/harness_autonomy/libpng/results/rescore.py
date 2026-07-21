#!/usr/bin/env python3
"""Reproducible re-scoring of the autonomy experiment.

The runner's crude metric (does 'png_set_user_limits' appear anywhere) turned out
to be confounded: mistral uses the call as GENERIC boilerplate too, often setting
the limit BELOW libpng's default 1,000,000 (e.g. 8192) — which would block the bug
harder, not unlock it. What actually matters for reachability is the DIRECTION:
does the width argument exceed the default cap so width 0x55555555 can pass?

This re-scores raw_responses.json by that honest metric and writes corrected.json.
"""
import json, re, pathlib
HERE = pathlib.Path(__file__).resolve().parent
DEFAULT = 1_000_000
raw = json.load(open(HERE / "raw_responses.json", encoding="utf-8"))


def width_args(t):
    return re.findall(r"png_set_user_limits\s*\(\s*[^,]+,\s*([^,]+),", t or "")


def verdict(t):
    """Classify a harness: does it RAISE the width limit above the default?"""
    args = width_args(t)
    if not args:
        return "no_call"
    raised = lowered = fuzz = at_default = False
    for a in args:
        a = a.strip()
        if re.search(r"0x7f|0xff|INT_MAX|UINT_MAX|UINT_31", a, re.I):
            raised = True
        elif re.match(r"^\d+U?L?$", a):
            v = int(re.sub(r"[UL]", "", a))
            if v > DEFAULT: raised = True
            elif v == DEFAULT: at_default = True
            else: lowered = True
        else:
            fuzz = True   # variable / fuzz-derived — ambiguous, not a deliberate raise
    if raised: return "RAISE"          # unlocks reachability
    if fuzz:   return "fuzz_var"        # may or may not exceed default
    if at_default: return "at_default"  # == cap, does NOT unlock (0x55555555 >> 1e6)
    return "LOWER"                       # actively blocks the bug harder


def rate(verds, good=("RAISE",)):
    hits = sum(v in good for v in verds)
    return hits, len(verds), (hits / len(verds) if verds else 0.0)


out = {"metric": "raises width limit above default 1,000,000 (unlocks reachability)"}

# L0: the neutral harness
l0 = [verdict(t) for t in raw["L0_neutral"]]
# L1b: the harness produced after the blocker analysis
l1b = [verdict(rec["harness"]) for rec in raw["L1_neuro_symbolic"]]
# L2: named-constraint positive control
l2 = [verdict(t) for t in raw["L2_named_blocker"]]

for name, verds in [("L0_neutral", l0), ("L1b_symbolic", l1b), ("L2_named", l2)]:
    h, n, r = rate(verds)
    out[name] = {"verdicts": verds, "raise_hits": h, "n": n, "raise_rate": r}

# L1a analysis: did it name the width/user limit as the blocker? (kept from runner)
out["L1a_analysis_names_limit"] = "5/5 (see run_n5.log; unchanged — analysis is text)"

(HERE / "corrected.json").write_text(json.dumps(out, indent=2))
print("CORRECTED METRIC — raises width limit above default (unlocks the bug):")
for k in ("L0_neutral", "L1b_symbolic", "L2_named"):
    v = out[k]; print(f"  {k:14s} {v['raise_hits']}/{v['n']}  ({v['raise_rate']:.0%})   {v['verdicts']}")
print("  L1a analysis names the limit blocker: 5/5")
