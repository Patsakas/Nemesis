#!/usr/bin/env python3
"""Generate the control arm: random seeds that reach the parser.

Why this exists
---------------
A control arm of uniform random bytes is only fair when the target accepts
arbitrary input. NEMESIS harnesses often do not: the cJSON harness carries five
`continue` gates, and measurement showed only 5.4% of random 27-byte inputs get
past them. An unfiltered random arm would therefore lose before the parser ran,
and "measured seeds beat random seeds" would really mean "measured seeds pass
the entry checks" — a claim about the gates, not about structure.

Rejection sampling equalises the starting line. B and C then share seed count,
seed length, and parser reachability, and the only remaining difference is
whether the bytes have structure. That is the question worth asking.

How acceptance is decided
-------------------------
Not by parsing the harness for predicates — that is brittle and specific to how
they happen to be written. Instead the probe binary is the oracle: run the
candidate and accept it if it reaches a real fraction of what a genuine seed
reaches. This needs no knowledge of the target and works wherever a probe
binary exists.

Why the default is perturbation, not uniform random
---------------------------------------------------
Uniform random bytes cannot form a control for a text format. Measured on
cJSON: zero of 30,000 random 27-byte inputs reached even half the coverage of a
real JSON seed. Not a low rate — none. Random bytes are not valid JSON and
never will be, so an unfiltered random arm would be a strawman and a filtered
one cannot be built at all.

Perturbing a real seed fixes this and is a better control everywhere, including
the binary targets where uniform random *did* work. The measured arm takes a
real seed and changes one measured field; this control takes the same seed and
changes the same number of bytes at random offsets. Both start valid, both make
the same amount of change, and the only difference left is WHERE the change
lands — which is exactly the thing being tested.

Against uniform random the comparison also carries "is a real seed better than
noise", which was never in question.

Usage:
  python scripts/gen_control_seeds.py --probe <probe-bin> --out <dir> \
      --count 30 --like seeds/json/valid.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nemesis.recon.byte_influence import ShowmapRunner  # noqa: E402

# A candidate must reach this share of what a REAL seed covers to count as
# having got into the parser.
#
# An earlier version compared against the floor instead — what a degenerate
# input covers — with a 1.25x margin. On cJSON that floor is 4 edges, so the
# bar sat at 5, and candidates cleared it by picking up a single extra edge on
# the way to being rejected. Only 10 of 30 "accepted" seeds actually passed the
# harness predicates, and their median coverage was 5 against a real seed's 91.
# The control arm would still have been crippled, just less obviously.
#
# Anchoring to a real seed asks the right question: did this input get where
# the genuine one gets?
ACCEPT_FRACTION = 0.5


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True, help="probe binary (recon/probe_build.py)")
    ap.add_argument("--out", required=True, help="directory to write accepted seeds into")
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--length", type=int, default=0,
                    help="seed length in bytes; required unless --like is given")
    ap.add_argument("--like", default="",
                    help="a real seed: sets both the length and the coverage "
                         "bar a candidate must clear (REQUIRED for a fair "
                         "control — see ACCEPT_FRACTION)")
    ap.add_argument("--mode", choices=("perturb", "uniform"), default="perturb",
                    help="perturb (default): mutate the reference seed at random "
                         "offsets — the correct control, since it differs from "
                         "the measured arm only in WHERE the change lands. "
                         "uniform: draw bytes from scratch; only viable on "
                         "targets that accept arbitrary input.")
    ap.add_argument("--mutations", type=int, default=1,
                    help="bytes to perturb per seed in perturb mode. Ignored "
                         "when --match-corpus is given.")
    ap.add_argument("--match-corpus", default="",
                    help="directory of measured seeds to match byte-for-byte. "
                         "For each one, count how many bytes it changed from "
                         "the reference and change the SAME NUMBER at random "
                         "offsets. Without this the arms differ in how much "
                         "they changed, not only in where — a measured seed "
                         "that varied an 8-byte field is not comparable to a "
                         "control that flipped one byte.")
    ap.add_argument("--max-attempts", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=4242, help="RNG seed, for reproducibility")
    ap.add_argument("--stats-out", default="", help="write acceptance stats JSON here")
    args = ap.parse_args()

    length = args.length
    if args.like:
        length = len(Path(args.like).read_bytes())
    if length <= 0:
        print("give --length or --like", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    runner = ShowmapRunner(args.probe, timeout=10)
    work = Path(tempfile.mkdtemp(prefix="control_seeds_"))
    candidate = work / "cand.bin"

    # Floor: what a degenerate input covers — startup plus whatever rejection
    # path the harness takes. Measured rather than assumed, since it varies.
    candidate.write_bytes(b"\x00" * length)
    floor = len(runner.edges_for(candidate))

    if args.like:
        reference = len(runner.edges_for(Path(args.like)))
        threshold = max(reference * ACCEPT_FRACTION, floor + 1)
        print(f"floor {floor} edges, reference seed {reference} edges "
              f"— accepting at or above {threshold:.0f}")
    else:
        # Without a reference the bar can only be "better than nothing", which
        # is too weak to build a fair control from. Allowed, but say so.
        reference = 0
        threshold = floor + 1
        print(f"floor {floor} edges — accepting above {threshold:.0f}")
        print("WARNING: no --like reference given, so the bar is only 'one edge "
              "above a degenerate input'. Candidates can clear that while still "
              "being rejected at an entry check. Pass --like <real seed>.",
              file=sys.stderr)

    rng = random.Random(args.seed)
    base = Path(args.like).read_bytes() if args.like else None

    # Per-seed mutation budget, matched to the measured arm when asked. A
    # measured seed that varied an 8-byte field changed 8 bytes; matching it
    # with a 1-byte flip would compare amount of change, not placement.
    budgets: list[int] = []
    if args.match_corpus and base is not None:
        for f in sorted(Path(args.match_corpus).iterdir()):
            if not f.is_file():
                continue
            d = f.read_bytes()
            if len(d) != len(base):
                continue
            n = sum(1 for x, y in zip(d, base, strict=False) if x != y)
            if n:
                budgets.append(n)
        if budgets:
            print(f"matching {len(budgets)} measured seeds: "
                  f"{min(budgets)}-{max(budgets)} bytes changed "
                  f"(median {sorted(budgets)[len(budgets) // 2]})")
        else:
            print("WARNING: --match-corpus produced no usable budgets; "
                  "falling back to --mutations", file=sys.stderr)

    accepted = attempts = 0
    while accepted < args.count and attempts < args.max_attempts:
        attempts += 1
        if args.mode == "uniform" or base is None:
            data = bytes(rng.randrange(256) for _ in range(length))
        else:
            # Perturb the reference instead of drawing from scratch. See the
            # --mode help: uniform random cannot reach a text parser at all.
            n_mut = budgets[accepted % len(budgets)] if budgets else args.mutations
            data = bytearray(base)
            # Distinct offsets, so n_mut really is the number of bytes changed
            # rather than an upper bound with collisions.
            for pos in rng.sample(range(len(data)), min(n_mut, len(data))):
                data[pos] = rng.randrange(256)
            data = bytes(data)
        candidate.write_bytes(data)
        if len(runner.edges_for(candidate)) >= threshold:
            (out / f"control_{accepted:04d}.bin").write_bytes(data)
            accepted += 1

    rate = accepted / attempts if attempts else 0.0
    print(f"accepted {accepted}/{args.count} after {attempts} attempts "
          f"(acceptance rate {rate:.4%})")

    if accepted < args.count:
        # Not a failure to hide: if random bytes essentially never reach the
        # parser, an "equalised" control cannot be built, and that fact is
        # itself a finding about the target rather than about the seeds.
        print("WARNING: could not fill the control arm. Random input almost "
              "never reaches this parser, so no fair random control exists at "
              "this length — report that rather than using a short arm.",
              file=sys.stderr)

    if args.stats_out:
        Path(args.stats_out).write_text(json.dumps({
            "probe": args.probe, "length": length,
            "floor_edges": floor, "reference_edges": reference,
            "threshold": threshold,
            "requested": args.count, "accepted": accepted,
            "attempts": attempts, "acceptance_rate": rate,
        }, indent=2), encoding="utf-8")

    return 0 if accepted == args.count else 2


if __name__ == "__main__":
    raise SystemExit(main())
