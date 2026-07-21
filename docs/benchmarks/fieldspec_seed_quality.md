# Seed-quality benchmark — measured fieldspec vs the alternatives

Reproduce with `scripts/bench_fieldspec.py`. No LLM call, no fuzzing campaign,
fixed RNG — runs in minutes and is deterministic.

## What is measured

Given 40 seeds generated from each source, how much of the target do they reach?
Coverage of the generated corpus is a leading indicator for fuzzing outcome
(Rebert 2014: ~1% more coverage correlates with ~0.92% more bugs found) and is
measurable without a campaign.

Arms:

| arm | what it is |
|---|---|
| `original` | the single real seed the spec was measured from — what we already had |
| `random` | uniform random bytes, same length — the floor |
| `all-at-once` | one spec varying **every** measured field simultaneously |
| `measured` | one spec **per field**, the rest held at observed values |

All arms are run against a *probe binary* (`nemesis/recon/probe_build.py`), never
the AFL fuzzing binary — that one receives no input outside `afl-fuzz` and reports
identical coverage for every seed.

## Results

40 seeds per arm. Probe seed chosen by measured parser depth.

| target | probe seed | influential bytes | | `original` | `random` | `all-at-once` | `measured` |
|---|---|---|---|---|---|---|---|
| **libtiff** | 2504 B | 294/2504 (11.7%) | unique edges | 378 | 3 | 207 | **237** |
| | | | mean/seed | 378.0 | 3.0 | 24.1 | **220.2** |
| | | | distinct sets | 1 | 1 | 7 | 4 |
| **libpng** | 325 B | 296/325 (91.1%) | unique edges | 304 | 91 | 91 | **280** |
| | | | mean/seed | 304.0 | 91.0 | 91.0 | **234.2** |
| | | | distinct sets | 1 | 1 | 1 | 11 |
| **cJSON** | 27 B | 27/27 (100%) | unique edges | 104 | 29 | 43 | **112** |
| | | | mean/seed | 104.0 | 4.6 | 5.7 | **44.6** |
| | | | distinct sets | 1 | 4 | 5 | 4 |

## Reading these

**Varying one field at a time is what makes measured structure usable.** libpng
shows this most starkly: `all-at-once` is *identical* to `random` on every metric.
Rendering boundary values into all ten measured fields destroys the 8-byte PNG
signature, so those seeds are rejected at exactly the point uniform noise is, and
the arm carries no information at all. On libtiff the same mistake still reached
207 edges only because its header survived more often.

**The margin tracks how much of the input is inert.** The influential-byte
fraction spans 11.7% (libtiff, large compressed payload) to 100% (cJSON, a
character-by-character parser). Where most bytes matter, knowing which ones do
buys little — the measured spec earns its cost on binary container formats, and
that is the honest scope of the claim.

**Generated seeds do not replace real ones.** On libtiff and libpng the measured
arm stays below the seed it was derived from (237 vs 378, 280 vs 304); only on
cJSON does it exceed it. These are exploration inputs, and the corpus they belong
in is the union with the real ones, not a substitute for them.

**Distinct edge sets are a weak metric here.** Seeds differing in one field reach
the same deep code and look alike, so the count stays low even when mean coverage
per seed is 9x higher. A corpus of 20 deep seeds beats 100 shallow ones; the
fuzzing A/B should measure paths and crashes, not corpus diversity.

## Fuzzing campaign — the measured advantage does not survive a matched control

**Headline: measured field structure gives no benefit over changing the same
number of bytes at random positions.** An earlier version of this campaign
reported the opposite. That control was wrong.

libpng, 4 minutes per run, 5 repeats per arm. Arms are matched on seed count
(25), seed length, reference seed, and number of bytes changed (median 8, range
1–128). The only difference is *where* the changes land.

| arm | | per-run edges found |
|---|---|---|
| A | real corpus only | 311, 312, 312, 312, 418 |
| B | + seeds varying **measured** fields | 469, 470, 471, 471, 500 |
| C | + seeds varying **random** positions | 471, 471, 471, 471, 494 |

| comparison | pairs | exact p | |
|---|---|---|---|
| **B vs C** | 5/25 for B, 12/25 for C | **0.635** | **no difference** |
| B vs A | 25/25 | 0.008 | significant |
| C vs A | 25/25 | 0.008 | significant — *the control does this too* |

### What changed and why the first result was wrong

The first campaign used uniform random bytes as the control. Those are not
valid PNGs: they die at the 8-byte signature check, exactly where noise dies.
So `B vs C` was really asking "are structured seeds better than garbage?", and
the answer to that was never in doubt. It reported p = 0.008 and it measured
the wrong thing.

Replacing the control with *the same reference seed, the same number of bytes
changed, at random offsets* removes that confound. The difference disappears:
p = 0.635, with the control ahead in more pairings than the measured arm.

### What the data does support

Adding valid perturbations of a real seed helps a lot — both B and C beat the
baseline in every pairing at p = 0.008, moving 312 edges to ~471. That is a
real effect and it is worth having.

But it comes from the seeds being **valid variations of a real input**, not from
knowing which bytes steer control flow. On this target, at this budget, the
measured field structure contributed nothing detectable beyond that.

### Scope of this negative result

One target, one budget, five repeats, coverage rather than crashes. It does not
show that byte-influence inference is worthless — the structure it recovers is
real and verifiable (see the sections above). It shows that *using that
structure to place mutations in generated seeds* did not beat placing them at
random, which was the specific claim being tested.

### libpng had almost no room to show a difference

Choosing libpng for this test was a design error, visible in numbers that were
already published here before the campaign ran.

If a share *p* of a file's bytes influence control flow, then a **random**
position already lands on an influential byte *p* of the time. Measured
placement can only win in the remaining `1 − p`:

| target | influential bytes | random hits one | **selection advantage** |
|---|---|---|---|
| **libpng** ← tested here | 296/325 = 91.1 % | 91.1 % | **8.9 %** |
| cJSON | 27/27 = 100 % | 100 % | **0 %** |
| libtiff | 294/2504 = 11.7 % | 11.7 % | **88.3 %** |

On libpng the control was picking influential bytes nine times out of ten by
accident. A null result there is close to guaranteed whether or not the method
has value, so this experiment had little power to detect the effect it was
built to test.

This does not retract the result. On libpng, at this budget, measured placement
added nothing — that was measured and it stands. What it does not support is the
general claim that measured placement never helps.

### Prediction, recorded before the libtiff run

libtiff is the target where the effect must appear if it exists: a random
position misses 88 % of the time there, so the control is a real opponent rather
than a near-equivalent.

> **If measured placement has value, libtiff is where it shows. If B does not
> beat C there either, the placement hypothesis fails generally — there is no
> remaining headroom to appeal to.**

Same protocol, same matched control, no changes to the method.

## Fuzzing campaign (superseded — uniform-random control)

Seed coverage is a leading indicator. This is the campaign that tests whether it
translates into fuzzing. Reproduce with `scripts/bench_campaign.sh` and
`scripts/bench_report.py`.

libpng, 8 real seeds, 4 minutes per run, 5 repeats per arm:

| arm | | edges found (median [range]) |
|---|---|---|
| A | real corpus | 312 [311–428] |
| B | real + 30 measured seeds | **398 [383–398]** |
| C | real + 30 random seeds | 312 [311–321] |

| comparison | pairs favouring first | exact p | |
|---|---|---|---|
| **B vs C** | 25/25 | **0.008** | same seed count, different content |
| B vs A | 20/25 | 0.151 | confounded — more seeds *and* different seeds |
| C vs A | 12/25 | 0.952 | control: adding seeds alone changes nothing |

> **Superseded.** The control in this run was uniform random bytes, which are
> not valid PNGs and fail at the signature check. The comparison therefore
> measured "structure vs garbage" rather than "measured placement vs random
> placement". Kept for the record; see the matched-control campaign above for
> the corrected result.

**B vs C was read as the comparison that answers the question.** Both arms carry
38 seeds, so a difference between them can only come from *which* seeds. Every
one of the 25 pairings favours the measured corpus, at p = 0.008. This is the
number the matched control later overturned.

**C vs A is the control, and it behaves.** Thirty extra random seeds moved
nothing (12/25 pairs, p = 0.95), so the gain in B is not "more seeds".

**B vs A does not reach significance** (p = 0.15) because of a single baseline
run that reached 428 edges while the other four sat at 311–312. That run is not
an error — AFL is stochastic and one run found a productive path the others
missed — but it is enough to make the ranges overlap at five repeats. Note this
comparison is confounded anyway: A has 8 seeds against B's 38.

### What this does and does not show

It shows that at a four-minute budget on libpng, a corpus enriched with measured
seeds explored more than the same-sized corpus enriched with random ones, and
that the difference is unlikely to be chance.

It does not show faster bug discovery. **No arm produced a single crash**, which
is expected at four minutes on a hardened libpng and means the metric that
matters most is untested. It is one target, one budget, five repeats. The
`--sensitivity` output on this data also reports that the plateau diagnosis flips
across its threshold grid, so no claim is made about whether the budget truncated
any arm.
