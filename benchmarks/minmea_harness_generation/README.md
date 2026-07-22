# minmea — harness soundness and generation quality

Why a generated harness that compiles, links, runs and reports success can
still be worthless — and what NEMESIS now does about it.

Target: [kosma/minmea](https://github.com/kosma/minmea), NMEA 0183 parser,
pure C, ~2.5k LOC. Unlike libnmea it ships its own ClusterFuzzLite harness.

## Status of everything in this directory

| artifact | executed? |
|---|---|
| `invalid/mistral_small_4_variadic_ub.c` | yes — produced by a real run, kept as a regression fixture |
| `validation/model_verdicts_run*.json` | yes — 7 models, 1 and 3 samples respectively |
| `extract_validation.py` | tested on synthetic log input only |
| `generation_benchmark.py` | **never run end to end.** No results exist yet |

The benchmark script is committed because the protocol it encodes is the point;
its numbers do not exist yet. Do not cite it as a result.

## The failure it documents

Recon selected `minmea_scan`, correctly — it is the varargs core that all nine
`minmea_parse_*` functions delegate to. The architect then generated:

```c
const char *formats[] = { "t", "tT", "tciiiiiiiiiiiiifff",
                          "tiii;iiifiiifiiifiiif", /* … 14 total */ };
for (size_t i = 0; i < 14; i++)
    minmea_scan(buf, formats[i], &output.type, &output.time,
                &output.fval, &output.cval, &output.ival, &output.dval);
```

`minmea_scan(const char *sentence, const char *format, ...)` consumes one
pointer per format character, `;` and `_` excepted. `"tciiiiiiiiiiiiifff"`
needs 18. Six are passed. Every directive past the sixth reads whatever sits in
the varargs area and dereferences it — **undefined behaviour in the harness**,
not a bug in minmea.

That run produced **11 AFL crashes. Zero reproduce under ASan** when replayed
through a standalone build of the same harness. They were artifacts of the
harness's own UB — exactly the false positives a maintainer rejects on sight.

## Model choice does not fix this

Same prompt, same task, completed samples across two runs:

| model | sound / samples |
|---|---|
| `mistralai/mistral-small-4-119b-2603` (the configured architect) | **0 / 3** |
| `z-ai/glm-5.2` | 3 / 3 |
| `openai/gpt-oss-120b` | 2 / 3 |
| `mistralai/mistral-large-3-675b-instruct-2512` | 1 / 3 |
| `qwen/qwen3.5-397b-a17b` | 0 / 1 |
| `nvidia/nemotron-3-ultra-550b-a55b` | 0 / 1 — returned reasoning, not code |
| `poolside/laguna-xs-2.1` | 0 / 1 — invented printf directives, called `va_start` in a non-variadic function |
| `minimaxai/minimax-m3` | 0 completed — timed out |

A better model lowers the rate. Only a check removes the class. Sample sizes
are small; treat this as screening, not an estimate.

## What was added

`nemesis/symbolic/variadic_arity.py`, wired into
`InstrumentedBuilder.build_harness` — the one function every compile path
reaches. Two rules, both agnostic to the format language:

1. the format argument must be statically resolvable (a literal, or a
   single-assignment `const char *f = "...";`). An array element cannot be
   checked, and a fixed argument list cannot match a varying format anyway.
2. once resolved, directives must not exceed the arguments passed.

Rule 2 can over-reject a mini-language where most characters consume nothing.
That is the deliberate direction: a rejected harness is regenerated, an
accepted-but-unsound one silently poisons everything downstream.

The gate first went into `_compile_harness_with_repair`, passed 23 unit tests,
and logged **zero** events in a real run — the harness-variant path calls
`build_harness` directly. `tests/test_harness_validation_integration.py` now
asserts the call happens on the real path, and was verified by deleting the
wiring and watching it go red.

## What the gate then revealed

With the gate active the generator produced a sound but nearly useless harness:

```c
char type[6] = {0};
minmea_scan(buf, "t", type);      /* one directive, one argument */
```

Its own comment: *"the only format that can be safely used in a variadic call
without knowing the exact argument list."* Line coverage of `minmea_scan`:
**21.35%**.

Refinement iteration 1 rewrote it to nine calls covering every directive plus
one three-directive format, reaching **76.56%** — a 3.6× gain, with no
coverage-aware feedback at any point.

The run recorded neither number. It exited on AFL bitmap growth 2ms after the
check, before measuring. Both figures above were measured afterwards by hand,
replaying the saved corpus through a clean instrumented build.

That is two distinct findings, and they motivated the changes in
`nemesis/pipeline.py`:

- the quality score had **no exploration term**. On these two harnesses it read
  0.8824 → 1.0000, and the entire rise came from AFL map density; reachability
  was saturated at 100% in both and `corpus_paths` was past its cap. Line
  coverage contributed zero. A harness adding eight calls that all fail
  immediately would have scored the same.
- bitmap expansion was a terminal success condition rather than a signal to
  measure. Had coverage *fallen*, that path would have been equally satisfied.

## Reproducing the model comparison

```sh
python benchmarks/minmea_harness_generation/generation_benchmark.py \
    config/targets/minmea.yaml out.json screening
```

`screening` is n=10 with repair budget 1; `evaluation` is n=30 with budget 2.
Recon and the analysis context are computed once and reused, so the architect
model is the only variable. Every report carries `evaluation_valid` — a
degraded provider endpoint inflates latency and truncates samples, and results
gathered through one are not comparable with results gathered through a healthy
one.
