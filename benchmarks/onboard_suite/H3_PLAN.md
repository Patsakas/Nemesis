# H3 Stage 2 — T3 feasibility (pre-registered)

Written before the experiment and before the endpoint recovers. This is **not a model
benchmark**. It asks one question:

> **Can an unknown genuine artifact be turned autonomously into a compilable fuzz harness,
> on even one or two real projects?**

That threshold, not 25/25 builds, is what changes NEMESIS from a build-acquisition framework
into an autonomous fuzzing tool. The benchmark records **T3 = 0/25 in every run to date**,
including the v1 run whose provider chain was intact, so the wall is real and independent of
the 2026-07-27 outage.

## 1. Why it is framed as feasibility, not benchmarking

`16 tokens → "ok"` measures nothing that matters here. The measured chain is:

```
T2 genuine artifact  →  real harness prompt (~20K tokens)  →  valid structured output
                     →  compile succeeds  →  T4
```

Stage 1 (2026-07-27) did its only job — eliminating dead paths — and cannot pick a winner.
It is on record that small-prompt latency misleads on exactly this workload: DeepSeek-V4-Pro
answers a trivial prompt in 33 s and was dropped in May for tripping the circuit breaker on
22K-token harness prompts.

## 2. Dataset — qualification gate first

The seven genuine-T2 repositories, split by what a failure would tell us:

| Group | Repos | Role |
|---|---|---|
| **Primary** | astera, gensio, libdc | real artifact, real API surface, genuinely hard harness generation |
| **Secondary** | tiny-AES-c, bcg729, pg_ivm | easier or special cases — tiny-AES-c and bcg729 are small single-library targets; pg_ivm is the `.so` case |
| **Held out** | onomondo-uicc | untouched until a chain decision is fixed, then used once to confirm it |

The reserve exists because H2b showed how quickly small *n* manufactures confidence. If a
result looks decisive across six repositories, onomondo-uicc is one that no choice was tuned
against — and it is a useful one, being the only other repo with a concretely pinned function
in its frozen config.

**Staged execution, to avoid burning 20K-token prompts on a dead end:**

```
Stage 2A   gpt-oss-120b  ×  astera, gensio, libdc
              |
     compile rate > 0  ──yes──>  Stage 2B: full model matrix × primary + secondary
              |
              no
              |
              v
     STOP. Analyse failure modes before spending anything further.
```

A compile rate of zero for the baseline model on the primary group is itself the finding, and
it is cheaper to read than four models × seven repositories.

## 2a. Baseline arm — a deterministic control for the pipeline itself

Before any model is judged, the pipeline must be shown to work. This is the T3 analogue of
the frozen control: **if a known-good harness fails to get through, the experiment is
measuring infrastructure, not generation.**

Fixtures already committed to this repository, used as-is:

| Fixture | Expected |
|---|---|
| `benchmarks/libnmea_harness_e2e/harnesses/nmea_parse.c` | **passes every stage** |
| `benchmarks/libnmea_harness_e2e/harnesses/nmea_load_parsers.BROKEN.c` | **rejected** — it declares that it does not feed the fuzz buffer to the parser |
| `benchmarks/minmea_harness_generation/invalid/mistral_small_4_variadic_ub.c` | **rejected** — known-invalid, variadic UB |

A positive fixture alone would only show the pipeline says *yes*. The negatives show it can
say *no*, and they fail at different depths: the variadic case should die at validation or
compile, while the BROKEN nmea harness plausibly **compiles and links and still is not a
fuzzer**, because its defect is semantic. Establishing exactly where each one dies is part of
the baseline's job, and it defines the pipeline's discrimination before any model output is
scored against it.

**Gate:** if the positive fixture does not pass, or a negative one is accepted, Stage 2 does
not run. A model cannot be blamed for a stage that is broken or blind.

## 3. Model matrix

| Model | Why it is in |
|---|---|
| `openai/gpt-oss-120b` | baseline; the only model with recorded success on this workload |
| `z-ai/glm-5.2` | new candidate, alive, unproven here |
| `deepseek-ai/deepseek-v4-pro` | strong reasoning, **known prior failure at 22K tokens** — included precisely to test whether that still holds |
| `groq/llama-3.3-70b-versatile` | cross-vendor control; isolates "NVIDIA endpoint" from "model" |

Not included: `google/gemma-4-31b-it` (returned empty content under thinking — an ambiguous
signal, and an ambiguous signal is not a candidate) and `deepseek-ai/deepseek-v4-flash`
(timed out at 180 s in all three documented invocation forms).

## 4. The frozen-prompt invariant

> The request is identical across models. Only `provider/model` varies.

Same harness request, temperature, `max_tokens`, timeout, and the **same parser** on the way
out. If a model needs a different prompt to succeed, that is a finding about prompt
engineering and must be reported as a separate experiment — folding it in silently would mean
the arms no longer differ in one variable, which is the same defect the frozen-config
invariant exists to prevent.

## 5. Metrics

A ladder, because each rung fails for a different reason and collapsing them would hide which
one the model actually hit:

| Rung | Metric | What a failure here means |
|---|---|---|
| 1 | completion rate | the model answered at all, rather than timing out |
| 2 | valid output rate | it followed the output contract (schema) |
| 3 | **compile rate** | it produced real code — right includes, right syntax |
| 4 | link rate | it used APIs that actually exist in the artifact |
| 5 | **smoke pass rate** | the harness consumes the fuzz input and runs — the only rung that approaches T4 |

Rungs 3 and 5 are the ones that decide. A schema-valid harness that does not compile has not
solved T3; a harness that compiles and links but ignores the fuzz buffer is not a fuzzer —
which is precisely what the BROKEN baseline fixture is there to prove the pipeline can detect.

Time to valid harness is recorded as a descriptive tertiary figure, not as a criterion, and
never as raw latency.

## 6. Congestion is a censored observation, not a failure

The endpoint was visibly degraded when Stage 1 ran: `mistral-medium` needed **827.7 s** for a
one-token reply. Under those conditions a capable model times out and would be recorded as
incapable — the same error class as gifsicle's configure failure in H2b, and it gets the same
treatment:

```
model capable  →  provider overloaded  →  timeout  →  classified as failure   ✗ WRONG
```

**Pre-registered rule.** Before each arm, a health check: three consecutive one-token replies
from `openai/gpt-oss-120b` in under 15 s each. If it fails, the run does not start. Any
timeout during a run is classified `censored`, never `failed`, and the repository is re-run
once the health check passes again. Censored observations are reported in their own row and
never absorbed into either direction.

## 7. What this experiment cannot settle

T3 plausibly has several stacked constraints — model capability, prompt-size handling, context
window, output-format discipline, and knowledge of the build environment. A perfect model
still fails if it writes the wrong includes, assumes an API that does not exist, or emits a
harness that satisfies the schema but not the compiler.

So a null result here does **not** mean "no model can do this". It means the constraint is not
(only) model choice, and the next work is harness generation as a subsystem rather than
provider selection.

**The failure mode this section exists to prevent:** turning T3 into a search for the right
LLM. If Stage 2 returns T3 = 0 across four models, that is the answer, and the response is to
study harness generation — not to try a fifth model.

## 8. Decision rule, fixed in advance

- **T3 > 0 on Group B, reproducibly** → the chain is settled by measurement, and H2c/d/e
  become worthwhile: enlarging the genuine-T2 population now feeds a stage that can consume it.
- **T3 = 0 across all four models** → stop provider work. Do **not** run H2c/d/e; more
  repositories in front of a closed door is not progress. Harness generation becomes its own
  hypothesis series.

---

*Prerequisite completed 2026-07-27: the provider chain was repaired (`d103ba1`) after three of
six entries were found dead. That repair is maintenance and its architect choice is
provisional — this experiment is what decides it.*
