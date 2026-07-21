# Harness Reachability A/B — libpng CVE-2018-13785

## Claim this benchmark supports (and the one it does NOT)

**Supported (proven here):**

> A semantically-aware fuzzing harness can make a vulnerability *reachable* that
> a naive harness cannot — with the harness as the only variable.

**NOT claimed here** (see the provenance caveat below):

> ~~The LLM discovers the required semantic setup on its own.~~

Those are two different contributions. This directory isolates the first. The
second is tested separately in `experiments/harness_autonomy/libpng/`.

## The setup — one variable

| | Arm A (`arm_a_naive.c`) | Arm B (`arm_b_nemesis.c`) |
|---|---|---|
| library | libpng 1.6.34 | libpng 1.6.34 (same checkout) |
| compiler / flags | clang -g -O0 | clang -g -O0 (identical) |
| input | `trigger.png` | `trigger.png` (same file) |
| sequence | create → read_info → read_image | create → read_info → read_image |
| **the one difference** | default limits | **`png_set_user_limits(png_ptr, 0x7FFFFFFF, …)`** |

Everything except that single call is byte-identical. `diff arm_a_naive.c
arm_b_nemesis.c` is the whole experiment.

## Result (reproduced by `run_ab.sh ~/libpng_work`)

```
=== same trigger.png, same libpng, one-line harness difference ===
libpng warning: Image width exceeds user limit in IHDR
libpng error: Invalid IHDR data
arm A naive        exit=0   no signal -> NOT triggered (rejected before divide)
arm B NEMESIS      exit=136 SIGFPE  -> TRIGGERED (reached the divide)
```

Arm A: `png_check_IHDR` rejects width `0x55555555` (> default cap 1,000,000) and
`png_error` longjmps out before the `row_factor` divide. Arm B: the raised cap
lets the width through; `row_factor` wraps to 0 in 32-bit arithmetic and
`PNG_UINT_32_MAX / row_factor` is a divide-by-zero (SIGFPE). Same input, same
library — the harness is the only thing that changed. **Confound-free.**

## Why this is a real result and not the confounded "60 s rediscovery"

The README's old libpng "60 s" number used NEMESIS's custom mutator, which
**hardcodes** the trigger constant `0x55555555` (`templates/mutator/adapters/png.c`)
— the human handed the fuzzer the answer. That is retracted. This A/B uses **no
mutator**: it feeds one fixed input to two harnesses and measures reachability.
The variable is the harness, nothing else.

## Provenance caveat — do NOT read this as "autonomous discovery"

`png_set_user_limits` is a good idea, but *whose* idea? It also appears in a saved
harness (`config/targets/libpng/harnesses/png_check_chunk_length.c`), so NEMESIS
could be *replaying* it rather than *reasoning* it. This benchmark cannot tell the
difference — it only shows the call *works*.

The companion experiment `experiments/harness_autonomy/libpng/` settles the
provenance under a no-leakage protocol (N=5, mistral-small, scored on whether the
harness *raises* the width limit above the default — the direction that actually
unlocks the bug, not just whether the function name appears). Measured result
(**outcome C**):

| condition | raises the limit → unlocks bug |
|---|---|
| L0 — neutral goal, LLM only | **0/5** |
| L1 — LLM + guard/overflow source surfaced (fix NOT named) | **3/5** (blocker identified 5/5) |
| L2 — constraint named in prose | **5/5** |

From a neutral goal the model **never** raises the limit — even though it clearly
knows `png_set_user_limits` exists (it reaches for it 60% of the time, but to
*lower* the cap as generic hardening). Only when a symbolic/source layer surfaces
the guard does it point the call the right way.

So the honest framing is **neuro-symbolic, not autonomous**: the symbolic layer
supplies the *direction* of the fix; the LLM synthesizes the API call. Neither
alone suffices. The word "autonomous discovery" stays out of the writeup.

## Reproduce

```bash
# needs a libpng 1.6.34 checkout with a generated pnglibconf.h
bash run_ab.sh /path/to/libpng            # e.g. ~/libpng_work
```
Oracle is the signal number (SIGFPE = 8), so no sanitizer or symbolizer is
involved — nothing to hang off-TTY.
