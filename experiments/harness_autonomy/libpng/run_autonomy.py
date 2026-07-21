#!/usr/bin/env python3
"""Harness autonomy / provenance experiment for CVE-2018-13785.

Tests whether the LLM DISCOVERS png_set_user_limits (neuro-symbolic) or merely
REPLAYS it from a saved harness. Three assistance levels, N reps each, scored on
whether the generated code contains png_set_user_limits. See README.md.

Faithful to production: model = NEMESIS architect (mistral-small-4-119b), temp 0.2.
No leakage: the libpng harness_template and saved harnesses are never loaded.
"""
import json, os, re, sys, time, pathlib, urllib.request, urllib.error

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]           # experiments/harness_autonomy/libpng -> repo root
MODEL = "mistralai/mistral-small-4-119b-2603"
URL = "https://integrate.api.nvidia.com/v1/chat/completions"
TEMP, MAXTOK, N = 0.2, 16384, int(os.environ.get("N", "5"))
NEEDLE = "png_set_user_limits"


def load_key():
    for line in (REPO / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("NVIDIA_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    sys.exit("NVIDIA_API_KEY not found in .env")


def extract_generic_system():
    """Pull HARNESS_STRATEGY_A_SYSTEM verbatim from the source (no import)."""
    src = (REPO / "nemesis" / "neural" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'HARNESS_STRATEGY_A_SYSTEM\s*=\s*"""(.*?)"""', src, re.DOTALL)
    if not m:
        sys.exit("could not extract HARNESS_STRATEGY_A_SYSTEM")
    return m.group(1).strip()


def chat(key, system, user):
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": TEMP, "max_tokens": MAXTOK,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "Accept": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                data = json.loads(r.read())
            return data["choices"][0]["message"]["content"]
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError) as e:
            if isinstance(e, urllib.error.HTTPError):
                sys.stderr.write(f"  HTTP {e.code}: {e.read()[:300].decode(errors='ignore')}\n")
            if attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


def has_call(text):
    return NEEDLE in (text or "")


def mentions_limit_bypass(text):
    """Does the blocker analysis identify raising the width/user limit as the bypass?"""
    t = (text or "").lower()
    return ("user_width_max" in t or "user limit" in t or "width limit" in t
            or "width_max" in t) and ("raise" in t or "increase" in t or "larger"
            in t or "bypass" in t or "exceed" in t or "set" in t or "limit" in t)


API = (HERE / "input" / "api_subset.txt").read_text(encoding="utf-8")
SNIPPETS = (HERE / "input" / "source_snippets.txt").read_text(encoding="utf-8")
BLOCKER_SYS = (REPO / "prompts" / "blocker_analysis.md").read_text(encoding="utf-8")
GENERIC_SYS = extract_generic_system()

OUTFMT = ('\n\nReturn ONLY JSON: {"c_code": "<complete AFL++ harness C source>", '
          '"rationale": "<one paragraph: what setup the PNG read path needs and why>"}')

# ---- L0: neutral, LLM-only. No source, no blocker, no CVE. ----
L0_USER = f"""Target library: libpng 1.6.34.

Public read-path API available to you:
{API}

Goal: write an AFL++ persistent-mode harness that fuzzes the PNG reading path
(png_create_read_struct -> png_read_info -> png_read_image) on an in-memory PNG
supplied by the fuzzer. Exercise the decoder thoroughly.{OUTFMT}"""

# ---- L1 step A: blocker analysis over the source (discover the guard). ----
L1A_USER = f"""Target function: png_check_chunk_length (pngrutil.c), on the IDAT path.
Its divide-by-zero branch has 0% fuzzing coverage.

Call chain and source:
{SNIPPETS}

Analyze per your task: why is the vulnerable branch unreachable in a normal
fuzzing run, and what is the minimal change to a fuzzing harness that would make
it reachable? Be specific about the guard that stops it."""

# ---- L2: constraint named (NOT the API). Positive control for recall. ----
L2_USER = f"""Target library: libpng 1.6.34.

Public read-path API available to you:
{API}

NOTE: png_check_IHDR rejects any image whose width exceeds user_width_max
(default 1,000,000) with "Image width exceeds user limit", which aborts the read.
To reach code paths that need a large declared width, your harness must raise that
per-struct limit before calling png_read_info.

Goal: write an AFL++ persistent-mode harness that fuzzes the PNG reading path and
CAN reach large-width code paths.{OUTFMT}"""


def run():
    key = load_key()
    results = {"model": MODEL, "temp": TEMP, "N": N, "levels": {}}
    raw = {}

    def do_level(name, system, user, scorer, reps=N):
        hits, texts = 0, []
        print(f"\n=== {name} (N={reps}) ===")
        for i in range(reps):
            out = chat(key, system, user)
            h = scorer(out)
            hits += int(h)
            texts.append(out)
            print(f"  rep {i+1}: {'HIT ' + NEEDLE if h else 'no ' + NEEDLE}")
        results["levels"][name] = {"hits": hits, "reps": reps, "rate": hits / reps}
        raw[name] = texts
        return texts

    # L0
    do_level("L0_neutral", GENERIC_SYS, L0_USER, has_call)

    # L1: two-step per rep (analysis -> harness), scored separately
    print(f"\n=== L1_neuro_symbolic (N={N}) ===")
    l1a_hits = l1b_hits = 0
    l1_texts = []
    for i in range(N):
        analysis = chat(key, BLOCKER_SYS, L1A_USER)
        a_hit = mentions_limit_bypass(analysis)
        # step B: neutral harness gen WITH the analysis appended as findings
        b_user = (L0_USER + "\n\nStatic-analysis findings for this target:\n"
                  + analysis[:4000])
        harness = chat(key, GENERIC_SYS, b_user)
        b_hit = has_call(harness)
        l1a_hits += int(a_hit); l1b_hits += int(b_hit)
        l1_texts.append({"analysis": analysis, "harness": harness})
        print(f"  rep {i+1}: analysis_names_limit={a_hit}  harness_has_call={b_hit}")
    results["levels"]["L1a_analysis_names_limit"] = {"hits": l1a_hits, "reps": N, "rate": l1a_hits / N}
    results["levels"]["L1b_harness_has_call"] = {"hits": l1b_hits, "reps": N, "rate": l1b_hits / N}
    raw["L1_neuro_symbolic"] = l1_texts

    # L2 positive control
    do_level("L2_named_blocker", GENERIC_SYS, L2_USER, has_call)

    (HERE / "results" / "results.json").write_text(json.dumps(results, indent=2))
    (HERE / "results" / "raw_responses.json").write_text(json.dumps(raw, indent=2)[:2_000_000])

    print("\n" + "=" * 56 + "\nSUMMARY (rate = png_set_user_limits appearance)")
    for k, v in results["levels"].items():
        print(f"  {k:32s} {v['hits']}/{v['reps']}  ({v['rate']:.0%})")
    print("=" * 56)


if __name__ == "__main__":
    run()
