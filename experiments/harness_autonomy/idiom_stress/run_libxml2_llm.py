#!/usr/bin/env python3
"""Layer-2 (LLM) recovery test for the idiom-stress experiment — libxml2 Case C.

The deterministic extractor (Layer 1) finds 0 setters in libxml2: its relaxation
mechanism is the PARSE FLAG `XML_PARSE_HUGE`, not a `_set_*_max` function, so no
name-idiom heuristic can ever reach it. This asks whether the LLM (Layer 2)
recovers it: given the HUGE-gated guard source, does it identify XML_PARSE_HUGE as
the relaxation lever and say to apply it in the harness (via the parse options)?

Leakage note: the guard snippet contains `XML_PARSE_HUGE` in the ternary (that is
how libxml2 writes the guard). So this measures recognition + application, not
blind discovery — the same bridge tested for libpng (field visible, API not).
"""
import json, os, re, sys, time, pathlib, urllib.request, urllib.error

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
MODEL = "mistralai/mistral-small-4-119b-2603"
URL = "https://integrate.api.nvidia.com/v1/chat/completions"
TEMP, MAXTOK, N = 0.2, 8192, int(os.environ.get("N", "5"))


def load_key():
    for line in (REPO / ".env").read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("NVIDIA_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    sys.exit("NVIDIA_API_KEY not in .env")


def chat(key, system, user):
    body = json.dumps({"model": MODEL, "messages": [
        {"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": TEMP, "max_tokens": MAXTOK}).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())["choices"][0]["message"]["content"]
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            if attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


BLOCKER_SYS = (REPO / "prompts" / "blocker_analysis.md").read_text(encoding="utf-8")
GUARD = (HERE / "input" / "libxml2_guard.c").read_text(encoding="utf-8")

USER = f"""Target: xmlParseNameComplex in libxml2 parser.c. Deep-name / long-name
code paths past the length check have 0% fuzzing coverage.

Source:
```c
{GUARD}
```

The harness calls xmlReadMemory(buf, len, "n", NULL, 0) with default options.
Analyze: why is the long-name path unreachable with default options, and what is
the minimal harness change that makes it reachable? Name the specific option/flag."""


def scores(t):
    tl = (t or "").lower()
    return {
        "names_HUGE": "xml_parse_huge" in tl,
        "applies_via_options": any(k in tl for k in
            ["xmlreadmemory", "xmlctxtuseoptions", "xmlctxtsetoptions",
             "options", "third argument", "flags argument"]),
    }


def run():
    key = load_key()
    recs, huge, applied = [], 0, 0
    print(f"=== libxml2 Case C — Layer-2 LLM recovery (N={N}) ===")
    for i in range(N):
        out = chat(key, BLOCKER_SYS, USER)
        s = scores(out)
        huge += s["names_HUGE"]; applied += s["names_HUGE"] and s["applies_via_options"]
        recs.append({"scores": s, "text": out})
        print(f"  rep{i+1}: names XML_PARSE_HUGE={s['names_HUGE']}  applies_via_options={s['applies_via_options']}")
    res = {"target": "libxml2", "case": "C (flag, not setter)", "N": N,
           "names_HUGE": huge, "applies_correctly": applied}
    (HERE / "libxml2_llm_result.json").write_text(json.dumps({"summary": res, "raw": recs}, indent=2)[:1_500_000])
    print(f"\nSUMMARY: names XML_PARSE_HUGE {huge}/{N};  names+applies correctly {applied}/{N}")


if __name__ == "__main__":
    run()
