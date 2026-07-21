#!/usr/bin/env python3
"""Mechanism-inference ladder (libxml2) — where does the LLM's Case-C success
come from? Three difficulty levels, same model/temp/N, blocker-analysis prompt.

  L1 recognition       : the guard shows `options & XML_PARSE_HUGE` verbatim.
  L2 nearby inference  : the guard uses an ALIAS; `#define ALIAS XML_PARSE_HUGE`
                         sits elsewhere in the same snippet — two points to join.
  L3 mechanism inference: the guard shows ONLY a hardcoded `maxLength =
                         XML_MAX_NAME_LENGTH` reject. No flag, no option, no
                         setter anywhere. Does the model infer that a separate
                         configuration mechanism exists that relaxes it?

Neutral term: "mechanism inference", not "blind discovery".

CONFOUND (stated up front): libxml2 is famous; at L3 a model may RECALL
XML_PARSE_HUGE from priors rather than INFER a mechanism from the guard. So L3
success here conflates inference with recall — a clean L3 needs an obscure library.
The L1->L2->L3 CONTRAST is still informative: a drop shows dependence on the flag
being present; no drop suggests recall is doing the work.
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
    sys.exit("no key")


def chat(key, system, user):
    body = json.dumps({"model": MODEL, "messages": [
        {"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": TEMP, "max_tokens": MAXTOK}).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    for a in range(3):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())["choices"][0]["message"]["content"]
        except (urllib.error.URLError, urllib.error.HTTPError):
            if a == 2:
                raise
            time.sleep(5 * (a + 1))


BLOCKER_SYS = (REPO / "prompts" / "blocker_analysis.md").read_text(encoding="utf-8")

# ---- guard variants (derived from libxml2 parser.c xmlParseNameComplex) ----
_L1 = """static const xmlChar *
xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
    int len = 0, l, c;
    int maxLength = (ctxt->options & XML_PARSE_HUGE) ?
                    XML_MAX_TEXT_LENGTH :   /* 10000000 */
                    XML_MAX_NAME_LENGTH;    /* 50000    */
    /* ... consume name characters, accumulating len ... */
    if (len > maxLength) {
        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Name");
        return(NULL);
    }
    /* ... deeper long-name handling (0% coverage) ... */
}"""

_L2 = """/* near the top of parser.c: */
#define NAME_LIMIT_OVERRIDE  XML_PARSE_HUGE

/* ... hundreds of lines later ... */
static const xmlChar *
xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
    int len = 0, l, c;
    int maxLength = (ctxt->options & NAME_LIMIT_OVERRIDE) ?
                    XML_MAX_TEXT_LENGTH : XML_MAX_NAME_LENGTH;
    /* ... consume name characters, accumulating len ... */
    if (len > maxLength) {
        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Name");
        return(NULL);
    }
    /* ... deeper long-name handling (0% coverage) ... */
}"""

_L3 = """static const xmlChar *
xmlParseNameComplex(xmlParserCtxtPtr ctxt) {
    int len = 0, l, c;
    int maxLength = XML_MAX_NAME_LENGTH;   /* 50000 */
    /* ... consume name characters, accumulating len ... */
    if (len > maxLength) {
        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Name");
        return(NULL);
    }
    /* ... deeper long-name handling (0% coverage) ... */
}"""


def user_prompt(guard):
    return (f"Target: xmlParseNameComplex in libxml2 parser.c. The long-name path "
            f"past the length check has 0% fuzzing coverage.\n\nSource:\n```c\n{guard}\n```\n\n"
            f"The harness calls xmlReadMemory(buf, len, \"n\", NULL, 0) with default "
            f"options. Analyze: why is the long-name path unreachable, and what is the "
            f"minimal harness change (not a source patch) that makes it reachable?")


def score(t):
    tl = (t or "").lower()
    names_huge = "xml_parse_huge" in tl
    config_opt = names_huge or (("huge" in tl or "parse option" in tl or "parser option" in tl)
                 and any(k in tl for k in ["option", "xmlreadmemory", "xmlctxtuseoptions", "flag"]))
    src_patch = any(k in tl for k in ["recompile", "modify the #define", "change xml_max",
                    "redefine", "edit the source", "patch the constant", "increase xml_max"])
    return {"names_HUGE": names_huge, "config_option": config_opt, "source_patch": src_patch}


def run():
    key = load_key()
    out = {"model": MODEL, "N": N, "levels": {}}
    for name, guard in [("L1_recognition", _L1), ("L2_nearby", _L2), ("L3_mechanism", _L3)]:
        hits = {"names_HUGE": 0, "config_option": 0, "source_patch": 0}
        raw = []
        print(f"\n=== {name} (N={N}) ===")
        for i in range(N):
            r = chat(key, BLOCKER_SYS, user_prompt(guard))
            s = score(r)
            for k in hits:
                hits[k] += int(s[k])
            raw.append({"score": s, "text": r})
            print(f"  rep{i+1}: HUGE={s['names_HUGE']} config_opt={s['config_option']} src_patch={s['source_patch']}")
        out["levels"][name] = {"hits": hits, "raw": raw}
    (HERE / "mechanism_inference_result.json").write_text(json.dumps(out, indent=2)[:2_000_000])
    print("\n" + "=" * 56 + "\nLADDER (names XML_PARSE_HUGE / proposes config option / proposes source patch)")
    for k, v in out["levels"].items():
        h = v["hits"]
        print(f"  {k:16s} HUGE {h['names_HUGE']}/{N}   config-opt {h['config_option']}/{N}   src-patch {h['source_patch']}/{N}")


if __name__ == "__main__":
    run()
