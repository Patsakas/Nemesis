"""Round-trip seed synthesis via the library's own WRITE/ENCODE API.

Background
----------
The hardest benchmarks for NEMESIS (lz4 literal-length, libwebp VP8L Huffman,
libtiff custom-tag DE==0x0200) all share one property: the bug lives DEEP in a
decoder, past strict structural validation (magic bytes, framing, CRCs, length
prefixes). Vanilla AFL byte-flips starting from a thin generic seed almost
never synthesise a structurally-valid input that *reaches* that depth — the
parser rejects the mutation at the first integrity check.

But almost every format library that can *decode* a format can also *encode*
it. `libpng` has `png_write_*`, `libtiff` has `TIFFWriteEncodedStrip`, `lz4`
has `LZ4_compress_HC`, `brotli` has `BrotliEncoderCompress`. If we call the
WRITE API with fuzzed-but-plausible parameters and capture its output, we get a
*structurally-perfect* input that passes 100% of the decoder's validation — the
ideal seed to then hand to AFL for mutation.

NEMESIS port
------------
1. `extract_write_api()` greps the library's public headers for encode/write
   function declarations (heuristic name match: write/encode/compress/save/...).
   These go into the prompt so the LLM uses real signatures, not hallucinations.

2. `synthesize_producer_source()` asks the architect LLM for a C program with
   the contract

        producer <out_path> <rng_seed>

   that calls the encode API with parameters biased by `rng_seed`, then writes
   the encoded bytes to `out_path`.

3. The caller compiles it (linking the already-built target library — the
   `compile_fn` callback wires in the symbolic stage's target-specific link
   logic) and `run_producer()` invokes it N times with distinct rng_seeds,
   collecting unique non-empty outputs into the AFL `-i` directory.

4. The existing `_prevalidate_seeds` / `_minimize_seeds` stages then drop any
   crashers and corpus duplicates, so the producer does not need to be perfect.

Generality
----------
No per-library logic: the encode-API list is extracted from headers, the rest
of the context (format_spec, cve_records, target func) is the same bundle the
mutator/seedgen stages already build. Any failure is non-fatal — the caller
falls back to the byte-level seed sources with no regression.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging

    from nemesis.neural import LLMClient


# Heuristic: a public function is an "encoder/writer" candidate if its name
# contains one of these stems. Kept deliberately broad — the LLM filters the
# list down to the ones that actually produce the target format.
_WRITE_STEMS = (
    "write", "encode", "compress", "save", "serialize", "serialise",
    "deflate", "pack", "dump", "create", "build", "make", "emit",
)

# Declarations matching these are NOT encoders even though the name matches a
# stem (avoid feeding the LLM obvious decoder/allocator noise).
_WRITE_ANTISTEMS = ("decode", "decompress", "read", "parse", "load", "free", "destroy")


def extract_write_api(
    source_root: Path,
    header_rels: list[str],
    max_decls: int = 40,
) -> list[str]:
    """Grep public headers for encode/write function declarations.

    `header_rels` are paths relative to source_root (the target's
    `harness_includes`). Returns up to `max_decls` one-line signatures.
    Best-effort and pure — never raises.
    """
    decls: list[str] = []
    seen: set[str] = set()
    # A C function declaration ending in ';' that spans up to a few lines.
    # We normalise whitespace so multi-line prototypes collapse to one line.
    decl_re = re.compile(
        r"\b([A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;{]*\))\s*;",
        re.DOTALL,
    )
    for rel in header_rels or []:
        if len(decls) >= max_decls:
            break
        try:
            hdr = (source_root / rel)
            if not hdr.is_file():
                continue
            text = hdr.read_text(errors="replace")
        except OSError:
            continue
        for m in decl_re.finditer(text):
            full, fname = m.group(1), m.group(2)
            low = fname.lower()
            if not any(stem in low for stem in _WRITE_STEMS):
                continue
            if any(anti in low for anti in _WRITE_ANTISTEMS):
                continue
            sig = re.sub(r"\s+", " ", full).strip()
            if len(sig) > 200 or sig in seen:
                continue
            seen.add(sig)
            decls.append(sig + ";")
            if len(decls) >= max_decls:
                break
    return decls


_PRODUCER_SYSTEM = """\
You write a SMALL C program that GENERATES one valid input file for a parser
fuzzing harness by driving the library's own WRITE / ENCODE / COMPRESS API.

Why: byte-level fuzzers struggle to synthesise structurally-valid inputs that
pass a decoder's integrity checks (magic, framing, CRC, length prefixes). By
calling the library's encoder we obtain a perfectly-valid input which the
fuzzer can then mutate into the buggy neighbourhood.

Contract — your program is invoked as:

    producer <out_path> <rng_seed>

* Parse argv[1] as the output path, argv[2] as an integer rng_seed.
* Call srand((unsigned)rng_seed) at startup and use rand() to VARY the
  encode parameters (dimensions, levels, counts, payload bytes) across
  invocations — the harness runs you hundreds of times and needs DIVERSE
  outputs, not the same file repeatedly.
* Drive the WRITE/ENCODE API to produce ONE valid encoded artefact and write
  the resulting bytes to argv[1]. If the API encodes to a memory buffer,
  fwrite the buffer; if it writes to a FILE*/fd, encode straight to argv[1].
* Bias some parameters toward "extreme but plausible" values (dimensions near
  the type limit, counts at 0 / 1 / max, deeply-nested structures) so the
  produced seeds drive coverage into the deep decoder paths.
* Keep outputs reasonably small (<= 64 KiB) to keep AFL exec rate high.
* Return 0 on success; non-zero (and write nothing) on any internal error.

HARD RULES:
* Use ONLY the library's public headers (listed below) and libc. No network,
  no reading other files, no system()/exec.
* Use ONLY functions that appear in the provided API declarations or are
  standard libc. Do NOT invent function names or guess signatures.
* The program MUST define `int main(int argc, char **argv)`.
* Output ONLY the C source — no markdown fences, no prose.
"""


_PRODUCER_USER_TEMPLATE = """\
Library: {library}
Format: {format_name}
Target decoder function (the parser we ultimately fuzz): {target_func}

Public headers you may #include (relative paths — include the ones you need):
{headers_block}

Encode / write API declarations extracted from those headers (use these EXACT
signatures — do not invent others):
{api_block}

{format_spec_block}

{cve_block}

Write the complete C `producer` program now (no markdown, no prose).
It must `#include` the relevant public header(s), build one valid {format_name}
artefact via the encode API with rand()-varied parameters, and write the bytes
to argv[1].
"""


def _strip_code_fences(text: str) -> str:
    text = (text or "").strip()
    fence = re.match(r"^```(?:c|cpp)?\s*\n(.*)\n```\s*$", text, re.DOTALL)
    if fence:
        return fence.group(1).strip()
    if text.startswith("```"):
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _validate_producer(source: str) -> tuple[bool, str]:
    if len(source) < 120:
        return False, f"source too short ({len(source)} chars)"
    if "main" not in source or "argv" not in source:
        return False, "no main(argc, argv) entry point"
    if not re.search(r"#\s*include", source):
        return False, "no #include — cannot reach the encode API"
    for bad in ("system(", "popen(", "execve(", "execl(", "fork("):
        if bad in source:
            return False, f"forbidden call: {bad}"
    return True, ""


def synthesize_producer_source(
    library_name: str,
    target_func: str,
    format_name: str,
    header_rels: list[str],
    api_decls: list[str],
    format_spec: str,
    cve_records: list[dict],
    client: LLMClient,
    log: logging.Logger | None = None,
) -> str:
    """Ask the architect LLM for a C seed-producer program. "" on failure."""
    from nemesis.neural import ModelRole

    if not api_decls:
        # Without at least one encode signature the LLM would have to
        # hallucinate the API — skip rather than risk garbage.
        if log:
            log.info("roundtrip.no_write_api")
        return ""

    headers_block = "\n".join(f"  #include \"{h}\"" for h in header_rels[:12]) or "  (none found)"
    api_block = "\n".join(f"  {d}" for d in api_decls[:40])

    if format_spec:
        format_spec_block = (
            "<format_spec>\n"
            "Reference for the bytes that carry encoding decisions — bias your "
            "varied parameters toward these fields:\n\n"
            f"{format_spec[:3000]}\n"
            "</format_spec>"
        )
    else:
        format_spec_block = ""

    if cve_records:
        lines = ["<cve_history>", "Recent CVEs — bias parameters toward these code paths:"]
        for rec in cve_records[:3]:
            lines.append(f"  {rec.get('id', '?')}: {rec.get('description', '')[:300]}")
        lines.append("</cve_history>")
        cve_block = "\n".join(lines)
    else:
        cve_block = ""

    prompt = _PRODUCER_USER_TEMPLATE.format(
        library=library_name,
        format_name=format_name or "binary",
        target_func=target_func or "(none)",
        headers_block=headers_block,
        api_block=api_block,
        format_spec_block=format_spec_block,
        cve_block=cve_block,
    )

    try:
        response = client.complete(
            prompt=prompt,
            system=_PRODUCER_SYSTEM,
            stage="roundtrip.synth",
            target_func=target_func or library_name,
            role=ModelRole.ARCHITECT,
        )
    except Exception as exc:  # noqa: BLE001 — non-fatal, fall back
        if log:
            log.warning("roundtrip.llm_failed", error=str(exc))
        return ""

    source = _strip_code_fences(response or "")
    ok, reason = _validate_producer(source)
    if not ok:
        if log:
            log.warning("roundtrip.source_rejected", reason=reason, excerpt=source[:300])
        return ""
    if log:
        log.info("roundtrip.source_synthesised", chars=len(source))
    return source


def run_producer(
    producer_bin: Path,
    out_dir: Path,
    n_seeds: int = 100,
    rng_seed_base: int = 0x5EED_C0DE,
    per_seed_timeout_s: float = 5.0,
    max_seed_bytes: int = 1 << 18,
    log: logging.Logger | None = None,
) -> int:
    """Run a compiled producer N times; copy unique non-empty seeds into out_dir.

    Returns the number of distinct seeds written. Pure I/O — never raises.
    """
    if not producer_bin or not Path(producer_bin).exists():
        return 0
    out_dir.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    next_index = 0
    failures = 0
    with tempfile.TemporaryDirectory(prefix="nemesis_roundtrip_") as workdir:
        wp = Path(workdir)
        for i in range(n_seeds):
            rng_seed = rng_seed_base + i * 2654435761  # Knuth multiplicative spread
            buf = wp / f"raw_{i:04d}.bin"
            try:
                proc = subprocess.run(
                    [str(producer_bin), str(buf), str(rng_seed & 0x7FFFFFFF)],
                    capture_output=True,
                    timeout=per_seed_timeout_s,
                    cwd=str(wp),
                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"},
                )
            except (subprocess.TimeoutExpired, OSError):
                failures += 1
                continue
            if proc.returncode != 0 or not buf.is_file():
                failures += 1
                continue
            try:
                data = buf.read_bytes()
            except OSError:
                failures += 1
                continue
            if not data or len(data) > max_seed_bytes:
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            dest = out_dir / f"roundtrip_{next_index:04d}_{digest[:12]}.bin"
            try:
                shutil.copyfile(buf, dest)
                next_index += 1
            except OSError:
                pass
    if log:
        log.info("roundtrip.produced", unique=next_index, failures=failures, attempted=n_seeds)
    return next_index


def synthesize_and_run(
    *,
    config,
    seeds_dir: Path,
    compile_fn: Callable[[Path, Path], bool],
    client: LLMClient,
    nemesis_root: Path,
    log: logging.Logger,
    n_seeds: int = 100,
) -> int:
    """Top-level entry: extract API → synthesise producer → compile → run.

    `compile_fn(producer_c_path, out_bin_path) -> bool` is supplied by the
    caller (the symbolic stage) so the target-specific library link logic lives
    in one place. Returns the number of seeds added to seeds_dir (0 on any
    failure — always non-fatal).
    """
    target = config.target
    library_name = target.name or ""
    if not library_name:
        return 0

    source_root = Path(os.path.expandvars(os.path.expanduser(str(target.source_root))))
    header_rels = list(getattr(target, "harness_includes", []) or [])
    api_decls = extract_write_api(source_root, header_rels)
    if not api_decls:
        log.info("roundtrip.skipped_no_encode_api", library=library_name)
        return 0

    magic = getattr(target, "magic_bytes", {}) or {}
    format_name = next(iter(magic), "binary")

    pinned = list(getattr(target, "pinned_funcs", []) or [])
    target_func = pinned[0].func_name if pinned else ""

    targets_dir = nemesis_root / "config" / "targets"
    try:
        from nemesis.recon.format_specs import get_format_spec
        format_spec = get_format_spec(library_name, targets_dir=targets_dir) or ""
    except Exception:  # noqa: BLE001
        format_spec = ""
    try:
        from nemesis.recon import cve_context as _cc
        cve_records = _cc.get_or_fetch(
            library_name=library_name, targets_dir=targets_dir, max_cves=3, log=log,
        )
    except Exception:  # noqa: BLE001
        cve_records = []

    source = synthesize_producer_source(
        library_name=library_name,
        target_func=target_func,
        format_name=format_name,
        header_rels=header_rels,
        api_decls=api_decls,
        format_spec=format_spec,
        cve_records=cve_records,
        client=client,
        log=log,
    )
    if not source:
        return 0

    work = nemesis_root / "workspace" / "roundtrip"
    work.mkdir(parents=True, exist_ok=True)
    bare = library_name.lower().removeprefix("lib") or library_name.lower()
    src_path = work / f"{bare}_producer.c"
    bin_path = work / f"{bare}_producer"
    src_path.write_text(source)

    try:
        ok = compile_fn(src_path, bin_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("roundtrip.compile_raised", error=str(exc))
        return 0
    if not ok or not bin_path.exists():
        log.warning("roundtrip.compile_failed")
        return 0

    count = run_producer(bin_path, seeds_dir, n_seeds=n_seeds, log=log)
    log.info("roundtrip.appended_to_corpus", seeds=count, dir=str(seeds_dir))
    return count
