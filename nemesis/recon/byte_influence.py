"""Coverage-differential byte-influence probing → measured field structure.

What this does
--------------
Given an instrumented binary and one seed, work out which input bytes actually
steer the program, and group them into fields. Not by reading a format spec,
and not by asking an LLM — by measuring.

The method: run the seed to get a baseline edge map, then for each byte offset
substitute a handful of probe values and re-run. Any edge that appears or
disappears is attributed to that byte. Bytes whose edge sets overlap and that
sit next to each other are the same field.

Output is a `fieldspec` — the exact JSON shape `fieldspec_seedgen.py` already
interprets — so this is a new *producer* for an existing pipeline, not a new
subsystem. Fields carry `source: "coverage"` and a confidence, which the
interpreter ignores and the LLM can use.

What it can and cannot recover
------------------------------
It recovers STRUCTURE: offsets, widths, groupings. It does not recover
SEMANTICS. A measured 2-byte integer is reported as an integer; whether it is
a length prefix for a later region, an element count, or a checksum cannot be
derived from control flow alone, and inventing that relationship would be
worse than leaving it out. Semantic labelling is the LLM's job downstream.

Requires a probe binary, not the fuzzing binary
-----------------------------------------------
The fuzzing binary cannot be probed. NEMESIS harnesses are AFL++ persistent
mode with shared-memory test cases (`__AFL_FUZZ_INIT()` sets
`__afl_sharedmem_fuzzing = 1`); run outside afl-fuzz the runtime reports
"disabling shared memory testcases" and the harness then receives no input at
all. Every input produces the same handful of edges — valid JSON, deep nesting
and pure garbage alike — so no byte can ever look influential. Measured on
cJSON: identical 9-edge map for all six probes, 0 of 11 bytes influential.

What works is a *probe binary*: the same harness source compiled with the AFL
persistent macros `#undef`'d and replaced by a stub that reads stdin (the
`_AFL_STUB_HEADER` shape already used for standalone crash reproduction), built
with `afl-clang-fast` for instrumentation and linked with the same sanitizer
flags as the library. On cJSON that turns a flat 9 edges into 4-93 edges
depending on input, and 0% influential bytes into 100%.

The same blindness affects `afl-cmin` on these binaries ("Found 0 unique tuples
across 5 files", keeps none), so the pre-fuzz seed minimisation is already a
no-op for persistent harnesses. Pre-existing, unrelated to this module, and
fixable the same way.

Input delivery is the other half of that trap: a target that reads stdin, given
a path on argv, parses nothing and looks exactly like a target whose bytes do
not matter. `ShowmapRunner` therefore detects the mode rather than assuming it.

Seed quality bounds everything
------------------------------
Probing can only see fields the seed actually reaches. An LZ4 frame seed that
failed the frame-magic check produced exactly one influential byte — the magic
itself — because parsing stopped there. That is not a failure of the method; it
is the method correctly reporting that nothing past byte 0 was ever executed.
Read a shallow result as "this seed does not exercise the parser" before
reading it as "this format has no structure", and check `baseline_edges` in the
artifacts to tell the two apart.

Known limitation, measured not assumed
--------------------------------------
Coverage probing cannot recover every byte of a multi-byte field. On the
validation target, `width` occupies bytes 4-7, but no value of byte 7 changes
which branch is taken — 0x100 and 0x1FF both fall in the same range — so byte 7
is invisible to any control-flow-based method. Only bytes 4-6 are observed.

This is mitigated, not solved, by alignment-aware snapping: a 3-byte group is
almost certainly a 4-byte field whose low byte never mattered. Snapped fields
are marked (`observed_size` differs from `size`) and take a confidence penalty,
so downstream consumers can tell a measurement from an inference.

Why the clustering rule is what it is
-------------------------------------
Three rules were tried against a target with known layout:

  equality of edge sets — splits real fields. Byte 6 of `width` can drive the
      value to 0 and reach a branch bytes 4-5 cannot, so its edge set differs
      while belonging to the same field.
  non-empty intersection — merges unrelated fields. The magic gates all later
      parsing, so it shares an edge with everything downstream.
  Jaccard similarity — separates both correctly. magic vs width scores 0.125;
      bytes within `width` score 0.33-1.0.

Hence Jaccard, with the threshold exposed as a parameter rather than fixed: one
target is one datapoint, and the right value is a question for benchmarking.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from nemesis.logging import get_logger

# Probe values per byte. A single bit-flip is not enough: on the validation
# target it found only 2 of the 3 observable `width` bytes, because flipping a
# middle byte kept the value inside the same range. These six span the ranges a
# comparison is likely to split on — zero, small, signed boundary, high bit,
# all-ones — plus the byte's own complement.
DEFAULT_PROBE_VALUES: tuple[int, ...] = (0x00, 0x01, 0x7F, 0x80, 0xFF)

# Adjacent bytes join a field when their edge sets are this similar.
# See the module docstring for why equality and intersection both fail.
#
# Swept against the known-layout target: the correct layout is recovered for
# any threshold in [0.15, 0.30]. Below 0.15 the magic merges into the field
# after it; at 0.35 and above a 4-byte integer splits into 2+1. 0.25 sits
# inside that window with margin on both sides rather than on its edge — but
# one target is one datapoint, which is why this is a parameter and every
# caller can override it.
DEFAULT_JACCARD_THRESHOLD = 0.25

# Natural field widths to snap an observed run up to.
SNAP_WIDTHS: tuple[int, ...] = (1, 2, 4, 8)

# Multiplier applied per byte inferred rather than observed. A 3-byte
# observation snapped to 4 is a weaker claim than a 4-byte observation.
SNAP_CONFIDENCE_PENALTY = 0.85

# Runs used to establish the baseline. Programs with hash seeds, timing, or
# uninitialised reads produce different maps for identical input; without
# repeats that noise makes every byte look influential.
DEFAULT_BASELINE_RUNS = 3

# Probing costs one execution per byte per probe value. Past this many bytes,
# probe a strided sample instead of every offset — headers live at the front,
# and a multi-megabyte seed would otherwise cost millions of executions.
DEFAULT_MAX_PROBE_BYTES = 4096


@dataclass
class ByteInfluence:
    """Per-byte probing result."""

    offset: int
    edges: frozenset[str]          # edge IDs this byte can add or remove
    probed: bool = True            # False when skipped by sampling

    @property
    def influential(self) -> bool:
        return bool(self.edges)


@dataclass
class MeasuredField:
    """A run of adjacent bytes that behave as one unit."""

    offset: int
    size: int                      # after snapping
    observed_size: int             # bytes actually seen to influence control flow
    confidence: float
    edges: frozenset[str] = field(default_factory=frozenset)

    @property
    def snapped(self) -> bool:
        return self.size != self.observed_size


class ShowmapRunner:
    """Runs `afl-showmap` and returns the set of edge IDs hit.

    Isolated behind a class so tests can substitute a fake without needing AFL
    installed, and so the subprocess details stay in one place.

    `input_mode` decides how the test case reaches the target: "stdin" pipes it,
    "argv" passes a path as the first argument, "auto" (the default) works it
    out by trying both once. Getting this wrong is silent and total — a target
    that reads stdin, handed a path on argv, parses nothing and reports the
    same handful of edges for every input, so no byte ever looks influential.
    NEMESIS's own stub harnesses read stdin; many standalone parsers take a
    path. Guessing either way would break half the targets.
    """

    def __init__(self, binary: str | Path, timeout: int = 5,
                 showmap_bin: str = "afl-showmap",
                 input_mode: str = "auto",
                 env: dict[str, str] | None = None) -> None:
        self.binary = str(binary)
        self.timeout = timeout
        self.showmap_bin = showmap_bin
        self.input_mode = input_mode
        self.env = env
        self.log = get_logger("recon.byte_influence")

    def edges_for(self, input_path: str | Path) -> frozenset[str]:
        """Edge IDs covered by running the target on `input_path`.

        Returns an empty set on any failure. A crashing or timing-out probe is
        a normal outcome here — we are deliberately feeding malformed input —
        and must not abort the sweep.
        """
        if self.input_mode == "auto":
            self.input_mode = self._detect_input_mode(input_path)
        return self._run(input_path, self.input_mode)

    def _detect_input_mode(self, input_path: str | Path) -> str:
        """Pick whichever of stdin/argv actually gets the input into the target.

        More edges means more of the program ran, which means the input was
        read. Ties go to stdin: it is what the project's own harnesses use, and
        an argv-reading target handed nothing on stdin still runs its startup
        path, so a tie is far more likely to be argv doing nothing.
        """
        by_stdin = len(self._run(input_path, "stdin"))
        by_argv = len(self._run(input_path, "argv"))
        mode = "argv" if by_argv > by_stdin else "stdin"
        self.log.info(
            "showmap.input_mode_detected",
            mode=mode, stdin_edges=by_stdin, argv_edges=by_argv,
        )
        return mode

    def _run(self, input_path: str | Path, mode: str) -> frozenset[str]:
        with tempfile.NamedTemporaryFile(suffix=".map", delete=False) as tmp:
            map_path = Path(tmp.name)
        cmd = [self.showmap_bin, "-o", str(map_path), "-q", "--", self.binary]
        if mode == "argv":
            cmd.append(str(input_path))
        try:
            with open(input_path, "rb") as fh:
                subprocess.run(
                    cmd,
                    stdin=fh if mode == "stdin" else subprocess.DEVNULL,
                    capture_output=True, timeout=self.timeout, env=self.env,
                )
            return self._parse_map(map_path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self.log.debug("showmap.failed", error=str(exc), mode=mode)
            return frozenset()
        finally:
            try:
                map_path.unlink()
            except OSError:
                pass

    @staticmethod
    def _parse_map(map_path: Path) -> frozenset[str]:
        """Parse afl-showmap output: one `edge_id:hit_count` per line."""
        try:
            text = map_path.read_text(errors="replace")
        except OSError:
            return frozenset()
        return frozenset(
            line.split(":", 1)[0].strip()
            for line in text.splitlines()
            if ":" in line
        )


# ── Probing ─────────────────────────────────────────────────


def select_probe_seed(
    runner: ShowmapRunner,
    candidates: list[Path],
    max_candidates: int = 40,
) -> Path | None:
    """Pick the seed that drives the parser deepest, not the smallest one.

    Probing can only discover fields the seed actually reaches, so the seed
    choice bounds the result before any analysis happens. Depth is measured
    directly — edge count for that input — because nothing cheaper predicts it.

    Size in particular does not. Measured across the OSS-Fuzz libtiff corpus:
    the smallest seed (166 bytes) reached 297 edges while the deepest (637)
    was 8258 bytes, and the largest available (106 KB) reached only 349. An
    earlier version of this picked the smallest file to keep probing cheap and
    would have chosen close to the worst candidate.

    Ties break toward the smaller file, since probing costs one execution per
    byte per probe value. Only the first `max_candidates` are measured — this
    costs one execution each, and corpora run to tens of thousands of files.
    """
    log = get_logger("recon.byte_influence")
    usable = [c for c in candidates if c.is_file() and c.stat().st_size > 0]
    if not usable:
        return None

    scored: list[tuple[int, int, Path]] = []
    for path in usable[:max_candidates]:
        depth = len(runner.edges_for(path))
        scored.append((depth, -path.stat().st_size, path))

    depth, neg_size, best = max(scored)
    log.info(
        "probe.seed_selected", seed=best.name, edges=depth, bytes=-neg_size,
        considered=len(scored),
    )
    if depth == 0:
        # Nothing ran for any candidate — probing would report that no byte
        # matters, which says more about the binary than about the format.
        log.warning("probe.no_seed_reaches_target", considered=len(scored))
        return None
    return best


def measure_baseline(runner: ShowmapRunner, seed: bytes, work_dir: Path,
                     runs: int = DEFAULT_BASELINE_RUNS) -> tuple[frozenset[str], frozenset[str]]:
    """Return (stable_edges, flaky_edges) for the unmodified seed.

    Edges that do not appear in every run are non-deterministic and are
    excluded from all later comparisons — otherwise they show up as spurious
    differences and every byte looks influential.
    """
    seed_path = work_dir / "baseline.bin"
    seed_path.write_bytes(seed)

    observed: list[frozenset[str]] = [
        runner.edges_for(seed_path) for _ in range(max(1, runs))
    ]
    stable = frozenset.intersection(*observed) if observed else frozenset()
    union = frozenset.union(*observed) if observed else frozenset()
    return stable, union - stable


def probe_bytes(
    runner: ShowmapRunner,
    seed: bytes,
    work_dir: Path,
    baseline: frozenset[str],
    flaky: frozenset[str] = frozenset(),
    probe_values: tuple[int, ...] = DEFAULT_PROBE_VALUES,
    max_probe_bytes: int = DEFAULT_MAX_PROBE_BYTES,
) -> list[ByteInfluence]:
    """Substitute probe values at each offset and record which edges move.

    Cost is len(seed) x len(probe_values) executions, so seeds longer than
    `max_probe_bytes` are sampled on a stride. Sampling loses fields, it does
    not corrupt the ones it finds.
    """
    log = get_logger("recon.byte_influence")
    n = len(seed)
    stride = 1 if n <= max_probe_bytes else (n // max_probe_bytes) + 1
    if stride > 1:
        log.info("probe.sampling", seed_len=n, stride=stride,
                 note="seed longer than max_probe_bytes; probing a sample")

    probe_path = work_dir / "probe.bin"
    results: list[ByteInfluence] = []

    for i in range(n):
        if i % stride != 0:
            results.append(ByteInfluence(offset=i, edges=frozenset(), probed=False))
            continue

        moved: set[str] = set()
        original = seed[i]
        for value in probe_values:
            if value == original:
                continue          # no-op probe tells us nothing
            mutated = bytearray(seed)
            mutated[i] = value
            probe_path.write_bytes(bytes(mutated))
            edges = runner.edges_for(probe_path)
            if not edges:
                # Empty map means the run failed outright rather than covering
                # nothing; treating it as "every edge disappeared" would mark
                # the byte maximally influential on a harness error.
                continue
            moved |= (edges ^ baseline) - flaky
        results.append(ByteInfluence(offset=i, edges=frozenset(moved)))

    return results


# ── Clustering and snapping (pure functions — no I/O) ───────


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Similarity of two edge sets. 0.0 when either is empty."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def cluster_fields(
    influences: list[ByteInfluence],
    threshold: float = DEFAULT_JACCARD_THRESHOLD,
) -> list[list[ByteInfluence]]:
    """Group adjacent influential bytes whose edge sets are similar enough.

    Inert bytes terminate a group: a byte that steers nothing sits between
    fields, or is payload. Note this compares each byte to the PREVIOUS one in
    the run rather than to the group as a whole — within a wide integer,
    similarity decays from the high byte down, and comparing against the group
    head would split fields that a pairwise walk keeps together.
    """
    groups: list[list[ByteInfluence]] = []
    current: list[ByteInfluence] = []

    for inf in influences:
        if not inf.influential:
            if current:
                groups.append(current)
                current = []
            continue
        if current and jaccard(inf.edges, current[-1].edges) >= threshold:
            current.append(inf)
        else:
            if current:
                groups.append(current)
            current = [inf]

    if current:
        groups.append(current)
    return groups


def snap_width(observed: int, widths: tuple[int, ...] = SNAP_WIDTHS) -> int:
    """Round an observed run length up to the next natural field width.

    A 3-byte observation is almost always a 4-byte field whose low byte never
    changed the control flow. Runs longer than the largest natural width are
    left alone — those are byte arrays, not integers.
    """
    for w in widths:
        if observed <= w:
            return w
    return observed


def fields_from_groups(
    groups: list[list[ByteInfluence]],
    snap: bool = True,
    penalty: float = SNAP_CONFIDENCE_PENALTY,
) -> list[MeasuredField]:
    """Turn byte groups into fields, snapping widths and scoring confidence.

    Confidence starts at 1.0 for a group observed at a natural width and is
    multiplied by `penalty` for each byte that was inferred rather than seen.
    """
    fields: list[MeasuredField] = []
    for group in groups:
        observed = len(group)
        size = snap_width(observed) if snap else observed
        inferred = max(0, size - observed)
        confidence = penalty ** inferred
        edges: frozenset[str] = frozenset()
        for member in group:
            edges |= member.edges
        fields.append(MeasuredField(
            offset=group[0].offset,
            size=size,
            observed_size=observed,
            confidence=round(confidence, 3),
            edges=edges,
        ))
    return fields


# ── Fieldspec emission ──────────────────────────────────────


def fields_to_fieldspec(
    fields: list[MeasuredField],
    seed: bytes,
    method: str = "jaccard-snap",
) -> dict:
    """Render measured fields as the fieldspec JSON `fieldspec_seedgen` reads.

    Gaps between fields become `bytes` regions so the rendered seed keeps its
    original length and later fields stay at their measured offsets.

    Only structural kinds are emitted — `const` for what looks like a fixed
    signature, `int` for measured numeric fields, `bytes` for everything else.
    Deliberately never `len`: a length-to-region relationship cannot be derived
    from control flow, and guessing one would produce seeds that are
    confidently wrong. That inference belongs to the LLM, which can read this
    spec and propose it.

    The `source` / `confidence` / `method` keys ride along untouched:
    `build_from_fieldspec` reads only the keys it knows via `.get()`, so extra
    metadata costs nothing and needs no interpreter change.
    """
    spec_fields: list[dict] = []
    cursor = 0

    for f in sorted(fields, key=lambda x: x.offset):
        if f.offset > cursor:
            spec_fields.append({
                "kind": "bytes",
                "name": f"gap_{cursor}",
                "min": f.offset - cursor,
                "max": f.offset - cursor,
                "fill": "random",
                "source": "coverage",
            })
        chunk = seed[f.offset:f.offset + f.size]
        entry: dict = {
            "kind": "int" if f.size in SNAP_WIDTHS else "bytes",
            "source": "coverage",
            "confidence": f.confidence,
            "method": method,
        }
        if entry["kind"] == "int":
            entry["size"] = f.size
            entry["endian"] = "be"
            # Keep the observed value alongside boundary values, so rendered
            # seeds stay close enough to valid to get past early checks.
            observed_value = int.from_bytes(chunk, "big") if chunk else 0
            entry["values"] = _interesting_values(observed_value, f.size)
        else:
            entry["name"] = f"field_{f.offset}"
            entry["min"] = f.size
            entry["max"] = f.size
            entry["fill"] = "random"
        if f.snapped:
            entry["observed_size"] = f.observed_size
        spec_fields.append(entry)
        cursor = f.offset + f.size

    if cursor < len(seed):
        spec_fields.append({
            "kind": "bytes",
            "name": "tail",
            "min": len(seed) - cursor,
            "max": len(seed) - cursor,
            "fill": "random",
            "source": "coverage",
        })

    return {"fields": spec_fields}


def _interesting_values(observed: int, size: int) -> list[int]:
    """Boundary values for a measured integer field, plus what was there.

    The observed value matters: a spec made only of extremes produces seeds
    that fail the first validity check, never reaching the code the field
    actually controls.
    """
    bits = size * 8
    top = (1 << bits) - 1
    candidates = [observed, 0, 1, top, top // 2, (top // 2) + 1]
    if bits >= 16:
        candidates += [0xFF, 0x100]
    # Dedup, preserve order, keep in range.
    seen: set[int] = set()
    out: list[int] = []
    for v in candidates:
        v &= top
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ── Orchestration ───────────────────────────────────────────


def infer_fieldspec(
    probe_binary: str | Path,
    seed: bytes,
    work_dir: str | Path,
    threshold: float = DEFAULT_JACCARD_THRESHOLD,
    probe_values: tuple[int, ...] = DEFAULT_PROBE_VALUES,
    baseline_runs: int = DEFAULT_BASELINE_RUNS,
    max_probe_bytes: int = DEFAULT_MAX_PROBE_BYTES,
    snap: bool = True,
    dump_artifacts: bool = True,
    runner: ShowmapRunner | None = None,
) -> dict | None:
    """Probe `seed` against `probe_binary` and return a measured fieldspec.

    `probe_binary` must be a build that reports honest per-input coverage when
    run offline — see recon/probe_build.py. Passing the AFL *fuzzing* binary
    is the one mistake that fails silently: it receives no input outside
    afl-fuzz, so every probe returns the same map and this reports that no
    byte matters. The parameter is named for what it must be, not for what it
    is, because that mistake costs hours to diagnose from the outside.

    Returns None when nothing could be measured (no baseline coverage, or no
    influential bytes) — the caller should fall back to the LLM-synthesised
    spec rather than proceeding with an empty one.

    Every intermediate stage is written to `work_dir` when `dump_artifacts` is
    set. When this produces a poor spec on a real target, the question is
    always which stage went wrong — probing, clustering, or snapping — and
    that is unanswerable from the final JSON alone.
    """
    log = get_logger("recon.byte_influence")
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    runner = runner or ShowmapRunner(probe_binary)

    baseline, flaky = measure_baseline(runner, seed, work, runs=baseline_runs)
    if not baseline:
        log.warning("infer.no_baseline_coverage", binary=str(probe_binary),
                    note="target produced no edges; is the binary instrumented?")
        return None
    if flaky:
        log.info("infer.flaky_edges_excluded", count=len(flaky))

    influences = probe_bytes(
        runner, seed, work, baseline, flaky,
        probe_values=probe_values, max_probe_bytes=max_probe_bytes,
    )
    n_influential = sum(1 for i in influences if i.influential)
    if n_influential == 0:
        # Almost always means the target never saw the input rather than that
        # the input does not matter. The usual cause is an AFL++ persistent
        # harness with shared-memory test cases, which receives nothing when
        # run outside afl-fuzz (see the module docstring).
        log.warning(
            "infer.no_influential_bytes", seed_len=len(seed),
            hint=("target produced identical coverage for every probe; if this "
                  "is an AFL persistent/shared-memory harness it never received "
                  "the input — probe a binary that reads argv or stdin"),
        )
        return None

    groups = cluster_fields(influences, threshold=threshold)
    fields = fields_from_groups(groups, snap=snap)
    spec = fields_to_fieldspec(fields, seed)

    log.info(
        "infer.done",
        seed_len=len(seed), baseline_edges=len(baseline),
        influential_bytes=n_influential, fields=len(fields),
        snapped=sum(1 for f in fields if f.snapped), threshold=threshold,
    )

    if dump_artifacts:
        _dump(work, baseline, flaky, influences, fields, spec, threshold)
    return spec


def _dump(work: Path, baseline: frozenset[str], flaky: frozenset[str],
          influences: list[ByteInfluence], fields: list[MeasuredField],
          spec: dict, threshold: float) -> None:
    """Write each stage separately so a bad result can be localised."""
    out = work / "byte_influence"
    out.mkdir(parents=True, exist_ok=True)
    try:
        (out / "baseline.json").write_text(json.dumps({
            "stable_edges": sorted(baseline),
            "flaky_edges": sorted(flaky),
        }, indent=2), encoding="utf-8")
        (out / "probes.json").write_text(json.dumps([
            {"offset": i.offset, "probed": i.probed, "edges": sorted(i.edges)}
            for i in influences
        ], indent=2), encoding="utf-8")
        (out / "fields.json").write_text(json.dumps({
            "threshold": threshold,
            "fields": [
                {"offset": f.offset, "size": f.size,
                 "observed_size": f.observed_size, "snapped": f.snapped,
                 "confidence": f.confidence, "edges": sorted(f.edges)}
                for f in fields
            ],
        }, indent=2), encoding="utf-8")
        (out / "fieldspec.json").write_text(
            json.dumps(spec, indent=2), encoding="utf-8")
    except OSError as exc:
        get_logger("recon.byte_influence").debug("dump.failed", error=str(exc))
