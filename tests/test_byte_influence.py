"""
Tests for coverage-differential byte-influence probing.

Two layers. The clustering, snapping and fieldspec logic are pure functions
over edge sets, so they are driven with synthetic data — fast, deterministic,
and able to express cases a real target would take hours to produce.

The probing itself is driven through a fake ShowmapRunner implementing a
target with a KNOWN field layout. That matters more than it sounds: the
interesting failures of this technique are not crashes, they are silently
plausible field boundaries. Ground truth is the only way to see them.

The fake models the real behaviour measured on an instrumented toy target,
including the awkward parts:
  - byte 6 of a 4-byte integer reaches a branch bytes 4-5 cannot (it can drive
    the value to zero), so its edge set DIFFERS from theirs;
  - byte 7, the low byte, changes no branch at all and is invisible;
  - the magic gates everything downstream, so it shares an edge with every
    later field.
Any clustering rule that mishandles those three is wrong, and each of them
broke an earlier version of this code.
"""

import json
from pathlib import Path

import pytest

from nemesis.recon.byte_influence import (
    DEFAULT_JACCARD_THRESHOLD,
    ByteInfluence,
    MeasuredField,
    ShowmapRunner,
    cluster_fields,
    fields_from_groups,
    fields_to_fieldspec,
    infer_fieldspec,
    jaccard,
    snap_width,
)

# ── Fake target with a known layout ─────────────────────────
#
#   offset  field    size
#   0-3     magic    4
#   4-7     width    4   (byte 7 invisible — see module docstring)
#   8       flags    1
#   9-10    count    2
#   11+     payload  (inert)

BASE_EDGES = frozenset({"5", "11", "13", "17", "19", "21", "23"})

# Edge sets each byte can move, mirroring the measured toy target.
_BYTE_EDGES = {
    0: {"8", "11", "13", "14", "16", "18", "19"},   # magic — gates everything
    1: {"8", "11", "13", "14", "16", "18", "19"},
    2: {"8", "11", "13", "14", "16", "18", "19"},
    3: {"8", "11", "13", "14", "16", "18", "19"},
    4: {"10", "11"},                                 # width high bytes
    5: {"10", "11"},
    6: {"9", "11"},                                  # width — can reach zero
    7: set(),                                        # width low byte: invisible
    8: {"12", "13", "14", "15"},                     # flags
    9: {"16", "17"},                                 # count
    10: {"16", "17"},
}


class FakeRunner(ShowmapRunner):
    """ShowmapRunner that synthesises maps from _BYTE_EDGES, no AFL needed."""

    def __init__(self, seed: bytes, flaky: set[str] | None = None):
        self.seed = seed
        self.flaky = flaky or set()
        self._flaky_toggle = False
        self.calls = 0

    def edges_for(self, input_path):
        self.calls += 1
        data = Path(input_path).read_bytes()
        edges = set(BASE_EDGES)
        # strict=False on purpose: probe files are the same length as the seed,
        # but a truncated one must compare what overlaps rather than raise.
        for i, (orig, cur) in enumerate(zip(self.seed, data, strict=False)):
            if orig != cur:
                edges ^= _BYTE_EDGES.get(i, set())
        if self.flaky:
            # Alternate on every call so the edge is genuinely unstable.
            self._flaky_toggle = not self._flaky_toggle
            if self._flaky_toggle:
                edges |= self.flaky
        return frozenset(edges)


@pytest.fixture
def seed() -> bytes:
    return b"TOYF" + (256).to_bytes(4, "big") + b"\x01" + (50).to_bytes(2, "little") + bytes(range(16))


def _influences(offsets_and_edges) -> list[ByteInfluence]:
    return [ByteInfluence(offset=o, edges=frozenset(e))
            for o, e in offsets_and_edges]


# ── jaccard ─────────────────────────────────────────────────


def test_jaccard_identical_sets():
    assert jaccard(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0


def test_jaccard_disjoint_sets():
    assert jaccard(frozenset({"a"}), frozenset({"b"})) == 0.0


def test_jaccard_empty_is_zero():
    assert jaccard(frozenset(), frozenset({"a"})) == 0.0
    assert jaccard(frozenset(), frozenset()) == 0.0


def test_jaccard_partial_overlap():
    assert jaccard(frozenset({"a", "b"}), frozenset({"b", "c"})) == pytest.approx(1 / 3)


# ── cluster_fields ──────────────────────────────────────────


def test_clustering_recovers_known_layout():
    """The whole point: correct groups on the measured edge sets."""
    influences = _influences((i, _BYTE_EDGES[i]) for i in range(11))
    groups = cluster_fields(influences)
    spans = [(g[0].offset, g[-1].offset) for g in groups]
    assert spans == [(0, 3), (4, 6), (8, 8), (9, 10)]


def test_clustering_does_not_merge_magic_into_width():
    """REGRESSION: a non-empty-intersection rule merges these. The magic gates
    all later parsing, so it shares edge 11 with width — but Jaccard is
    1/8 = 0.125, well under threshold."""
    influences = _influences([(3, _BYTE_EDGES[3]), (4, _BYTE_EDGES[4])])
    groups = cluster_fields(influences)
    assert len(groups) == 2


def test_clustering_keeps_width_bytes_together_despite_differing_edges():
    """REGRESSION: an equality rule splits these. Byte 6 can drive width to
    zero and reach a branch bytes 4-5 cannot, so its edge set differs — but
    they are one field."""
    influences = _influences([(4, _BYTE_EDGES[4]), (5, _BYTE_EDGES[5]),
                              (6, _BYTE_EDGES[6])])
    groups = cluster_fields(influences)
    assert len(groups) == 1
    assert [b.offset for b in groups[0]] == [4, 5, 6]


def test_inert_byte_terminates_a_group():
    influences = _influences([(0, {"a"}), (1, set()), (2, {"a"})])
    groups = cluster_fields(influences)
    assert len(groups) == 2


def test_clustering_compares_to_previous_byte_not_group_head():
    """Similarity decays from the high byte of a wide integer downward.
    Comparing every byte to the group HEAD splits such a field; comparing to
    the previous byte walks the decay correctly."""
    influences = _influences([
        (0, {"a", "b", "c", "d"}),
        (1, {"a", "b", "c"}),      # jaccard vs head = 0.75
        (2, {"b", "c"}),           # vs head = 0.5, vs prev = 0.67
        (3, {"c"}),                # vs head = 0.25 (would split), vs prev = 0.5
    ])
    groups = cluster_fields(influences)
    assert len(groups) == 1


def test_threshold_is_a_parameter_not_a_constant():
    """One target is one datapoint — the threshold has to be tunable for
    benchmarking, not baked in."""
    influences = _influences([(0, {"a", "b"}), (1, {"b", "c"})])  # jaccard 1/3
    assert len(cluster_fields(influences, threshold=0.30)) == 1
    assert len(cluster_fields(influences, threshold=0.50)) == 2


@pytest.mark.parametrize("threshold", [0.15, 0.20, 0.25, 0.30])
def test_known_layout_recovered_across_the_working_window(threshold):
    """Swept on the real target: [0.15, 0.30] all recover the layout. Pinning
    the whole window, not just the default, so a future tweak that narrows it
    shows up here rather than in a benchmark weeks later."""
    influences = _influences((i, _BYTE_EDGES[i]) for i in range(11))
    fields = fields_from_groups(cluster_fields(influences, threshold=threshold))
    assert [(f.offset, f.size) for f in fields] == [(0, 4), (4, 4), (8, 1), (9, 2)]


def test_default_threshold_sits_inside_the_window_with_margin():
    """0.30 was the original default and is the exact top edge of the working
    window — one target's worth of drift would break it. The default belongs
    inside the window, not on its boundary."""
    assert 0.15 < DEFAULT_JACCARD_THRESHOLD < 0.30


def test_threshold_too_low_merges_neighbouring_fields():
    """Documents the lower failure mode: the magic gates everything, so at a
    low enough threshold it absorbs the field after it."""
    influences = _influences((i, _BYTE_EDGES[i]) for i in range(11))
    fields = fields_from_groups(cluster_fields(influences, threshold=0.10))
    assert (0, 8) in [(f.offset, f.size) for f in fields]


def test_threshold_too_high_splits_a_single_field():
    """Documents the upper failure mode: a 4-byte integer breaks into 2+1
    because its low bytes reach fewer branches than its high bytes."""
    influences = _influences((i, _BYTE_EDGES[i]) for i in range(11))
    fields = fields_from_groups(cluster_fields(influences, threshold=0.50))
    layout = [(f.offset, f.size) for f in fields]
    assert (4, 4) not in layout
    assert len(layout) > 4


def test_clustering_empty_input():
    assert cluster_fields([]) == []


def test_clustering_all_inert():
    assert cluster_fields(_influences([(0, set()), (1, set())])) == []


# ── snap_width ──────────────────────────────────────────────


@pytest.mark.parametrize("observed,expected", [
    (1, 1), (2, 2), (3, 4), (4, 4), (5, 8), (7, 8), (8, 8),
])
def test_snap_rounds_to_natural_widths(observed, expected):
    assert snap_width(observed) == expected


def test_snap_leaves_long_runs_alone():
    """A 20-byte run is a byte array, not an integer — do not round it to 32."""
    assert snap_width(20) == 20


# ── fields_from_groups ──────────────────────────────────────


def test_snapping_recovers_the_invisible_low_byte():
    """The measured limitation: only bytes 4-6 of `width` are observable.
    Snapping is what turns that into the real 4-byte field."""
    groups = [_influences((i, _BYTE_EDGES[i]) for i in (4, 5, 6))]
    fields = fields_from_groups(groups)
    assert fields[0].offset == 4
    assert fields[0].size == 4
    assert fields[0].observed_size == 3
    assert fields[0].snapped is True


def test_snapped_fields_take_a_confidence_penalty():
    """An inferred byte is a weaker claim than an observed one, and downstream
    consumers must be able to tell the difference."""
    exact = fields_from_groups([_influences([(0, {"a"}), (1, {"a"})])])
    snapped = fields_from_groups([_influences([(0, {"a"}), (1, {"a"}), (2, {"a"})])])
    assert exact[0].confidence == 1.0
    assert snapped[0].confidence < 1.0
    assert snapped[0].snapped is True


def test_unsnapped_field_is_full_confidence():
    fields = fields_from_groups([_influences([(0, {"a"}), (1, {"a"}),
                                              (2, {"a"}), (3, {"a"})])])
    assert fields[0].size == 4
    assert fields[0].observed_size == 4
    assert fields[0].confidence == 1.0
    assert fields[0].snapped is False


def test_snapping_can_be_disabled():
    groups = [_influences([(0, {"a"}), (1, {"a"}), (2, {"a"})])]
    assert fields_from_groups(groups, snap=False)[0].size == 3


# ── fields_to_fieldspec ─────────────────────────────────────


def test_fieldspec_is_accepted_by_the_existing_interpreter(seed):
    """The whole design rests on this: a measured spec must be renderable by
    the interpreter that already exists, with no changes to it."""
    import random

    from nemesis.recon.fieldspec_seedgen import build_from_fieldspec, validate_fieldspec

    fields = [MeasuredField(offset=0, size=4, observed_size=4, confidence=1.0),
              MeasuredField(offset=4, size=4, observed_size=3, confidence=0.85)]
    spec = fields_to_fieldspec(fields, seed)

    ok, err = validate_fieldspec(spec)
    assert ok, err
    rendered = build_from_fieldspec(spec["fields"], random.Random(0))
    assert isinstance(rendered, bytes) and len(rendered) > 0


def test_fieldspec_metadata_survives_the_interpreter(seed):
    """source/confidence ride along because build_from_fieldspec reads known
    keys via .get() and ignores the rest — verified, not assumed."""
    import random

    from nemesis.recon.fieldspec_seedgen import build_from_fieldspec

    spec = fields_to_fieldspec(
        [MeasuredField(offset=0, size=4, observed_size=4, confidence=1.0)], seed)
    assert spec["fields"][0]["source"] == "coverage"
    assert spec["fields"][0]["confidence"] == 1.0
    assert spec["fields"][0]["method"] == "jaccard-snap"
    build_from_fieldspec(spec["fields"], random.Random(0))  # must not raise


def test_fieldspec_preserves_seed_length(seed):
    """Gaps and tail become byte regions so later fields keep their measured
    offsets — a spec that renders short would misplace every field after it."""
    import random

    from nemesis.recon.fieldspec_seedgen import build_from_fieldspec

    fields = [MeasuredField(offset=4, size=4, observed_size=4, confidence=1.0)]
    spec = fields_to_fieldspec(fields, seed)
    rendered = build_from_fieldspec(spec["fields"], random.Random(0))
    assert len(rendered) == len(seed)


def test_fieldspec_keeps_the_observed_value(seed):
    """A spec of pure extremes produces seeds that fail the first validity
    check and never reach the code the field controls."""
    fields = [MeasuredField(offset=4, size=4, observed_size=4, confidence=1.0)]
    spec = fields_to_fieldspec(fields, seed)
    int_field = next(f for f in spec["fields"] if f["kind"] == "int")
    assert 256 in int_field["values"]        # the value actually in the seed


def test_fieldspec_includes_boundary_values(seed):
    fields = [MeasuredField(offset=4, size=4, observed_size=4, confidence=1.0)]
    spec = fields_to_fieldspec(fields, seed)
    values = next(f for f in spec["fields"] if f["kind"] == "int")["values"]
    assert 0 in values
    assert 0xFFFFFFFF in values


def test_fieldspec_never_emits_len_kind(seed):
    """Deliberate: a length-to-region relationship cannot be derived from
    control flow. Emitting one would make seeds confidently wrong. That
    inference is the LLM's job, reading this spec."""
    fields = [MeasuredField(offset=0, size=4, observed_size=4, confidence=1.0),
              MeasuredField(offset=9, size=2, observed_size=2, confidence=1.0)]
    spec = fields_to_fieldspec(fields, seed)
    assert all(f["kind"] != "len" for f in spec["fields"])


def test_fieldspec_marks_snapped_fields(seed):
    fields = [MeasuredField(offset=4, size=4, observed_size=3, confidence=0.85)]
    spec = fields_to_fieldspec(fields, seed)
    int_field = next(f for f in spec["fields"] if f["kind"] == "int")
    assert int_field["observed_size"] == 3


# ── infer_fieldspec (end to end, fake runner) ───────────────


def test_infer_recovers_the_known_layout(seed, tmp_path):
    """End to end against ground truth: four fields at the right offsets and
    widths, including the one only snapping can complete."""
    spec = infer_fieldspec("dummy", seed, tmp_path, runner=FakeRunner(seed))
    assert spec is not None
    ints = [f for f in spec["fields"] if f["kind"] == "int"]
    assert len(ints) == 4

    offsets = []
    cursor = 0
    for f in spec["fields"]:
        if f["kind"] == "int":
            offsets.append((cursor, f["size"]))
            cursor += f["size"]
        else:
            cursor += f["max"]
    assert offsets == [(0, 4), (4, 4), (8, 1), (9, 2)]


def test_infer_ignores_payload_bytes(seed, tmp_path):
    """16 inert payload bytes must produce zero fields — false positives here
    would send mutation budget at bytes that do nothing."""
    spec = infer_fieldspec("dummy", seed, tmp_path, runner=FakeRunner(seed))
    tail = [f for f in spec["fields"] if f.get("name") == "tail"]
    assert tail and tail[0]["min"] == 16


def test_infer_returns_none_without_baseline_coverage(seed, tmp_path):
    """An uninstrumented binary yields no edges. Returning None lets the caller
    fall back to the LLM spec instead of proceeding with nonsense."""
    class Dead(ShowmapRunner):
        def __init__(self): pass
        def edges_for(self, path): return frozenset()

    assert infer_fieldspec("dummy", seed, tmp_path, runner=Dead()) is None


def test_infer_returns_none_when_nothing_is_influential(tmp_path):
    class Flat(ShowmapRunner):
        def __init__(self): pass
        def edges_for(self, path): return frozenset({"1", "2"})

    assert infer_fieldspec("dummy", b"AAAA", tmp_path, runner=Flat()) is None


def test_flaky_edges_are_excluded(seed, tmp_path):
    """Non-determinism (hash seeds, timing) otherwise makes every byte look
    influential. The unstable edge must not reach any field."""
    runner = FakeRunner(seed, flaky={"999"})
    spec = infer_fieldspec("dummy", seed, tmp_path, runner=runner,
                           baseline_runs=4)
    assert spec is not None
    fields = json.loads((tmp_path / "byte_influence" / "fields.json")
                        .read_text(encoding="utf-8"))
    for f in fields["fields"]:
        assert "999" not in f["edges"]


def test_artifacts_are_written_per_stage(seed, tmp_path):
    """When a real target produces a poor spec, the question is which stage
    failed — unanswerable from the final JSON alone."""
    infer_fieldspec("dummy", seed, tmp_path, runner=FakeRunner(seed))
    out = tmp_path / "byte_influence"
    for name in ("baseline.json", "probes.json", "fields.json", "fieldspec.json"):
        assert (out / name).exists(), f"{name} missing"
    probes = json.loads((out / "probes.json").read_text(encoding="utf-8"))
    assert len(probes) == len(seed)


def test_artifacts_can_be_disabled(seed, tmp_path):
    infer_fieldspec("dummy", seed, tmp_path, runner=FakeRunner(seed),
                    dump_artifacts=False)
    assert not (tmp_path / "byte_influence").exists()


def test_sampling_kicks_in_on_large_seeds(tmp_path):
    """Cost is bytes x probe values; a multi-megabyte seed would otherwise be
    millions of executions. Sampling loses fields, it must not corrupt them."""
    big = b"TOYF" + bytes(5000)
    runner = FakeRunner(big)
    infer_fieldspec("dummy", big, tmp_path, runner=runner, max_probe_bytes=100)
    probes = json.loads((tmp_path / "byte_influence" / "probes.json")
                        .read_text(encoding="utf-8"))
    assert sum(1 for p in probes if p["probed"]) < len(big)


def test_threshold_reaches_the_artifacts(seed, tmp_path):
    """Benchmark sweeps need to know which threshold produced which result."""
    infer_fieldspec("dummy", seed, tmp_path, runner=FakeRunner(seed),
                    threshold=0.42)
    fields = json.loads((tmp_path / "byte_influence" / "fields.json")
                        .read_text(encoding="utf-8"))
    assert fields["threshold"] == 0.42


# ── ShowmapRunner map parsing ───────────────────────────────


def test_parse_map_reads_edge_ids(tmp_path):
    p = tmp_path / "m.map"
    p.write_text("000005:1\n000011:3\n000013:1\n")
    assert ShowmapRunner._parse_map(p) == frozenset({"000005", "000011", "000013"})


def test_parse_map_tolerates_junk(tmp_path):
    p = tmp_path / "m.map"
    p.write_text("000005:1\ngarbage\n\n000011:2\n")
    assert ShowmapRunner._parse_map(p) == frozenset({"000005", "000011"})


def test_parse_map_missing_file(tmp_path):
    assert ShowmapRunner._parse_map(tmp_path / "nope.map") == frozenset()


# ── Input-mode detection ────────────────────────────────────
#
# Getting this wrong is silent and total: a stdin-reading target handed a path
# on argv parses nothing and reports the same few edges for every input, which
# is indistinguishable from "no byte matters". Measured on cJSON: argv gave 4
# edges, stdin gave 91.


class ModeRunner(ShowmapRunner):
    """Records which mode was used; reports edges only for the mode it accepts."""

    def __init__(self, accepts: str):
        self.accepts = accepts
        self.modes_tried: list[str] = []
        self.input_mode = "auto"
        self.log = ShowmapRunner("x").log

    def _run(self, input_path, mode):
        self.modes_tried.append(mode)
        if mode == self.accepts:
            return frozenset({"1", "2", "3", "4", "5"})
        return frozenset({"1"})        # startup path only — input never read


def test_detects_stdin_target(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"data")
    runner = ModeRunner(accepts="stdin")
    assert len(runner.edges_for(p)) == 5
    assert runner.input_mode == "stdin"


def test_detects_argv_target(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"data")
    runner = ModeRunner(accepts="argv")
    assert len(runner.edges_for(p)) == 5
    assert runner.input_mode == "argv"


def test_mode_detection_runs_once_then_sticks(tmp_path):
    """Detection costs two extra executions. Paying that per probe would double
    the cost of the whole sweep."""
    p = tmp_path / "in.bin"
    p.write_bytes(b"data")
    runner = ModeRunner(accepts="stdin")
    runner.edges_for(p)
    n_after_first = len(runner.modes_tried)
    runner.edges_for(p)
    runner.edges_for(p)
    assert n_after_first == 3          # stdin probe, argv probe, real run
    assert len(runner.modes_tried) == n_after_first + 2


def test_tie_prefers_stdin(tmp_path):
    """When neither mode reads the input, stdin is the safer default: it is what
    the project's own stub harnesses use."""
    p = tmp_path / "in.bin"
    p.write_bytes(b"data")
    runner = ModeRunner(accepts="neither")
    runner.edges_for(p)
    assert runner.input_mode == "stdin"


def test_explicit_mode_skips_detection(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"data")
    runner = ModeRunner(accepts="argv")
    runner.input_mode = "argv"
    runner.edges_for(p)
    assert runner.modes_tried == ["argv"]


# ── Wiring into the seed pipeline ───────────────────────────
#
# The measured spec is worth nothing if the orchestrator never asks for it, or
# if a failure here costs the run its seeds. These pin both.


def _orchestrator(tmp_path, build_dir=None):
    from nemesis.config import NemesisConfig
    from nemesis.fuzzing import AFLOrchestrator

    cfg = NemesisConfig()
    cfg.target.build_dir = str(build_dir or (tmp_path / "build"))
    orch = AFLOrchestrator.__new__(AFLOrchestrator)   # skip heavy __init__
    orch.config = cfg
    orch.workspace = tmp_path / "ws"
    from nemesis.logging import get_logger
    orch.log = get_logger("test")
    return orch


def test_feature_flag_is_registered():
    from nemesis.feature_flags import is_enabled
    assert is_enabled("byte_influence") is True     # default on


def test_disable_flag_turns_it_off(monkeypatch, tmp_path):
    monkeypatch.setenv("NEMESIS_DISABLE_BYTE_INFLUENCE", "1")
    orch = _orchestrator(tmp_path)
    assert orch._measured_fieldspec(tmp_path) is None


def _build_with_harness(tmp_path):
    """Build dir containing the harness source the probe is compiled from."""
    build = tmp_path / "build"
    build.mkdir(exist_ok=True)
    (build / "fuzz_nemesis.c").write_text("int main(void){return 0;}\n")
    return build


def _stub_probe(monkeypatch, path):
    import nemesis.recon.probe_build as pb_mod
    monkeypatch.setattr(pb_mod, "build_probe_binary", lambda **kw: path)


def test_returns_none_without_harness_source(tmp_path):
    """No harness source → nothing to build a probe from, so fall back to the
    LLM spec rather than probing the persistent fuzz binary, which would
    silently report that no byte matters."""
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")
    assert _orchestrator(tmp_path)._measured_fieldspec(seeds) is None


def test_returns_none_when_probe_build_fails(tmp_path, monkeypatch):
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")
    _stub_probe(monkeypatch, None)
    assert _orchestrator(tmp_path, build)._measured_fieldspec(seeds) is None


def test_returns_none_without_seeds(tmp_path):
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    assert _orchestrator(tmp_path, build)._measured_fieldspec(seeds) is None


def test_probing_failure_does_not_raise(tmp_path, monkeypatch):
    """This is an optimisation over the LLM path. If it throws, the run loses
    its seeds entirely — so every failure has to become a None."""
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")
    _stub_probe(monkeypatch, tmp_path / "probe_bin")

    import nemesis.recon.byte_influence as bi_mod

    def boom(**kwargs):
        raise RuntimeError("afl-showmap exploded")
    monkeypatch.setattr(bi_mod, "infer_fieldspec", boom)

    assert _orchestrator(tmp_path, build)._measured_fieldspec(seeds) is None


def test_probe_build_failure_does_not_raise(tmp_path, monkeypatch):
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")

    import nemesis.recon.probe_build as pb_mod

    def boom(**kw):
        raise RuntimeError("compiler vanished")
    monkeypatch.setattr(pb_mod, "build_probe_binary", boom)

    assert _orchestrator(tmp_path, build)._measured_fieldspec(seeds) is None


def test_deepest_seed_is_chosen_not_the_smallest(tmp_path, monkeypatch):
    """REGRESSION: this used to pick the smallest file to keep probing cheap.
    Measured on the OSS-Fuzz libtiff corpus, size does not predict depth — the
    smallest seed (166 B) reached 297 edges while the deepest (637) was 8258 B
    — so that heuristic picked close to the worst candidate available."""
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "shallow_small.bin").write_bytes(b"XY")          # small, shallow
    (seeds / "deep_big.bin").write_bytes(b"D" * 500)          # big, deep
    _stub_probe(monkeypatch, tmp_path / "probe_bin")

    class DepthRunner(ShowmapRunner):
        def __init__(self, *a, **k):
            self.input_mode = "stdin"
        def edges_for(self, path):
            data = Path(path).read_bytes()
            return frozenset(str(i) for i in range(50)) if b"D" in data \
                else frozenset({"1"})

    captured = {}

    import nemesis.recon.byte_influence as bi_mod
    monkeypatch.setattr(bi_mod, "ShowmapRunner", DepthRunner)

    def capture(*, probe_binary, seed, work_dir, runner=None):
        captured["seed"] = seed
        return {"fields": [{"kind": "int", "size": 1}]}
    monkeypatch.setattr(bi_mod, "infer_fieldspec", capture)

    spec = _orchestrator(tmp_path, build)._measured_fieldspec(seeds)
    assert spec is not None
    assert captured["seed"] == b"D" * 500     # the deep one, despite being larger


def test_returns_none_when_no_seed_reaches_the_target(tmp_path, monkeypatch):
    """Zero edges for every candidate says more about the binary than about the
    format — reporting "no byte matters" from that would be a lie."""
    build = _build_with_harness(tmp_path)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")
    _stub_probe(monkeypatch, tmp_path / "probe_bin")

    class DeadRunner(ShowmapRunner):
        def __init__(self, *a, **k):
            self.input_mode = "stdin"
        def edges_for(self, path):
            return frozenset()

    import nemesis.recon.byte_influence as bi_mod
    monkeypatch.setattr(bi_mod, "ShowmapRunner", DeadRunner)

    assert _orchestrator(tmp_path, build)._measured_fieldspec(seeds) is None


def test_cmin_uses_the_analysis_binary_not_the_fuzz_binary(tmp_path, monkeypatch):
    """REGRESSION: afl-cmin against the persistent fuzzing binary sees identical
    coverage for every seed and keeps none of them ("0 unique tuples across 5
    files", measured on cJSON). The step then silently does nothing — no seeds
    are lost, because the caller falls back to the unminimised corpus, but the
    minimisation never happens."""
    build = _build_with_harness(tmp_path)
    (build / "fuzz_nemesis").write_bytes(b"\x7fELF")
    probe = tmp_path / "probe_bin"
    probe.write_bytes(b"\x7fELF")
    _stub_probe(monkeypatch, probe)

    orch = _orchestrator(tmp_path, build)
    resolved = orch.analysis_binary()
    assert resolved == probe
    assert resolved.name != "fuzz_nemesis"


def test_analysis_binary_is_built_once(tmp_path, monkeypatch):
    """Both cmin call sites and byte-influence probing ask for it; rebuilding
    per call would recompile the harness several times per run."""
    build = _build_with_harness(tmp_path)
    calls = []

    import nemesis.recon.probe_build as pb_mod

    def counting(**kw):
        calls.append(1)
        return tmp_path / "probe_bin"
    monkeypatch.setattr(pb_mod, "build_probe_binary", counting)

    orch = _orchestrator(tmp_path, build)
    orch.analysis_binary()
    orch.analysis_binary()
    orch.analysis_binary()
    assert len(calls) == 1


def test_analysis_binary_none_when_no_harness_source(tmp_path):
    assert _orchestrator(tmp_path).analysis_binary() is None


def test_probe_binary_is_used_not_the_fuzz_binary(tmp_path, monkeypatch):
    """REGRESSION: probing the persistent fuzz binary returns a plausible zero
    — it receives no input outside afl-fuzz, so every byte looks inert."""
    build = _build_with_harness(tmp_path)
    (build / "fuzz_nemesis").write_bytes(b"\x7fELF")   # the WRONG binary
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.bin").write_bytes(b"AAAA")
    probe = tmp_path / "probe_bin"
    _stub_probe(monkeypatch, probe)

    captured = {}

    import nemesis.recon.byte_influence as bi_mod

    class LiveRunner(ShowmapRunner):
        def __init__(self, *a, **k):
            self.input_mode = "stdin"
        def edges_for(self, path):
            return frozenset({"1", "2"})
    monkeypatch.setattr(bi_mod, "ShowmapRunner", LiveRunner)

    def capture(*, probe_binary, seed, work_dir, runner=None):
        captured["binary"] = probe_binary
        return {"fields": []}
    monkeypatch.setattr(bi_mod, "infer_fieldspec", capture)

    _orchestrator(tmp_path, build)._measured_fieldspec(seeds)
    assert captured["binary"] == probe
    assert captured["binary"].name != "fuzz_nemesis"
