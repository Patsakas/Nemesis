"""Phase 3: coverage-feedback seed evolution (genetic operators + glue)."""

from __future__ import annotations

import random
from pathlib import Path

from nemesis.recon import seed_evolve as ev

# ── pure operators ────────────────────────────────────────────────────────

def test_mutate_changes_data_but_stays_bytes():
    rng = random.Random(1)
    out = ev.mutate_bytes(b"AAAAAAAA", rng)
    assert isinstance(out, bytes)
    assert out != b"AAAAAAAA"  # at least one edit applied


def test_mutate_empty_input():
    rng = random.Random(1)
    out = ev.mutate_bytes(b"", rng)
    assert isinstance(out, bytes) and len(out) >= 1


def test_splice_combines_head_and_tail():
    rng = random.Random(0)
    out = ev.splice(b"HEAD", b"TAIL", rng)
    assert isinstance(out, bytes)


def test_splice_handles_empty():
    rng = random.Random(0)
    assert ev.splice(b"", b"X", rng) == b"X"
    assert ev.splice(b"Y", b"", rng) == b"Y"


def test_breed_is_deterministic_and_unique():
    winners = [b"hello world", b"goodbye moon"]
    a = ev.breed(winners, 20, rng_seed=42)
    b = ev.breed(winners, 20, rng_seed=42)
    assert a == b                                # reproducible
    assert len(a) == len(set(a))                 # unique
    assert all(c not in winners for c in a)      # never re-emit parents


def test_breed_empty_pool():
    assert ev.breed([], 10, rng_seed=1) == []


def test_select_winners_orders_and_filters():
    scored = [(b"a", 0.1), (b"b", 0.9), (b"c", 0.0), (b"d", 0.5)]
    win = ev.select_winners(scored, keep=2, min_score=0.0)
    assert win == [b"b", b"d"]                    # top-2 above 0
    assert b"c" not in win                        # score 0 dropped


# ── runtime glue ──────────────────────────────────────────────────────────

class _Log:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass


def _seed_pool(tmp: Path, n: int):
    tmp.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (tmp / f"s{i}.bin").write_bytes(bytes([i]) * (i + 4))


def test_evolve_with_fitness_keeps_winners(tmp_path):
    seeds = tmp_path / "seeds"
    _seed_pool(seeds, 6)
    # fitness rewards longer seeds
    n = ev.evolve(
        config=object(), symbolic=object(), seeds_dir=seeds,
        harness=object(), log=_Log(),
        fitness_fn=lambda s: float(len(s)), n_offspring=10, keep=3,
    )
    assert n > 0
    assert sum(1 for f in seeds.iterdir() if f.name.startswith("evolve_")) == n


def test_evolve_no_fitness_breeds_from_all(tmp_path):
    seeds = tmp_path / "seeds"
    _seed_pool(seeds, 4)
    n = ev.evolve(
        config=object(), symbolic=object(), seeds_dir=seeds,
        harness=object(), log=_Log(), n_offspring=8,
    )
    assert n > 0


def test_evolve_empty_pool_returns_zero(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    n = ev.evolve(
        config=object(), symbolic=object(), seeds_dir=seeds,
        harness=object(), log=_Log(),
    )
    assert n == 0
