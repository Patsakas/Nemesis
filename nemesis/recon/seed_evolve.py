"""Coverage-feedback seed evolution (genetic seed scheduling).

Background
----------
The baseline flow generates seeds once and hands them to AFL. But NEMESIS
already *measures* whether a seed reaches the pinned function (the profiling
`reaches_target` signal). We can close the loop: score the current seed pool,
keep only the seeds that make genuine structural progress, and breed variations
of those winners back into the corpus before AFL starts. Deeply-validating
formats (lz4 token streams, TIFF IFDs) benefit most — a single seed that gets
*past* the validation is worth more than a thousand that bounce off it, and
breeding around it concentrates AFL's energy in the productive region.

This combines two of the proposed improvements:
  * #3 coverage-feedback evolution (select winners → breed)
  * #8 reaches-target gate (drop seeds that never reach the target)

Design
------
The genetic operators (`mutate_bytes`, `splice`, `breed`) are pure and seeded
by an explicit RNG so the produced corpus is reproducible across runs (and
unit-testable). The runtime fitness — "does this seed reach the target?" — is
injected as a callable so the heavy AFL/coverage machinery stays in the caller;
when no fitness function is available we fall back to breeding from the whole
pool (pure diversity injection, never harmful).

All failures are non-fatal: empty pool, no fitness, write error → 0 added.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import logging
    from nemesis.models import HarnessSpec


# ── pure genetic operators ────────────────────────────────────────────────

def mutate_bytes(data: bytes, rng: random.Random, max_edits: int = 8) -> bytes:
    """Apply a few cheap edits (flip / insert / delete) to `data`."""
    if not data:
        return bytes(rng.randrange(1, 16))
    buf = bytearray(data)
    n_edits = rng.randint(1, max_edits)
    for _ in range(n_edits):
        op = rng.random()
        if op < 0.6 and buf:                       # bit/byte flip
            i = rng.randrange(len(buf))
            buf[i] ^= 1 << rng.randrange(8)
        elif op < 0.8:                              # insert a byte
            i = rng.randrange(len(buf) + 1)
            buf.insert(i, rng.randrange(256))
        elif len(buf) > 1:                          # delete a byte
            del buf[rng.randrange(len(buf))]
    return bytes(buf)


def splice(a: bytes, b: bytes, rng: random.Random) -> bytes:
    """Single-point crossover: head of `a` + tail of `b`."""
    if not a:
        return b
    if not b:
        return a
    ca = rng.randrange(len(a))
    cb = rng.randrange(len(b))
    return a[:ca] + b[cb:]


def breed(
    winners: list[bytes],
    n_offspring: int,
    rng_seed: int,
    max_bytes: int = 1 << 18,
) -> list[bytes]:
    """Produce `n_offspring` unique children from the winner pool.

    Deterministic given (winners, n_offspring, rng_seed). Mixes mutation and
    crossover. Returns fewer than requested if uniqueness saturates the small
    neighbourhood of a tiny winner pool.
    """
    if not winners or n_offspring <= 0:
        return []
    rng = random.Random(rng_seed)
    out: list[bytes] = []
    seen: set[bytes] = {w for w in winners}  # don't re-emit the parents
    attempts = 0
    budget = n_offspring * 12
    while len(out) < n_offspring and attempts < budget:
        attempts += 1
        if len(winners) >= 2 and rng.random() < 0.5:
            child = splice(rng.choice(winners), rng.choice(winners), rng)
        else:
            child = mutate_bytes(rng.choice(winners), rng)
        if not child or len(child) > max_bytes:
            continue
        if child in seen:
            continue
        seen.add(child)
        out.append(child)
    return out


def select_winners(
    scored: list[tuple[bytes, float]],
    keep: int,
    min_score: float = 0.0,
) -> list[bytes]:
    """Top-`keep` seeds by score, dropping anything at/below `min_score`."""
    qualifying = [(s, sc) for s, sc in scored if sc > min_score]
    qualifying.sort(key=lambda t: t[1], reverse=True)
    return [s for s, _ in qualifying[:keep]]


# ── runtime glue ──────────────────────────────────────────────────────────

def _load_pool(seeds_dir: Path, max_bytes: int, cap: int = 400) -> list[bytes]:
    pool: list[bytes] = []
    try:
        files = [f for f in seeds_dir.iterdir() if f.is_file()]
    except OSError:
        return []
    for f in sorted(files, key=lambda p: p.name):
        if len(pool) >= cap:
            break
        try:
            if 0 < f.stat().st_size <= max_bytes:
                pool.append(f.read_bytes())
        except OSError:
            continue
    return pool


def evolve(
    *,
    config,
    symbolic,
    seeds_dir: Path,
    harness: "HarnessSpec",
    target_func: str = "",
    log: "logging.Logger",
    fitness_fn: Optional[Callable[[bytes], float]] = None,
    keep: int = 8,
    n_offspring: int = 40,
    rng_seed: int = 0xE7011E,
    max_bytes: int = 1 << 18,
) -> int:
    """Score the current seed pool, keep winners, breed variations into it.

    `fitness_fn(seed_bytes) -> float` is the reach/coverage oracle. When None
    (no runtime oracle wired), every seed scores equally and we breed from the
    whole pool — diversity injection that can only help. Returns the number of
    new seeds written.
    """
    pool = _load_pool(seeds_dir, max_bytes)
    if not pool:
        log.info("evolve.empty_pool")
        return 0

    if fitness_fn is not None:
        scored: list[tuple[bytes, float]] = []
        for s in pool:
            try:
                scored.append((s, float(fitness_fn(s))))
            except Exception:  # noqa: BLE001 — a bad probe must not abort evolution
                scored.append((s, 0.0))
        winners = select_winners(scored, keep, min_score=0.0)
        if not winners:
            # Nothing reached the target — fall back to the full pool so we
            # still inject diversity rather than giving up.
            log.info("evolve.no_winners_fallback_full_pool")
            winners = pool[:keep]
        else:
            log.info("evolve.winners_selected", winners=len(winners), pool=len(pool))
    else:
        log.info("evolve.no_fitness_breed_all")
        winners = pool[:keep]

    children = breed(winners, n_offspring, rng_seed, max_bytes=max_bytes)
    if not children:
        log.info("evolve.no_offspring")
        return 0

    seeds_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for c in children:
        digest = hashlib.sha256(c).hexdigest()[:12]
        dest = seeds_dir / f"evolve_{written:03d}_{digest}.bin"
        if dest.exists():
            continue
        try:
            dest.write_bytes(c)
            written += 1
        except OSError:
            pass
    log.info("evolve.children_written", count=written)
    return written
