"""GET /api/targets/{name}/functions — every function in a target, with both
OSS-Fuzz and NEMESIS coverage, plus PUT .../pins to pin/unpin them.

The function list comes from the OSS-Fuzz Introspector `all-functions` endpoint
(unfiltered — recon's <50% coverage filter is deliberately NOT applied here, so
well-covered functions show up too). Results are cached under the workspace
because that call is a slow network round-trip. Libraries that are not in
OSS-Fuzz fall back to a local source scan, which yields no OSS-Fuzz coverage.

Pins are written back into config/targets/{name}.yaml with ruamel so the
hand-written comments and formatting in those files survive: entries that stay
pinned are left byte-identical (keeping fields like `indirect_reach` and their
comments), only additions and removals are applied.
"""

from __future__ import annotations

import json
import time
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from nemesis.api.routes.coverage import _run_matches_target

router = APIRouter(prefix="/api/targets", tags=["functions"])

_CACHE_TTL_SECONDS = 24 * 3600


# Advanced per-pin knobs surfaced in the dashboard, with their defaults. Only
# values that differ from the default are written, so configs stay minimal.
PIN_OPTIONS: dict[str, Any] = {
    "indirect_reach": False,
    "direct_internal": False,
    "force_no_blocker": False,
    "differential_oracle": False,
    "threaded_oracle": False,
    "auto_expose": False,
    "harness_hint": "",
    "differential_reference": "",
    "needed_headers": [],
    "output_invariants": [],
}


class FunctionInfo(BaseModel):
    func_name: str
    file_path: str = ""
    line: int = 0
    oss_fuzz_coverage_pct: float = -1.0   # -1 = unknown (not in OSS-Fuzz / no data)
    nemesis_coverage_pct: float = -1.0    # -1 = NEMESIS has not measured it
    complexity: int = 0
    pinned: bool = False
    status: str = ""                      # status from the run that measured it
    pin_options: dict[str, Any] = {}      # advanced knobs, only when pinned


class FunctionsResponse(BaseModel):
    target_name: str
    source: str = "none"                  # introspector | local_scan | none
    run_id: str = ""                      # run the NEMESIS coverage came from
    cached: bool = False
    functions: list[FunctionInfo] = []
    pinned_count: int = 0


class PinEntry(BaseModel):
    func_name: str
    file_path: str = ""
    line: int = 0
    # Advanced knobs (see PIN_OPTIONS). Anything left at its default is not
    # written into the YAML, and is removed from an entry that previously had it.
    indirect_reach: bool = False
    direct_internal: bool = False
    force_no_blocker: bool = False
    differential_oracle: bool = False
    threaded_oracle: bool = False
    auto_expose: bool = False
    harness_hint: str = ""
    differential_reference: str = ""
    needed_headers: list[str] = []
    output_invariants: list[str] = []


class PinRequest(BaseModel):
    pins: list[PinEntry] = []


class PinResponse(BaseModel):
    target_name: str
    pinned_count: int
    config_path: str


# ── helpers ──────────────────────────────────────────────────


def _target_config_path(target_name: str) -> Path:
    return Path("config/targets") / f"{target_name}.yaml"


def _load_cfg(target_name: str):
    """Resolve the merged config for a target (same layering the CLI uses)."""
    from nemesis.config import load_config  # lazy: keeps API startup fast

    cfg_path = _target_config_path(target_name)
    if not cfg_path.exists():
        raise HTTPException(status_code=404, detail=f"No config for target {target_name}")
    return load_config(default_path=Path("config/default.yaml"), target_path=cfg_path)


def _introspector_functions(cfg, workspace: Path, refresh: bool) -> tuple[list[dict], bool]:
    """All functions from the Introspector API, cached on disk. (funcs, was_cached)"""
    project = getattr(cfg.target, "oss_fuzz_project", "") or ""
    if not project:
        return [], False

    cache_file = workspace / "introspector_cache" / f"{project}.json"
    if not refresh and cache_file.exists():
        try:
            blob = json.loads(cache_file.read_text(encoding="utf-8"))
            if time.time() - float(blob.get("fetched_at", 0)) < _CACHE_TTL_SECONDS:
                return list(blob.get("functions", [])), True
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    from nemesis.recon import IntrospectorParser  # lazy

    raw = IntrospectorParser(cfg)._fetch_endpoint("all-functions", project)
    if raw:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(
                json.dumps({"fetched_at": time.time(), "functions": raw}),
                encoding="utf-8",
            )
        except OSError:
            pass
    return raw, False


def _from_introspector(
    raw: list[dict],
    project: str,
    exclude_dirs: set[str] | None = None,
    exclude_files: list[str] | None = None,
) -> list[FunctionInfo]:
    """Parse the Introspector `all-functions` payload into FunctionInfo.

    Quirks of that API handled here: instrumented builds report names prefixed
    with ``OSS_FUZZ_`` (the real symbol is what the source calls it), and the
    payload mixes in system/libc++ functions plus the project's own OSS-Fuzz
    harness code. The same exclusions recon uses (``introspector.exclude_dirs``
    / ``exclude_files``) are applied so the dashboard does not offer you the
    fuzzer itself as a fuzz target.
    """
    import fnmatch

    src_prefix = f"/src/{project}/"
    skip_dirs = exclude_dirs or set()
    skip_files = exclude_files or []
    by_name: dict[str, FunctionInfo] = {}

    for f in raw:
        name = f.get("function_name", "") or ""
        path = str(f.get("function_filename", "") or "")
        if not name or not path.startswith(src_prefix):
            continue
        rel = path[len(src_prefix):]
        if set(PurePosixPath(rel).parts[:-1]) & skip_dirs:
            continue
        if any(fnmatch.fnmatch(PurePosixPath(rel).name, pat) for pat in skip_files):
            continue
        if name.startswith("OSS_FUZZ_"):
            name = name[len("OSS_FUZZ_"):]

        info = FunctionInfo(
            func_name=name,
            file_path=rel,
            line=int(f.get("source_line_begin", 0) or 0),
            oss_fuzz_coverage_pct=float(f.get("runtime_coverage_percent", 0) or 0),
            complexity=int(f.get("accummulated_complexity", 0) or 0),
        )
        # Stripping the prefix can collide with an unprefixed twin; keep the
        # better-covered one so we never understate what OSS-Fuzz reaches.
        prev = by_name.get(name)
        if prev is None or info.oss_fuzz_coverage_pct > prev.oss_fuzz_coverage_pct:
            by_name[name] = info

    return list(by_name.values())


def _from_local_scan(cfg) -> list[FunctionInfo]:
    from nemesis.recon import IntrospectorParser  # lazy

    targets = IntrospectorParser(cfg)._scan_local_source()
    return [
        FunctionInfo(
            func_name=t.func_name,
            file_path=t.file_path,
            line=t.line,
            oss_fuzz_coverage_pct=-1.0,   # local scan has no OSS-Fuzz data
            complexity=t.complexity,
        )
        for t in targets
    ]


def _pin_options_of(pin: Any) -> dict[str, Any]:
    """Current advanced-knob values for a configured pin (all keys, defaults included)."""
    return {key: getattr(pin, key, default) for key, default in PIN_OPTIONS.items()}


def _nemesis_coverage(workspace: Path, target_name: str) -> tuple[dict[str, tuple[float, str]], str]:
    """Map func_name -> (nemesis_coverage_pct, status) from this target's latest run."""
    runs: list[tuple[Path, float]] = []
    if workspace.exists():
        for p in workspace.iterdir():
            rf = p / "results.json"
            if p.is_dir() and rf.exists():
                runs.append((p, rf.stat().st_mtime))
    runs.sort(key=lambda x: x[1], reverse=True)

    for run_dir, _ in runs:
        try:
            data = json.loads((run_dir / "results.json").read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if not data.get("results") or not _run_matches_target(data, target_name):
            continue

        out: dict[str, tuple[float, str]] = {}
        for r in data["results"]:
            fn = r.get("target", {}).get("func_name", "")
            if not fn:
                continue
            # prefer source coverage; fall back to function coverage
            cov = float(r.get("source_coverage_pct", -1.0))
            if cov < 0:
                cov = float(r.get("function_coverage_pct", -1.0))
            out[fn] = (cov, str(r.get("status", "")))
        return out, str(data.get("run_id", run_dir.name))

    return {}, ""


# ── routes ───────────────────────────────────────────────────


@router.get("/{target_name}/functions", response_model=FunctionsResponse)
def list_functions(
    target_name: str,
    request: Request,
    refresh: bool = Query(False, description="Bypass the Introspector cache"),
) -> FunctionsResponse:
    """Every function in the target, with OSS-Fuzz coverage, NEMESIS coverage and pin state."""
    cfg = _load_cfg(target_name)
    workspace = Path(request.app.state.workspace)
    project = getattr(cfg.target, "oss_fuzz_project", "") or ""

    raw, cached = _introspector_functions(cfg, workspace, refresh)
    if raw:
        funcs = _from_introspector(
            raw, project,
            set(cfg.introspector.exclude_dirs),
            list(cfg.introspector.exclude_files),
        )
        source = "introspector"
    else:
        funcs = _from_local_scan(cfg)
        source = "local_scan" if funcs else "none"
        cached = False

    nem, run_id = _nemesis_coverage(workspace, target_name)
    pinned = {p.func_name for p in getattr(cfg.target, "pinned_funcs", [])}

    pin_by_name = {p.func_name: p for p in getattr(cfg.target, "pinned_funcs", [])}
    for f in funcs:
        f.pinned = f.func_name in pinned
        if f.pinned:
            f.pin_options = _pin_options_of(pin_by_name[f.func_name])
        if f.func_name in nem:
            f.nemesis_coverage_pct, f.status = nem[f.func_name]

    # Surface pinned functions the source list didn't know about, so the UI
    # never silently drops something the user pinned by hand.
    known = {f.func_name for f in funcs}
    for p in getattr(cfg.target, "pinned_funcs", []):
        if p.func_name not in known:
            cov, status = nem.get(p.func_name, (-1.0, ""))
            funcs.append(FunctionInfo(
                func_name=p.func_name, file_path=p.file_path, line=p.line,
                nemesis_coverage_pct=cov, status=status, pinned=True,
                pin_options=_pin_options_of(p),
            ))

    # Pinned first, then least-covered by OSS-Fuzz (the interesting end), then name.
    funcs.sort(key=lambda f: (
        not f.pinned,
        f.oss_fuzz_coverage_pct if f.oss_fuzz_coverage_pct >= 0 else 1e9,
        f.func_name,
    ))

    return FunctionsResponse(
        target_name=target_name, source=source, run_id=run_id, cached=cached,
        functions=funcs, pinned_count=sum(1 for f in funcs if f.pinned),
    )


@router.put("/{target_name}/pins", response_model=PinResponse)
def set_pins(target_name: str, body: PinRequest) -> PinResponse:
    """Replace the pinned function set, preserving the config's comments/formatting.

    Entries that remain pinned are left untouched — including hand-tuned fields
    like `indirect_reach`, `harness_hint` and their comments.
    """
    from ruamel.yaml import YAML  # lazy

    cfg_path = _target_config_path(target_name)
    if not cfg_path.exists():
        raise HTTPException(status_code=404, detail=f"No config for target {target_name}")

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    try:
        data = yaml.load(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Cannot parse {cfg_path}: {exc}") from exc

    if data is None or "target" not in data:
        raise HTTPException(status_code=400, detail=f"{cfg_path} has no `target:` section")

    desired = {p.func_name: p for p in body.pins}
    seq = data["target"].get("pinned_funcs")
    if seq is None:
        seq = []
        data["target"]["pinned_funcs"] = seq

    # Drop unpinned (reverse order so indices stay valid)
    for i in range(len(seq) - 1, -1, -1):
        entry = seq[i]
        name = entry.get("func_name") if hasattr(entry, "get") else None
        if name not in desired:
            del seq[i]

    # Update advanced knobs on entries that stay pinned. Assigning into the
    # existing map keeps every other key — and its comments — untouched.
    # Only keys the caller explicitly sent are touched: a client that PUTs bare
    # {func_name} must not silently wipe hand-tuned settings in the YAML.
    for entry in seq:
        if not hasattr(entry, "get"):
            continue
        p = desired.get(entry.get("func_name"))
        if p is None:
            continue
        for key, default in PIN_OPTIONS.items():
            if key not in p.model_fields_set:
                continue
            value = getattr(p, key)
            if value != default:
                entry[key] = value
            elif key in entry:
                del entry[key]          # explicitly reset to default -> drop the noise

    # Append newly pinned, leaving existing entries byte-identical
    present = {e.get("func_name") for e in seq if hasattr(e, "get")}
    for name, p in desired.items():
        if name in present:
            continue
        new: dict[str, Any] = {"func_name": name}
        if p.file_path:
            new["file_path"] = p.file_path
        if p.line:
            new["line"] = p.line
        for key, default in PIN_OPTIONS.items():
            if key not in p.model_fields_set:
                continue
            value = getattr(p, key)
            if value != default:
                new[key] = value
        seq.append(new)

    try:
        with cfg_path.open("w", encoding="utf-8", newline="\n") as fh:
            yaml.dump(data, fh)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Cannot write {cfg_path}: {exc}") from exc

    return PinResponse(
        target_name=target_name, pinned_count=len(seq), config_path=str(cfg_path),
    )
