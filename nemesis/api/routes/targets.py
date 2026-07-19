"""GET /api/targets — configured target libraries."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetInfo(BaseModel):
    name: str
    oss_fuzz_project: str = ""
    source_root: str = ""
    work_root: str = ""
    has_pinned_funcs: bool = False
    pinned_func_count: int = 0
    strategy: str = "harness"


@router.get("/{target_name}/config")
def get_target_config(target_name: str) -> dict:
    """The fully resolved config for a target — the API twin of `nemesis config --show`."""
    from fastapi import HTTPException  # noqa: PLC0415

    from nemesis.config import load_config  # noqa: PLC0415

    cfg_path = Path("config/targets") / f"{target_name}.yaml"
    if not cfg_path.exists():
        raise HTTPException(status_code=404, detail=f"No config for target {target_name}")
    cfg = load_config(default_path=Path("config/default.yaml"), target_path=cfg_path)
    return {"target_name": target_name, "config_path": str(cfg_path),
            "config": cfg.model_dump(mode="json")}


@router.get("", response_model=list[TargetInfo])
def list_targets() -> list[TargetInfo]:
    """List all configured targets from config/targets/*.yaml."""
    import yaml

    targets_dir = Path("config/targets")
    if not targets_dir.exists():
        return []

    result = []
    for yaml_path in sorted(targets_dir.glob("*.yaml")):
        try:
            with open(yaml_path) as f:
                data = yaml.safe_load(f) or {}
            target_cfg = data.get("target", {})
            fuzzing_cfg = data.get("fuzzing", {})
            pinned = target_cfg.get("pinned_funcs", [])
            result.append(TargetInfo(
                name=target_cfg.get("name", yaml_path.stem),
                oss_fuzz_project=target_cfg.get("oss_fuzz_project", ""),
                source_root=target_cfg.get("source_root", ""),
                work_root=target_cfg.get("work_root", ""),
                has_pinned_funcs=len(pinned) > 0,
                pinned_func_count=len(pinned),
                strategy=fuzzing_cfg.get("strategy", "harness"),
            ))
        except Exception:
            result.append(TargetInfo(name=yaml_path.stem))

    return result
