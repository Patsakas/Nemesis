"""--resume must NOT skip funcs when the config was re-scoped between runs
(audit Batch 1: config_hash checkpoint guard)."""
from nemesis.config import load_config
from nemesis.pipeline import NemesisPipeline


def _pipeline(tmp_path):
    cfg = load_config()
    cfg.engine.work_dir = tmp_path
    return NemesisPipeline(cfg)


def test_resume_honored_when_config_unchanged(tmp_path):
    p = _pipeline(tmp_path)
    p._save_checkpoint("run1", ["fn_a", "fn_b"], "cjson")
    run_id, done = p._load_checkpoint("cjson")
    assert run_id == "run1"
    assert done == {"fn_a", "fn_b"}


def test_resume_discarded_when_sanitizer_profile_changes(tmp_path):
    p = _pipeline(tmp_path)
    p._save_checkpoint("run1", ["fn_a"], "cjson")
    # user re-scopes the run with a different sanitizer profile
    p.config.target.sanitizer_profile = "msan"
    run_id, done = p._load_checkpoint("cjson")
    assert run_id == "" and done == set(), "stale checkpoint must be ignored"


def test_resume_discarded_when_build_flags_change(tmp_path):
    p = _pipeline(tmp_path)
    p._save_checkpoint("run1", ["fn_a"], "cjson")
    p.config.target.build.configure = "cmake .. -DEXTRA=1"
    _, done = p._load_checkpoint("cjson")
    assert done == set()


def test_resume_discarded_for_different_target(tmp_path):
    p = _pipeline(tmp_path)
    p._save_checkpoint("run1", ["fn_a"], "cjson")
    _, done = p._load_checkpoint("libpng")
    assert done == set()


def test_fingerprint_stable_across_calls(tmp_path):
    p = _pipeline(tmp_path)
    assert p._config_fingerprint() == p._config_fingerprint()
