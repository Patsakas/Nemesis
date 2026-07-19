"""LibraryMemory persistence (audit Batch 1): atomic save + corrupt-file
recovery. Untested before; it persists cross-run priors injected into prompts."""
from nemesis.library_memory import LibraryMemory


def test_roundtrip_persists_across_instances(tmp_path):
    m = LibraryMemory("cjson", tmp_path)
    m.record_type_fix("cJSON *", "cJSON.h")
    m.record_forbidden_pattern("cJSON_InitHooks")

    # a fresh instance reads what was saved
    m2 = LibraryMemory("cjson", tmp_path)
    assert m2._data["type_fixes"]["cJSON *"]["header"] == "cJSON.h"
    assert "cJSON_InitHooks" in m2._data["forbidden_patterns"]


def test_save_is_atomic_no_tmp_left_behind(tmp_path):
    m = LibraryMemory("lib", tmp_path)
    m.record_type_fix("T", "t.h")
    leftovers = list((tmp_path / "library_memory").glob("*.tmp*"))
    assert leftovers == [], f"atomic save left temp files: {leftovers}"


def test_corrupt_file_resets_to_empty_not_crash(tmp_path):
    mem_dir = tmp_path / "library_memory"
    mem_dir.mkdir(parents=True)
    (mem_dir / "lib.json").write_text("{ this is not valid json")
    # should not raise; returns the empty default structure
    m = LibraryMemory("lib", tmp_path)
    assert m._data["type_fixes"] == {}
    assert m._data["forbidden_patterns"] == []
