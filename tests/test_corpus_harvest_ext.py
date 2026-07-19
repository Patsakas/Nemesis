"""Phase 3 #7: extension-based corpus harvesting helpers."""

from __future__ import annotations

from nemesis.pipeline import derive_seed_extensions, is_under_test_dir


def test_derive_from_explicit_config():
    exts = derive_seed_extensions([], [".TIFF", "raw"], "")
    assert "tiff" in exts and "raw" in exts


def test_derive_strips_format_prefix_from_magic_keys():
    exts = derive_seed_extensions(["format_png", "format_gif"], None, "")
    assert "png" in exts and "gif" in exts


def test_derive_text_format_hints_from_library_name():
    # libxml2 has no binary magic at offset 0 — name-driven hints fill the gap
    exts = derive_seed_extensions([], None, "libxml2")
    assert "xml" in exts
    json_exts = derive_seed_extensions([], None, "cJSON")
    assert "json" in json_exts


def test_derive_empty_when_nothing_known():
    assert derive_seed_extensions([], None, "") == set()


def test_is_under_test_dir():
    assert is_under_test_dir(("libtiff", "test", "images", "a.tif"))
    assert is_under_test_dir(("foo", "tests", "b.xml"))
    assert is_under_test_dir(("pkg", "examples", "c.json"))
    assert not is_under_test_dir(("src", "main", "config.json"))
