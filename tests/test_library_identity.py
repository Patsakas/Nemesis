"""H2b — artifact identity-aware library resolution.

The witness is astera: its config names a vendored dependency, the renamed-output
strategy repaired that name into the vendored file, and resolution *succeeded* at
selecting an archive the harness could not link against. Name resolution and identity
resolution answer different questions (H2b_PLAN.md §1).
"""

from __future__ import annotations

from pathlib import Path

from nemesis.library_resolver import LibraryResolver


def _tree(root: Path, files: dict[str, int]) -> None:
    for rel, size in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x00" * size)


ASTERA = {"libastera.a": 300, "dep/glfw/src/libglfw3.a": 900}


class TestIdentityOff:
    """Default behaviour is unchanged: the operator is independently disableable."""

    def test_vendored_resolution_is_left_alone(self, tmp_path):
        _tree(tmp_path, ASTERA)
        res = LibraryResolver().resolve(tmp_path, "dep/glfw/src/libglfw.a")
        assert res.found
        assert res.path.name == "libglfw3.a"        # the pre-H2b outcome, reproduced
        assert res.strategy == "fuzzy_glob"


class TestIdentityOn:
    def test_vendored_selection_is_re_decided(self, tmp_path):
        _tree(tmp_path, ASTERA)
        res = LibraryResolver(identity_aware=True).resolve(
            tmp_path, "dep/glfw/src/libglfw.a")
        assert res.path.name == "libastera.a"
        assert res.strategy == "identity_ownership"
        # the discarded selection stays in the trace: the question during debugging is
        # not what it picked but what it rejected and why
        assert any("identity:" in c and "libglfw3.a" in c for c in res.candidates_checked)

    def test_size_does_not_override_ownership(self, tmp_path):
        # the vendored archive is 3x larger; ownership decides, not size
        _tree(tmp_path, ASTERA)
        res = LibraryResolver(identity_aware=True).resolve(tmp_path, "libglfw.a")
        assert res.path.name == "libastera.a"

    def test_project_owned_resolution_is_untouched(self, tmp_path):
        # the regression guard: repos whose configured name is already correct
        _tree(tmp_path, {"src/libuicc.a": 100, "dep/x/libdep.a": 50})
        res = LibraryResolver(identity_aware=True).resolve(tmp_path, "src/libuicc.a")
        assert res.path.name == "libuicc.a"
        assert res.strategy == "exact_path"          # not re-decided
        assert not any("identity:" in c for c in res.candidates_checked)

    def test_vendored_only_tree_keeps_the_vendored_artifact(self, tmp_path):
        # no project-owned artifact exists to prefer — "nothing right to choose" is a
        # distinct outcome from "chose wrongly" (H2b_PLAN 5.1 no_candidate)
        _tree(tmp_path, {"dep/glfw/src/libglfw3.a": 900})
        res = LibraryResolver(identity_aware=True).resolve(
            tmp_path, "dep/glfw/src/libglfw.a")
        assert res.path.name == "libglfw3.a"
        assert any("identity:no_project_artifact" in c for c in res.candidates_checked)

    def test_unresolvable_name_is_not_rescued(self, tmp_path):
        # H2b re-decides a selection; it does not invent one where resolution failed
        _tree(tmp_path, {"dep/x/libdep.so": 10})
        res = LibraryResolver(identity_aware=True).resolve(tmp_path, "libnothing.a")
        assert res.found is False
        assert res.strategy == "not_found"
