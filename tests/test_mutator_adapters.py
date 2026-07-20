"""
Compile-and-exercise tests for the structure-aware mutator adapters.

A broken custom mutator does not produce bad test cases — it segfaults
afl-fuzz itself, so the whole run dies and the failure looks like an AFL
problem rather than an adapter problem. That makes "it compiles" far too weak
a bar, so each adapter is built against tests/mutator_harness.c and run for
thousands of rounds against a valid seed for its format.

The harness runs two phases (see its header comment for why both are needed):
  1. through `afl_custom_fuzz`, checking the AFL contract;
  2. calling the hooks directly on buffers malloc'd to the exact data size, so
     a semantic overflow lands in an ASAN redzone instead of being masked by
     the scaffold's 1 MB scratch buffer.

Sanitizers are used when the toolchain has them (clang on Linux/WSL, which is
where NEMESIS actually runs); elsewhere the harness still catches contract
violations and canary corruption on its own.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ADAPTERS = REPO / "nemesis" / "templates" / "mutator" / "adapters"
HARNESS = Path(__file__).resolve().parent / "mutator_harness.c"

# (adapter file stem, harness seed macro)
CASES = [
    ("tar", "SEED_TAR"),
    ("zip", "SEED_ZIP"),
    ("asn1_der", "SEED_ASN1"),
    ("protobuf", "SEED_PROTOBUF"),
]

ROUNDS = "20000"


def _compiler() -> str | None:
    for cc in ("clang", "gcc", "cc"):
        if shutil.which(cc):
            return cc
    return None


CC = _compiler()
needs_cc = pytest.mark.skipif(CC is None, reason="no C compiler available")


def _sanitizer_flags(cc: str) -> list[str]:
    """ASAN/UBSan when the toolchain supports them.

    mingw's gcc ships without libasan, so probe rather than assume: a hard
    dependency here would skip the whole suite on Windows, where the adapters
    still benefit from the contract and canary checks.
    """
    probe = subprocess.run(
        [cc, "-fsanitize=address,undefined", "-xc", "-", "-o", "/dev/null"],
        input="int main(void){return 0;}",
        capture_output=True, text=True,
    )
    if probe.returncode == 0:
        return ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    return []


@needs_cc
@pytest.mark.parametrize("stem,seed_macro", CASES)
def test_adapter_compiles_and_survives_fuzzing(stem, seed_macro, tmp_path):
    source = ADAPTERS / f"{stem}.c"
    assert source.exists(), f"adapter {source} is missing"

    binary = tmp_path / f"{stem}_harness"
    cmd = [
        CC, "-O1", "-g", "-w",
        *_sanitizer_flags(CC),
        f"-DADAPTER=\"{source.as_posix()}\"",
        f"-D{seed_macro}",
        "-o", str(binary), str(HARNESS),
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    assert build.returncode == 0, f"build failed:\n{build.stderr}"

    run = subprocess.run(
        [str(binary), ROUNDS], capture_output=True, text=True, timeout=300,
    )
    assert run.returncode == 0, (
        f"adapter {stem} failed exercise:\n{run.stdout}\n{run.stderr}"
    )
    # Both phases must actually have run — a harness that silently skipped
    # phase 2 would report success while testing nothing that matters.
    assert "phase 1" in run.stdout
    assert "phase 2" in run.stdout


@needs_cc
def test_harness_detects_an_injected_overflow(tmp_path):
    """Negative control: without this, "N rounds clean" proves nothing.

    Injects a one-byte write at buf[buf_size] into the tar adapter. Note this
    is only detectable in the harness's phase 2 — under `afl_custom_fuzz` the
    write lands inside the scaffold's 1 MB scratch buffer and no sanitizer
    can see it, which is exactly why phase 2 exists.
    """
    flags = _sanitizer_flags(CC)
    if not flags:
        pytest.skip("no sanitizer support — overflow would be undetectable")

    broken = tmp_path / "tar_broken.c"
    original = (ADAPTERS / "tar.c").read_text(encoding="utf-8")
    anchor = "    uint32_t op = nm_xorshift32(rng) % 7;"
    assert anchor in original, "anchor line changed — update this test"
    broken.write_text(
        original.replace(anchor, "    buf[buf_size] = 0x41;\n" + anchor)
        # The adapter is compiled from a different directory, so its relative
        # include of the scaffold has to be rewritten to an absolute one.
        .replace(
            '#include "../mutator_scaffold.h"',
            f'#include "{(ADAPTERS.parent / "mutator_scaffold.h").as_posix()}"',
        ),
        encoding="utf-8",
    )

    binary = tmp_path / "tar_broken"
    build = subprocess.run(
        [CC, "-O1", "-g", "-w", *flags,
         f'-DADAPTER="{broken.as_posix()}"', "-DSEED_TAR",
         "-o", str(binary), str(HARNESS)],
        capture_output=True, text=True,
    )
    assert build.returncode == 0, f"build failed:\n{build.stderr}"

    run = subprocess.run(
        [str(binary), "5000"], capture_output=True, text=True, timeout=300,
    )
    assert run.returncode != 0, "harness passed a deliberately broken adapter"
    assert "AddressSanitizer" in run.stderr or "runtime error" in run.stderr


# ── Static checks that need no compiler ─────────────────────


@pytest.mark.parametrize("stem,_seed", CASES)
def test_adapter_implements_the_full_contract(stem, _seed):
    """The scaffold declares four hooks and calls all four; a missing one is a
    link error at fuzz time, long after onboarding reported success."""
    src = (ADAPTERS / f"{stem}.c").read_text(encoding="utf-8")
    for hook in (
        "nm_adapter_has_signature",
        "nm_adapter_parse",
        "nm_adapter_fix_integrity",
        "nm_adapter_apply_targeted",
    ):
        assert f"static {'int' if hook != 'nm_adapter_fix_integrity' else 'void'} {hook}" in src \
            or f"{hook}(" in src, f"{stem}.c does not define {hook}"


@pytest.mark.parametrize("stem,_seed", CASES)
def test_adapter_includes_the_scaffold(stem, _seed):
    src = (ADAPTERS / f"{stem}.c").read_text(encoding="utf-8")
    assert '#include "../mutator_scaffold.h"' in src


@pytest.mark.parametrize("stem,_seed", CASES)
def test_adapter_documents_its_integrity_decision(stem, _seed):
    """Three of these formats carry no recomputable checksum, and ZIP's CRC is
    deliberately left broken. That is a real design decision per format, so it
    has to be stated rather than left as an empty function someone later
    "fixes" by adding a CRC that defeats the mutation."""
    src = (ADAPTERS / f"{stem}.c").read_text(encoding="utf-8")
    body_start = src.index("nm_adapter_fix_integrity(uint8_t *buf")
    preamble = src[max(0, body_start - 600):body_start]
    assert "checksum" in preamble.lower() or "crc" in preamble.lower(), (
        f"{stem}.c: fix_integrity needs a comment explaining the choice"
    )
