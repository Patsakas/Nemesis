"""Build a *probe binary* — the analysis-time twin of the fuzzing harness.

Why a second binary exists
--------------------------
The fuzzing harness cannot be analysed offline. It is AFL++ persistent mode
with shared-memory test cases, and outside `afl-fuzz` the runtime reports
"disabling shared memory testcases" — the harness then receives no input at
all. Every input produces the same handful of edges, so `afl-showmap` and
`afl-cmin` both see a program whose behaviour never changes. Measured on cJSON:
a flat 9 edges for valid JSON, deep nesting and garbage alike.

The probe binary is the same harness source, same library, same sanitizer
flags — but with the persistent macros replaced by a stub that reads stdin
once. That makes it drivable by any offline AFL tool. On cJSON it turns 9 flat
edges into 4-93 depending on input.

This is deliberately NOT the debug build. The debug build drops AFL
instrumentation entirely, so it has no coverage map to read; the probe build
keeps `afl-clang-fast` instrumentation and only changes how the input arrives.

Two traps this encodes, both of which cost real time to find
-------------------------------------------------------------
`#undef` before redefining. `afl-clang-fast` injects its own definitions of
`__AFL_FUZZ_INIT` and friends, so a stub that merely `#define`s them loses to
the compiler's own and the binary silently goes back to shared-memory mode.

Link with the library's sanitizer flags. The instrumented library is built with
ASan, so omitting `-fsanitize=address` from the probe's link line produces
`undefined reference to __asan_report_load4`. That error reads like an AFL
problem and is not — it cost three failed attempts before being spotted.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from nemesis.logging import get_logger

# Mirrors _AFL_STUB_HEADER in nemesis/symbolic/__init__.py, with the `#undef`
# guards that standalone reproduction does not need: that path compiles with
# plain clang, which never defines these. Under afl-clang-fast the compiler's
# own definitions arrive first and win without the undefs.
_AFL_MACROS = (
    "__AFL_FUZZ_INIT",
    "__AFL_INIT",
    "__AFL_LOOP",
    "__AFL_FUZZ_TESTCASE_LEN",
    "__AFL_FUZZ_TESTCASE_BUF",
    "__AFL_COVERAGE",
    "__AFL_COVERAGE_ON",
    "__AFL_COVERAGE_OFF",
)

PROBE_STUB_HEADER = (
    "/* NEMESIS probe stub — persistent-mode macros replaced by a one-shot\n"
    " * stdin read, so offline AFL tools (showmap, cmin) can drive this binary.\n"
    " * The undefs matter: afl-clang-fast defines these itself. */\n"
    "#include <stdio.h>\n"
    "#include <stdint.h>\n"
    + "".join(f"#undef {m}\n" for m in _AFL_MACROS)
    + "static uint8_t __nm_probe_buf[1 << 20];\n"
      "static int     __nm_probe_len = 0;\n"
      "static int     __nm_probe_called = 0;\n"
      "#define __AFL_FUZZ_INIT()\n"
      "#define __AFL_INIT()\n"
      "#define __AFL_LOOP(n) (__nm_probe_called++ == 0 ? \\\n"
      "    (__nm_probe_len = (int)fread(__nm_probe_buf, 1, sizeof(__nm_probe_buf), stdin), 1) : 0)\n"
      "#define __AFL_FUZZ_TESTCASE_LEN  __nm_probe_len\n"
      "#define __AFL_FUZZ_TESTCASE_BUF  __nm_probe_buf\n"
      "#define __AFL_COVERAGE()\n"
      "#define __AFL_COVERAGE_ON()\n"
      "#define __AFL_COVERAGE_OFF()\n"
)

# Same sanitizer configuration the instrumented library is built with. Shared
# rather than restated so the two cannot drift: a probe linked against an
# ASan library without these fails at link time, and one built with *different*
# sanitizer settings would measure a different program than the fuzzer runs.
PROBE_SANITIZER_FLAGS = "-fsanitize=address -fno-omit-frame-pointer"
PROBE_OPT_FLAGS = "-O1 -g"


def _is_cpp_harness(source: str, extra_flags: str = "") -> bool:
    """Same C++ detection the fuzz harness compile uses (symbolic stage)."""
    return (
        "c++" in extra_flags.lower()
        or "std::" in source
        or "namespace " in source
        or 'extern "C"' in source
        or "#include <string>" in source
        or "#include <vector>" in source
    )


def probe_source_for(harness_source: str) -> str:
    """Return the harness source rewritten to read stdin."""
    return PROBE_STUB_HEADER + harness_source


def _fingerprint(source: str, lib: Path | None, link_libs: str) -> str:
    """Identity of a probe build: source + library mtime/size + link line.

    Rebuilding on every probe would dominate the cost of a sweep, but a stale
    binary would silently measure the previous harness. The library's mtime and
    size are included because a rebuilt library with unchanged harness source
    is still a different program.
    """
    h = hashlib.sha256()
    h.update(source.encode("utf-8", errors="replace"))
    h.update(link_libs.encode("utf-8"))
    if lib and lib.exists():
        st = lib.stat()
        h.update(f"{st.st_mtime_ns}:{st.st_size}".encode())
    return h.hexdigest()[:16]


def build_probe_binary(
    harness_source_path: str | Path,
    library_archive: str | Path | None,
    out_dir: str | Path,
    include_dirs: list[str] | None = None,
    link_libs: str = "",
    extra_flags: str = "",
    timeout: int = 180,
) -> Path | None:
    """Compile a probe binary from a fuzz harness source. None on failure.

    Never raises: probing is an optimisation, and a build failure here must
    leave the caller free to fall back rather than take the run down with it.
    Reuses an existing binary when source, library and link line are unchanged.
    """
    log = get_logger("recon.probe_build")
    src_path = Path(harness_source_path)
    if not src_path.exists():
        log.debug("probe.no_harness_source", path=str(src_path))
        return None

    try:
        harness_source = src_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("probe.unreadable_source", error=str(exc))
        return None

    lib = Path(library_archive) if library_archive else None
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    stamp = _fingerprint(harness_source, lib, link_libs)
    binary = out / f"probe_{stamp}"
    if binary.exists():
        log.debug("probe.cached", binary=str(binary))
        return binary

    probe_src = out / f"probe_{stamp}.c"
    try:
        probe_src.write_text(probe_source_for(harness_source), encoding="utf-8")
    except OSError as exc:
        log.debug("probe.write_failed", error=str(exc))
        return None

    compiler = "afl-clang-fast++" if _is_cpp_harness(harness_source, extra_flags) else "afl-clang-fast"
    if shutil.which(compiler) is None:
        log.warning("probe.no_compiler", compiler=compiler)
        return None

    cmd = [compiler, *PROBE_OPT_FLAGS.split(), *PROBE_SANITIZER_FLAGS.split()]
    for inc in include_dirs or []:
        cmd += ["-I", str(inc)]
    if extra_flags:
        cmd += extra_flags.split()
    cmd += ["-o", str(binary), str(probe_src)]
    if lib and lib.exists():
        cmd.append(str(lib))
    if link_libs:
        cmd += link_libs.split()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("probe.build_error", error=str(exc))
        return None

    if result.returncode != 0 or not binary.exists():
        tail = (result.stderr or "")[-400:]
        log.warning(
            "probe.build_failed", returncode=result.returncode, stderr=tail,
            hint=("undefined __asan_report_* means the sanitizer flags are "
                  "missing from the link line, not an AFL problem"),
        )
        return None

    log.info("probe.built", binary=str(binary), compiler=compiler)
    return binary
