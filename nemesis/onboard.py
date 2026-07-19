"""
NEMESIS target onboarding — auto-generate YAML config for a new C library.

Scans the source tree for build system clues, detects library targets and
public headers, calls the LLM to generate a harness template, and writes a
ready-to-use NEMESIS YAML config.

Usage:
    nemesis onboard --source-root ~/libpng --project-name libpng
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from nemesis.config import NemesisConfig
from nemesis.logging import get_logger

# ── YAML block-scalar helpers ────────────────────────────────


class _LiteralStr(str):
    """Forces yaml.dump to render this string with | (literal block scalar) style."""


class _FoldedStr(str):
    """Forces yaml.dump to render this string with > (folded block scalar) style."""


def _literal_representer(dumper: yaml.Dumper, data: _LiteralStr):  # type: ignore[override]
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


def _folded_representer(dumper: yaml.Dumper, data: _FoldedStr):  # type: ignore[override]
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">")


yaml.add_representer(_LiteralStr, _literal_representer)
yaml.add_representer(_FoldedStr, _folded_representer)


# ── find_package → linker-flag mapping ──────────────────────

_FIND_PACKAGE_MAP: dict[str, str] = {
    "ZLIB": "-lz",
    "BZip2": "-lbz2",
    "LibLZMA": "-llzma",
    "OpenSSL": "-lcrypto -lssl",
    "JPEG": "-ljpeg",
    "PNG": "-lpng",
    "ZSTD": "-lzstd",
    "WebP": "-lwebp",
    "JBIG": "-ljbig",
    "Deflate": "-ldeflate",
    "LERC": "-lLerc",
    "CMath": "-lm",
    # Fix 154: Abseil — RE2-class C++ projects depend on a fan-out of absl_*
    # static libraries. We list the most commonly-referenced ones; the linker
    # silently ignores any that aren't actually used.
    "absl": (
        "-labsl_strings -labsl_str_format_internal -labsl_strings_internal "
        "-labsl_synchronization -labsl_hash -labsl_city -labsl_low_level_hash "
        "-labsl_throw_delegate -labsl_int128 -labsl_raw_logging_internal "
        "-labsl_log_severity -labsl_base -labsl_spinlock_wait "
        "-labsl_malloc_internal -labsl_time -labsl_time_zone "
        "-labsl_civil_time -labsl_log_internal_check_op "
        "-labsl_log_internal_message -labsl_log_internal_format "
        "-labsl_log_internal_globals -labsl_log_internal_proto "
        "-labsl_log_internal_log_sink_set -labsl_log_internal_nullguard "
        "-labsl_log_globals -labsl_log_sink"
    ),
    "ICU": "-licuuc -licudata",
}


# Fix 154: hint map — find_package(X) → apt package name for the user.
# Surfaced in YAML header so `nemesis onboard` for a C++ project tells the
# user exactly what to apt-install before running. We do NOT auto-sudo.
_APT_HINT_MAP: dict[str, str] = {
    "ZLIB": "zlib1g-dev",
    "BZip2": "libbz2-dev",
    "LibLZMA": "liblzma-dev",
    "OpenSSL": "libssl-dev",
    "JPEG": "libjpeg-dev",
    "PNG": "libpng-dev",
    "ZSTD": "libzstd-dev",
    "WebP": "libwebp-dev",
    "JBIG": "libjbig-dev",
    "Deflate": "libdeflate-dev",
    "absl": "libabsl-dev",
    "ICU": "libicu-dev",
    "LERC": "liblerc-dev",
    "Threads": "(builtin)",
}


# Fix 154: tokens that signal a project is C++ (vs pure C). Any one match in
# CMakeLists or a top-level source listing flips is_cpp=True.
_CPP_CMAKE_TOKENS = (
    # Only unambiguous C++ tokens — `set_target_properties` and
    # `target_compile_features` appear in pure-C CMakeLists too (cJSON uses
    # set_target_properties for OUTPUT_NAME), so they would false-positive.
    "CMAKE_CXX_STANDARD", "CXX_STANDARD", "cxx_std_",
)
# Source-file extensions only. Headers (.hpp/.hh/.hxx) are a weaker signal:
# pure-C libraries frequently ship convenience C++ wrapper headers (e.g.
# libsndfile/src/sndfile.hh wrapping the C API, libxml2 same pattern).
# A lone .hh next to a .h.in is binding-only, not a project-language
# declaration. The CXX_STANDARD CMake-token fallback still catches genuinely
# header-only C++ libs that set CMAKE_CXX_STANDARD.
_CPP_FILE_EXTS = (".cpp", ".cxx", ".cc", ".c++")


_C_WRAPPER_RATIO = 10  # .c outnumbers .cpp/.cxx/.cc by this factor → C library


def _detect_cpp_project(source_root: Path) -> bool:
    """Best-effort: is the LIBRARY ITSELF C++ (as opposed to C with optional
    C++ wrappers / consumers)?

    Two stages of evidence:

    1. Count `.c` vs `.cpp/.cxx/.cc/.c++` files in the source tree (bounded
       scan, skip non-library dirs). If C dominates by `_C_WRAPPER_RATIO`x,
       any C++ source is treated as a wrapper of the C API and the library
       stays C. This rescues:
         - libtiff:    50+ .c files + libtiff/tif_stream.cxx → C
         - libsndfile: 50+ .c files + Octave/sndfile.cc (already in skip
           dir, but if it weren't, the ratio would still keep it C)
       Real C++ libraries (RE2, abseil, flatbuffers) have many .cc/.cpp and
       few or no .c files, so the ratio breaks the wrong way → C++.

    2. If no C++ sources at all, fall back to CMAKE_CXX_STANDARD / cxx_std_NN
       in CMakeLists.txt — that covers genuinely header-only C++ libs.

    Skip dirs filter out non-library trees that would distort the count
    (test/, build/, contrib/, language bindings, CLI consumers, etc.).
    """
    if not source_root.exists():
        return False
    skip_segs = {"build", ".git", "test", "tests", "testbed", "doc", "docs",
                 "examples", "fuzz", "fuzzers", "bench", "benchmarks",
                 # Language bindings + CLI consumer programs frequently bring
                 # in C++ source without making the library itself C++.
                 # Concrete cases this rescues:
                 #   libsndfile/programs/sndfile-play-beos.cpp,
                 #   libsndfile/Octave/sndfile.cc,
                 #   libxml2/python/, libssh/binding/, ...
                 "programs", "tools", "cli",
                 "octave", "python", "ruby", "perl", "java", "csharp",
                 "bindings", "binding", "swig", "wrapper", "wrappers",
                 # Contrib trees frequently host third-party helpers in a
                 # different language than the core library. libtiff has
                 # contrib/stream/tiffstream.cpp, contrib/win_dib/Tiffile.cpp,
                 # contrib/oss-fuzz/*.cc — none of which make libtiff C++.
                 "contrib",
                 # NEMESIS's own build artefacts live inside source_root
                 # (per target.debug_build_dir convention). CMake's compiler-
                 # identification helper drops CMakeCXXCompilerId.cpp into
                 # every CMakeFiles/<ver>/ tree even for pure-C projects.
                 "build_debug", "build_ubsan", "build_coverage", "build_fuzz",
                 "cmakefiles"}

    def _skipped(path: Path) -> bool:
        return any(seg.lower() in skip_segs for seg in path.parts)

    c_count = 0
    cpp_count = 0
    files_scanned = 0
    for path in source_root.rglob("*"):
        if files_scanned >= 2000:
            break
        if _skipped(path):
            continue
        if path.is_file():
            files_scanned += 1
            suf = path.suffix.lower()
            if suf == ".c":
                c_count += 1
            elif suf in _CPP_FILE_EXTS:
                cpp_count += 1

    if cpp_count == 0:
        # No C++ sources anywhere — only signal left is CMakeLists tokens
        # (covers header-only C++ libs like Catch2 that set CXX_STANDARD).
        for cm in source_root.glob("CMakeLists.txt"):
            try:
                text = cm.read_text(errors="replace")
            except OSError:
                continue
            if any(tok in text for tok in _CPP_CMAKE_TOKENS):
                return True
        return False

    if c_count == 0:
        return True  # pure C++ project, no .c at all

    # Both exist. If C heavily dominates, the .cpp/.cc/.cxx are wrappers.
    if c_count >= _C_WRAPPER_RATIO * cpp_count:
        return False
    return True


def _detect_findpackage_deps(source_root: Path) -> list[str]:
    """Return CMake find_package() targets present in this tree (deduped).

    Used purely to render an actionable apt-install hint in the YAML header
    when an external dependency might not be installed system-wide.
    """
    seen: set[str] = set()
    out: list[str] = []
    for pattern in ("**/CMakeLists.txt", "**/*.cmake"):
        for cf in source_root.glob(pattern):
            rel = cf.relative_to(source_root)
            if any(seg in {"build", ".git", "test", "tests"} for seg in rel.parts):
                continue
            if len(rel.parts) > 4:
                continue
            try:
                text = cf.read_text(errors="replace")
            except OSError:
                continue
            for m in re.finditer(
                r"find_package\s*\(\s*([A-Za-z][A-Za-z0-9_]*)\b",
                text,
            ):
                pkg = m.group(1)
                if pkg in seen:
                    continue
                seen.add(pkg)
                out.append(pkg)
    return out


def _system_has_lib(linker_flag: str) -> bool:
    """
    Return True if the system's linker can resolve every -l<name> token in `flag`.
    Some optional codec deps (Deflate, LERC) declare find_package() but the dev
    package may be uninstalled (.so symlink missing → linking fails). We probe
    `gcc -print-file-name=lib<name>.so` and check the result actually exists.
    """
    import os
    import subprocess
    for token in linker_flag.split():
        if not token.startswith("-l"):
            continue
        name = token[2:]
        try:
            out = subprocess.run(
                ["gcc", f"-print-file-name=lib{name}.so"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            # When gcc cannot resolve, it echoes the input back unchanged (no /path/)
            if out == f"lib{name}.so" or not os.path.exists(out):
                # try .a fallback
                out_a = subprocess.run(
                    ["gcc", f"-print-file-name=lib{name}.a"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                if out_a == f"lib{name}.a" or not os.path.exists(out_a):
                    return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return True  # don't filter on probe error — let build fail visibly
    return True


# ── Fix 152: oracle-expansion candidacy probe ───────────────

# Tokens that indicate a library uses threading. We check headers and source
# for any of these — a match means TSan + threaded_oracle is plausibly useful.
_THREADING_TOKENS = (
    "pthread.h",        # POSIX threads
    "<thread>",         # C++ std::thread header
    "std::thread",      # C++ std::thread usage
    "omp.h",            # OpenMP
    "#pragma omp",      # OpenMP pragmas
    "_Atomic",          # C11 atomics — implies multi-threaded mutation
    "atomic_",          # stdatomic.h functions
    "GThread",          # GLib threading
    "uv_thread_",       # libuv threading
)

# Link deps that are MSan-safe even on a vanilla distro: math/dl/pthread are
# typically static or trivially MSan-instrumentable. Any OTHER -l flag means
# external runtime that needs MSan-rebuild → MSan candidacy drops to MAYBE.
_MSAN_SAFE_LIBS = frozenset({"-lm", "-ldl", "-lpthread", "-lrt", "-lc"})


def _scan_threading_evidence(source_root: Path, scan_budget: int = 1500) -> list[str]:
    """Return up to N source files that contain at least one threading token.

    Bounded scan — `scan_budget` files max — so onboard stays fast even on
    large trees. Empty result means "looks single-threaded".
    """
    if not source_root.exists():
        return []
    hits: list[str] = []
    files_scanned = 0
    for path in source_root.rglob("*.[ch]"):
        if files_scanned >= scan_budget:
            break
        # Skip obvious non-library trees
        if any(seg in {"test", "tests", "build", ".git", "examples", "doc"}
               for seg in path.parts):
            continue
        files_scanned += 1
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if any(tok in text for tok in _THREADING_TOKENS):
            try:
                hits.append(str(path.relative_to(source_root)))
            except ValueError:
                hits.append(path.name)
            if len(hits) >= 20:
                break
    return hits


def _msan_external_deps(link_libs: str) -> list[str]:
    """Return -l flags that aren't on the MSan-safe baseline list."""
    if not link_libs:
        return []
    flags = [tok for tok in link_libs.split() if tok.startswith("-l")]
    return [f for f in flags if f not in _MSAN_SAFE_LIBS]


def _probe_oracle_candidates(source_root: Path, link_libs: str) -> dict:
    """Heuristic probe — is this library a candidate for TSan / MSan tracks?

    Returns:
      {
        "tsan_candidate":     bool,
        "threading_evidence": list[str],   # up to 20 files where threading appears
        "msan_candidate":     bool,
        "msan_blockers":      list[str],   # external -l deps that block MSan
      }
    """
    threading_files = _scan_threading_evidence(source_root)
    msan_blockers = _msan_external_deps(link_libs)
    return {
        "tsan_candidate": bool(threading_files),
        "threading_evidence": threading_files,
        "msan_candidate": not msan_blockers,
        "msan_blockers": msan_blockers,
    }


def _format_findpackage_comment(deps: list[str]) -> str:
    """Render find_package() deps as YAML-comment install hints (Fix 154)."""
    if not deps:
        return ""
    lines = ["#", "# External dependencies (CMake find_package):"]
    apt_pkgs: list[str] = []
    for pkg in deps:
        hint = _APT_HINT_MAP.get(pkg)
        if hint == "(builtin)":
            continue  # Threads is in libc, no install needed
        if hint:
            lines.append(f"#   {pkg:18s} → apt install {hint}")
            apt_pkgs.append(hint)
        else:
            lines.append(f"#   {pkg:18s} → (no apt hint; check distro packages)")
    if apt_pkgs:
        lines.append("#")
        lines.append(f"#   Bulk install: sudo apt install {' '.join(apt_pkgs)}")
    return "\n".join(lines) + "\n"


def _format_oracle_hints_comment(hints: dict) -> str:
    """Render the probe result as YAML-comment guidance for the user."""
    lines = ["#", "# Oracle expansion candidates (Fix 148-150):"]
    if hints["tsan_candidate"]:
        ev = hints["threading_evidence"]
        lines.append(
            f"#   TSan candidate:  YES (threading tokens found in {len(ev)} file(s))"
        )
        for f in ev[:3]:
            lines.append(f"#                    - {f}")
        if len(ev) > 3:
            lines.append(f"#                    + {len(ev) - 3} more")
        lines.append(
            "#                    → enable: set sanitizer_profile: tsan,"
        )
        lines.append(
            "#                      tsan_supported: true, AND threaded_oracle: true"
        )
        lines.append(
            "#                      on at least one pinned_func."
        )
    else:
        lines.append(
            "#   TSan candidate:  NO (no pthread/std::thread/OpenMP/_Atomic in source)"
        )
    if hints["msan_candidate"]:
        lines.append(
            "#   MSan candidate:  YES (no external link deps that need MSan-rebuild)"
        )
        lines.append(
            "#                    → enable: set sanitizer_profile: msan and"
        )
        lines.append(
            "#                      msan_supported: true. Run as a SEPARATE campaign;"
        )
        lines.append(
            "#                      mutually exclusive with the default ASAN build."
        )
    else:
        blockers = " ".join(hints["msan_blockers"])
        lines.append(
            f"#   MSan candidate:  MAYBE (external deps need MSan-rebuild: {blockers})"
        )
        lines.append(
            "#                    → before enabling, rebuild deps with -fsanitize=memory"
        )
        lines.append(
            "#                      or accept a false-positive flood from those libs."
        )
    return "\n".join(lines)


class TargetOnboarder:
    """Auto-detect library metadata and write a NEMESIS target YAML config."""

    def __init__(self, config: NemesisConfig | None = None) -> None:
        self.config = config
        self.log = get_logger("onboard")

    # ── Build system detection ───────────────────────────────

    def detect_build_system(self, source_root: Path) -> str:
        """Return 'cmake', 'autoconf', or 'meson' based on marker files.

        When both CMakeLists.txt and configure.ac exist (libsndfile-class:
        mature autotools + experimental cmake), probe the cmake configure
        to verify it actually works. libsndfile 1.0.28 ships a CMakeLists.txt
        with a broken regex on line 54 — building it produces immediate
        cmake errors. Detecting "cmake" without probing forces NEMESIS to
        fail at the first build step, even though autoconf would work fine.
        Probe is bounded at 30s; failure → autoconf fallback.
        """
        has_cmake = (source_root / "CMakeLists.txt").exists()
        has_autoconf = (
            (source_root / "configure.ac").exists()
            or (source_root / "configure").exists()
        )
        has_meson = (source_root / "meson.build").exists()

        if has_cmake and has_autoconf:
            if self._cmake_configure_works(source_root):
                return "cmake"
            self.log.warning(
                "build_system.cmake_broken",
                note=("CMakeLists.txt present but cmake configure fails; "
                      "falling back to autoconf"),
            )
            return "autoconf"
        if has_cmake:
            return "cmake"
        if has_autoconf:
            return "autoconf"
        if has_meson:
            return "meson"
        self.log.warning("build_system.unknown", path=str(source_root))
        return "cmake"  # safest default for security-relevant C libs

    def _cmake_configure_works(self, source_root: Path) -> bool:
        """Run a minimal cmake configure in a tmp dir; True iff exit==0.

        Bounded at 30s. Used only to break ties when both cmake and autoconf
        are present in the source tree — we'd rather take 5–30s once at
        onboard time than discover at build time that an experimental
        CMakeLists.txt is broken.
        """
        import shutil
        import subprocess
        import tempfile

        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            self.log.debug("cmake_probe.no_cmake_binary")
            return False
        with tempfile.TemporaryDirectory(prefix="nemesis_cmake_probe_") as tmp:
            try:
                result = subprocess.run(
                    [cmake_bin, "-S", str(source_root), "-B", tmp],
                    capture_output=True, text=True, timeout=30,
                )
                ok = result.returncode == 0
                self.log.debug(
                    "cmake_probe.result",
                    exit=result.returncode,
                    stderr_tail=result.stderr[-200:] if result.stderr else "",
                )
                return ok
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                self.log.debug("cmake_probe.error", error=str(exc))
                return False

    def _detect_autotools_lib(self, source_root: Path) -> tuple[str, str]:
        """For autotools builds, walk Makefile.am files for `lib<name>_la_SOURCES`
        / `LIBADD` patterns to find where the library is built and what its
        target name is.

        Returns (source_subdir_relative_to_source_root, target_name).
        Both empty when no Makefile.am candidate is found.

        Picks the topmost (shortest path) candidate so we get the core library
        rather than a contrib helper sublib.
        """
        candidates: list[tuple[Path, str]] = []
        skip = {"test", "tests", "build", ".git", "doc", "docs",
                "examples", "contrib"}
        for makefile_am in source_root.glob("**/Makefile.am"):
            rel = makefile_am.relative_to(source_root)
            if any(seg.lower() in skip for seg in rel.parts):
                continue
            if len(rel.parts) > 4:
                continue
            try:
                text = makefile_am.read_text(errors="replace")
            except OSError:
                continue
            for m in re.finditer(
                r"\blib([A-Za-z][A-Za-z0-9_\-]*)_la_(SOURCES|LIBADD)\b", text
            ):
                candidates.append((makefile_am, m.group(1)))
        if not candidates:
            return "", ""
        # Pick by shortest path depth → most likely the core library
        candidates.sort(key=lambda c: (len(c[0].parts), c[0].parts))
        mam, target = candidates[0]
        sub_rel = mam.parent.relative_to(source_root)
        sub_str = str(sub_rel) if sub_rel != Path(".") else ""
        return sub_str, target

    def _detect_autotools_disable_flags(self, source_root: Path) -> list[str]:
        """Probe configure.ac / configure for known optional-dep disable flags.

        Returns a list of `--disable-…` / `--without-…` flags to add to the
        autotools configure command. Goal: keep fuzzing build self-contained
        by turning off optional features that pull external codec deps not
        guaranteed to be MSan-safe or even installed (FLAC, Ogg, Vorbis,
        Python bindings, etc.). Without this, libsndfile autoconf fails on
        a system without libflac-dev installed.
        """
        candidates: list[str] = []
        sources = [
            source_root / "configure.ac",
            source_root / "configure",
        ]
        text = ""
        for src in sources:
            if src.exists():
                try:
                    text = src.read_text(errors="replace")
                    break
                except OSError:
                    continue
        if not text:
            return []
        # Common patterns that signal an opt-out flag exists. We match the
        # AC_ARG_ENABLE / AC_ARG_WITH macro forms in configure.ac, plus the
        # plaintext "--disable-X" forms in the generated configure.
        wanted = (
            "external-libs",  # libsndfile, libsox
            "external_libs",
            "python",         # libxml2, etc.
            "docs",
            "examples",
            "tests",
            "regtest",
            "tools",
        )
        for flag in wanted:
            patterns = (
                rf"AC_ARG_ENABLE\s*\(\s*\[?{re.escape(flag)}\]?",
                rf"AC_ARG_WITH\s*\(\s*\[?{re.escape(flag)}\]?",
                rf"--disable-{re.escape(flag)}\b",
                rf"--without-{re.escape(flag)}\b",
            )
            if any(re.search(p, text) for p in patterns):
                # Choose the form most likely to apply: external-libs uses
                # --disable, python uses --without, etc. Default to --disable
                # but keep --without for explicit "with" macros only.
                if flag == "python":
                    candidates.append("--without-python")
                else:
                    candidates.append(f"--disable-{flag}")
        return candidates

    # ── Library metadata detection ───────────────────────────

    def detect_library_info(self, source_root: Path, project_name: str) -> dict:
        """
        Scan source tree to infer cmake target, library filename, include paths,
        public headers, and linker flags.

        Returns dict with keys:
          cmake_lib_target, library_name, source_subdir, include_subdir,
          harness_includes, link_libs
        """
        # Strip leading "lib" from project_name when forming the default
        # library filename, otherwise we get pathological double-prefixes
        # like `liblibxml2.a` for libxml2 / `liblibpng.a` for libpng. The
        # cmake target detection downstream may still override this.
        _base = project_name.lower().removeprefix("lib")
        result: dict = {
            "cmake_lib_target": project_name,
            "library_name": f"lib{_base}.a",
            "source_subdir": "",
            "include_subdir": "",
            "harness_includes": [],
            "link_libs": "-lm",
        }

        # ── cmake_lib_target: walk all CMakeLists.txt collecting add_library() candidates ──
        # Many libraries (libtiff, libpng, libxml2, ...) declare add_library() in a
        # subdirectory CMakeLists.txt, not the top-level one (e.g. libtiff/CMakeLists.txt
        # has `add_library(tiff ...)`). Some repos also have helper sublibs (port/,
        # tools/) — we collect ALL matches and rank them by relevance to project_name.
        cmake_match_path: Path | None = None
        cmake_match_target: str = ""

        # Compute "base name" variants: strip common decorations from project_name
        # so "libtiff_cve2022" → ["libtiff_cve2022", "libtiff", "tiff", ...]
        base_variants: list[str] = []

        def _add_variant(s: str) -> None:
            s = s.lower()
            if s and s not in base_variants:
                base_variants.append(s)

        _add_variant(project_name)
        # Strip _cveYYYY, _vN, _N.N.N suffixes
        stripped = re.sub(r"_(cve\d+|v\d+|\d+(\.\d+)+).*$", "", project_name, flags=re.IGNORECASE)
        _add_variant(stripped)
        # Also strip leading "lib"
        if stripped.lower().startswith("lib"):
            _add_variant(stripped[3:])
        if project_name.lower().startswith("lib"):
            _add_variant(project_name[3:])

        skip_segments = {"build", ".git", "test", "tests", "doc", "docs", "examples", "contrib"}

        # Collect every (cmake_file, target_name, full_line) candidate
        candidates: list[tuple[Path, str]] = []
        for cmake_file in sorted(source_root.glob("**/CMakeLists.txt")):
            rel = cmake_file.relative_to(source_root)
            if any(seg in skip_segments for seg in rel.parts):
                continue
            if len(rel.parts) > 4:
                continue
            try:
                content = cmake_file.read_text(errors="replace")
            except OSError:
                continue
            # CMake permits add_library(name [STATIC|SHARED|MODULE|OBJECT] sources...)
            # — the type keyword is OPTIONAL (defaults to BUILD_SHARED_LIBS). We must
            # still skip add_library(name INTERFACE|IMPORTED|ALIAS ...) which are not
            # real compiled libs. Negative lookahead does the trick.
            for m in re.finditer(
                r"add_library\s*\(\s*(\w+)\s+(?!INTERFACE\b|IMPORTED\b|ALIAS\b)\S",
                content,
                re.IGNORECASE,
            ):
                candidates.append((cmake_file, m.group(1)))

        def _score(cmake_file: Path, target: str) -> int:
            t = target.lower()
            sub = cmake_file.parent.relative_to(source_root)
            sub_name = sub.parts[0].lower() if sub.parts else ""
            score = 0
            for v in base_variants:
                # Strip _static suffix from target before matching against
                # base_variants so `png_static` still matches the `png` variant.
                t_canon = t[:-len("_static")] if t.endswith("_static") else t
                if t_canon == v:
                    score += 100
                elif t_canon in v or v in t_canon:
                    score += 40
                if sub_name == v:
                    score += 60
                elif sub_name and (sub_name in v or v in sub_name):
                    score += 20
            # Prefer the explicit static variant when both exist (libpng has
            # both `add_library(png SHARED ...)` and `add_library(png_static STATIC ...)`).
            # The static one is what AFL+ASAN needs.
            if t.endswith("_static"):
                score += 50
            # Penalise known helper sublibs that are NOT the main library
            HELPER_SUBDIRS = {"port", "tools", "util", "utils", "common", "compat"}
            if sub_name in HELPER_SUBDIRS:
                score -= 80
            return score

        if candidates:
            candidates.sort(key=lambda c: _score(c[0], c[1]), reverse=True)
            cmake_match_path, cmake_match_target = candidates[0]
            self.log.debug(
                "cmake.candidates",
                ranked=[(str(p.relative_to(source_root)), t, _score(p, t)) for p, t in candidates[:5]],
            )

        if cmake_match_target and cmake_match_path is not None:
            result["cmake_lib_target"] = cmake_match_target
            # library_name MUST include the source_subdir prefix because cmake builds
            # produce $build_dir/$source_subdir/lib<target>.a, not $build_dir/lib<target>.a.
            sub_rel = cmake_match_path.parent.relative_to(source_root)
            sub_str = str(sub_rel) if sub_rel != Path(".") else ""
            result["source_subdir"] = sub_str
            lib_basename = f"lib{cmake_match_target.lower()}.a"
            result["library_name"] = f"{sub_str}/{lib_basename}" if sub_str else lib_basename
            self.log.info(
                "cmake.library_found",
                target=cmake_match_target,
                source_subdir=result["source_subdir"],
                library_name=result["library_name"],
                cmake_file=str(cmake_match_path.relative_to(source_root)),
            )
        else:
            self.log.warning(
                "cmake.no_add_library",
                fallback=result["cmake_lib_target"],
            )
            # source_subdir fallback: first directory containing .c files
            for candidate in [project_name, project_name.lower(), "src", "lib", "source"]:
                candidate_path = source_root / candidate
                if candidate_path.is_dir() and list(candidate_path.glob("*.c")):
                    result["source_subdir"] = candidate
                    break

        # Build a name variant set used for include/header probing.
        # When the project_name is wrapper-style ("libtiff_cve2022") and CMake
        # detection found the real lib target ("tiff"), prefer the real target.
        name_variants: list[str] = []
        for n in [
            cmake_match_target, cmake_match_target.lower() if cmake_match_target else "",
            project_name, project_name.lower(),
            project_name.lstrip("lib"), project_name.lower().lstrip("lib"),
        ]:
            if n and n not in name_variants:
                name_variants.append(n)

        # ── include_subdir: include/{variant}/ > include/ > src/{variant}/ > lib/ > source_subdir ──
        inc_candidates: list[str] = []
        for n in name_variants:
            inc_candidates.append(f"include/{n}")
        inc_candidates.append("include")
        # libwebp layout: public headers live at src/{variant}/ (src/webp/*.h),
        # NOT include/{variant}/. Without this branch the onboarder leaves
        # harness_includes empty and the architect has no API surface to scan.
        for n in name_variants:
            inc_candidates.append(f"src/{n}")
        # libsndfile / libvorbis / libogg layout: public header sits directly
        # at src/sndfile.h (or src/sndfile.h.in, a cmake configure_file
        # template that becomes sndfile.h after `cmake ..`). The src/{variant}
        # branch above doesn't catch this because there's no src/sndfile/
        # subdir — the header is one level higher. The .h.in template probe
        # happens in the header-detection block below.
        inc_candidates.append("src")
        # expat layout: public header lives at lib/expat.h (the root has
        # CMakeLists.txt so source_subdir stays empty, and `include/` does
        # not exist). Without `lib/` and `lib/{variant}/` here the onboarder
        # detects no headers and leaves harness_template as TODO.
        for n in name_variants:
            inc_candidates.append(f"lib/{n}")
        inc_candidates.append("lib")
        # Also try source_subdir/include patterns (libtiff: libtiff/ holds both .c and .h)
        if result["source_subdir"]:
            inc_candidates.append(result["source_subdir"])
        for inc_candidate in inc_candidates:
            inc_path = source_root / inc_candidate
            if inc_path.is_dir() and list(inc_path.glob("*.h")):
                result["include_subdir"] = inc_candidate
                break
        if not result["include_subdir"]:
            result["include_subdir"] = result["source_subdir"]

        # ── harness_includes: well-known public header name patterns per name variant ──
        # Fix 154: many C++ projects (RE2: re2/re2.h, flatbuffers: flatbuffers/*.h)
        # ship public headers under <source_root>/<project_name>/ rather than the
        # standard `include/`. Try BOTH layouts and prefer name-matching results.
        inc_dirs: list[tuple[Path, str]] = []
        if result["include_subdir"]:
            inc_dirs.append((source_root / result["include_subdir"], result["include_subdir"]))
        inc_dirs.append((source_root, ""))
        # RE2-style: <source_root>/<project_name>/  (matches each name variant)
        for n in name_variants:
            sub = source_root / n
            if sub.is_dir():
                inc_dirs.append((sub, n))
        _seen: set[str] = set()
        header_candidates: list[str] = []
        for n in name_variants:
            for suffix in ["", "io", "_api", "lib"]:
                for ext in (".h", ".hpp", ".hh"):  # Fix 154: probe C++ extensions too
                    _h = f"{n}{suffix}{ext}"
                    if _h not in _seen:
                        _seen.add(_h)
                        header_candidates.append(_h)
        # When a probe target ends in `.h` and the file itself is missing but
        # a `<name>.h.in` sibling exists, the .h IS shipped — it just hasn't
        # been generated yet because cmake configure runs at build time
        # (configure_file). We record the .h name (its post-configure path)
        # so harness compile picks it up; _read_headers falls back to reading
        # the .in template for LLM context.
        def _header_exists(inc_dir: Path, name: str) -> bool:
            if (inc_dir / name).exists():
                return True
            if name.endswith(".h") and (inc_dir / f"{name}.in").exists():
                return True
            return False

        # Record harness_includes relative to include_subdir (so _read_headers
        # joins source_root + include_subdir + name and gets the right path).
        # Without this, headers found at source_root/src would be recorded as
        # "src/sndfile.h" AND include_subdir would be "src" → double-prefix.
        include_root = (
            source_root / result["include_subdir"]
            if result["include_subdir"] else source_root
        )

        def _rel_to_include_root(full: Path, fallback_prefix: str, name: str) -> str:
            try:
                return str(full.relative_to(include_root)).replace("\\", "/")
            except ValueError:
                # Header lives outside include_root (RE2-style root-adjacent
                # layout where include_subdir didn't get set). Fall back to
                # the prefix the caller computed.
                return f"{fallback_prefix}/{name}" if fallback_prefix else name

        found_headers: list[str] = []
        for inc_dir, prefix in inc_dirs:
            if not inc_dir.is_dir():
                continue
            for h in header_candidates:
                if _header_exists(inc_dir, h):
                    rel = _rel_to_include_root(inc_dir / h, prefix, h)
                    if rel not in found_headers:
                        found_headers.append(rel)
            if found_headers:
                break  # stop at first matching dir
        if not found_headers:
            for inc_dir, prefix in inc_dirs:
                if not inc_dir.is_dir():
                    continue
                for ext in ("*.h", "*.hpp", "*.hh"):
                    for hp in sorted(inc_dir.glob(ext))[:1]:
                        rel = _rel_to_include_root(hp, prefix, hp.name)
                        if rel not in found_headers:
                            found_headers.append(rel)
                # Last-resort fallback: bare `.h.in` template (cmake
                # configure_file). Record without the trailing `.in` so the
                # eventually-compiled harness includes the post-configure
                # filename. _read_headers handles the `.in` content fallback.
                for hp in sorted(inc_dir.glob("*.h.in"))[:1]:
                    real_name = hp.name[:-3]  # strip ".in"
                    real_path = hp.parent / real_name
                    rel = _rel_to_include_root(real_path, prefix, real_name)
                    if rel not in found_headers:
                        found_headers.append(rel)
                if found_headers:
                    break
        result["harness_includes"] = found_headers

        # ── link_libs from find_package() calls (walk CMakeLists.txt + *.cmake) ──
        # Many libraries (libtiff, libpng, libxml2) put find_package() calls inside
        # cmake/<Codec>.cmake helper files rather than the main CMakeLists.txt. Walk
        # both — without this, codec/compression deps end up missing from link_libs.
        link_text_parts: list[str] = []
        for pattern in ("**/CMakeLists.txt", "**/*.cmake"):
            for cf in source_root.glob(pattern):
                rel = cf.relative_to(source_root)
                if any(seg in skip_segments for seg in rel.parts) or len(rel.parts) > 4:
                    continue
                try:
                    link_text_parts.append(cf.read_text(errors="replace"))
                except OSError:
                    continue
        link_text = "\n".join(link_text_parts)
        parts: list[str] = []
        for pkg, flag in _FIND_PACKAGE_MAP.items():
            if re.search(
                r"find_package\s*\(\s*" + re.escape(pkg),
                link_text,
                re.IGNORECASE,
            ):
                # Fix 154: per-token filter. A fan-out flag (e.g. absl with 20+
                # -labsl_* tokens) loses individual libs across distros; keep
                # only those actually installed rather than dropping the whole
                # set when any one token can't be resolved.
                tokens = [t for t in flag.split() if t.startswith("-l")]
                resolved = [t for t in tokens if _system_has_lib(t)]
                if resolved:
                    parts.extend(resolved)
                    self.log.debug(
                        "cmake.dependency", pkg=pkg,
                        kept=len(resolved), dropped=len(tokens) - len(resolved),
                    )
                else:
                    self.log.info(
                        "cmake.dependency_unlinkable",
                        pkg=pkg, flag=flag,
                        note="dev package missing — codec likely disabled at cmake configure",
                    )
        if "-lm" not in parts:
            parts.append("-lm")
        # Fix 154: detect C++ project. When True, prepend -lstdc++ -lpthread to
        # link_libs (RE2/abseil/protobuf-class targets). The detection runs ONCE
        # here; the result is propagated through `result["is_cpp"]` for the
        # build-command generator and the harness-template prompt.
        is_cpp = _detect_cpp_project(source_root)
        result["is_cpp"] = is_cpp
        if is_cpp:
            cpp_baseline = ["-lstdc++", "-lpthread"]
            for lib in cpp_baseline:
                if lib not in parts:
                    parts.insert(0, lib)
        result["link_libs"] = " ".join(parts)

        # ── Detect project-specific option() declarations to override ──
        # Some libraries (libpng, openssl, …) declare their own SHARED/STATIC
        # /TESTS options that override CMake's BUILD_SHARED_LIBS. Auto-emit
        # `-D<NAME>=OFF/ON` flags so the build wrapper produces a static archive
        # that AFL+ASAN can link against. Without this, libpng's PNG_SHARED ON
        # default produces only `libpng16d.so` and the harness compile fails
        # to find the .a archive.
        #   - *_SHARED / *_FRAMEWORK              → OFF (no shared libs)
        #   - *_STATIC                             → ON  (need static archive)
        #   - *_TESTS / *_BUILD_TESTING / *_EXAMPLES / *_TOOLS / *_DEMO → OFF
        extra_cmake_flags: list[str] = []
        seen_opts: set[str] = set()
        # link_text_parts already contains every CMakeLists + *.cmake we collected.
        for content in link_text_parts:
            for m in re.finditer(
                # Fix 156b: allow leading whitespace before `option(` —
                # lcms2 (and many others) indent these inside if() blocks.
                r"^[ \t]*option\s*\(\s*([A-Za-z][A-Za-z0-9_]*)\s",
                content,
                re.MULTILINE,
            ):
                name = m.group(1)
                if name in seen_opts:
                    continue
                seen_opts.add(name)
                upper = name.upper()
                # Avoid reverse-engineering already-correct options
                if upper in ("BUILD_SHARED_LIBS",):
                    continue  # already handled by the standard configure line
                if upper.endswith("_STATIC"):
                    extra_cmake_flags.append(f"-D{name}=ON")
                elif (
                    upper.endswith("_SHARED")
                    or upper.endswith("_FRAMEWORK")
                    or upper.endswith("_TESTS")
                    or upper.endswith("_BUILD_TESTING")
                    or upper.endswith("_EXAMPLES")
                    or upper.endswith("_DEMO")
                    or upper.endswith("_DEMOS")
                    or upper.endswith("_TOOLS")
                    or upper.endswith("_DOCS")
                    or upper.endswith("_BENCH")
                    or upper.endswith("_BENCHMARKS")
                ):
                    extra_cmake_flags.append(f"-D{name}=OFF")
        result["extra_cmake_flags"] = " ".join(extra_cmake_flags)
        if extra_cmake_flags:
            self.log.info(
                "cmake.options_detected",
                count=len(extra_cmake_flags),
                flags=extra_cmake_flags[:8],
            )

        return result

    # ── Build command generation ─────────────────────────────

    def generate_build_commands(
        self,
        cmake_lib_target: str,
        build_system: str = "cmake",
        extra_cmake_flags: str = "",
        is_cpp: bool = False,
        autotools_disable_flags: list[str] | None = None,
        source_subdir: str = "",
    ) -> dict:
        """
        Return AFL++ fuzz and ASAN debug build commands for a cmake target.

        Raises NotImplementedError for non-cmake build systems with a helpful message.

        extra_cmake_flags: project-specific cmake -D flags detected by
        detect_library_info() (e.g. -DPNG_SHARED=OFF -DPNG_STATIC=ON
        -DPNG_TESTS=OFF). Appended to all four configure variants so static
        archives are produced consistently across fuzz / debug / ubsan / cov.
        """
        if build_system not in ("cmake", "autoconf"):
            raise NotImplementedError(
                f"{build_system} build system support not yet implemented — "
                "fill in build commands manually in the generated YAML"
            )

        # `-fno-sanitize=function`: UBSan's function-pointer-CFI check
        # produces a "runtime error: call to function ... through pointer
        # to incorrect function type" diagnostic any time a callback API
        # (TIFFClientOpen, png_set_read_fn, brotli stream callbacks, ...) is
        # invoked through a function pointer whose static type at the call
        # site doesn't EXACTLY match the type at the function definition.
        # LLM-generated harnesses regularly produce trivial mismatches like
        # `unsigned long` vs `uint64_t` in callback typedefs (same width,
        # different type in C). The check then flags every parser run as a
        # crash, masking real bugs. Disabling it is standard practice for
        # fuzz harnesses with callback APIs and keeps the rest of UBSan
        # (divide-by-zero, integer overflow, OOB access, …) intact.
        #
        # `alignment` is also dropped: a misaligned load/store is UB but rarely
        # the real vulnerability, and with -fno-sanitize-recover it ABORTS before
        # ASAN can report the out-of-bounds access the misaligned pointer sits on
        # — masking OOB read/write bugs as generic CWE-758 (measured on rpng).
        _NO_FN_CFI = " -fno-sanitize=function,alignment"
        c_flags_fuzz = (
            "-g -fsanitize=address"
            " -Wno-error -Wno-unused-variable -Wno-unused-parameter"
            " -Wno-uninitialized -Wno-deprecated-declarations"
        )
        c_flags_debug = (
            "-g -O1 -fsanitize=address,undefined" + _NO_FN_CFI +
            " -fno-omit-frame-pointer"
            " -Wno-error -Wno-unused-variable -Wno-unused-parameter"
            " -Wno-uninitialized -Wno-deprecated-declarations"
        )
        c_flags_ubsan = (
            "-g -O1 -fsanitize=undefined" + _NO_FN_CFI +
            " -fno-sanitize-recover=undefined"
            " -fno-omit-frame-pointer"
            " -Wno-error -Wno-unused-variable -Wno-unused-parameter"
            " -Wno-uninitialized -Wno-deprecated-declarations"
        )
        # Source-based coverage instrumentation. Without these flags
        # `nemesis/pipeline.py::_measure_source_coverage` returns -1 → "n/a"
        # in `harness.quality_score line_cov=` log lines and the feedback
        # loop loses precise per-line coverage feedback when refining.
        c_flags_coverage = (
            "-g -O0 -fprofile-instr-generate -fcoverage-mapping"
            " -Wno-error -Wno-unused-variable -Wno-unused-parameter"
            " -Wno-uninitialized -Wno-deprecated-declarations"
        )

        # Plain single-line strings — YAML will render them correctly as scalars.
        # Using _FoldedStr with embedded \n causes PyYAML to emit blank lines
        # (double newlines in folded block = literal \n when parsed, not space).
        extra = f" {extra_cmake_flags}".rstrip() if extra_cmake_flags else ""

        def _cmake_configure(c_flags: str, compiler: str = "clang") -> str:
            # Fix 154: when project is C++ (detected by _detect_cpp_project),
            # also pass -DCMAKE_CXX_FLAGS so the same sanitizer / warning flags
            # apply to .cpp/.cxx/.cc compilation. Pure-C projects get only the
            # original CMAKE_C_FLAGS path → no behaviour change for them.
            cxx_flags_arg = f' -DCMAKE_CXX_FLAGS="{c_flags}"' if is_cpp else ""
            return (
                "rm -f CMakeCache.txt &&"
                f" CC={compiler} CXX={compiler}++"
                " cmake .."
                f" -DCMAKE_C_COMPILER={compiler}"
                f" -DCMAKE_CXX_COMPILER={compiler}++"
                " -DCMAKE_BUILD_TYPE=Debug"
                f' -DCMAKE_C_FLAGS="{c_flags}"'
                f"{cxx_flags_arg}"
                " -DBUILD_SHARED_LIBS=OFF"
                + extra
            )

        if build_system == "autoconf":
            # Out-of-tree autoconf build: $build_dir/../configure ... && make.
            # If configure script doesn't exist (only configure.ac), bootstrap
            # via autogen.sh / autoreconf -fi first. --enable-static produces
            # the .a archive AFL+ASAN can link against; --disable-shared keeps
            # the build cheap.
            #
            # autotools_disable_flags: extra --disable-X / --without-Y flags
            # detected from configure.ac by _detect_autotools_disable_flags.
            # Typically: --disable-external-libs (libsndfile, libsox),
            # --without-python (libxml2), --disable-docs / --disable-tests.
            # Without these, an autoconf build can fail when optional codec
            # dev packages (libflac-dev, libogg-dev) aren't installed.
            extra_autoconf = list(autotools_disable_flags or [])
            # `--without-python` was the historical hardcoded default; keep
            # it unless the probe already added it, to preserve behaviour
            # on libraries whose configure.ac doesn't mention python.
            if "--without-python" not in extra_autoconf:
                extra_autoconf.append("--without-python")
            extra_autoconf_str = " " + " ".join(extra_autoconf) if extra_autoconf else ""

            def _autoconf_configure(c_flags: str, compiler: str = "clang") -> str:
                # Self-heal in-source configuration before the out-of-tree build.
                # autotools aborts an out-of-tree `../configure` with "source
                # directory already configured; run make distclean" when the
                # source tree (..) carries a prior in-source config.status. A
                # pristine clone is fine, but a manually-built source — or one
                # rsync'd from such — does not. Best-effort distclean + stamp
                # removal makes the configure robust; it never touches tracked
                # source files (distclean keeps configure/configure.ac).
                bootstrap = (
                    "{ (cd .. && make distclean) >/dev/null 2>&1; true; };"
                    " rm -f ../config.status ../config.log >/dev/null 2>&1 || true;"
                    " [ -x ../configure ] || (cd .. && (./autogen.sh --help >/dev/null 2>&1"
                    " && ./autogen.sh --without-python || autoreconf -fi))"
                )
                return (
                    f"{bootstrap} &&"
                    f" CC={compiler} CXX={compiler}++"
                    f' CFLAGS="{c_flags}"'
                    f' CXXFLAGS="{c_flags}"'
                    " ../configure"
                    " --enable-static --disable-shared"
                    f"{extra_autoconf_str}"
                )

            configure = _autoconf_configure(c_flags_fuzz, "afl-clang-fast")
            debug_configure = _autoconf_configure(c_flags_debug, "clang")
            ubsan_configure = _autoconf_configure(c_flags_ubsan, "clang")
            coverage_configure = _autoconf_configure(c_flags_coverage, "clang")
            # Target only the library, not the full tree: autotools projects
            # often have tests/ subdirs with extra tool dependencies (GNU
            # autogen for libsndfile's tests, gengetopt for libsox, etc.)
            # we don't need for fuzzing and that fail when those tools aren't
            # installed. `cmake_lib_target` is the libtool target name (e.g.
            # "sndfile" → libsndfile.la); `source_subdir` is the relative
            # directory of the Makefile.am that builds it (e.g. "src").
            # `make -C <subdir> lib<target>.la` only touches that subtree.
            if source_subdir and cmake_lib_target:
                make_cmd = (
                    f"make -j$(nproc) -C {source_subdir} "
                    f"lib{cmake_lib_target.lower()}.la"
                )
            elif cmake_lib_target:
                make_cmd = f"make -j$(nproc) lib{cmake_lib_target.lower()}.la"
            else:
                make_cmd = "make -j$(nproc)"
            return {
                "configure": configure,
                "make": make_cmd,
                "debug_configure": debug_configure,
                "debug_make": make_cmd,
                "ubsan_configure": ubsan_configure,
                "ubsan_make": make_cmd,
                "coverage_configure": coverage_configure,
                "coverage_make": make_cmd,
            }

        configure = _cmake_configure(c_flags_fuzz, "afl-clang-fast")
        debug_configure = _cmake_configure(c_flags_debug, "clang")
        ubsan_configure = _cmake_configure(c_flags_ubsan, "clang")
        coverage_configure = _cmake_configure(c_flags_coverage, "clang")

        make_cmd = f"make -j$(nproc) {cmake_lib_target}"
        return {
            "configure": configure,
            "make": make_cmd,
            "debug_configure": debug_configure,
            "debug_make": make_cmd,
            "ubsan_configure": ubsan_configure,
            "ubsan_make": make_cmd,
            "coverage_configure": coverage_configure,
            "coverage_make": make_cmd,
        }

    # ── Public header reading (truncated) ────────────────────

    _LICENSE_HEADER_RE = re.compile(r"^\s*/\*[\s\S]*?\*/\s*")
    _STRUCT_BLOCK_RE = re.compile(
        # Matches `typedef struct [tag] { ... } NAME;` with one level of
        # nested braces tolerated (most C struct fields use simple types,
        # but nested struct/union members do occur — at most one level of
        # nesting keeps the regex bounded and predictable).
        r"typedef\s+struct(?:\s+\w+)?\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}\s*\w+\s*;",
        re.DOTALL,
    )

    def _strip_leading_license(self, content: str) -> str:
        """Drop the first block comment + any trailing single-line comments.

        Most C headers open with a 10-50 line license block plus a doxygen
        summary. For an LLM that needs to understand the API, this is pure
        noise that competes with real declarations for the byte budget.
        We only strip the LEADING block — comments mid-file (function
        doxygen, struct field annotations) stay because they often clarify
        parameter semantics. Stops as soon as we hit a non-comment line.
        """
        m = self._LICENSE_HEADER_RE.match(content)
        if m:
            content = content[m.end():]
        lines = content.split("\n")
        skip = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                skip += 1
            else:
                break
        return "\n".join(lines[skip:])

    def _extract_struct_definitions(self, content: str) -> str:
        """Pull every `typedef struct ... { ... } NAME ;` to a prepended block.

        Why: harness generation needs to know the EXACT field order of
        callback-bearing structs (libsndfile SF_VIRTUAL_IO, libpng
        png_struct, libtiff TIFFRGBValue, ...). When a header is large the
        struct definition can sit past the MAX_BYTES truncation point —
        the LLM then guesses field order from training data and
        confidently emits a wrong initialiser (e.g. swapping
        sf_vio_get_filelen and sf_vio_read because both have the same
        signature). Surfacing structs to the top guarantees they're in the
        prompt regardless of where they live in the source file.

        Generic mechanism: regex-extracts every `typedef struct` block
        with bounded nesting. Library-agnostic — works for any C header.
        """
        blocks = self._STRUCT_BLOCK_RE.findall(content)
        if not blocks:
            return ""
        return (
            "// ── struct definitions (surfaced for callback ABI clarity) ──\n"
            + "\n\n".join(blocks)
            + "\n\n"
        )

    def _read_headers(
        self, source_root: Path, include_subdir: str, harness_includes: list[str]
    ) -> str:
        """Read public header content for the LLM context, generically
        prioritising API structure over boilerplate.

        Three layered transforms keep the per-header budget productive:
          1. License/leading-comment strip (saves ~1-3KB of legal text).
          2. Struct-definition extraction prepended (guarantees callback
             struct layouts appear in the prompt even when truncation
             would otherwise cut them off).
          3. Hard cap at MAX_BYTES so the prompt stays within token limits.

        MAX_BYTES bumped 8KB → 32KB on 2026-05-13 after a libsndfile run
        where the LLM never saw `SF_VIRTUAL_IO` (line 545 in sndfile.h)
        because of the old 8KB cap, then generated a harness with the
        callback fields in the wrong order — a bug that no compile-time
        repair could fix because every repair LLM call inherited the
        same wrong-template-as-system-prompt.
        """
        MAX_BYTES = 32 * 1024
        inc_dir = source_root / include_subdir if include_subdir else source_root
        parts: list[str] = []
        total = 0

        for header_name in harness_includes:
            header_path = inc_dir / header_name
            # cmake configure_file fallback: the actual on-disk source is
            # <name>.h.in (autotools/cmake template that becomes <name>.h
            # after configure). We read .in directly — the @VAR@ placeholders
            # don't break the LLM's parsing of API declarations.
            if not header_path.exists():
                in_variant = header_path.parent / f"{header_path.name}.in"
                if in_variant.exists():
                    header_path = in_variant
            if not header_path.exists():
                continue
            raw = header_path.read_text(errors="replace")
            stripped = self._strip_leading_license(raw)
            structs_excerpt = self._extract_struct_definitions(stripped)
            # Bundle: struct definitions first (guaranteed in prompt),
            # then the linearly-read header content. Some redundancy
            # (structs appear twice if they fit twice) is acceptable —
            # repetition is cheap for the LLM compared to missing data.
            if structs_excerpt:
                bundle = (
                    f"// === {header_name} (callback ABI surfaced) ===\n"
                    f"{structs_excerpt}"
                    f"// === {header_name} (full content) ===\n"
                    f"{stripped}"
                )
            else:
                bundle = f"// === {header_name} ===\n{stripped}"
            available = MAX_BYTES - total
            if len(bundle) > available:
                bundle = bundle[:available] + "\n... (truncated)\n"
            parts.append(bundle)
            total += len(bundle)
            if total >= MAX_BYTES:
                break

        return "\n".join(parts)

    # ── Main entry point ─────────────────────────────────────

    def generate_yaml(
        self,
        source_root: Path,
        project_name: str,
        oss_fuzz_project: str = "",
        work_root: str = "",
        output: str = "",
        neural=None,
    ) -> Path:
        """
        Detect library metadata, optionally call the LLM for a harness template,
        and write a NEMESIS YAML config file.

        Returns the output path.
        """
        source_root = Path(source_root).expanduser().resolve()
        oss_fuzz_project = oss_fuzz_project or project_name
        work_root_str = work_root or f"$HOME/{project_name}_work"
        output_path = Path(output) if output else Path(f"config/targets/{project_name}.yaml")

        self.log.info("onboard.start", project=project_name, source=str(source_root))

        # Step 1: Detect build system
        build_system = self.detect_build_system(source_root)
        self.log.info("onboard.build_system", system=build_system)

        # Step 2: Detect library metadata
        info = self.detect_library_info(source_root, project_name)
        autotools_flags: list[str] = []
        if build_system == "autoconf":
            # Override cmake-derived metadata with autotools-derived where it
            # disagrees. `detect_library_info` walks CMakeLists.txt to find
            # the library target — when we're actually using autoconf
            # (because cmake was probe-rejected), the cmake-based source_subdir
            # and library_name are wrong. libsndfile is the canonical case:
            # CMakeLists.txt at root says `add_library(sndfile SHARED ...)`
            # → source_subdir="" → libsndfile.a expected at build_dir root.
            # Autotools actually places it at src/.libs/libsndfile.a.
            auto_subdir, auto_target = self._detect_autotools_lib(source_root)
            if auto_target:
                info["cmake_lib_target"] = auto_target
                info["source_subdir"] = auto_subdir
                lib_basename = f"lib{auto_target.lower()}.a"
                info["library_name"] = (
                    f"{auto_subdir}/.libs/{lib_basename}" if auto_subdir
                    else f".libs/{lib_basename}"
                )
                self.log.info(
                    "autotools.library_found",
                    target=auto_target,
                    source_subdir=auto_subdir,
                    library_name=info["library_name"],
                )
            elif not info["library_name"].startswith(".libs/"):
                # Fallback for projects without Makefile.am `lib*_la_SOURCES`:
                # at least prefix .libs/ so the libtool archive can be found.
                info["library_name"] = f".libs/{info['library_name']}"
            # Always probe configure.ac for optional-dep disable flags so
            # the build doesn't fail on a system missing optional codec
            # dev packages (libflac-dev, libogg-dev for libsndfile).
            autotools_flags = self._detect_autotools_disable_flags(source_root)
            if autotools_flags:
                self.log.info("autotools.disable_flags", flags=autotools_flags)
        cmake_lib_target = info["cmake_lib_target"]
        self.log.info(
            "onboard.library_info",
            cmake_target=cmake_lib_target,
            lib=info["library_name"],
            source_subdir=info["source_subdir"],
            include_subdir=info["include_subdir"],
            headers=info["harness_includes"],
            link_libs=info["link_libs"],
        )

        # Step 3: Generate build commands
        try:
            build_cmds = self.generate_build_commands(
                cmake_lib_target,
                build_system,
                extra_cmake_flags=info.get("extra_cmake_flags", ""),
                is_cpp=info.get("is_cpp", False),  # Fix 154
                autotools_disable_flags=autotools_flags,
                source_subdir=info["source_subdir"],
            )
        except NotImplementedError as exc:
            self.log.warning("onboard.build_cmds_skip", reason=str(exc))
            placeholder = f"# TODO: {exc}"
            build_cmds = {
                "configure": placeholder,
                "make": f"make -j$(nproc) {cmake_lib_target}",
                "debug_configure": placeholder,
                "debug_make": f"make -j$(nproc) {cmake_lib_target}",
            }

        # Step 4: Read public headers (capped at 8KB)
        headers_content = self._read_headers(
            source_root, info["include_subdir"], info["harness_includes"]
        )

        # Step 5: LLM generates harness_template, magic_bytes, harness_includes,
        # and bonus_func_patterns (recon scoring hints).
        harness_template = "# TODO: fill in harness template manually"
        magic_bytes: dict = {}
        final_includes: list[str] = info["harness_includes"]
        bonus_func_patterns: dict = {}

        if neural and headers_content:
            try:
                harness_template, magic_bytes, llm_includes, bonus_func_patterns = (
                    neural.generate_onboard_template(project_name, headers_content)
                )
                if not harness_template:
                    harness_template = "# TODO: fill in harness template manually"
                if llm_includes:
                    final_includes = llm_includes
                # Defensive: ensure the terminal "Output ONLY valid JSON with:" mandate
                # exists. The mandate is the contract that lets the next-stage harness
                # LLM return strict JSON instead of just continuing the ```c block.
                # Mistral Medium and similar models occasionally omit this mandate even
                # when the prompt requires it. Without it, every variant generation
                # silently fails JSON extraction.
                if "Output ONLY valid JSON" not in harness_template:
                    harness_template = harness_template.rstrip() + "\n\n" + (
                        'Output ONLY valid JSON with:\n'
                        '{\n'
                        '  "target_func": "function_name",\n'
                        f'  "input_format": "{project_name}-specific input description",\n'
                        '  "c_code": "complete C harness source code using the template above",\n'
                        '  "seed_commands": ["shell commands to generate seed files"],\n'
                        '  "compile_flags": "-g -O1 -fno-omit-frame-pointer"\n'
                        '}\n'
                    )
                    self.log.info(
                        "onboard.injected_json_mandate",
                        note="LLM omitted terminal JSON mandate; appended programmatically",
                    )
                self.log.info(
                    "onboard.llm_ok",
                    magic_formats=list(magic_bytes.keys()),
                    includes=final_includes,
                    bonus_patterns=list(bonus_func_patterns.keys())[:10],
                )
            except Exception as exc:
                self.log.warning("onboard.llm_failed", error=str(exc))
                harness_template = (
                    f"# LLM generation failed: {exc}\n# TODO: fill in manually"
                )
        elif not headers_content:
            self.log.warning("onboard.no_headers", note="harness_template left as TODO")

        # Step 5b: Auto-link existing seed corpora.
        # If the LLM identified file-format magic bytes (e.g. "TIFF"), check whether the
        # repo already has a corresponding seed directory at $HOME/Nemesis/seeds/<format>/
        # and wire it into seeds.formats so AFL has real input to mutate from on first run.
        # Without this, AFL starts from empty inputs and is unlikely to find format-aware
        # bugs within a 15-min budget per target.
        seeds_formats: dict = {}
        nemesis_root = Path("~/Nemesis").expanduser()
        if not nemesis_root.exists():
            # Fallback: assume cwd is the repo root
            nemesis_root = Path.cwd()
        seeds_root = nemesis_root / "seeds"
        if magic_bytes and seeds_root.exists():
            for fmt_name in magic_bytes:
                # Try lower-case, original case, and "tiff" → "tiff" (already lower) variants
                for candidate in (fmt_name.lower(), fmt_name, fmt_name.lower().rstrip("12345")):
                    cand_dir = seeds_root / candidate
                    if cand_dir.is_dir() and any(cand_dir.iterdir()):
                        seeds_formats[candidate] = f"$HOME/Nemesis/seeds/{candidate}"
                        self.log.info(
                            "onboard.seeds_linked",
                            format=candidate,
                            n_files=sum(1 for _ in cand_dir.iterdir()),
                        )
                        break

        # Step 5c: Synthesise the format-spec snippet (Tier 0, 2026-05-07).
        # Writes plain text to config/targets/<project_name>/format_spec.txt.
        # `format_specs.get_format_spec()` reads this file at fuzz time and
        # falls back to its legacy hardcoded dict when absent — so failure
        # here is non-fatal: the mutator synthesiser will recall the format
        # from training data instead.
        if neural and headers_content:
            try:
                from nemesis.recon import format_spec_synthesis as _fss

                # Pick a sample seed (first file from any linked seed dir)
                # to ground the LLM in the actual on-wire layout.
                sample_seed_path: Path | None = None
                for seed_dir_str in seeds_formats.values():
                    seed_dir = Path(seed_dir_str.replace("$HOME", str(Path.home())))
                    if seed_dir.is_dir():
                        for f in seed_dir.iterdir():
                            if f.is_file() and f.stat().st_size > 0:
                                sample_seed_path = f
                                break
                    if sample_seed_path:
                        break

                spec_text = _fss.synthesize_format_spec(
                    library_name=project_name,
                    headers_content=headers_content,
                    client=neural.client,
                    sample_seed_path=sample_seed_path,
                    log=self.log,
                )
                if spec_text:
                    targets_dir = output_path.parent  # config/targets/
                    cache_path = _fss.write_cached(project_name, spec_text, targets_dir)
                    self.log.info(
                        "onboard.format_spec_cached",
                        path=str(cache_path),
                        length=len(spec_text),
                    )
            except Exception as exc:
                self.log.warning("onboard.format_spec_failed", error=str(exc))

        # Step 5d (Fix 152): probe whether the library is a candidate for the
        # MSan/TSan oracle expansions. Output goes into the YAML header comment
        # so the user sees actionable hints, but no schema changes — opt-in
        # remains explicit (sanitizer_profile + the *_supported flag).
        oracle_hints = _probe_oracle_candidates(source_root, info.get("link_libs", ""))

        # Step 5e (Fix 154): detect external find_package() deps so the YAML
        # header lists apt-install hints up front. Especially important for C++
        # projects (RE2 → absl, protobuf → absl, filament → ICU, etc.) where
        # missing dev packages cause cmake to fail before NEMESIS even starts.
        findpkg_deps = _detect_findpackage_deps(source_root)
        self.log.info(
            "onboard.oracle_hints",
            tsan=oracle_hints["tsan_candidate"],
            msan=oracle_hints["msan_candidate"],
            threading_files=len(oracle_hints["threading_evidence"]),
        )

        # Step 6: Assemble config dict
        cfg: dict = {
            "fuzzing": {
                "timeout_hours": 0.25,
            },
            "target": {
                "name": project_name,
                "oss_fuzz_project": oss_fuzz_project,
                "source_root": f"$HOME/{project_name}_clean",
                "work_root": work_root_str,
                "build_dir": f"{work_root_str}/build_fuzz",
                "debug_build_dir": f"$HOME/{project_name}_clean/build_debug",
                # Without these explicit paths, the LLVM-coverage and UBSan-only
                # builds run cmake in the NEMESIS cwd (Path("") default), which
                # silently fails. That means `harness.quality_score line_cov=` is
                # always "n/a" and the differential UBSan oracle never fires.
                "ubsan_build_dir": f"$HOME/{project_name}_clean/build_ubsan",
                "coverage_build_dir": f"$HOME/{project_name}_clean/build_coverage",
                "build": build_cmds,
                "repro_binary": "",
                "repro_args": [],
                "source_subdir": info["source_subdir"],
                "include_subdir": info["include_subdir"],
                "library_name": info["library_name"],
                "link_libs": info["link_libs"],
                "harness_includes": final_includes,
                "harness_template": _LiteralStr(harness_template + "\n"),
                "api_func_fixes": {},
                "magic_bytes": magic_bytes,
            },
            "recon_scoring": {
                "bonus_patterns": {},
                "bonus_func_patterns": bonus_func_patterns,
                "penalty_dirs": ["test", "tests", "doc", "docs", "man"],
                "penalty_files": [],
                "penalty_funcs": [],
                "low_value_files": {},
            },
            "seeds": {
                "formats": seeds_formats,
                "oss_fuzz_corpus": f"$HOME/Nemesis/seeds/oss_fuzz_corpus_{project_name}",
                "oss_fuzz_fuzzer_names": [],
            },
        }

        # Step 7: Write YAML
        output_path.parent.mkdir(parents=True, exist_ok=True)
        header_comment = (
            "# Auto-generated by `nemesis onboard`. Review all paths before running.\n"
            f"# Source scanned: {source_root}\n"
            f"# Build system:   {build_system}\n"
            f"# Language:       {'C++' if info.get('is_cpp') else 'C'}\n"
            + _format_findpackage_comment(findpkg_deps)
            + _format_oracle_hints_comment(oracle_hints)
            + "\n"
        )
        # width=10000 prevents PyYAML from wrapping long strings inside scalar values
        yaml_body = yaml.dump(
            cfg,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=10000,
        )
        output_path.write_text(header_comment + yaml_body, encoding="utf-8")

        self.log.info("onboard.done", output=str(output_path))
        return output_path
