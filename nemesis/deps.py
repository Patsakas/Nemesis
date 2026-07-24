"""Automated, auditable dependency recovery for the build stage (v0.2, H1).

The onboarding baseline (benchmarks/onboard_suite/BASELINE_FINDINGS.md) measured
that build acquisition — not harness synthesis — is the dominant obstacle: 8 of the
15 in-scope repositories failed with an *environmental* missing dependency. This
module is the H1 response. It does the dependency resolution a human currently does
by hand, from inside `nemesis setup`, so the work stays at the benchmark's
intervention level 0 (the runner never acts; NEMESIS does).

Design constraints, in priority order:

  1. **Safe.** The tool only ever installs a package name that either lives in the
     curated table below or passes `_is_allowed()`. A package *name* is never a
     substring taken from the build log — the log is only ever *matched*, never
     executed. A malicious `configure` that prints "install evil-pkg" installs
     nothing.

  2. **Deterministic / reproducible.** Two resolvers: `curated` and
     `curated+apt-file`. Neither consults an LLM: a reviewer with the same repo,
     container and apt snapshot gets the same result. LLM-suggested packages are
     deliberately out of scope for v0.2 (they would turn "dependency resolution"
     into "LLM package prediction", a different and non-reproducible study).

  3. **Honest.** Resolution is `extract artifact → map → install → retry`, and each
     step is recorded. An install that does not let the build progress is counted
     as a *false-positive install*, so "installed 10 packages, build still failed"
     can never be mis-read as success.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nemesis.logging import get_logger

log = get_logger("deps")


# The one security property to keep in mind everywhere in this file:
#   THE BUILD LOG IS INPUT FOR CLASSIFICATION, NEVER INPUT FOR COMMAND EXECUTION.
# A log line is matched to decide *which allow-listed package* to install; no
# substring of a log is ever passed to a shell or to apt as a name.


# ── What kind of thing is missing ───────────────────────────
# The failure surface differs by build system, so we normalise to an *artifact*
# (a header, a pkg-config module, a CMake package, a library, a compiler, a
# program) before mapping to a package. This is what lets one table serve
# cmake/meson/autotools alike, and what the baseline's 8 DEP failures all reduce to.


@dataclass(frozen=True)
class MissingArtifact:
    kind: str   # header | pkgconfig | cmake_pkg | library | compiler | program
    name: str   # e.g. "turbojpeg.h", "gmime-3.0", "SDL2", "pcap", "Fortran", "pg_config"
    raw: str    # the log line it was extracted from, for the audit trail

    def key(self) -> tuple[str, str]:
        return (self.kind, self.name.lower())


# ── Extractors: build-log text → missing artifact(s) ────────
# Ordered; every extractor runs and its matches are collected (a single log can
# report several missing things). Written against the *real* baseline error
# strings — each pattern below is exercised by tests/test_deps.py.

_EXTRACTORS: list[tuple[re.Pattern[str], str]] = [
    # clang: fatal error: 'cng.h' file not found
    # gcc:   fatal error: zlib.h: No such file or directory
    (re.compile(r"""fatal error:\s*['"]?([\w./+-]+\.h(?:pp|xx)?)['"]?\s*:?\s*"""
                r"""(?:no such file|file not found)""", re.I), "header"),
    # cmake custom Find module: "Could not find turbojpeg.h in /opt/..."
    (re.compile(r"could not find\s+([\w./+-]+\.h(?:pp|xx)?)\b", re.I), "header"),
    # pkg-config (autotools/meson): "No package 'gmime-3.0' found",
    # "Package 'sdl3', required by 'virtual:world', not found"
    (re.compile(r"(?:no package|package)\s*'([^']+?)'(?:\s*,)?\s*"
                r"(?:found|required by|not found)", re.I), "pkgconfig"),
    # autotools bespoke wording: "Unable to locate gmime development files"
    (re.compile(r"unable to locate\s+([\w.+-]+?)\s+development", re.I), "pkgconfig"),
    # cmake find_package config mode:
    #   Could not find a package configuration file provided by "SDL2"
    (re.compile(r'package configuration file provided by\s*"([^"]+)"', re.I),
     "cmake_pkg"),
    # cmake FindPackageHandleStandardArgs: "Could NOT find OpenAL (missing: ...)",
    # "Could NOT find Boost"
    (re.compile(r"could not find\s+([A-Za-z][\w+]*)\s*\(", re.I), "cmake_pkg"),
    # cmake message(): "The pcap library is required." / "The net library is required."
    (re.compile(r"\b(?:the\s+)?([\w+-]+)\s+library is required", re.I), "library"),
    # cmake: "No CMAKE_Fortran_COMPILER could be found"
    (re.compile(r"no\s+CMAKE_(\w+)_COMPILER", re.I), "compiler"),
    # meson/autotools: "Program 'sdcc' not found", "Program pg_config found: NO"
    (re.compile(r"program\s*'?([\w.+-]+?)'?\s*(?:not found|found:\s*no)\b", re.I),
     "program"),
]


def extract_missing(text: str) -> list[MissingArtifact]:
    """Return every missing artifact named in a build log, in first-seen order,
    de-duplicated by (kind, name). Pure: no side effects, no network."""
    seen: set[tuple[str, str]] = set()
    out: list[MissingArtifact] = []
    for pat, kind in _EXTRACTORS:
        for m in pat.finditer(text):
            name = m.group(1).strip()
            art = MissingArtifact(kind=kind, name=name, raw=m.group(0).strip())
            if art.key() not in seen:
                seen.add(art.key())
                out.append(art)
    return out


# ── Curated artifact → package table ────────────────────────
# Keyed by (kind, name.lower()). Seeded from the 8 measured baseline DEP failures
# plus the common long tail. Every value here is, by construction, allow-listed:
# adding a row is the deliberate, reviewable act of trusting a package.

_CURATED: dict[tuple[str, str], list[str]] = {
    # ── the 8 measured baseline failures ──
    ("header", "turbojpeg.h"): ["libturbojpeg0-dev"],
    ("pkgconfig", "gmime"): ["libgmime-3.0-dev"],            # "Unable to locate gmime"
    ("pkgconfig", "gmime-3.0"): ["libgmime-3.0-dev"],
    ("library", "pcap"): ["libpcap-dev"],
    ("compiler", "fortran"): ["gfortran"],
    ("cmake_pkg", "sdl2"): ["libsdl2-dev"],
    ("pkgconfig", "sdl3"): ["libsdl3-dev"],
    ("cmake_pkg", "sdl3"): ["libsdl3-dev"],
    ("program", "pg_config"): ["libpq-dev", "postgresql-server-dev-all"],
    ("cmake_pkg", "openal"): ["libopenal-dev"],
    ("pkgconfig", "openal"): ["libopenal-dev"],
    # ── common long tail (headers) ──
    ("header", "zlib.h"): ["zlib1g-dev"],
    ("header", "bzlib.h"): ["libbz2-dev"],
    ("header", "lzma.h"): ["liblzma-dev"],
    ("header", "png.h"): ["libpng-dev"],
    ("header", "jpeglib.h"): ["libjpeg-dev"],
    ("header", "zstd.h"): ["libzstd-dev"],
    ("header", "openssl/ssl.h"): ["libssl-dev"],
    ("header", "ssl.h"): ["libssl-dev"],
    ("header", "sqlite3.h"): ["libsqlite3-dev"],
    ("header", "curl/curl.h"): ["libcurl4-openssl-dev"],
    ("header", "expat.h"): ["libexpat1-dev"],
    ("header", "pcap.h"): ["libpcap-dev"],
    # ── common long tail (cmake packages / libraries) ──
    ("cmake_pkg", "zlib"): ["zlib1g-dev"],
    ("cmake_pkg", "png"): ["libpng-dev"],
    ("cmake_pkg", "jpeg"): ["libjpeg-dev"],
    ("cmake_pkg", "openssl"): ["libssl-dev"],
    ("cmake_pkg", "boost"): ["libboost-all-dev"],
    ("cmake_pkg", "curl"): ["libcurl4-openssl-dev"],
    ("cmake_pkg", "sqlite3"): ["libsqlite3-dev"],
    ("cmake_pkg", "freetype"): ["libfreetype-dev"],
    ("library", "z"): ["zlib1g-dev"],
    # ── common long tail (programs / pkg-config) ──
    ("pkgconfig", "libpcap"): ["libpcap-dev"],
    ("pkgconfig", "openssl"): ["libssl-dev"],
    ("pkgconfig", "zlib"): ["zlib1g-dev"],
    ("program", "gfortran"): ["gfortran"],
}

# Header names are matched on their basename too, so a full path
# ("openssl/ssl.h") and a bare header ("ssl.h") both resolve when either is listed.


# Package names an apt-file result must look like before we trust it. The base
# archive names development packages `*-dev`; restricting to that (plus a tiny set
# of known non-`-dev` toolchain packages and any operator-supplied extras) keeps a
# stray apt-file hit from installing something arbitrary.
_ALLOWED_PKG_RE = re.compile(r"^lib[a-z0-9.+-]+-dev$|^[a-z0-9][a-z0-9.+-]*-dev$")
_ALLOWED_EXTRA = {"gfortran", "g++", "libpq-dev", "postgresql-server-dev-all"}


@dataclass
class Resolution:
    """One resolution decision, ready to be installed and recorded."""
    artifact: MissingArtifact
    packages: list[str]
    provenance: str            # "curated" | "apt-file"
    apt_file_db: str | None = None   # DB snapshot marker when provenance == "apt-file"


def _apt_file_db_marker() -> str:
    """A best-effort fingerprint of the apt-file/Contents DB, so an apt-file
    resolution is reproducible-checkable later: the same header can map to a
    different package after the DB is refreshed. Returns 'tool_version@db_mtime'."""
    try:
        ver = subprocess.run(["apt-file", "--version"], capture_output=True,
                             text=True, timeout=10)
        vtag = (ver.stdout or ver.stderr or "").strip().splitlines()[0] if ver.stdout \
            or ver.stderr else "apt-file"
    except (FileNotFoundError, subprocess.TimeoutExpired, IndexError):
        vtag = "apt-file"
    mtime = "?"
    lists = Path("/var/lib/apt/lists")
    if lists.is_dir():
        contents = list(lists.glob("*Contents*"))
        if contents:
            mtime = str(int(max(p.stat().st_mtime for p in contents)))
    return f"{vtag}@{mtime}"


def probe_capabilities() -> dict[str, bool]:
    """Check the runner can actually install packages. The real failure mode is
    not only 'no sudo' — it can be a container with no apt, an offline runner, or
    broken sources. Reported so a preflight can block before an unattended run
    silently degrades into 'install always fails'."""
    caps: dict[str, bool] = {}
    caps["apt_available"] = shutil.which("apt-get") is not None
    caps["apt_file_available"] = shutil.which("apt-file") is not None
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10)
        caps["sudo_noninteractive"] = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        caps["sudo_noninteractive"] = False
    caps["network_access"] = _tcp_reachable("archive.ubuntu.com", 80)
    caps["apt_update_possible"] = (
        caps["apt_available"] and caps["sudo_noninteractive"] and caps["network_access"]
    )
    return caps


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@dataclass
class DependencyResolver:
    """Maps build failures to installable packages under strict limits.

    `mode`:
        "off"              — never resolve (parity with pre-H1 behaviour).
        "curated"          — curated table only; unknowns are left unresolved.
        "curated+apt-file" — fall back to `apt-file` for headers / pkg-config /
                             programs, validated against the allow-list. Default.
    """
    mode: str = "curated+apt-file"
    extra_allowlist: set[str] = field(default_factory=set)
    dry_run: bool = False       # tests set this; resolve() still works, install() no-ops
    _apt_updated: bool = field(default=False, init=False)

    # ── allow-list ──
    def _is_allowed(self, pkg: str) -> bool:
        return (
            pkg in _ALLOWED_EXTRA
            or pkg in self.extra_allowlist
            or bool(_ALLOWED_PKG_RE.match(pkg))
        )

    # ── curated lookup, with header-basename fallback ──
    def _curated(self, art: MissingArtifact) -> list[str] | None:
        hit = _CURATED.get(art.key())
        if hit:
            return hit
        if art.kind == "header" and "/" in art.name:
            base = art.name.rsplit("/", 1)[-1]
            return _CURATED.get(("header", base.lower()))
        return None

    # ── apt-file fallback (deterministic given an apt-file DB snapshot) ──
    def _apt_file(self, art: MissingArtifact) -> tuple[list[str], str] | None:
        if self.mode != "curated+apt-file":
            return None
        if art.kind not in ("header", "pkgconfig", "program"):
            return None  # only file-backed artifacts are apt-file-searchable
        if art.kind == "header":
            needle = "/" + art.name.rsplit("/", 1)[-1]      # match path suffix
        elif art.kind == "pkgconfig":
            needle = f"/{art.name}.pc"
        else:
            needle = f"/bin/{art.name}"
        try:
            res = subprocess.run(
                ["apt-file", "search", "--package-only", needle],
                capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.warning("deps.apt_file_unavailable", error=str(exc))
            return None
        if res.returncode != 0:
            return None
        cands = [p.strip() for p in res.stdout.splitlines() if p.strip()]
        allowed = [p for p in cands if self._is_allowed(p)]
        if not allowed:
            return None
        # Prefer the shortest allowed name: `-dev` variants are shorter than their
        # multiarch/debug siblings, and the canonical package is rarely the longest.
        best = min(allowed, key=len)
        return [best], _apt_file_db_marker()

    def resolve(
        self, error_text: str, already_installed: set[str] | None = None
    ) -> Resolution | None:
        """First installable resolution for a build log, skipping anything already
        installed (which would loop). Returns None when nothing maps — the caller
        must treat that as unresolved, not retry."""
        if self.mode == "off":
            return None
        already = already_installed or set()
        for art in extract_missing(error_text):
            pkgs = self._curated(art)
            prov = "curated"
            db_marker: str | None = None
            if pkgs is None:
                af = self._apt_file(art)
                if af is not None:
                    pkgs, db_marker = af
                    prov = "apt-file"
            if not pkgs:
                continue
            pkgs = [p for p in pkgs if self._is_allowed(p)]
            if not pkgs or set(pkgs) <= already:
                continue
            return Resolution(artifact=art, packages=pkgs, provenance=prov,
                              apt_file_db=db_marker)
        return None

    # ── the only impure operation ──
    def install(self, packages: list[str]) -> bool:
        """`sudo -n apt-get install` the packages. `-n` fails fast rather than
        blocking on a password prompt in an unattended run. Returns success."""
        if self.dry_run:
            log.info("deps.install_dry_run", packages=packages)
            return True
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        if not self._apt_updated:
            # One refresh per process so a just-published or uncached package name
            # resolves; failure here is non-fatal (install may still succeed).
            subprocess.run(["sudo", "-n", "apt-get", "update"],
                           capture_output=True, text=True, timeout=180, env=env)
            self._apt_updated = True
        try:
            res = subprocess.run(
                ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends",
                 *packages],
                capture_output=True, text=True, timeout=600, env=env,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.error("deps.install_failed", packages=packages, error=str(exc))
            return False
        if res.returncode != 0:
            log.error("deps.install_failed", packages=packages,
                      error=(res.stderr or res.stdout)[-300:])
            return False
        log.info("deps.install_ok", packages=packages)
        return True
