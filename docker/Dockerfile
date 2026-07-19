# ============================================================
# NEMESIS Docker Image
# ============================================================
# Multi-stage build: base tools → Python env → application
#
# Build:  docker build -t nemesis .
# Run:    docker run -v ./targets:/targets -v ./results:/results nemesis run -t libarchive

FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    python3-venv \
    gdb \
    cscope \
    ctags \
    # AFL++ dependencies
    clang \
    llvm \
    llvm-dev \
    lld \
    libc++-dev \
    libc++abi-dev \
    # libarchive build deps (example target)
    zlib1g-dev \
    libbz2-dev \
    liblzma-dev \
    libxml2-dev \
    libssl-dev \
    libacl1-dev \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# ── AFL++ ───────────────────────────────────────────────────

FROM base AS aflpp

RUN git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus /opt/aflpp \
    && cd /opt/aflpp \
    && make distrib -j$(nproc) \
    && make install \
    && rm -rf /opt/aflpp/.git

# ── Python environment ──────────────────────────────────────

FROM aflpp AS python-env

# Create virtual environment
RUN python3 -m venv /opt/nemesis-env
ENV PATH="/opt/nemesis-env/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml /tmp/nemesis/
RUN pip install --no-cache-dir /tmp/nemesis/ && rm -rf /tmp/nemesis

# ── Application ─────────────────────────────────────────────

FROM python-env AS app

WORKDIR /opt/nemesis

# Copy application code
COPY nemesis/ nemesis/
COPY config/ config/
COPY prompts/ prompts/

# Install in development mode
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Verify installation
RUN nemesis --version

# ── Runtime configuration ───────────────────────────────────

# Volumes
VOLUME ["/targets", "/results"]

# Default workspace
ENV NEMESIS_ENGINE__WORK_DIR=/results

# Entry point
ENTRYPOINT ["nemesis"]
CMD ["--help"]
