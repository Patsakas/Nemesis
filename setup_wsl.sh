#!/usr/bin/env bash
# =============================================================
# NEMESIS — WSL2 Setup Script
# Τρέξε μία φορά μετά το: git clone ... ~/Nemesis
# =============================================================
set -e

NEMESIS_DIR="$HOME/Nemesis"
LIBARCHIVE_CLEAN="$HOME/libarchive_clean"
LIBARCHIVE_WORK="$HOME/libarchive_work"

echo "============================================="
echo "  NEMESIS WSL2 Setup"
echo "============================================="

# ── 1. System dependencies ──────────────────────────────────
echo ""
echo "[1/7] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential cmake git gdb rsync \
    clang llvm lld \
    python3 python3-pip python3-venv \
    pkg-config autoconf automake libtool \
    zlib1g-dev libbz2-dev liblzma-dev \
    libzstd-dev libxml2-dev libssl-dev \
    libacl1-dev locales

sudo locale-gen en_US.UTF-8
grep -q 'export LANG=en_US.UTF-8' ~/.bashrc || echo 'export LANG=en_US.UTF-8' >> ~/.bashrc
grep -q 'export LC_ALL=en_US.UTF-8' ~/.bashrc || echo 'export LC_ALL=en_US.UTF-8' >> ~/.bashrc

# ── 2. AFL++ ────────────────────────────────────────────────
echo ""
echo "[2/7] Building AFL++..."
if command -v afl-fuzz &>/dev/null; then
    echo "  AFL++ already installed: $(afl-fuzz --version 2>&1 | head -1)"
else
    cd ~
    git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus.git
    cd AFLplusplus
    make -j"$(nproc)"
    sudo make install
    cd ~
    echo "  AFL++ installed: $(afl-fuzz --version 2>&1 | head -1)"
fi

# ── 3. Python venv + NEMESIS ────────────────────────────────
echo ""
echo "[3/7] Installing NEMESIS Python package..."
cd "$NEMESIS_DIR"
python3 -m venv nemesis-env
source nemesis-env/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"
echo "  nemesis installed: $(nemesis --version 2>/dev/null || echo 'ok')"

# Auto-activate venv in .bashrc
if ! grep -q 'Nemesis/nemesis-env' ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# NEMESIS" >> ~/.bashrc
    echo "source \$HOME/Nemesis/nemesis-env/bin/activate" >> ~/.bashrc
fi

# ── 4. AFL env vars ─────────────────────────────────────────
echo ""
echo "[4/7] Setting AFL environment variables..."
if ! grep -q 'AFL_NO_AFFINITY' ~/.bashrc; then
    cat >> ~/.bashrc << 'EOF'

# AFL++ / NEMESIS runtime
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
EOF
fi

# core_pattern (may fail on WSL — that's OK)
echo core | sudo tee /proc/sys/kernel/core_pattern &>/dev/null || true

# ── 5. libarchive_clean ─────────────────────────────────────
echo ""
echo "[5/7] Cloning libarchive..."
if [ -d "$LIBARCHIVE_CLEAN/.git" ]; then
    echo "  libarchive_clean already exists, skipping."
else
    git clone https://github.com/libarchive/libarchive.git "$LIBARCHIVE_CLEAN"
fi

# ── 6. libarchive_work ──────────────────────────────────────
echo ""
echo "[6/7] Creating libarchive_work (rsync from clean)..."
mkdir -p "$LIBARCHIVE_WORK/build_fuzz"
mkdir -p "$LIBARCHIVE_CLEAN/build_debug"
rsync -a --delete "$LIBARCHIVE_CLEAN/" "$LIBARCHIVE_WORK/"

# ── 7. Build libarchive (AFL-instrumented) ──────────────────
echo ""
echo "[7/7] Building AFL-instrumented libarchive..."
cd "$LIBARCHIVE_WORK/build_fuzz"
rm -f CMakeCache.txt
CC=afl-clang-fast CXX=afl-clang-fast++ \
cmake .. \
    -DCMAKE_C_COMPILER=afl-clang-fast \
    -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -fsanitize=address -Wno-error -Wno-unused-variable -Wno-unused-parameter -Wno-uninitialized -Wno-format-security -Wno-unused-const-variable -Wno-unused-function -Wno-deprecated-declarations" \
    -DENABLE_TEST=OFF \
    2>&1 | tail -5
make -j"$(nproc)" archive_static 2>&1 | tail -5

# Verify AFL instrumentation
AFL_SYMS=$(nm libarchive/libarchive.a 2>/dev/null | grep -c "__afl_" || echo 0)
if [ "$AFL_SYMS" -gt 0 ]; then
    echo "  libarchive.a instrumented: $AFL_SYMS AFL symbols ✓"
else
    echo "  WARNING: libarchive.a has 0 AFL symbols — check build output above!"
fi

# ── Done ────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "  Setup complete!"
echo "============================================="
echo ""
echo "  ΣΗΜΑΝΤΙΚΟ: Βάλε το Anthropic API key:"
echo ""
echo "    echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc"
echo "    source ~/.bashrc"
echo ""
echo "  Τότε τρέξε:"
echo ""
echo "    cd ~/Nemesis"
echo "    source nemesis-env/bin/activate"
echo "    nemesis run --target libarchive"
echo ""
