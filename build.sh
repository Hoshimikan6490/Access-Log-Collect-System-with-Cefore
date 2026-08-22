#!/bin/bash

set -e

echo "=== Install dependencies ==="

sudo apt update
sudo apt install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git

echo "=== Clean previous build ==="

make distclean >/dev/null 2>&1 || true

echo "=== Configure ==="

autoconf
automake
./configure --enable-cache --enable-debug

echo "=== Build ==="

sudo make

echo "=== Install ==="

sudo make install
sudo ldconfig

echo "=== Done ==="

echo "Check cache mode with:"
echo "  cefstatus"
