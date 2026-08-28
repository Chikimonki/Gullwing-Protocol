#!/bin/bash
set -e

MOABI="/mnt/d/moabi"

# Find zig — check both locations
if command -v zig &> /dev/null; then
    ZIG="zig"
elif [ -x "/opt/zig/zig" ]; then
    ZIG="/opt/zig/zig"
elif [ -x "${MOABI}/zig" ]; then
    ZIG="${MOABI}/zig"
else
    echo "ERROR: zig not found"
    exit 1
fi

echo "╔══════════════════════════════════╗"
echo "║  Moabi Build System              ║"
echo "╚══════════════════════════════════╝"
echo ""
echo "Zig:    $($ZIG version)"
echo "Root:   ${MOABI}"
echo ""

mkdir -p "${MOABI}/bin"

echo "[1/1] Building moabi-entropy..."
$ZIG build-exe \
    "${MOABI}/src/analyzer/entropy.zig" \
    -lc \
    -O ReleaseSafe \
    --name moabi-entropy \
    -femit-bin="${MOABI}/bin/moabi-entropy" \
    2>&1

if [ $? -eq 0 ] && [ -f "${MOABI}/bin/moabi-entropy" ]; then
    echo "[OK] moabi-entropy"
    echo ""
    echo "╔══════════════════════════════════╗"
    echo "║  Test Run: /usr/bin/ls           ║"
    echo "╚══════════════════════════════════╝"
    echo ""
    "${MOABI}/bin/moabi-entropy" /usr/bin/ls
else
    echo "[FAIL] Compilation failed"
    echo ""
    echo "If you see errors, paste them back and we will fix."
fi
