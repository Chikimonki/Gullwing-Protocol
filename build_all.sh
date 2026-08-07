#!/bin/bash
ZIG=/mnt/d/zig_versions/zig-linux-x86_64-0.13.0/zig
SRC=/mnt/d/moabi/src
BIN=/mnt/d/moabi/bin

echo "Building MOABI Binary Analysis Suite..."

TOOLS=(
    moabi-entropy
    moabi-elfparse
    moabi-caves
    moabi-strings
    moabi-symbols
    moabi-hashdeep
    moabi-report
    moabi-baseline
)

for tool in "${TOOLS[@]}"; do
    echo "  Building $tool..."
    $ZIG build-exe $SRC/$tool.zig -O ReleaseSafe -femit-bin=$BIN/$tool
    if [ $? -eq 0 ]; then
        echo "  ✓ $tool"
    else
        echo "  ✗ $tool FAILED"
    fi
done

echo ""
echo "Done. Binaries in $BIN/"
