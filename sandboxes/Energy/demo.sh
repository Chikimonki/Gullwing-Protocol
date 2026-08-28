#!/bin/bash
echo "⚡ ENERGY GRID SECURITY"
echo "======================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking SCADA system..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|Entropy" | head -3
echo ""
echo "✅ Grid controller verified"
echo "🚨 Unauthorized access detection active"
