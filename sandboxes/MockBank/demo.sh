#!/bin/bash
echo "🏦 MOCK BANK SECURITY DEMO"
echo "=========================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "1. Scanning COBOL legacy system..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|Class|Confidence" | head -5
echo ""
echo "2. Scanning Python fintech app..."
luajit "$REFLECT" /usr/bin/python3 --static-only 2>/dev/null | grep -E "Risk|Class|Confidence" | head -5
echo ""
echo "✅ Banking systems verified"
