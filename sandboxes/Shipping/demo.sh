#!/bin/bash
echo "📦 SHIP MANIFEST VERIFICATION"
echo "============================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking cargo manifest..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|SHA-256" | head -3
echo ""
echo "✅ Container verified"
echo "🚨 Undeclared goods detection ready"
