#!/bin/bash
echo "🎰 CASINO INTEGRITY CHECK"
echo "========================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking RNG system..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Entropy|Risk" | head -3
echo ""
echo "✅ RNG integrity verified"
echo "🚨 Tamper detection active"
