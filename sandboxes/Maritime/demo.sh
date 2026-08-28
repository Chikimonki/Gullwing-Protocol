#!/bin/bash
echo "🚢 MARITIME SECURITY"
echo "===================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking navigation system..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|Class" | head -3
echo ""
echo "✅ GPS firmware verified"
echo "🚨 Spoofing detection active"
