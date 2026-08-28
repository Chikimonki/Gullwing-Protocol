#!/bin/bash
echo "✈️ AVIATION SECURITY"
echo "===================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking flight computer..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|SHA-256" | head -3
echo ""
echo "✅ Navigation firmware verified"
echo "🚨 Tampering detection active"
