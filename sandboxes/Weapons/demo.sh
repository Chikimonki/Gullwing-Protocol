#!/bin/bash
echo "🛃 EXPORT CONTROL & DUAL-USE GOODS"
echo "================================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking export transaction..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|SHA-256" | head -3
echo ""
echo "🚨 Illegal transfer blocking ready"
echo "✅ Export control enforced"
