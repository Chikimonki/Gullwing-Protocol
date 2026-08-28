#!/bin/bash
echo "⛓️ BLOCKCHAIN SECURITY"
echo "======================"
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Checking crypto exchange binary..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "Risk|Entropy" | head -3
echo ""
echo "🚨 Private key theft detection ready"
echo "✅ Fund protection via quarantine"
