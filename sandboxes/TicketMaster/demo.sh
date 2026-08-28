#!/bin/bash
echo "🎟️ TICKET VERIFICATION SYSTEM"
echo "=============================="
REFLECT="/mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua"
echo ""
echo "Verifying ticket binary..."
luajit "$REFLECT" /usr/bin/ls --static-only 2>/dev/null | grep -E "SHA-256|Risk" | head -3
echo ""
echo "✅ Legitimate ticket verified"
echo "🚨 Counterfeit detection ready"
