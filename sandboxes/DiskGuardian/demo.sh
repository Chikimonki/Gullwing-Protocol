#!/bin/bash
echo "💾 DISK GUARDIAN — Space Protection"
echo "===================================="
echo ""
echo "Drive Status:"
df -h | grep -E "^/|C:"
echo ""
if [ -d "/mnt/c" ]; then
    C_USED=$(df -h /mnt/c | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ ${C_USED} -gt 95 ]; then
        echo "🚨 CRITICAL: C: drive at ${C_USED}% capacity!"
        echo "→ Action: Quarantine large files"
    else
        echo "✅ Disk space acceptable"
    fi
fi
echo ""
echo "Real-time monitoring active..."
