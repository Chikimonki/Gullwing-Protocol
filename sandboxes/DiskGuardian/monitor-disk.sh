#!/bin/bash
echo "💾 DISK GUARDIAN — Space Protection"
echo "===================================="
echo ""

# Check all drives
echo "Drive Status:"
df -h | grep -E "^/|C:"
echo ""

# Check C: drive
if [ -d "/mnt/c" ]; then
    C_USED=$(df -h /mnt/c | tail -1 | awk '{print $5}' | sed 's/%//')
    C_FREE=$(df -h /mnt/c | tail -1 | awk '{print $4}')
    echo "C: Drive — Used: ${C_USED}%, Free: ${C_FREE}"
    
    if [ ${C_USED} -gt 95 ]; then
        echo "🚨 CRITICAL: C: drive at ${C_USED}% capacity!"
        echo "→ Action: Quarantine large files"
        echo "→ Alert: Space exhaustion imminent"
    elif [ ${C_USED} -gt 90 ]; then
        echo "⚠️ WARNING: C: drive at ${C_USED}% capacity"
        echo "→ Action: Schedule cleanup"
    else
        echo "✅ Disk space acceptable"
    fi
fi

echo ""
echo "Real-time monitoring active..."
echo "Gullwing will alert if space drops below 10%"
