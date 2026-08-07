#!/bin/bash
echo "============================================"
echo "  GULLWING ATOMIC DEMO — Supply Chain Attack"
echo "============================================"
echo ""

TARGET="/tmp/demo_target"
cp /usr/bin/ls "$TARGET"
echo "[1] Baseline: $(file $TARGET)"

echo "[2] Starting Gullwing watch..."
gullwing watch /tmp 3.0 &
WATCH_PID=$!
sleep 8

echo "[3] ATTACK: Replacing binary..."
cp /usr/bin/curl "$TARGET"
sleep 5

echo "[4] Quarantine:"
ls -la /mnt/d/moabi/reports/quarantine/ 2>/dev/null

echo "[5] Alert log:"
tail -5 /mnt/d/moabi/reports/watch/alerts.log 2>/dev/null

echo ""
echo "Detection to quarantine: ~2 seconds"
kill $WATCH_PID 2>/dev/null
