#!/bin/bash
echo "🔪 Killing all Gullwing servers..."
echo ""

# Kill Python frontend
echo "Killing frontend (port 8081)..."
fuser -k 8081/tcp 2>/dev/null
pkill -9 -f "python3 -m http.server" 2>/dev/null

# Kill API server
echo "Killing API server (port 9393)..."
fuser -k 9393/tcp 2>/dev/null
pkill -9 -f "moabi-serve" 2>/dev/null
pkill -9 -f "luajit.*serve" 2>/dev/null

sleep 2

# Verify
echo ""
if lsof -i :8081 2>/dev/null | grep -q LISTEN; then
    echo "❌ Port 8081 still in use"
else
    echo "✅ Port 8081 free"
fi

if lsof -i :9393 2>/dev/null | grep -q LISTEN; then
    echo "❌ Port 9393 still in use"
else
    echo "✅ Port 9393 free"
fi
