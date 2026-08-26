#!/bin/bash
# Bulletproof server starter

echo "=== Starting Gullwing Server ==="

# Kill ALL processes that might be using the port
echo "Killing existing processes..."
pkill -9 -f "moabi-serve" 2>/dev/null
pkill -9 -f "luajit" 2>/dev/null
sleep 2

# Free the port using multiple methods
echo "Freeing port 9393..."
fuser -k 9393/tcp 2>/dev/null
sleep 1
fuser -k 9393/tcp 2>/dev/null
sleep 1

# Verify port is free
if lsof -i :9393 2>/dev/null | grep -q LISTEN; then
    echo "⚠️ Port still in use, trying alternative..."
    # Find exact PID
    PID=$(lsof -ti :9393 2>/dev/null)
    if [ ! -z "$PID" ]; then
        kill -9 $PID 2>/dev/null
        sleep 2
    fi
fi

# Start the server
echo "Starting server..."
cd /mnt/d/The-Gullwing-Protocol/CORE/gullwing-cormorant
nohup luajit src/moabi-serve.lua > /tmp/gullwing-server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/gullwing-server.pid

# Wait for startup
sleep 3

# Check if it's running
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "✅ Server started (PID: $SERVER_PID)"
    
    # Test health
    HEALTH=$(curl -s http://127.0.0.1:9393/health 2>/dev/null)
    if [ ! -z "$HEALTH" ]; then
        echo "✅ Health check passed: $HEALTH"
    else
        echo "⚠️ Server running but health check failed"
    fi
else
    echo "❌ Server failed to start"
    cat /tmp/gullwing-server.log
fi
