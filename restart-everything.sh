#!/bin/bash
echo "🔄 RESTARTING GULLWING PROTOCOL"
echo "================================"

# Kill everything
./kill-servers.sh

sleep 2

# Start API server
echo ""
echo "Starting API server..."
./start-server.sh

sleep 2

# Start frontend
echo ""
echo "Starting frontend..."
cd src/extension
nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ../..

echo "Frontend PID: $FRONTEND_PID"

sleep 2

# Verify
echo ""
echo "=== VERIFICATION ==="
echo "API: $(curl -s http://127.0.0.1:9393/health 2>/dev/null || echo 'OFFLINE')"
echo "Frontend: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/unified.html 2>/dev/null || echo 'OFFLINE')"
echo ""
echo "✅ Open: http://127.0.0.1:8081/unified.html"
