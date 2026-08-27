#!/bin/bash
echo "🚀 STARTING GULLWING PROTOCOL"
echo "=============================="

# Start API server
echo "1. Starting API server..."
./start-server.sh

# Start frontend
echo ""
echo "2. Starting frontend..."
cd src/extension
python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ../..

echo "   Frontend PID: $FRONTEND_PID"
echo ""

# Wait for servers
sleep 2

# Test everything
echo "3. Testing..."
echo ""
echo "✅ API: http://127.0.0.1:9393"
echo "✅ Frontend: http://127.0.0.1:8081/unified.html"
echo ""

# Run tests
./test-all-features.sh

echo ""
echo "✅ Everything started!"
echo ""
echo "Open http://127.0.0.1:8081/unified.html in your browser"
