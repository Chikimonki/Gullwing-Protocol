#!/bin/bash
# Start both API and frontend servers

# Kill any existing servers
pkill -f "moabi-serve.lua" 2>/dev/null
pkill -f "python3 -m http.server" 2>/dev/null

# Start API server
echo "Starting API server on http://127.0.0.1:9393"
luajit src/moabi-serve.lua &
API_PID=$!

# Start frontend server
echo "Starting frontend on http://127.0.0.1:8081"
cd src/extension
python3 -m http.server 8081 --bind 127.0.0.1 &
FRONTEND_PID=$!
cd ../..

echo ""
echo "✅ API: http://127.0.0.1:9393"
echo "✅ Frontend: http://127.0.0.1:8081/unified.html"
echo ""
echo "Press Ctrl+C to stop both servers"
trap "kill $API_PID $FRONTEND_PID 2>/dev/null" INT
wait
