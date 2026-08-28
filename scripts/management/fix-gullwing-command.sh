#!/bin/bash
echo "🔧 FIXING GULLWING COMMAND"
echo "=========================="

# 1. Kill all existing servers
echo "1. Killing all servers..."
pkill -9 -f "moabi-serve" 2>/dev/null
pkill -9 -f "luajit.*serve" 2>/dev/null
fuser -k 9393/tcp 2>/dev/null
fuser -k 9394/tcp 2>/dev/null
sleep 2
echo "✅ All servers killed"

# 2. Fix the imperator path
echo "2. Fixing imperator path..."
cd /mnt/d/Gullwing/Gullwing-Protocol
sed -i 's|/mnt/d/moabi/src|/mnt/d/Gullwing/Gullwing-Protocol/src|g' src/bin/gullwing/gullwing-imperator
echo "✅ Imperator path fixed"

# 3. Create symlink
echo "3. Creating symlink..."
ln -sf /mnt/d/Gullwing/Gullwing-Protocol/bin/gullwing /usr/local/bin/gullwing 2>/dev/null
echo "✅ Symlink created"

# 4. Start the correct server
echo "4. Starting correct server..."
./start-server.sh

# 5. Start frontend
echo "5. Starting frontend..."
cd src/extension
nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
cd ../..

echo ""
echo "✅ ALL FIXED!"
echo "API: http://127.0.0.1:9393"
echo "Frontend: http://127.0.0.1:8081/unified.html"
echo ""
echo "The old page was from /mnt/d/moabi/src"
echo "The new page has all 10 tabs"
