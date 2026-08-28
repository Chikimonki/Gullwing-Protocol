#!/bin/bash
echo "=== TESTING ALL GULLWING FEATURES ==="
echo ""

# Test 1: API Health
echo "1. API Health:"
curl -s http://127.0.0.1:9393/health
echo ""

# Test 2: Basic Analysis (form-encoded)
echo "2. Basic Analysis (ls):"
curl -s -X POST http://127.0.0.1:9393/reflect \
  -d "path=/usr/bin/ls" | head -5
echo ""

# Test 3: WCC
echo "3. WCC Binary Unlinking:"
curl -s -X POST http://127.0.0.1:9393/wcc \
  -d "path=/usr/bin/ls" | head -5
echo ""

# Test 4: Metamorph
echo "4. Metamorph Comparison:"
curl -s -X POST http://127.0.0.1:9393/metamorph/compare \
  -d "path1=/usr/bin/ls&path2=/usr/bin/ls" | head -5
echo ""

# Test 5: Frontend Files
echo "5. Frontend Files:"
for file in unified.html arcade.html dashboard.html vehicle.html cormorant.html; do
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8081/$file | grep -q "200"; then
        echo "  ✅ $file accessible"
    else
        echo "  ❌ $file NOT accessible"
    fi
done

echo ""
echo "=== TEST COMPLETE ==="
