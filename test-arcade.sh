#!/bin/bash
echo "=== TESTING ARCADE ==="
echo ""

# Test each game
for game in golf cobol detective entropy procurement fleet; do
    echo "--- $game ---"
    curl -s -X POST http://127.0.0.1:9393/api/run-game \
      -H "Content-Type: application/json" \
      -d "{\"game\":\"$game\"}" | python3 -m json.tool 2>/dev/null | head -10
    echo ""
done
