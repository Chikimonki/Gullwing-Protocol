#!/bin/bash
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           GULLWING ARCADE — COMPLETE TEST SUITE          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Test all games
for game in golf cobol detective entropy procurement fleet; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🎮 Testing: $game"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ "$game" == "golf" ]; then
        # Test all levels of golf
        for level in cheat list 1 2 3; do
            echo ""
            echo "--- Level: $level ---"
            curl -s -X POST http://127.0.0.1:9393/api/run-game \
              -d "game=$game&level=$level" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('output','No output')[:200])"
        done
    else
        curl -s -X POST http://127.0.0.1:9393/api/run-game \
          -d "game=$game" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('output','No output')[:200])"
    fi
    echo ""
done

echo "✅ Arcade test complete!"
