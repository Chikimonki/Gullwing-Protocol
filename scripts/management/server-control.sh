#!/bin/bash

case "$1" in
    start)
        echo "Starting Gullwing server..."
        # Kill any existing processes
        pkill -9 -f "luajit.*moabi-serve" 2>/dev/null
        sudo fuser -k 9393/tcp 2>/dev/null
        sleep 2
        
        # Start new server
        nohup luajit src/moabi-serve.lua > /tmp/gullwing-server.log 2>&1 &
        echo $! > /tmp/gullwing-server.pid
        sleep 3
        
        # Verify
        if curl -s http://127.0.0.1:9393/health > /dev/null 2>&1; then
            echo "✅ Server started successfully (PID: $(cat /tmp/gullwing-server.pid))"
            echo "📝 Log: /tmp/gullwing-server.log"
        else
            echo "❌ Server failed to start. Log:"
            tail -20 /tmp/gullwing-server.log
        fi
        ;;
    stop)
        echo "Stopping Gullwing server..."
        if [ -f /tmp/gullwing-server.pid ]; then
            PID=$(cat /tmp/gullwing-server.pid)
            kill -9 $PID 2>/dev/null
            rm /tmp/gullwing-server.pid
        fi
        pkill -9 -f "luajit.*moabi-serve" 2>/dev/null
        sudo fuser -k 9393/tcp 2>/dev/null
        sleep 1
        echo "✅ Stopped"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        echo "=== Server Status ==="
        if curl -s http://127.0.0.1:9393/health > /dev/null 2>&1; then
            echo "✅ Server is running"
            curl -s http://127.0.0.1:9393/health
            echo ""
        else
            echo "❌ Server is not running"
        fi
        echo ""
        echo "=== Processes ==="
        ps aux | grep "luajit.*moabi-serve" | grep -v grep
        ;;
    log)
        tail -f /tmp/gullwing-server.log
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|log}"
        exit 1
        ;;
esac
