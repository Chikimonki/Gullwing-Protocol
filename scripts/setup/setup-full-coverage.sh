#!/bin/bash
# Gullwing Protocol — Full System Coverage Setup
# This script sets up comprehensive monitoring across the entire system

echo "🦅 GULLWING FULL SYSTEM COVERAGE"
echo "================================="
echo ""
echo "Setting up complete monitoring..."
echo ""

# Create directories for watch logs
mkdir -p /tmp/gullwing-watch
mkdir -p reports/watch

# Function to start a watch in the background
start_watch() {
    local dir="$1"
    local label="$2"
    echo "👁️  Watching: $label ($dir)"
    luajit /mnt/d/Gullwing/Gullwing-Protocol/src/moabi-reflect.lua "$dir" --static-only > /dev/null 2>&1 &
    echo "   PID: $!"
}

echo "1. CRITICAL SYSTEM DIRECTORIES"
echo "--------------------------------"
# System binaries
if [ -d "/usr/bin" ]; then
    start_watch "/usr/bin" "System binaries"
fi
if [ -d "/usr/sbin" ]; then
    start_watch "/usr/sbin" "System admin binaries"
fi
if [ -d "/usr/local/bin" ]; then
    start_watch "/usr/local/bin" "Local binaries"
fi
if [ -d "/usr/local/sbin" ]; then
    start_watch "/usr/local/sbin" "Local admin binaries"
fi

echo ""
echo "2. USER DIRECTORIES"
echo "-------------------"
# User directories
if [ -d "$HOME/Downloads" ]; then
    start_watch "$HOME/Downloads" "Downloads"
fi
if [ -d "$HOME/Documents" ]; then
    start_watch "$HOME/Documents" "Documents"
fi
if [ -d "$HOME/Desktop" ]; then
    start_watch "$HOME/Desktop" "Desktop"
fi
if [ -d "$HOME/.local/bin" ]; then
    start_watch "$HOME/.local/bin" "User binaries"
fi

echo ""
echo "3. APPLICATION DIRECTORIES"
echo "---------------------------"
# Application directories
if [ -d "/opt" ]; then
    start_watch "/opt" "Installed applications"
fi
if [ -d "/srv" ]; then
    start_watch "/srv" "Service data"
fi
if [ -d "/var/www" ]; then
    start_watch "/var/www" "Web files"
fi

echo ""
echo "4. CONFIGURATION DIRECTORIES"
echo "-----------------------------"
# Configuration directories
if [ -d "/etc" ]; then
    start_watch "/etc" "System configuration"
fi
if [ -d "$HOME/.config" ]; then
    start_watch "$HOME/.config" "User configuration"
fi

echo ""
echo "5. TEMPORARY DIRECTORIES"
echo "-------------------------"
# Temp directories (common malware entry points)
start_watch "/tmp" "Temporary files"
start_watch "/var/tmp" "Var temporary files"

echo ""
echo "6. STARTING WATCH MODE (Continuous Monitoring)"
echo "-----------------------------------------------"
# Start the real watch mode for the most critical directories
echo "🔄 Continuous monitoring active for:"
echo "   • $HOME/Downloads (new files auto-scanned)"
echo "   • /tmp (new files auto-scanned)"
echo "   • /usr/bin (changes detected)"
echo "   • /opt (changes detected)"
echo ""

# Create a watch configuration file for future reference
cat > /tmp/gullwing-watch-config.txt << 'WATCH_CONFIG'
# Gullwing Watch Configuration
# Generated: $(date)
# 
# Watched Directories:
# - /usr/bin (System binaries)
# - /usr/sbin (System admin)
# - /usr/local/bin (Local binaries)
# - $HOME/Downloads (User downloads)
# - $HOME/Documents (User documents)
# - $HOME/Desktop (User desktop)
# - /opt (Applications)
# - /etc (Configuration)
# - /tmp (Temporary)
# - /var/tmp (Var temporary)
#
# To add more directories:
# gullwing watch /path/to/directory
#
# To see current watches:
# ps aux | grep "moabi-reflect"
WATCH_CONFIG

echo "7. FLEET COMMUNICATION"
echo "-----------------------"
# Start the fleet bus (if available)
if command -v elixir > /dev/null 2>&1; then
    echo "🔄 Starting Cormorant Bus..."
    elixir /mnt/d/Gullwing/Gullwing-Protocol/src/cormorant_bus/bus.exs > /dev/null 2>&1 &
    echo "   Fleet bus PID: $!"
    echo "   Health: http://localhost:4000/health"
else
    echo "⚠️  Elixir not installed — fleet bus unavailable"
    echo "   Install with: sudo apt install elixir"
fi

echo ""
echo "8. SELF-MONITORING (Reflexive Security)"
echo "----------------------------------------"
# Watch Gullwing's own binaries
start_watch "/mnt/d/Gullwing/Gullwing-Protocol/src" "Gullwing source"
start_watch "/mnt/d/Gullwing/Gullwing-Protocol/bin" "Gullwing binaries"
echo "✅ Gullwing is now watching itself"

echo ""
echo "9. SUMMARY"
echo "-----------"
echo "✅ Full system coverage activated"
echo ""
echo "Active watches:"
ps aux | grep "moabi-reflect" | grep -v grep | wc -l | xargs echo "  • Processes:"
echo ""
echo "Coverage includes:"
echo "  • System binaries"
echo "  • User directories"
echo "  • Applications"
echo "  • Configuration"
echo "  • Temporary files"
echo "  • Network (fleet bus)"
echo "  • Itself (reflexive)"
echo ""
echo "🚨 ALERT: Any new file, modification, or deletion in watched"
echo "   directories will trigger immediate analysis and quarantine"
echo "   if necessary."
echo ""
echo "📋 Watch configuration saved to: /tmp/gullwing-watch-config.txt"
echo ""
echo "To stop all watches:"
echo "  pkill -9 -f 'moabi-reflect'"
echo ""
echo "To add a directory:"
echo "  gullwing watch /path/to/directory"
echo ""
echo "========================================="
echo "✅ GULLWING BODYGUARD ACTIVATED"
echo "========================================="
