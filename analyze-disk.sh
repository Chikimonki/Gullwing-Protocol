#!/bin/bash
echo "🔍 GULLWING DISK ANALYSIS"
echo "========================="
echo ""

echo "1. C: Drive Status:"
df -h /mnt/c | tail -1

echo ""
echo "2. WSL Disk Usage:"
sudo du -sh /var/lib/docker 2>/dev/null
du -sh ~/.ollama 2>/dev/null
du -sh /mnt/d/Gullwing 2>/dev/null

echo ""
echo "3. Windows Large Folders:"
# Check via cmd.exe
cmd.exe /c "dir C:\ /s /a:-h" 2>/dev/null | tail -5

echo ""
echo "4. Windows System Files:"
cmd.exe /c "dir C:\pagefile.sys C:\hiberfil.sys C:\swapfile.sys /a:-h" 2>/dev/null

echo ""
echo "5. Windows Component Store:"
cmd.exe /c "dir C:\Windows\WinSxS /s" 2>/dev/null | tail -3

echo ""
echo "6. WSL vhdx:"
ls -lh /mnt/c/Users/ccuk/AppData/Local/Packages/*/LocalState/*.vhdx 2>/dev/null
