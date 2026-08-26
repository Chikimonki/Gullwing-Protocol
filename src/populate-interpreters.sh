#!/usr/bin/env bash
# populate-interpreters.sh — push interpreter class to 20+
TRAIN="/mnt/d/moabi/reports/training/interpreter"

mkdir -p "$TRAIN"

echo "Adding interpreter samples..."

cp -n /usr/bin/python3*     "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/lua*         "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/luajit       "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/perl*        "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/ruby*        "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/php*         "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/tclsh*       "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/wish*        "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/awk          "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/gawk         "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/mawk         "$TRAIN/" 2>/dev/null || true
cp -n /usr/bin/node*        "$TRAIN/" 2>/dev/null || true

count=$(ls -1 "$TRAIN" 2>/dev/null | wc -l)
echo "Interpreter samples now: $count"

if [[ $count -lt 20 ]]; then
    echo "Still short. Install more with:"
    echo "sudo apt install -y php-cli tcl tk lua5.4 luajit pypy3 ruby-full"
fi
