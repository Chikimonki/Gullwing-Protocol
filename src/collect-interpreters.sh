#!/usr/bin/env bash
set -euo pipefail

DEST="/mnt/d/moabi/reports/training/interpreter"
mkdir -p "$DEST"

echo "Populating interpreter class..."

# Python family
for p in /usr/bin/python3 /usr/bin/python3.10 /usr/bin/python3.11 /usr/bin/python3.12 /usr/bin/pypy3; do
    [[ -x "$p" ]] && cp -n "$p" "$DEST/" 2>/dev/null || true
done

# Perl
[[ -x /usr/bin/perl ]] && cp -n /usr/bin/perl "$DEST/" 2>/dev/null || true

# Ruby
[[ -x /usr/bin/ruby ]] && cp -n /usr/bin/ruby "$DEST/" 2>/dev/null || true

# Lua family
for l in /usr/bin/lua5.1 /usr/bin/lua5.2 /usr/bin/lua5.3 /usr/bin/lua5.4 /usr/bin/luajit; do
    [[ -x "$l" ]] && cp -n "$l" "$DEST/" 2>/dev/null || true
done

# Others
for bin in /usr/bin/tclsh /usr/bin/php /usr/bin/node /usr/bin/awk /usr/bin/gawk; do
    [[ -x "$bin" ]] && cp -n "$bin" "$DEST/" 2>/dev/null || true
done

echo "Done. Current count: $(ls -1 "$DEST" | wc -l)"
