#!/usr/bin/env bash
# Populate MOABI training directories with real system binaries
set -euo pipefail

TRAIN="/mnt/d/moabi/reports/training"

echo "=== MOABI Training Data Population ==="
echo

# Helper: copy if exists, count successes
copy_if_exists() {
    local dest="$1"
    shift
    local count=0
    for src in "$@"; do
        if [[ -f "$src" && -x "$src" ]]; then
            local base=$(basename "$src")
            # Avoid overwriting existing samples with same name
            if [[ ! -f "$dest/$base" ]]; then
                cp -Lf "$src" "$dest/$base" 2>/dev/null && count=$((count+1))
            fi
        fi
    done
    echo $count
}

# ── shell (target: 15+ total) ───────────────────────────────────────────────
echo -n "  shell:           "
count=$(copy_if_exists "$TRAIN/shell" \
    /bin/sh /bin/bash /bin/dash \
    /usr/bin/sh /usr/bin/bash /usr/bin/dash \
    /usr/bin/rbash /bin/rbash \
    /usr/bin/zsh /bin/zsh 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/shell" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── interpreter (target: 15+ total) ─────────────────────────────────────────
echo -n "  interpreter:     "
count=$(copy_if_exists "$TRAIN/interpreter" \
    /usr/bin/python3 /usr/bin/python3.10 /usr/bin/python3.11 /usr/bin/python3.12 \
    /usr/bin/perl /usr/bin/perl5.* \
    /usr/bin/ruby /usr/bin/ruby3.* \
    /usr/bin/lua5.1 /usr/bin/lua5.2 /usr/bin/lua5.3 /usr/bin/lua5.4 \
    /usr/bin/lua /usr/bin/luajit \
    /usr/bin/awk /usr/bin/gawk /usr/bin/mawk \
    /usr/bin/tclsh /usr/bin/tclsh8.* \
    /usr/bin/php /usr/bin/php8.* \
    /usr/bin/node /usr/bin/nodejs 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/interpreter" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── compression (target: 15+ total) ─────────────────────────────────────────
echo -n "  compression:     "
count=$(copy_if_exists "$TRAIN/compression" \
    /usr/bin/gzip /usr/bin/gunzip /usr/bin/zcat \
    /usr/bin/bzip2 /usr/bin/bunzip2 /usr/bin/bzcat \
    /usr/bin/xz /usr/bin/unxz /usr/bin/xzcat \
    /usr/bin/zip /usr/bin/unzip /usr/bin/zipinfo \
    /usr/bin/tar \
    /usr/bin/lzma /usr/bin/unlzma \
    /usr/bin/lz4 /usr/bin/unlz4 \
    /usr/bin/zstd /usr/bin/unzstd 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/compression" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── network_tool (target: 20+ total) ────────────────────────────────────────
echo -n "  network_tool:    "
count=$(copy_if_exists "$TRAIN/network_tool" \
    /usr/bin/curl /usr/bin/wget \
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp \
    /usr/bin/rsync \
    /usr/bin/nc /usr/bin/netcat /usr/bin/ncat \
    /usr/bin/telnet \
    /usr/bin/ftp /usr/bin/ftpd \
    /usr/bin/ping /usr/bin/ping6 \
    /usr/bin/traceroute /usr/bin/tracepath \
    /usr/bin/dig /usr/bin/nslookup /usr/bin/host \
    /usr/bin/ncat /usr/bin/socat 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/network_tool" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── text_tool (target: 20+ total) ───────────────────────────────────────────
echo -n "  text_tool:       "
count=$(copy_if_exists "$TRAIN/text_tool" \
    /usr/bin/vim /usr/bin/vi /usr/bin/nano \
    /usr/bin/less /usr/bin/more /usr/bin/most \
    /usr/bin/cat /usr/bin/tac \
    /usr/bin/head /usr/bin/tail \
    /usr/bin/grep /usr/bin/egrep /usr/bin/fgrep \
    /usr/bin/sed /usr/bin/awk /usr/bin/gawk \
    /usr/bin/diff /usr/bin/patch /usr/bin/cmp \
    /usr/bin/sort /usr/bin/uniq /usr/bin/wc \
    /usr/bin/cut /usr/bin/paste /usr/bin/tr \
    /usr/bin/fmt /usr/bin/fold /usr/bin/column 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/text_tool" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── system_utility (already healthy, but add more) ──────────────────────────
echo -n "  system_utility:  "
count=$(copy_if_exists "$TRAIN/system_utility" \
    /usr/bin/ls /usr/bin/cp /usr/bin/mv /usr/bin/rm \
    /usr/bin/mkdir /usr/bin/rmdir /usr/bin/touch \
    /usr/bin/chmod /usr/bin/chown /usr/bin/chgrp \
    /usr/bin/ln /usr/bin/readlink \
    /usr/bin/stat /usr/bin/file \
    /usr/bin/ps /usr/bin/top /usr/bin/free /usr/bin/uptime \
    /usr/bin/kill /usr/bin/killall \
    /usr/bin/who /usr/bin/w /usr/bin/users \
    /usr/bin/id /usr/bin/whoami /usr/bin/groups \
    /usr/bin/pwd /usr/bin/cd /usr/bin/echo \
    /usr/bin/env /usr/bin/printenv \
    /usr/bin/which /usr/bin/whereis /usr/bin/locate \
    /usr/bin/find /usr/bin/xargs \
    /usr/bin/date /usr/bin/cal /usr/bin/timetravel 2>/dev/null || true)
existing=$(ls -1 "$TRAIN/system_utility" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

# ── shared_library (grab more .so files) ────────────────────────────────────
echo -n "  shared_library:  "
count=0
for libdir in /lib /usr/lib /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu; do
    if [[ -d "$libdir" ]]; then
        while IFS= read -r lib; do
            base=$(basename "$lib")
            if [[ ! -f "$TRAIN/shared_library/$base" ]]; then
                cp -Lf "$lib" "$TRAIN/shared_library/$base" 2>/dev/null && count=$((count+1))
            fi
        done < <(find "$libdir" -maxdepth 1 -type f -name "lib*.so*" 2>/dev/null | head -n 50)
    fi
done
existing=$(ls -1 "$TRAIN/shared_library" 2>/dev/null | wc -l)
echo "added $count (total: $existing)"

echo
echo "=== Summary ==="
echo "Run: luajit /mnt/d/moabi/src/moabi-ml.lua train /mnt/d/moabi/reports/training /mnt/d/moabi/reports/system.model"
echo "Then: luajit /mnt/d/moabi/src/moabi-ml.lua validate /mnt/d/moabi/reports/system.model"
