#!/usr/bin/env bash
# collect-samples.sh — populate MOABI training directories from system binaries
set -euo pipefail

TRAIN_DIR="${1:-/mnt/d/moabi/reports/training}"
PRIMARY_BIN_SRC="${2:-/usr/bin}"

echo "=== MOABI sample collector ==="
echo "Training root: $TRAIN_DIR"
echo "Primary binary source: $PRIMARY_BIN_SRC"
echo

SEARCH_DIRS=(
    "$PRIMARY_BIN_SRC"
    /usr/bin
    /bin
    /usr/sbin
    /sbin
    /usr/local/bin
)

copy_class() {
    local class="$1"
    shift

    mkdir -p "$TRAIN_DIR/$class"

    local added=0

    for name in "$@"; do
        local found=""

        for dir in "${SEARCH_DIRS[@]}"; do
            local candidate="$dir/$name"

            if [[ -f "$candidate" && -x "$candidate" ]]; then
                found="$candidate"
                break
            fi
        done

        if [[ -n "$found" ]]; then
            cp -Lf "$found" "$TRAIN_DIR/$class/$name" 2>/dev/null || true
            added=$((added + 1))
        fi
    done

    printf "  %-18s +%d samples\n" "$class" "$added"
}

copy_class system_utility \
    ls cat cp mv rm mkdir rmdir chmod chown chgrp ln touch stat \
    grep sed awk find xargs sort uniq wc head tail cut tr tee \
    true false test sleep date printf echo basename dirname env id whoami \
    uname df du ps top free uptime kill nice nohup yes seq expr

copy_class network_tool \
    curl wget ping ping6 ssh scp sftp rsync nc netcat ncat telnet ftp \
    dig nslookup host ip ss traceroute tracepath openssl

copy_class shell \
    bash sh dash zsh fish rbash

copy_class interpreter \
    python3 python perl ruby lua luajit node nodejs php tclsh wish

copy_class compression \
    gzip gunzip bzip2 bunzip2 xz unxz zip unzip tar zstd unzstd lz4 unlz4

copy_class text_tool \
    vim vi nano less more diff patch cmp comm strings iconv fold fmt expand unexpand

# Add shared libraries if present.
mkdir -p "$TRAIN_DIR/shared_library"

lib_added=0
for libdir in /lib /usr/lib /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu; do
    if [[ -d "$libdir" ]]; then
        while IFS= read -r lib; do
            base="$(basename "$lib")"
            cp -Lf "$lib" "$TRAIN_DIR/shared_library/$base" 2>/dev/null || true
            lib_added=$((lib_added + 1))
        done < <(find "$libdir" -maxdepth 1 -type f -name 'lib*.so*' 2>/dev/null | head -n 20)
    fi
done

printf "  %-18s +%d samples\n" "shared_library" "$lib_added"

echo
echo "Done."
echo
echo "Retrain with:"
echo "  luajit /mnt/d/moabi/src/moabi-ml.lua train \\"
echo "      /mnt/d/moabi/reports/training \\"
echo "      /mnt/d/moabi/reports/system.model"
