#!/usr/bin/env bash
TRAIN_DIR="${1:-/mnt/d/moabi/reports/training}"

echo "=== MOABI Sample Collector v2 ==="

CLASS_MAP=(
  "interpreter:python3 python3.11 python3.12 perl ruby node nodejs php lua luajit tclsh wish"
  "network_tool:curl wget ping ssh scp sftp rsync nc netcat openssl dig nslookup host ip ss traceroute ftp"
  "text_tool:vim nano less more diff patch strings iconv fold fmt expand unexpand"
  "compression:gzip gunzip bzip2 xz zip unzip tar zstd lz4"
  "shell:dash zsh fish rbash"
)

for entry in "${CLASS_MAP[@]}"; do
  class="${entry%%:*}"
  bins="${entry#*:}"
  mkdir -p "$TRAIN_DIR/$class"
  count=0
  for bin in $bins; do
    for dir in /usr/bin /bin /usr/sbin /usr/local/bin; do
      if [[ -f "$dir/$bin" && -x "$dir/$bin" ]]; then
        cp -n "$dir/$bin" "$TRAIN_DIR/$class/" 2>/dev/null && count=$((count+1))
        break
      fi
    done
  done
  printf "  %-18s +%d samples\n" "$class" "$count"
done

# Shared libraries
mkdir -p "$TRAIN_DIR/shared_library"
count=0
for dir in /usr/lib /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu; do
  if [[ -d "$dir" ]]; then
    for lib in "$dir"/lib*.so* ; do
      if [[ -f "$lib" ]]; then
        base=$(basename "$lib")
        cp -n "$lib" "$TRAIN_DIR/shared_library/$base" 2>/dev/null && count=$((count+1))
      fi
    done
  fi
done
printf "  %-18s +%d samples\n" "shared_library" "$count"

echo
echo "Retrain with:"
echo "luajit /mnt/d/moabi/src/moabi-ml.lua train $TRAIN_DIR /mnt/d/moabi/reports/system.model"
