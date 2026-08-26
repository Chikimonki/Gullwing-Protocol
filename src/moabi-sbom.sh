#!/usr/bin/env bash
# moabi-sbom.sh — full audit trail for a directory of binaries
set -u
TARGET_DIR="${1:?usage: moabi-sbom.sh <dir> [output.jsonl]}"
OUT="${2:-/mnt/d/moabi/reports/sbom-$(date +%Y%m%d-%H%M%S).jsonl}"
REFLECT=/mnt/d/moabi/src/moabi-reflect.lua

echo "MOABI SBOM scan: $TARGET_DIR -> $OUT"
> "$OUT"

for f in "$TARGET_DIR"/*; do
  [[ -f "$f" ]] || continue
  JSON_OUT="/mnt/d/moabi/reports/$(basename "$f").evidence.json"
  luajit "$REFLECT" "$f" --static-only --json "$JSON_OUT" >/dev/null 2>&1
  json="/mnt/d/moabi/reports/$(basename "$f").evidence.json"
  [[ -f "$json" ]] && cat "$json" >> "$OUT" && echo >> "$OUT"
done

echo "Records: $(grep -c '^{' "$OUT")"
echo "Verdicts:"
grep -o '"risk_tier":"[A-Z]*"' "$OUT" | sort | uniq -c
grep -o '"novelty_tier":"[A-Z]*"' "$OUT" | sort | uniq -c
