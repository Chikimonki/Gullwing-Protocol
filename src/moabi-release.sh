#!/usr/bin/env bash
# MOABI Release Artifact Generator
# Creates a self-contained, verifiable release directory

set -euo pipefail

TARGET_DIR="${1:-/mnt/d/moabi/bin}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RELEASE_DIR="/mnt/d/moabi/reports/releases/${TIMESTAMP}"

echo "========================================================"
echo "  MOABI Release Artifact Generator"
echo "========================================================"
echo "  Target:    $TARGET_DIR"
echo "  Output:    $RELEASE_DIR"
echo

mkdir -p "$RELEASE_DIR/evidence"

# Run SBOM scan
echo "  [1/4] Generating CycloneDX BOM..."
luajit /mnt/d/moabi/src/moabi-sbom.lua "$TARGET_DIR" --out "$RELEASE_DIR/software.cdx.json"

# Generate Model-BOM
echo "  [2/4] Generating Model-BOM..."
luajit /mnt/d/moabi/src/moabi-model-bom.lua \
    /mnt/d/moabi/reports/system.model \
    --out "$RELEASE_DIR/modelbom.json"

# Generate scan manifest
echo "  [3/4] Generating scan manifest..."
MODEL_HASH=$(sha256sum /mnt/d/moabi/reports/system.model | cut -d' ' -f1)

cat > "$RELEASE_DIR/scan-manifest.json" <<MANIFEST
{
  "root": "$TARGET_DIR",
  "timestamp": "$(date -Iseconds)",
  "tool_version": "MOABI v1.0",
  "model_hash": "$MODEL_HASH",
  "analysis_modes": ["ELF-static", "PE-static"],
  "cyclonedx_version": "1.6",
  "artifacts": {
    "software_bom": "software.cdx.json",
    "model_bom": "modelbom.json",
    "evidence_dir": "evidence/"
  }
}
MANIFEST

# Generate SHA256SUMS
echo "  [4/4] Generating integrity checksums..."
cd "$RELEASE_DIR"
sha256sum software.cdx.json modelbom.json scan-manifest.json > SHA256SUMS

echo
echo "  Release artifact created:"
echo "    $RELEASE_DIR/"
echo "    ├── software.cdx.json"
echo "    ├── modelbom.json"
echo "    ├── scan-manifest.json"
echo "    ├── SHA256SUMS"
echo "    └── evidence/"
echo
echo "  Verify integrity:"
echo "    cd $RELEASE_DIR && sha256sum -c SHA256SUMS"
echo "========================================================"
