#!/usr/bin/env bash
# ============================================================================
# MOABI-DELTA test fixture builder (hardened)
# Produces /tmp/test_clean and /tmp/test_tampered with a REAL dependency
# delta, then verifies the fixtures BEFORE you run moabi-delta.
#
# Fixes the two silent-failure modes:
#   1. `gcc -lcurl` failing because libcurl isn't installed -> falls back
#      to a dummy shared lib so the test never silently no-ops.
#   2. Modern linkers (--as-needed, default on Debian/Ubuntu) dropping
#      DT_NEEDED entries for libs that are never called -> the tampered
#      binary ACTUALLY CALLS the injected library.
# ============================================================================
set -euo pipefail   # <-- the key line your original script was missing

CLEAN_DIR=/tmp/test_clean
TAMPER_DIR=/tmp/test_tampered
rm -rf "$CLEAN_DIR" "$TAMPER_DIR"
mkdir -p "$CLEAN_DIR" "$TAMPER_DIR"

SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

cat > "$SRC/app.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("app"); return 0; }
EOF

# --- Clean build: vanilla ----------------------------------------------------
gcc "$SRC/app.c" -o "$CLEAN_DIR/app"
echo "[ok] clean build"

# --- Tampered build: prefer real libcurl, else dummy lib ---------------------
cat > "$SRC/app_tampered.c" <<'EOF'
#include <stdio.h>
EOF

if echo '#include <curl/curl.h>' | gcc -E -x c - >/dev/null 2>&1; then
    # Real path: link libcurl AND actually call into it so DT_NEEDED sticks
    cat >> "$SRC/app_tampered.c" <<'EOF'
#include <curl/curl.h>
int main(void) {
    curl_version_info_data *v = (void*)0;
    v = curl_version_info(CURLVERSION_NOW);
    printf("app, curl %s\n", v ? v->version : "?");
    return 0;
}
EOF
    gcc "$SRC/app_tampered.c" -o "$TAMPER_DIR/app" -lcurl
    echo "[ok] tampered build linked REAL libcurl"
else
    echo "[warn] libcurl dev headers not found -> using dummy lib fallback"
    echo "       (install libcurl-dev / libcurl4-openssl-dev for the real path)"
    cat > "$SRC/probe.c" <<'EOF'
void moabi_probe(void) {}
EOF
    cat >> "$SRC/app_tampered.c" <<'EOF'
extern void moabi_probe(void);
int main(void) { moabi_probe(); puts("app"); return 0; }
EOF
    gcc -shared -fPIC "$SRC/probe.c" -o "$TAMPER_DIR/libprobe.so"
    gcc "$SRC/app_tampered.c" -o "$TAMPER_DIR/app" \
        -L"$TAMPER_DIR" -lprobe -Wl,-rpath,'$ORIGIN'
    echo "[ok] tampered build linked dummy libprobe.so"
fi

# --- Pre-flight verification: refuse to run moabi-delta on bad fixtures ------
H_CLEAN=$(sha256sum "$CLEAN_DIR/app"   | awk '{print $1}')
H_TAMPER=$(sha256sum "$TAMPER_DIR/app" | awk '{print $1}')
echo
echo "clean:    $H_CLEAN"
echo "tampered: $H_TAMPER"
if [ "$H_CLEAN" = "$H_TAMPER" ]; then
    echo "[FAIL] Hashes identical — fixtures are identical, aborting." >&2
    exit 1
fi

D_CLEAN=$(readelf -d "$CLEAN_DIR/app"   | grep NEEDED | sort)
D_TAMPER=$(readelf -d "$TAMPER_DIR/app" | grep NEEDED | sort)
echo
echo "clean DT_NEEDED:";    echo "$D_CLEAN"
echo "tampered DT_NEEDED:"; echo "$D_TAMPER"
if [ "$D_CLEAN" = "$D_TAMPER" ]; then
    echo "[FAIL] DT_NEEDED sets identical — Gullwing has nothing to diff." >&2
    exit 1
fi
if ! "$TAMPER_DIR/app" >/dev/null; then
    echo "[FAIL] tampered binary does not execute." >&2
    exit 1
fi

echo
echo "[PASS] Fixtures valid: hashes differ AND dependency trees differ."
echo
echo "Next step:"
echo "  moabi-delta $CLEAN_DIR $TAMPER_DIR    # (your actual invocation)"
echo "  syft dir:$TAMPER_DIR -o cyclonedx-json   # package-level cross-check"
