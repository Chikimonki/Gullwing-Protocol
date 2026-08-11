#!/usr/bin/env bash
# ============================================================================
# MOABI / GULLWING detection-matrix fixture builder
# Extends moabi_test_harness.sh into a 4-scenario matrix:
#
#   A. baseline        clean binary                          expect: libc only
#   B. added_dt_needed  tampered lib, called at runtime       expect: DETECTED
#   C. dlopen_shadow   lib loaded via dlopen(), never linked expect: INVISIBLE
#                      (structural blind spot of DT_NEEDED-based scanning)
#   D. static          statically linked binary              expect: NO ENTRIES
#                      (second blind spot — everything inside, nothing declared)
#
# Scenarios C and D are NEGATIVE CONTROLS: they document the limits of
# DT_NEEDED-based detection for your CRA evidence file. If Gullwing/Moabi
# claims to see them, great — you have proof. If not, you have proof of the
# documented limitation, and know to pair with `syft dir:` / static analysis.
# ============================================================================
set -euo pipefail

ROOT=${1:-/tmp/moabi_scenarios}
rm -rf "$ROOT"; mkdir -p "$ROOT"
SRC=$(mktemp -d); trap 'rm -rf "$SRC"' EXIT

cat > "$SRC/app.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("app"); return 0; }
EOF

report() {  # <dir> <label> <expectation>
    echo "----------------------------------------------------------------"
    echo "[$2]  $1"
    echo "  expected: $3"
    echo "  ground truth (readelf -d | NEEDED):"
    readelf -d "$1/app" 2>/dev/null | grep NEEDED | sed 's/^/    /' \
        || echo "    (no NEEDED entries)"
}

# --- A. baseline ------------------------------------------------------------
mkdir -p "$ROOT/A_baseline"
gcc "$SRC/app.c" -o "$ROOT/A_baseline/app"
report "$ROOT/A_baseline" "A baseline" "libc only"

# --- B. added dependency via DT_NEEDED (real libcurl if possible) -----------
mkdir -p "$ROOT/B_added_dt_needed"
if echo '#include <curl/curl.h>' | gcc -E -x c - >/dev/null 2>&1; then
    cat > "$SRC/app_b.c" <<'EOF'
#include <stdio.h>
#include <curl/curl.h>
int main(void) {
    curl_version_info_data *v = curl_version_info(CURLVERSION_NOW);
    printf("app, curl %s\n", v ? v->version : "?");
    return 0;
}
EOF
    gcc "$SRC/app_b.c" -o "$ROOT/B_added_dt_needed/app" -lcurl
    L="libcurl"
else
    echo "[warn] libcurl headers absent -> dummy-lib fallback for scenario B"
    echo 'void moabi_probe(void){}' > "$SRC/probe.c"
    cat > "$SRC/app_b.c" <<'EOF'
#include <stdio.h>
extern void moabi_probe(void);
int main(void) { moabi_probe(); puts("app"); return 0; }
EOF
    gcc -shared -fPIC "$SRC/probe.c" -o "$ROOT/B_added_dt_needed/libprobe.so"
    gcc "$SRC/app_b.c" -o "$ROOT/B_added_dt_needed/app" \
        -L"$ROOT/B_added_dt_needed" -lprobe -Wl,-rpath,'$ORIGIN'
    L="libprobe"
fi
report "$ROOT/B_added_dt_needed" "B added DT_NEEDED" "new $L entry -> DETECTED"

# --- C. dlopen shadow dependency (invisible to DT_NEEDED) --------------------
mkdir -p "$ROOT/C_dlopen_shadow"
echo 'void shadow_probe(void){}' > "$SRC/shadow.c"
cat > "$SRC/app_c.c" <<'EOF'
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("./libshadow.so", RTLD_NOW);
    if (h) { void (*f)(void) = (void(*)(void))dlsym(h, "shadow_probe");
             if (f) f(); dlclose(h); }
    puts("app"); return 0;
}
EOF
gcc -shared -fPIC "$SRC/shadow.c" -o "$ROOT/C_dlopen_shadow/libshadow.so"
gcc "$SRC/app_c.c" -o "$ROOT/C_dlopen_shadow/app" -ldl
report "$ROOT/C_dlopen_shadow" "C dlopen shadow" \
       "libshadow ABSENT from DT_NEEDED -> blind-spot probe"

# --- D. static binary (zero DT_NEEDED entries) -------------------------------
mkdir -p "$ROOT/D_static"
if gcc -static "$SRC/app.c" -o "$ROOT/D_static/app" 2>/dev/null; then
    report "$ROOT/D_static" "D static" "no NEEDED entries -> blind-spot probe"
else
    echo "[skip] static libc not available on this host (scenario D)"
fi

# --- Integrity: hashes must all differ between A and B -----------------------
HA=$(sha256sum "$ROOT/A_baseline/app"       | awk '{print $1}')
HB=$(sha256sum "$ROOT/B_added_dt_needed/app" | awk '{print $1}')
[ "$HA" != "$HB" ] || { echo "[FAIL] A and B identical"; exit 1; }

echo "================================================================"
echo "Fixtures ready in $ROOT"
echo
echo "Run each directory through moabi-delta / Gullwing, then score:"
echo "  B  -> should appear in the dependency delta"
echo "  C  -> expected MISS (DT_NEEDED can't see dlopen)."
echo "        If missed: cite as documented limitation; verify with"
echo "        'syft dir:' + 'strings app | grep libshadow'"
echo "  D  -> expected 0 relationships. Same remediation: pair with syft."
echo
echo "Keep the readelf ground-truth output next to each report for the"
echo "CRA technical documentation."
