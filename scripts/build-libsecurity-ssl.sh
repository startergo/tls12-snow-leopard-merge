#!/usr/bin/env bash
# build-libsecurity-ssl.sh — Compile libsecurity_ssl-55002 against 10.6 SDK
#
# Usage:
#   bash scripts/build-libsecurity-ssl.sh           # stock (baseline)
#   bash scripts/build-libsecurity-ssl.sh --patched # with TLS 1.2 changes applied

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
SDK="$ROOT/sdk/MacOSX10.6.sdk"
SRC="$ROOT/sources/libsecurity_ssl-55002/lib"
ASN1="$ROOT/sources/libsecurity_asn1-55000.2/lib"
KCHAIN="$ROOT/sources/libsecurity_keychain-55017/lib"
STUBS="$ROOT/stubs"
BUILD="$ROOT/build"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

PATCHED=0
[[ "${1:-}" == "--patched" ]] && PATCHED=1

echo -e "${YELLOW}=== Building libsecurity_ssl-55002 $([ $PATCHED -eq 1 ] && echo '[PATCHED — TLS 1.2]' || echo '[STOCK baseline]') ===${NC}"

[ -d "$SDK" ]    || die "SDK not found — run setup.sh"
[ -d "$SRC" ]    || die "libsecurity_ssl sources not found — run setup.sh"
[ -d "$ASN1" ]   || die "libsecurity_asn1 not found — run setup.sh"
[ -d "$KCHAIN" ] || die "libsecurity_keychain-55017 not found — run setup.sh"
[ -d "$STUBS/Security" ]      || die "stubs/Security/ not found — run post-setup.sh"
[ -d "$STUBS/security_asn1" ] || die "stubs/security_asn1/ not found — run post-setup.sh"
command -v clang >/dev/null    || die "clang not found"
ok "Preflight passed"

# ── Compiler flags ────────────────────────────────────────────────────────────
CFLAGS=(
    -arch x86_64
    -isysroot "$SDK"
    -mmacosx-version-min=10.6
    -target x86_64-apple-macos10.6
    -DNDEBUG -Os -g

    -I"$STUBS"
    -I"$SRC"
    -I"$ASN1"
    -I"$KCHAIN"
    -I"$SDK/System/Library/Frameworks/Security.framework/Headers"
    -I"$SDK/usr/include"

    -Wno-deprecated-declarations
    -Wno-unused-function
    -Wno-implicit-function-declaration
    -Wno-int-conversion
    -Wno-unused-variable
    -Wno-incompatible-pointer-types
    -Wno-pointer-sign
    -Wno-deprecated-non-prototype
    -Wno-enum-conversion
)

# Install name:
#   --patched  → absolute /tmp path so ssltest_direct can link against it directly
#   --stock    → @rpath for normal use
if [ $PATCHED -eq 1 ]; then
    INSTALL_NAME="/usr/local/lib/libsecurity_ssl_tls12.dylib"
else
    INSTALL_NAME="@rpath/libsecurity_ssl.dylib"
fi

LDFLAGS=(
    -arch x86_64
    -isysroot "$SDK"
    -mmacosx-version-min=10.6
    -target x86_64-apple-macos10.6
    -dynamiclib
    -install_name "$INSTALL_NAME"
    -F"$SDK/System/Library/Frameworks"
    -framework Security
    -framework CoreFoundation
)

# ── Files to skip permanently ─────────────────────────────────────────────────
SKIP_FILES=("securetransport++.cpp")

skip_file() {
    local f="$1" s
    for s in "${SKIP_FILES[@]}"; do
        [[ "$f" == "$s" ]] && return 0
    done
    return 1
}

# ── libsecurity_asn1 sources ──────────────────────────────────────────────────
ASN1_SOURCES=(
    "$ASN1/plarena.c"
    "$ASN1/nsprPortX.c"
    "$ASN1/secport.c"
    "$ASN1/secasn1d.c"
    "$ASN1/secasn1e.c"
    "$ASN1/secasn1u.c"
    "$ASN1/nssUtils.c"
    "$ASN1/keyTemplates.c"
)

# ── Build directory ───────────────────────────────────────────────────────────
BUILD_DIR="$BUILD/$([ $PATCHED -eq 1 ] && echo libssl-patched || echo libssl-stock)"
mkdir -p "$BUILD_DIR"

echo ""
echo "  Source:   $SRC"
echo "  ASN1:     $ASN1"
echo "  Keychain: $KCHAIN"
echo "  Output:   $BUILD_DIR"
echo ""

# ── Collect sources ───────────────────────────────────────────────────────────
SOURCES=()
while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    if skip_file "$base"; then
        echo "  [skip] $base"
    else
        SOURCES+=("$f")
    fi
done < <(find "$SRC" -maxdepth 1 \( -name "*.c" -o -name "*.cpp" \) -print0 | sort -z)

for f in "${ASN1_SOURCES[@]}"; do
    if [ -f "$f" ]; then
        SOURCES+=("$f")
    else
        warn "Missing ASN1 source: $f"
    fi
done

if [ $PATCHED -eq 1 ] && [ -f "$ROOT/docs/tls12Callouts.c" ]; then
    SOURCES+=("$ROOT/docs/tls12Callouts.c")
    ok "Added tls12Callouts.c"
fi

echo "Compiling ${#SOURCES[@]} source files…"

# ── Compile ───────────────────────────────────────────────────────────────────
OBJECTS=()
FAILED=0
for src in "${SOURCES[@]}"; do
    base="$(basename "$src" .c)"
    obj="$BUILD_DIR/$base.o"
    printf "  %-35s" "$base.c"
    if clang "${CFLAGS[@]}" -c "$src" -o "$obj" 2>"$BUILD_DIR/$base.err"; then
        echo "ok"
        OBJECTS+=("$obj")
    else
        echo -e "${RED}FAILED${NC}"
        cat "$BUILD_DIR/$base.err"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
[ $FAILED -gt 0 ] && warn "$FAILED file(s) failed"
ok "${#OBJECTS[@]} objects compiled"

# ── Link ──────────────────────────────────────────────────────────────────────
OUT="$BUILD_DIR/libsecurity_ssl.dylib"
echo ""
echo "Linking → $(basename "$OUT")"
clang "${LDFLAGS[@]}" "${OBJECTS[@]}" -o "$OUT" 2>&1 || die "Link failed"
ok "Linked: $OUT"

# ── Post-build checks ─────────────────────────────────────────────────────────
echo ""
lipo -info "$OUT"
echo ""
echo "TLS callout symbols:"
nm "$OUT" | grep -E "_Ssl3Callouts|_Tls1Callouts|_Tls12Callouts" | sort
echo ""
ok "Done → $OUT"
