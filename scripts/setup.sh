#!/usr/bin/env bash
# setup.sh — TLS 1.2 Snow Leopard project bootstrap
#
# Apple open-source sub-projects (all 10.6.8 / Security-55002 era):
#
#   libsecurity_ssl-55002        — primary merge target
#   libsecurity_asn1-55000.2     — keyTemplates.h, secasn1.h, nssUtils.h
#   libsecurity_keychain-55017   — SecCertificatePriv.h, SecTrustSettingsPriv.h
#                                  Version confirmed from:
#                                  opensource.apple.com/source/libsecurity_keychain/
#                                  libsecurity_keychain-55017/ (same 55xxx era as
#                                  libsecurity_ssl-55002; both ship with 10.6.8)
#
# Reference files:
#   Patches_Security-55002_4   — Leopard TLS 1.2 patch
#   Security.framework         — Leopard compiled binary
#   MacOSX10.6.sdk             — cross-compile SDK

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
DL="$ROOT/downloads"
SRC="$ROOT/sources"
PAT="$ROOT/patches"
SDK="$ROOT/sdk"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
skip() { echo -e "${YELLOW}⊘ $* (already present)${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

dl_apple() {
    local tarball="$1" project="$2"
    if [ ! -f "$DL/$tarball" ]; then
        if [ -f "$HOME/Downloads/$tarball" ]; then
            echo "  Found $tarball in ~/Downloads — copying…"
            cp "$HOME/Downloads/$tarball" "$DL/$tarball"
        else
            echo "  Downloading $tarball …"
            curl -fL --progress-bar \
                "https://opensource.apple.com/tarballs/$project/$tarball" \
                -o "$DL/$tarball" \
                || die "Failed: https://opensource.apple.com/tarballs/$project/$tarball"
        fi
        ok "$tarball"
    else
        skip "$tarball"
    fi
}

extract_apple_gz() {
    local tarball="$1" destname="$2"
    if [ ! -d "$SRC/$destname" ]; then
        echo "  Extracting $tarball …"
        tar -xzf "$DL/$tarball" -C "$SRC/"
        if [ ! -d "$SRC/$destname" ]; then
            ACTUAL=$(find "$SRC" -maxdepth 1 -type d -name "*$destname*" \
                     | grep -v "^$SRC/$destname$" | head -1 || true)
            [ -n "$ACTUAL" ] && mv "$ACTUAL" "$SRC/$destname" \
                || die "Cannot locate extracted directory for $tarball"
        fi
        ok "$destname"
    else
        skip "$destname"
    fi
}

echo -e "${YELLOW}=== TLS 1.2 Snow Leopard — Project Setup ===${NC}"
echo "Project root: $ROOT"
echo ""
echo "── Downloading Apple open-source (10.6.8 / 55xxx era) ─────────"

dl_apple "libsecurity_ssl-55002.tar.gz"      "libsecurity_ssl"
dl_apple "libsecurity_asn1-55000.2.tar.gz"   "libsecurity_asn1"
dl_apple "libsecurity_keychain-55017.tar.gz" "libsecurity_keychain"

echo ""
echo "── Downloading reference files ────────────────────────────────"

if [ ! -f "$DL/Patches_Security-55002_4.tar.bz2" ]; then
    echo "  Downloading Leopard TLS 1.2 patches…"
    curl -fL --progress-bar \
        "https://sourceforge.net/projects/leopard-webkit/files/Security%20framework/Patches/Patches_Security-55002_4.tar.bz2/download" \
        -o "$DL/Patches_Security-55002_4.tar.bz2" || die "Download failed"
    ok "Patches_Security-55002_4.tar.bz2"
else
    skip "Patches_Security-55002_4.tar.bz2"
fi

if [ ! -f "$DL/Security.framework.tar.bz2" ]; then
    echo "  Downloading Leopard Security.framework (reference binary)…"
    curl -fL --progress-bar \
        "https://sourceforge.net/projects/leopard-webkit/files/Security%20framework/Leopard/Universal/Security.framework.tar.bz2/download" \
        -o "$DL/Security.framework.tar.bz2" || die "Download failed"
    ok "Security.framework.tar.bz2"
else
    skip "Security.framework.tar.bz2"
fi

if [ ! -f "$DL/MacOSX10.6.sdk.tar.xz" ]; then
    echo "  Downloading macOS 10.6 SDK…"
    curl -fL --progress-bar \
        "https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX10.6.sdk.tar.xz" \
        -o "$DL/MacOSX10.6.sdk.tar.xz" || die "Download failed"
    ok "MacOSX10.6.sdk.tar.xz"
else
    skip "MacOSX10.6.sdk.tar.xz"
fi

echo ""
echo "── Extracting ─────────────────────────────────────────────────"

extract_apple_gz "libsecurity_ssl-55002.tar.gz"      "libsecurity_ssl-55002"
extract_apple_gz "libsecurity_asn1-55000.2.tar.gz"   "libsecurity_asn1-55000.2"
extract_apple_gz "libsecurity_keychain-55017.tar.gz" "libsecurity_keychain-55017"

if [ ! -d "$PAT/Patches_Security-55002_4" ]; then
    echo "  Extracting patches…"
    tar -xjf "$DL/Patches_Security-55002_4.tar.bz2" -C "$PAT/"
    ok "Patches_Security-55002_4"
else
    skip "Patches_Security-55002_4"
fi

if [ ! -d "$SRC/Security.framework" ]; then
    echo "  Extracting Security.framework…"
    tar -xjf "$DL/Security.framework.tar.bz2" -C "$SRC/"
    ok "Security.framework"
else
    skip "Security.framework"
fi

if [ ! -d "$SDK/MacOSX10.6.sdk" ]; then
    echo "  Extracting 10.6 SDK (large)…"
    tar -xJf "$DL/MacOSX10.6.sdk.tar.xz" -C "$SDK/"
    ok "MacOSX10.6.sdk"
else
    skip "MacOSX10.6.sdk"
fi

echo ""
echo "── Verification ───────────────────────────────────────────────"
echo ""

KCHAIN_LIB="$SRC/libsecurity_keychain-55017/lib"
[ -f "$SDK/MacOSX10.6.sdk/usr/include/stdio.h" ] \
    && ok "10.6 SDK valid" || die "SDK not valid"
[ -f "$KCHAIN_LIB/SecCertificatePriv.h" ] \
    && ok "SecCertificatePriv.h found (libsecurity_keychain-55017)" \
    || die "SecCertificatePriv.h missing"
[ -f "$KCHAIN_LIB/SecTrustSettingsPriv.h" ] \
    && ok "SecTrustSettingsPriv.h found (libsecurity_keychain-55017)" \
    || die "SecTrustSettingsPriv.h missing"

echo ""
ok "Setup complete"
echo ""
echo "Next: bash scripts/post-setup.sh"
echo "Then: bash scripts/build-libsecurity-ssl.sh"
