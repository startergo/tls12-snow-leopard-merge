#!/usr/bin/env bash
# post-setup.sh — Wire include paths after setup.sh has run.
#
# Creates symlinks so angle-bracket includes resolve correctly:
#
#   <security_asn1/foo.h>   → libsecurity_asn1-55000.2/lib/foo.h
#   <Security/foo.h>        → libsecurity_asn1-55000.2/lib/foo.h  (for asn1 SPI headers)
#   <Security/fooPriv.h>    → libsecurity_keychain-55017/lib/fooPriv.h
#   <Security/keyTemplates.h> → libsecurity_asn1-55000.2/lib/keyTemplates.h
#
# CRITICAL: Only non-SDK headers are symlinked into stubs/Security/.
# Public Security headers already in the 10.6 SDK (SecTrust.h, SecAccess.h,
# SecCertificate.h, etc.) must resolve from the SDK, not from our sources.
# The SDK check below enforces this — we only link a header if the SDK
# does NOT already provide it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
STUBS="$ROOT/stubs"
SRC="$ROOT/sources"
SDK="$ROOT/sdk/MacOSX10.6.sdk/System/Library/Frameworks/Security.framework/Headers"

GREEN='\033[0;32m'; NC='\033[0m'
ok() { echo -e "${GREEN}✓ $*${NC}"; }

KCHAIN_LIB="$SRC/libsecurity_keychain-55017/lib"
ASN1_LIB="$SRC/libsecurity_asn1-55000.2/lib"

[ -d "$KCHAIN_LIB" ] || { echo "libsecurity_keychain-55017 not found — run setup.sh"; exit 1; }
[ -d "$ASN1_LIB" ]   || { echo "libsecurity_asn1-55000.2 not found — run setup.sh"; exit 1; }
[ -d "$SDK" ]         || { echo "10.6 SDK not found — run setup.sh"; exit 1; }

# Remove stale symlinks from any previous wrong-version runs
echo "Cleaning stale symlinks …"
CLEANED=0
for dir in "$STUBS/Security" "$STUBS/security_asn1"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' f; do
        [ -L "$f" ] || continue
        target="$(readlink "$f")"
        if echo "$target" | grep -qE "libsecurity_keychain-(55050|37184)|Security-55002"; then
            rm "$f"
            CLEANED=$((CLEANED + 1))
        fi
    done < <(find "$dir" -maxdepth 1 -name "*.h" -print0)
done
ok "Cleaned $CLEANED stale symlinks"

# ── security_asn1/ ────────────────────────────────────────────────────────────
# Resolves: <security_asn1/nssUtils.h>, <security_asn1/secasn1.h>, etc.
mkdir -p "$STUBS/security_asn1"
COUNT=0
while IFS= read -r -d '' f; do
    dest="$STUBS/security_asn1/$(basename "$f")"
    if [ ! -e "$dest" ]; then
        ln -s "$f" "$dest"
        COUNT=$((COUNT + 1))
    fi
done < <(find "$ASN1_LIB" -maxdepth 1 -name "*.h" -print0)
ok "security_asn1/: $COUNT headers linked (libsecurity_asn1-55000.2)"

# ── stubs/Security/ ───────────────────────────────────────────────────────────
mkdir -p "$STUBS/Security"

# 1. libsecurity_asn1 headers that are included as <Security/foo.h> but are
#    NOT in the 10.6 SDK (e.g. secasn1t.h, x509defs.h, keyTemplates.h, etc.)
#    We check the SDK first — if it already has the header, skip it.
ASN1_COUNT=0
SDK_SKIP=0
while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    dest="$STUBS/Security/$base"
    if [ -e "$dest" ]; then
        continue   # already linked (e.g. from a previous run)
    fi
    if [ -f "$SDK/$base" ]; then
        SDK_SKIP=$((SDK_SKIP + 1))
        continue   # SDK already has it — let the SDK version win
    fi
    ln -s "$f" "$dest"
    ASN1_COUNT=$((ASN1_COUNT + 1))
done < <(find "$ASN1_LIB" -maxdepth 1 -name "*.h" -print0)
ok "Security/ (asn1 SPI): $ASN1_COUNT linked, $SDK_SKIP already in SDK"

# 2. libsecurity_keychain *Priv.h headers — declarations for private APIs
#    whose implementations live in the system Security.framework at runtime.
#    Again: only if the SDK doesn't already have them (it won't for *Priv.h).
PRIV_COUNT=0
while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    dest="$STUBS/Security/$base"
    if [ ! -e "$dest" ]; then
        ln -s "$f" "$dest"
        echo "  linked Security/$base"
        PRIV_COUNT=$((PRIV_COUNT + 1))
    fi
done < <(find "$KCHAIN_LIB" -maxdepth 1 -name "*Priv.h" -print0)
ok "Security/*Priv.h: $PRIV_COUNT linked (libsecurity_keychain-55017)"

echo ""
echo "stubs/Security/ symlink count: $(find "$STUBS/Security" -maxdepth 1 -name "*.h" -type l | wc -l | tr -d ' ')"
echo "stubs/security_asn1/ header count: $(find "$STUBS/security_asn1" -maxdepth 1 -name "*.h" | wc -l | tr -d ' ')"
echo ""
ok "Post-setup complete — ready to build"
echo "  Next: bash scripts/build-libsecurity-ssl.sh"
