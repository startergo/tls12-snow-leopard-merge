#!/usr/bin/env bash
# extract-and-relink.sh
#
# Strategy:
#   1. Copy the dyld shared cache from the VM to the Mac host
#   2. Use dyld_shared_cache_util (macOS host tool) to extract Security.dylib
#   3. Use ld -r + nm to identify and remove the libsecurity_ssl object
#      contributions from the extracted Security binary
#   4. Link a new Security.dylib = (Security - ssl_objects) + our patched ssl objects
#   5. Deploy back to VM + rebuild shared cache
#
# This script handles steps 1-2 (extraction). Run on the Mac host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

WORK="$ROOT/build/relink-security"
CACHE_LOCAL="$WORK/dyld_shared_cache_x86_64"
VM_CACHE="/var/db/dyld/dyld_shared_cache_x86_64"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

mkdir -p "$WORK"

# ── Step 1: copy cache from VM ─────────────────────────────────────────────
echo "Step 1: Copy dyld shared cache from VM..."
echo "  (this is ~100-200 MB, may take a minute over UTM shared network)"
if [ ! -f "$CACHE_LOCAL" ]; then
    scp $SSH_OPTS "${VM_HOST}:${VM_CACHE}" "$CACHE_LOCAL"
    ok "Cache copied → $CACHE_LOCAL"
else
    ok "Cache already present ($(du -sh "$CACHE_LOCAL" | cut -f1))"
fi

# ── Step 2: extract Security.dylib using host dyld tools ───────────────────
echo ""
echo "Step 2: Extract Security.dylib from shared cache..."

# Try dyld_shared_cache_util (present on macOS 11+)
# Try dsc_extractor (present as part of LLDB/Xcode)
# Try dyldinfo (present on macOS host as well)

SECURITY_OUT="$WORK/Security.dylib.extracted"

if command -v dyld_shared_cache_util &>/dev/null; then
    echo "  Using dyld_shared_cache_util..."
    EXTRACT_DIR="$WORK/cache_extract"
    mkdir -p "$EXTRACT_DIR"
    dyld_shared_cache_util -extract "$EXTRACT_DIR" "$CACHE_LOCAL" 2>&1 | grep -i security || true
    # Find the extracted Security
    FOUND=$(find "$EXTRACT_DIR" -name "Security" -path "*/Security.framework/*" 2>/dev/null | head -1)
    if [ -n "$FOUND" ]; then
        cp "$FOUND" "$SECURITY_OUT"
        ok "Extracted via dyld_shared_cache_util → $SECURITY_OUT"
    else
        warn "dyld_shared_cache_util ran but Security not found in output"
    fi
fi

if [ ! -f "$SECURITY_OUT" ]; then
    # Try dsc_extractor (ships with Xcode, path varies)
    DSC_EXTRACTOR=$(find /Applications/Xcode*.app -name "dsc_extractor" 2>/dev/null | head -1)
    if [ -n "$DSC_EXTRACTOR" ]; then
        echo "  Using dsc_extractor at $DSC_EXTRACTOR..."
        EXTRACT_DIR="$WORK/cache_extract_dsc"
        mkdir -p "$EXTRACT_DIR"
        "$DSC_EXTRACTOR" "$CACHE_LOCAL" "$EXTRACT_DIR" 2>&1 | tail -5
        FOUND=$(find "$EXTRACT_DIR" -name "Security" -path "*/Security.framework/*" 2>/dev/null | head -1)
        if [ -n "$FOUND" ]; then
            cp "$FOUND" "$SECURITY_OUT"
            ok "Extracted via dsc_extractor → $SECURITY_OUT"
        fi
    fi
fi

if [ ! -f "$SECURITY_OUT" ]; then
    warn "Could not auto-extract. Trying direct copy from VM (non-cache version)..."
    # The on-disk file is the pre-cache version — try it directly
    scp $SSH_OPTS "${VM_HOST}:/System/Library/Frameworks/Security.framework/Versions/A/Security" \
        "$SECURITY_OUT" 2>/dev/null || true
    if [ -f "$SECURITY_OUT" ]; then
        echo "  Copied on-disk Security (may be cache-modified stub)"
        file "$SECURITY_OUT"
    fi
fi

if [ ! -f "$SECURITY_OUT" ]; then
    die "Could not obtain Security binary. Try: bash scripts/extract-cache-on-vm.sh"
fi

# ── Step 3: Analyse what SSL symbols are present ──────────────────────────
echo ""
echo "Step 3: Analyse SSL symbols in extracted Security..."
echo ""
echo "SSL public API symbols:"
nm -g "$SECURITY_OUT" 2>/dev/null | grep -E "T _SSL" | head -20
echo ""
echo "Binary size: $(du -sh "$SECURITY_OUT" | cut -f1)"
echo "Arch: $(lipo -info "$SECURITY_OUT" 2>/dev/null || file "$SECURITY_OUT")"
