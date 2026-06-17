#!/usr/bin/env bash
# relink-security.sh
#
# Relinks the Snow Leopard Security.framework dylib with our patched
# libsecurity_ssl objects substituted in.
#
# APPROACH:
#   The Snow Leopard Security dylib (55002) is a monolithic dylib containing
#   all libsecurity_* subcomponents statically linked together. We cannot
#   simply "subtract" object files from an existing dylib.
#
#   Instead we use a two-stage interposition approach:
#
#   Stage 1 — DYLD_INSERT_LIBRARIES interposition:
#     Our patched libsecurity_ssl.dylib exports the same public SSL symbols
#     as Security.framework (SSLHandshake, SSLNewContext, etc.). With
#     DYLD_INSERT_LIBRARIES, dyld resolves these symbols from our dylib
#     FIRST, before looking in Security.
#
#     PROBLEM: Two-level namespace. On 10.6, binaries record which dylib
#     a symbol comes from at link time. A binary linked against
#     Security.framework will look for _SSLHandshake in Security, not in
#     an inserted library. DYLD_INSERT_LIBRARIES only works for flat
#     namespace lookups.
#
#     WORKAROUND: DYLD_FORCE_FLAT_NAMESPACE=1 + DYLD_INSERT_LIBRARIES
#     This degrades to flat namespace lookup — expensive but functional
#     for testing. Not suitable for production.
#
#   Stage 2 — True relink (production path):
#     We need the object files for ALL other libsecurity_* subcomponents.
#     These exist on opensource.apple.com for the Security-55002 tag:
#       libsecurity_cdsa_client, libsecurity_cdsa_utilities,
#       libsecurity_cdsa_utils, libsecurity_cms, libsecurity_codesigning,
#       libsecurity_cssm, libsecurity_keychain, libsecurity_ldap,
#       libsecurity_manifest, libsecurity_mds, libsecurity_ocspd,
#       libsecurity_pkcs12, libsecurity_smime, libsecurity_ssl,
#       libsecurity_transform, libsecurity_utilities
#     Download, build each, link together with our patched ssl objects.
#     This script handles Stage 1 for immediate smoke testing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
PATCHED_DYLIB="$ROOT/build/libssl-patched/libsecurity_ssl.dylib"
SDK="$ROOT/sdk/MacOSX10.6.sdk"

VM_HOST="${VM_HOST:-sl@slqemu.local}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
if [ -f "$ROOT/config.sh" ]; then . "$ROOT/config.sh"; fi
VM_HOST="${VM_HOST:-sl@slqemu.local}"
VM_PASS="${VM_SUDO_PASS:-}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

[ -f "$PATCHED_DYLIB" ] || die "Patched dylib not found"

echo "=== Stage 1: DYLD interposition smoke test ==="
echo ""
echo "Deploying libsecurity_ssl.dylib to VM for interposition test..."

# Copy our dylib to the VM
scp $SSH_OPTS "$PATCHED_DYLIB" "${VM_HOST}:/tmp/libsecurity_ssl_tls12.dylib"
ok "Copied to VM /tmp/libsecurity_ssl_tls12.dylib"

echo ""
echo "Running TLS tests via DYLD_FORCE_FLAT_NAMESPACE + DYLD_INSERT_LIBRARIES..."
echo "(This forces flat namespace resolution so our SSL symbols shadow Security's)"
echo ""

# The test: run curl with flat namespace + our dylib inserted.
# env -i clears proxy vars. DYLD_SHARED_REGION=avoid forces on-disk dylibs.
# DYLD_FORCE_FLAT_NAMESPACE makes symbol lookup flat so inserts work.
# DYLD_INSERT_LIBRARIES points to our patched dylib.
TEST_ENV='env -i
    HOME=/Users/sl
    PATH=/usr/bin:/bin:/usr/local/bin
    DYLD_SHARED_REGION=avoid
    DYLD_FORCE_FLAT_NAMESPACE=1
    DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib'

echo "Test 1: howsmyssl.com (shows negotiated TLS version)"
RESULT=$(ssh $SSH_OPTS "$VM_HOST" \
    "$TEST_ENV curl -s --max-time 20 https://howsmyssl.com/a/check" 2>/dev/null || echo "FAILED")

if echo "$RESULT" | grep -q '"tls_version":"TLS 1.2"'; then
    ok "TLS 1.2 negotiated! Interposition is working."
    echo "    $(echo "$RESULT" | grep -o '"tls_version":"[^"]*"')"
elif echo "$RESULT" | grep -q "tls_version"; then
    warn "Connected — version:"
    echo "    $(echo "$RESULT" | grep -o '"tls_version":"[^"]*"')"
    echo ""
    echo "    → Our SSL code is running but falling back. Check cipher suite availability."
else
    warn "Failed or no response: ${RESULT:0:200}"
    echo ""
    echo "    → Interposition may not be working. Try the direct install path."
fi

echo ""
echo "Test 2: tls12.badssl.com"
HTTP12=$(ssh $SSH_OPTS "$VM_HOST" \
    "$TEST_ENV curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://tls12.badssl.com/" \
    2>/dev/null || echo "000")
[ "$HTTP12" = "200" ] && ok "HTTP 200 — TLS 1.2 success" || warn "Got: HTTP $HTTP12"

echo ""
echo "Test 3: tls10.badssl.com (regression)"
HTTP10=$(ssh $SSH_OPTS "$VM_HOST" \
    "$TEST_ENV curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://tls10.badssl.com/" \
    2>/dev/null || echo "000")
[ "$HTTP10" = "200" ] && ok "HTTP 200 — TLS 1.0 still works" || warn "Got: HTTP $HTTP10"

echo ""
echo "=== Stage 1 complete ==="
echo ""
echo "If tests pass above, proceed to Stage 2 (full Security relink) with:"
echo "  bash scripts/build-full-security.sh"
echo ""
echo "Stage 2 downloads and builds all libsecurity_* subcomponents for Security-55002"
echo "and relinks them into a monolithic Security dylib with our TLS 1.2 SSL objects."
