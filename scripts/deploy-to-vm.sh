#!/usr/bin/env bash
# deploy-to-vm.sh — Copy the patched libsecurity_ssl.dylib into the Snow Leopard
# QEMU/UTM VM and run a quick TLS 1.2 smoke test.
#
# Usage:
#   bash scripts/deploy-to-vm.sh           # deploy + test
#   bash scripts/deploy-to-vm.sh --test-only  # test only (dylib already installed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
DYLIB="$ROOT/build/libssl-patched/libsecurity_ssl.dylib"

# Load local VM config (git-ignored). Copy config.sh.example -> config.sh.
if [ -f "$ROOT/config.sh" ]; then
    . "$ROOT/config.sh"
else
    echo "Missing $ROOT/config.sh — copy config.sh.example to config.sh and set VM_SUDO_PASS/VM_HOST" >&2
    exit 1
fi

VM_HOST="${VM_HOST:-sl@slqemu.local}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

VM_PASS="${VM_SUDO_PASS:?VM_SUDO_PASS not set in config.sh}"
# sudo wrapper: echo password to sudo -S, suppresses the password prompt
SUDO="echo ${VM_PASS} | sudo -S"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

ssh_run() { ssh $SSH_OPTS "$VM_HOST" "$@"; }
scp_put() { scp $SSH_OPTS "$1" "${VM_HOST}:$2"; }

# ─── Connectivity ─────────────────────────────────────────────────────────────
echo ""
echo "Checking VM connectivity..."
ssh_run "uname -sr" || die "Cannot reach $VM_HOST — is the VM running?"
ok "VM is up"

if [[ "${1:-}" != "--test-only" ]]; then

    # ─── Backup ───────────────────────────────────────────────────────────────
    [ -f "$DYLIB" ] || die "Patched dylib not found — run: bash scripts/build-libsecurity-ssl.sh --patched"
    echo ""
    echo "Backing up original libsecurity_ssl.dylib on VM..."
    ORIG="/System/Library/Frameworks/Security.framework/Versions/A/Libraries/libsecurity_ssl.dylib"
    BAK="/tmp/libsecurity_ssl.dylib.orig"
    ssh_run "
        if [ ! -f '$BAK' ]; then
            echo '${VM_PASS}' | sudo -S cp '$ORIG' '$BAK' && echo 'Backed up to $BAK'
        else
            echo 'Backup already exists at $BAK'
        fi
    "
    ok "Backup done"

    # ─── Copy ─────────────────────────────────────────────────────────────────
    echo ""
    echo "Copying patched dylib to VM /tmp/..."
    scp_put "$DYLIB" "/tmp/libsecurity_ssl_patched.dylib"
    ok "Copied"

    # ─── Install ──────────────────────────────────────────────────────────────
    echo ""
    echo "Installing patched dylib..."
    ssh_run "
        echo '${VM_PASS}' | sudo -S cp /tmp/libsecurity_ssl_patched.dylib '$ORIG'
        echo '${VM_PASS}' | sudo -S chmod 755 '$ORIG'
        echo 'Installed'
    "
    ok "Installed to $ORIG"

fi

# ─── Smoke tests ──────────────────────────────────────────────────────────────
# Use env -i to strip any proxy env vars (http_proxy, https_proxy, etc.)
# so curl goes direct — not through Squid — and the TLS handshake reaches
# the real server.
CURL_DIRECT="env -i HOME=/Users/sl PATH=/usr/bin:/bin:/usr/local/bin curl -s --max-time 20"

echo ""
echo "=== TLS 1.2 smoke tests (direct, bypassing proxy) ==="

# Test 1: howsmyssl — returns JSON with tls_version
echo ""
echo "Test 1: howsmyssl.com/a/check"
RESULT=$(ssh_run "$CURL_DIRECT https://howsmyssl.com/a/check" 2>/dev/null || echo "CURL_FAILED")
if echo "$RESULT" | grep -q '"tls_version":"TLS 1.2"'; then
    ok "TLS 1.2 negotiated!"
    echo "    $(echo "$RESULT" | grep -o '"tls_version":"[^"]*"')"
elif echo "$RESULT" | grep -q "tls_version"; then
    warn "Connected but NOT TLS 1.2:"
    echo "    $(echo "$RESULT" | grep -o '"tls_version":"[^"]*"')"
elif echo "$RESULT" | grep -q "CURL_FAILED"; then
    warn "curl failed (handshake error or network)"
else
    warn "Unexpected response: ${RESULT:0:120}"
fi

# Test 2: tls12.badssl.com — HTTP 200 only on TLS 1.2
echo ""
echo "Test 2: tls12.badssl.com (HTTP 200 = TLS 1.2 success)"
HTTP12=$(ssh_run "$CURL_DIRECT -o /dev/null -w '%{http_code}' https://tls12.badssl.com/" 2>/dev/null || echo "000")
if [ "$HTTP12" = "200" ]; then
    ok "HTTP 200 — TLS 1.2 handshake succeeded"
elif [ "$HTTP12" = "000" ]; then
    warn "curl failed (handshake error or network)"
else
    warn "HTTP $HTTP12 from tls12.badssl.com"
fi

# Test 3: tls10.badssl.com — regression: TLS 1.0 must still work
echo ""
echo "Test 3: tls10.badssl.com (regression — TLS 1.0 must still work)"
HTTP10=$(ssh_run "$CURL_DIRECT -o /dev/null -w '%{http_code}' https://tls10.badssl.com/" 2>/dev/null || echo "000")
if [ "$HTTP10" = "200" ]; then
    ok "HTTP 200 — TLS 1.0 still works (no regression)"
elif [ "$HTTP10" = "000" ]; then
    warn "curl failed on TLS 1.0 endpoint (possible regression)"
else
    warn "HTTP $HTTP10 from tls10.badssl.com"
fi

echo ""
echo "=== Done ==="
echo ""
echo "To restore original dylib:"
echo "  ssh $SSH_OPTS $VM_HOST \\"
echo "    \"echo ${VM_PASS} | sudo -S cp $BAK $ORIG\""
