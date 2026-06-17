#!/usr/bin/env bash
# compile-ssltest-direct.sh — Compile and run ssltest against our patched dylib directly

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=4 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

BASE_ENV='env -i HOME=/Users/sl PATH=/usr/bin:/bin'

echo "=== Step 1: Verify patched dylib install_name ==="
ssh $SSH_OPTS "$VM_HOST" "otool -L /tmp/libsecurity_ssl_tls12.dylib | head -3"

echo ""
echo "=== Step 2: Compile ssltest (direct link + system Security baseline) ==="
scp $SSH_OPTS "$ROOT/sources/ssltest.c" "${VM_HOST}:/tmp/ssltest.c"

ssh $SSH_OPTS "$VM_HOST" '
# Baseline binary: links against system Security.framework
gcc -std=c99 -o /tmp/ssltest_stock /tmp/ssltest.c \
    -framework Security -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 2>&1 && echo "stock: OK"

# Patched binary: links directly against our dylib
gcc -std=c99 -o /tmp/ssltest_direct /tmp/ssltest.c \
    /tmp/libsecurity_ssl_tls12.dylib \
    -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 2>&1 && echo "direct: OK"
'

run_test() {
    local label="$1" binary="$2" host="$3" prot="${4:-}"
    printf "\n--- %-10s %-28s prot=%-4s ---\n" "$label" "$host" "${prot:-default}"
    local cmd="$BASE_ENV $binary $host 443 $prot"
    ssh $SSH_OPTS "$VM_HOST" "$cmd 2>&1" || true
}

echo ""
echo "======================================================"
echo "STOCK (system Security.framework)"
echo "======================================================"
run_test "stock" "/tmp/ssltest_stock" "tls10.badssl.com"
run_test "stock" "/tmp/ssltest_stock" "www.howsmyssl.com"

echo ""
echo "======================================================"
echo "PATCHED (our libsecurity_ssl_tls12.dylib)"
echo "======================================================"
echo ""
echo "--- TLS 1.0 forced (enum=4, regression test) ---"
run_test "patched" "/tmp/ssltest_direct" "tls10.badssl.com" "4"

echo ""
echo "--- TLS 1.2 (default, howsmyssl) ---"
run_test "patched" "/tmp/ssltest_direct" "www.howsmyssl.com"

echo ""
echo "--- TLS 1.2 (default, tls12.badssl.com) ---"
run_test "patched" "/tmp/ssltest_direct" "tls12.badssl.com"

echo ""
echo "--- TLS 1.0 forced against howsmyssl (should downgrade) ---"
run_test "patched" "/tmp/ssltest_direct" "www.howsmyssl.com" "4"
