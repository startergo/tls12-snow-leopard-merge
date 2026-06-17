#!/usr/bin/env bash
# compile-ssltest-flat.sh
# Compile ssltest on the VM linking DIRECTLY against our patched dylib
# instead of Security.framework, using -flat_namespace so all SSL
# symbols resolve from our dylib rather than the system Security.

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=4 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

BASE_ENV='env -i HOME=/Users/sl PATH=/usr/bin:/bin'

echo "=== Compiling ssltest_patched — linked directly against patched dylib ==="

# Strategy: link against our patched dylib as the SSL provider.
# -flat_namespace: flat symbol lookup (no two-level namespace)
# -undefined suppress: allow missing symbols (ones not in our dylib)
# The patched dylib re-exports Security.framework via -framework Security
# at link time, so Security symbols resolve through that chain.
#
# Simpler approach: compile with -flat_namespace and use 
# DYLD_INSERT_LIBRARIES at runtime. The key is -flat_namespace at
# COMPILE time for ssltest, not just at runtime.

scp $SSH_OPTS \
    "$(dirname "$0")/../sources/ssltest.c" \
    "${VM_HOST}:/tmp/ssltest.c"

ssh $SSH_OPTS "$VM_HOST" '
echo "--- Attempt 1: -flat_namespace compile ---"
gcc -std=c99 -flat_namespace -o /tmp/ssltest_flat /tmp/ssltest.c \
    -framework Security \
    -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 2>&1 && echo "Compiled OK (flat)" || echo "Failed"

echo ""
echo "--- Attempt 2: link directly against patched dylib ---"
# Use the patched dylib as a direct link dependency.
# It exports SSLNewContext, SSLHandshake, etc.
# It already links against Security.framework for CDSA symbols.
gcc -std=c99 -o /tmp/ssltest_direct /tmp/ssltest.c \
    /tmp/libsecurity_ssl_tls12.dylib \
    -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 \
    -Wl,-rpath,/tmp \
    2>&1 && echo "Compiled OK (direct)" || echo "Failed"

echo ""
echo "--- Check what ssltest_flat links against ---"
otool -L /tmp/ssltest_flat 2>/dev/null || echo "not built"

echo ""
echo "--- Check what ssltest_direct links against ---"
otool -L /tmp/ssltest_direct 2>/dev/null || echo "not built"
'

echo ""
echo "=== Running tests with flat-namespace binary ==="
echo "--- Stock (no insert) ---"
ssh $SSH_OPTS "$VM_HOST" \
    "$BASE_ENV /tmp/ssltest_flat www.howsmyssl.com 443 2>&1" || true

echo ""
echo "--- Patched (with insert) ---"
ssh $SSH_OPTS "$VM_HOST" \
    "$BASE_ENV DYLD_SHARED_REGION=avoid DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib /tmp/ssltest_flat www.howsmyssl.com 443 2>&1" || true

echo ""
echo "=== Running tests with direct-linked binary ==="
echo "--- Direct link (always uses our dylib) ---"
ssh $SSH_OPTS "$VM_HOST" \
    "$BASE_ENV /tmp/ssltest_direct www.howsmyssl.com 443 2>&1" || true

echo ""
echo "--- Direct vs tls10 ---"
ssh $SSH_OPTS "$VM_HOST" \
    "$BASE_ENV /tmp/ssltest_direct tls10.badssl.com 443 2>&1" || true
