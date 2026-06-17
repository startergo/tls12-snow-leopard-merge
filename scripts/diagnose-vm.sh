#!/usr/bin/env bash
# diagnose-vm.sh — Step-by-step diagnosis of TLS test failures

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

ssh_run() { ssh $SSH_OPTS "$VM_HOST" "$@"; }

echo "=== 1. What SSL library does curl link against? ==="
ssh_run "otool -L /usr/bin/curl"

echo ""
echo "=== 2. Does curl even exist and work? ==="
ssh_run "curl --version 2>&1 | head -4"

echo ""
echo "=== 3. Basic HTTP (no TLS) — is curl/network working? ==="
ssh_run "env -i HOME=/Users/sl PATH=/usr/bin:/bin curl -sv --max-time 10 http://example.com/ 2>&1 | head -20"

echo ""
echo "=== 4. Does DYLD_INSERT_LIBRARIES load at all? ==="
# Use a simple binary that prints and exits — if it crashes with our dylib inserted,
# we'll see the error. Use /bin/ls as the guinea pig.
ssh_run "
DYLD_FORCE_FLAT_NAMESPACE=1 \
DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib \
DYLD_PRINT_LIBRARIES=1 \
/bin/ls /tmp/libsecurity_ssl_tls12.dylib 2>&1 | head -20
"

echo ""
echo "=== 5. Direct TLS test without DYLD — what version does stock curl get? ==="
ssh_run "env -i HOME=/Users/sl PATH=/usr/bin:/bin curl -s --max-time 15 'https://www.howsmyssl.com/a/check' 2>/dev/null | python -c 'import sys,json; d=json.load(sys.stdin); print d[\"tls_version\"]' 2>/dev/null || echo 'failed or no python json'"

echo ""
echo "=== 6. What is the actual curl error on TLS 1.2 sites? ==="
ssh_run "env -i HOME=/Users/sl PATH=/usr/bin:/bin curl -v --max-time 15 https://tls12.badssl.com/ 2>&1 | tail -20"

echo ""
echo "=== 7. Network connectivity — can VM reach external hosts? ==="
ssh_run "env -i HOME=/Users/sl PATH=/usr/bin:/bin curl -sv --max-time 10 http://neverssl.com/ 2>&1 | grep -E 'Connected|HTTP|curl|Failed' | head -10"
