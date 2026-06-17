#!/usr/bin/env bash
# find-ssl-dylib.sh — locate libsecurity_ssl.dylib on the Snow Leopard VM

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

ssh $SSH_OPTS "$VM_HOST" '
echo "=== find libsecurity_ssl.dylib ==="
find /System/Library/Frameworks/Security.framework -name "libsecurity_ssl*" 2>/dev/null
find /usr/lib -name "libsecurity_ssl*" 2>/dev/null
find /System/Library/PrivateFrameworks -name "libsecurity_ssl*" 2>/dev/null

echo ""
echo "=== Security.framework layout ==="
ls -la /System/Library/Frameworks/Security.framework/
ls -la /System/Library/Frameworks/Security.framework/Versions/A/ 2>/dev/null || true

echo ""
echo "=== what libsecurity_ssl.dylib the running Security links against ==="
otool -L /System/Library/Frameworks/Security.framework/Security 2>/dev/null | grep -i ssl || echo "(none)"

echo ""
echo "=== dyld shared cache check ==="
ls /var/db/dyld/ 2>/dev/null || echo "no dyld cache dir"
'
