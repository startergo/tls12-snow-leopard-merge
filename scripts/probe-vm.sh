#!/usr/bin/env bash
# probe-vm.sh — Understand the Snow Leopard Security framework structure
# and figure out how to inject our patched libsecurity_ssl.dylib

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

ssh $SSH_OPTS "$VM_HOST" '
echo "=== Security dylib link chain ==="
otool -L /System/Library/Frameworks/Security.framework/Security | head -30

echo ""
echo "=== Does Security export SSLHandshake? ==="
nm -g /System/Library/Frameworks/Security.framework/Security 2>/dev/null | grep -E "SSLHandshake|SSLConnect|SSLNewContext" | head -10

echo ""
echo "=== Does Security export _Ssl3Callouts / _Tls1Callouts? ==="
nm -g /System/Library/Frameworks/Security.framework/Security 2>/dev/null | grep -E "Callouts" | head -10

echo ""
echo "=== Shared cache — is Security in it? ==="
# update_dyld_shared_cache puts stuff in the cache; check if Security is listed
if [ -f /var/db/dyld/dyld_shared_cache_x86_64.map ]; then
    grep -c "Security.framework" /var/db/dyld/dyld_shared_cache_x86_64.map || echo "0 matches"
else
    echo "no map file"
fi

echo ""
echo "=== DYLD environment variable support ==="
# On SL, DYLD_INSERT_LIBRARIES works for non-SIP processes (SIP doesnt exist)
/usr/bin/env | grep -i dyld || echo "(no DYLD vars set)"

echo ""
echo "=== curl links against Security? ==="
otool -L /usr/bin/curl | grep -i security

echo ""
echo "=== OS version detail ==="
sw_vers
'
