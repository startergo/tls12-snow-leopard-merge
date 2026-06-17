#!/usr/bin/env bash
# inspect-security-dylib.sh — Understand what subcomponents are baked into
# the Snow Leopard monolithic Security.framework dylib, and what we need to
# source to relink it with our patched libsecurity_ssl objects.

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

SECURITY="/System/Library/Frameworks/Security.framework/Versions/A/Security"

ssh $SSH_OPTS "$VM_HOST" "
echo '=== Security version string ==='
what '$SECURITY' 2>/dev/null | head -20 || strings '$SECURITY' | grep -E '^@\(#\)' | head -20

echo ''
echo '=== Subcomponent library names visible in strings ==='
strings '$SECURITY' | grep -E 'libsecurity_' | sort -u | head -40

echo ''
echo '=== Total exported symbol count ==='
nm -g '$SECURITY' 2>/dev/null | grep ' T ' | wc -l

echo ''
echo '=== SSL-related exported symbols ==='
nm -g '$SECURITY' 2>/dev/null | grep -i 'SSL\|SecureTransport\|TLS' | head -40

echo ''
echo '=== dyld shared cache — can we extract Security from it? ==='
# dyld_shared_cache_util or dyld_info might be available
which dyld_shared_cache_util 2>/dev/null || echo 'no dyld_shared_cache_util'
which dyld_info 2>/dev/null || echo 'no dyld_info'
ls /usr/bin/dyld* 2>/dev/null || echo 'no dyld tools in /usr/bin'

echo ''
echo '=== update_dyld_shared_cache location ==='
which update_dyld_shared_cache 2>/dev/null || ls /usr/sbin/update_dyld_shared_cache 2>/dev/null || echo 'not found'

echo ''
echo '=== Can we invalidate the cache by touching the binary? ==='
# On 10.6, booting with DYLD_SHARED_REGION=avoid bypasses the cache
# Check if that env var works
echo 'DYLD_SHARED_REGION=avoid is the key env var on 10.6'
"
