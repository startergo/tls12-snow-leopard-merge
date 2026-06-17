#!/usr/bin/env bash
# test-securetransport.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=4 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }

ssh_run() { ssh $SSH_OPTS "$VM_HOST" "$@"; }

# ── Compile ───────────────────────────────────────────────────────────────
echo "=== Compiling ssltest on VM ==="
scp $SSH_OPTS "$ROOT/sources/ssltest.c" "${VM_HOST}:/tmp/ssltest.c"
ssh_run 'gcc -std=c99 -o /tmp/ssltest /tmp/ssltest.c \
    -framework Security -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 && echo "Compile OK"'
ok "ssltest compiled (has ${OVERALL_TIMEOUT_SEC:-20}s alarm + non-blocking connect)"

BASE_ENV='env -i HOME=/Users/sl PATH=/usr/bin:/bin'
DYLD_ENV='DYLD_SHARED_REGION=avoid DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib'

# run_ssltest <label> <dyld_env_or_empty> <host>
run_ssltest() {
    local label="$1" extra="$2" host="$3"
    printf "  %-10s %-28s  " "$label" "$host"
    # SSH timeout via -o ConnectTimeout + ssltest's own alarm(20)
    local out
    out=$(ssh $SSH_OPTS "$VM_HOST" "$BASE_ENV $extra /tmp/ssltest $host 443 2>&1" || true)
    local proto cipher http verdict
    proto=$(  echo "$out" | awk -F': ' '/Negotiated protocol/{print $2}')
    cipher=$( echo "$out" | awk -F': ' '/Negotiated cipher/{print $2}')
    http=$(   echo "$out" | awk -F': ' '/HTTP response/{print $2}')
    verdict=$(echo "$out" | grep -E 'SUCCESS|PARTIAL|FALLBACK|TIMEOUT|failed' | head -1)
    printf "%-18s  cipher=%-6s  http=%-12s  %s\n" \
        "${proto:-FAILED/TIMEOUT}" "${cipher:--}" "${http:--}" "${verdict:-}"
}

echo ""
echo "=== BASELINE: stock Security.framework ==="
run_ssltest "stock" "" "www.howsmyssl.com"
run_ssltest "stock" "" "tls12.badssl.com"
run_ssltest "stock" "" "tls10.badssl.com"

echo ""
echo "=== PATCHED: libsecurity_ssl_tls12.dylib injected ==="
run_ssltest "patched" "$DYLD_ENV" "www.howsmyssl.com"
run_ssltest "patched" "$DYLD_ENV" "tls12.badssl.com"
run_ssltest "patched" "$DYLD_ENV" "tls10.badssl.com"

echo ""
echo "=== VERBOSE: patched run → www.howsmyssl.com ==="
ssh_run "$BASE_ENV $DYLD_ENV /tmp/ssltest www.howsmyssl.com 443 2>&1" || true
