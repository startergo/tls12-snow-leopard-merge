#!/usr/bin/env bash
# wire-capture.sh — Capture the actual ClientHello bytes our patched dylib sends
# Uses tcpdump on the VM to capture the first few packets, then decodes them.

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=4 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

BASE_ENV='env -i HOME=/Users/sl PATH=/usr/bin:/bin:/usr/sbin:/sbin'
DYLD_ENV='DYLD_SHARED_REGION=avoid DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib'

echo "=== Capturing ClientHello from patched dylib ==="
echo "Running tcpdump in background, then ssltest, then decode..."

# Run tcpdump for 8 seconds capturing port 443 traffic, save to pcap
# Then run ssltest simultaneously
ssh $SSH_OPTS "$VM_HOST" "
    # Start tcpdump in background
    sudo -S tcpdump -i en0 -w /tmp/tls_capture.pcap -c 20 port 443 2>/dev/null &
    TCPDUMP_PID=\$!
    sleep 1

    # Run patched ssltest (will fail but we capture the ClientHello)
    $BASE_ENV $DYLD_ENV /tmp/ssltest www.howsmyssl.com 443 2>&1 || true

    sleep 1
    kill \$TCPDUMP_PID 2>/dev/null || true
    wait \$TCPDUMP_PID 2>/dev/null || true

    # Decode the capture - look for TLS ClientHello (content type 0x16, handshake 0x01)
    echo ''
    echo '=== Raw first TCP payload to port 443 ==='
    # Use strings/od to dump the pcap raw bytes looking for TLS records
    od -A x -t x1z /tmp/tls_capture.pcap 2>/dev/null | grep -A 4 '16 03' | head -40 || echo 'no TLS records found in capture'
" 2>/dev/null || true

echo ""
echo "=== Alternative: decode via openssl s_client from VM ==="
# Run openssl s_client which shows the cipher list being sent
ssh $SSH_OPTS "$VM_HOST" "
    $BASE_ENV openssl s_client -connect www.howsmyssl.com:443 \
        -servername www.howsmyssl.com \
        -cipher 'AES128-SHA256:AES256-SHA256' \
        -debug 2>&1 | grep -E 'cipher|Cipher|CONNECTED|Protocol|alert|error|SSL_connect' | head -20
" 2>/dev/null || echo "openssl test failed"

echo ""
echo "=== Check: does the server accept TLS 1.2 at all from stock openssl? ==="
ssh $SSH_OPTS "$VM_HOST" "
    $BASE_ENV openssl s_client -connect www.howsmyssl.com:443 \
        -servername www.howsmyssl.com 2>&1 | \
        grep -E 'Protocol|Cipher|CONNECTED|error' | head -10
" 2>/dev/null || echo "openssl s_client not available"
