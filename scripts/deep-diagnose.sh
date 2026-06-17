#!/usr/bin/env bash
# deep-diagnose.sh — Figure out exactly what's happening with the TLS negotiation

set -euo pipefail

VM_HOST="sl@slqemu.local"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=4 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

ssh_run() { ssh $SSH_OPTS "$VM_HOST" "$@"; }

BASE_ENV='env -i HOME=/Users/sl PATH=/usr/bin:/bin'
DYLD_ENV='DYLD_SHARED_REGION=avoid DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=/tmp/libsecurity_ssl_tls12.dylib'

echo "=== 1. Verify DYLD is actually routing through our SSLNewContext ==="
echo "    (Check if our patched dylib's symbol is resolved first)"
ssh_run "$BASE_ENV $DYLD_ENV DYLD_PRINT_LIBRARIES=1 /tmp/ssltest www.howsmyssl.com 443 2>&1 | head -5" || true

echo ""
echo "=== 2. What cipher suites does the patched dylib advertise? ==="
echo "    (Dump enabled ciphers via SSLGetEnabledCiphers before handshake)"
echo "    Writing cipher-dump test program..."

# Write a tiny program that just prints the enabled cipher list and exits
cat > /tmp/cipherlist_src.c << 'CSRC'
#include <stdio.h>
#include <Security/SecureTransport.h>

/* SHA-256 suite IDs not in 10.6 SDK */
static const char* cipher_name(unsigned c) {
    switch(c) {
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
        case 0x006B: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
        case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        case 0xC023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
        case 0xC027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        default:     return "other";
    }
}
int main(void) {
    SSLContextRef ctx = NULL;
    OSStatus err = SSLNewContext(false, &ctx);
    if (err) { fprintf(stderr, "SSLNewContext: %d\n", (int)err); return 1; }

    size_t n = 0;
    SSLGetNumberEnabledCiphers(ctx, &n);
    printf("Enabled cipher count: %zu\n", n);

    unsigned short *cs = (unsigned short *)malloc(n * sizeof(unsigned short));
    SSLGetEnabledCiphers(ctx, (SSLCipherSuite *)cs, &n);
    unsigned i;
    for (i = 0; i < n && i < 20; i++) {
        printf("  [%02u] 0x%04X  %s\n", i, cs[i], cipher_name(cs[i]));
    }
    if (n > 20) printf("  ... (%zu more)\n", n - 20);
    free(cs);
    SSLDisposeContext(ctx);
    return 0;
}
CSRC

scp $SSH_OPTS /tmp/cipherlist_src.c "${VM_HOST}:/tmp/cipherlist.c"
ssh_run 'gcc -std=c99 -o /tmp/cipherlist /tmp/cipherlist.c \
    -framework Security -framework CoreFoundation \
    -mmacosx-version-min=10.6 -arch x86_64 && echo "compile ok"'

echo ""
echo "--- Stock cipher list (first 20): ---"
ssh_run "$BASE_ENV /tmp/cipherlist" || true

echo ""
echo "--- Patched cipher list (first 20): ---"
ssh_run "$BASE_ENV $DYLD_ENV /tmp/cipherlist" || true

echo ""
echo "=== 3. Is the patched SSLNewContext actually being called? ==="
echo "    (nm the injected dylib for SSLNewContext offset vs Security)"
ssh_run "nm -g /tmp/libsecurity_ssl_tls12.dylib | grep SSLNewContext" || true
ssh_run "nm -g /System/Library/Frameworks/Security.framework/Security | grep SSLNewContext" || true

echo ""
echo "=== 4. Raw openssl s_client to see what version server accepts ==="
ssh_run "$BASE_ENV openssl s_client -connect www.howsmyssl.com:443 -tls1_2 2>&1 | grep -E 'Protocol|Cipher|CONNECTED|error' | head -10" 2>/dev/null || \
ssh_run "which openssl && openssl version" 2>/dev/null || echo "openssl not available"

echo ""
echo "=== 5. Verbose handshake with DYLD_PRINT_APIS ==="
ssh_run "$BASE_ENV $DYLD_ENV DYLD_PRINT_APIS=1 /tmp/ssltest www.howsmyssl.com 443 2>&1 | grep -E 'SSL|TLS|tls|ssl' | head -20" || true
