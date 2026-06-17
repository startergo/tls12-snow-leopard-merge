#!/usr/bin/env bash
# check-ciphersuite-constants.sh — verify which SHA-256 cipher constants exist
grep -n "SHA256\|0x003C\|0x003D\|0xC027\|0xC02B\|0xC02F" \
    /Users/macbookpro/tls12-snow-leopard-merge/sdk/MacOSX10.6.sdk/System/Library/Frameworks/Security.framework/Versions/A/Headers/CipherSuite.h \
    2>/dev/null | head -30 || echo "not found in SDK"

echo ""
echo "=== Local CipherSuite.h in source tree ==="
grep -n "SHA256\|0x003C\|0x003D\|0xC027\|0xC02B\|0xC02F" \
    /Users/macbookpro/tls12-snow-leopard-merge/sources/libsecurity_ssl-55002/lib/CipherSuite.h \
    2>/dev/null | head -30 || echo "not found in source"
