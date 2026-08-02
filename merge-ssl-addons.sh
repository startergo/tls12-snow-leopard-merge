#!/usr/bin/env bash
# merge-ssl-addons.sh
#
# The libsecurity_ssl xcodeproj does NOT reference the TLS 1.2 AES-GCM sources
# (sslGcm.c, sslGcmAes.c, sslGcmCipher.c) nor the new TLS 1.2 callouts table
# (tls12Callouts.c, which lives in docs/, outside lib/). So a clean
# `xcodebuild` of libsecurity_ssl produces an archive WITHOUT these objects,
# and the monolith relink then fails with undefined:
#   _SSLCipherAES_128_GCM, _SSLCipherAES_256_GCM  (from cipherSpecs.o)
#   _Tls12Callouts                                (from sslHandshakeHello.o)
#
# This script compiles those add-on translation units on the VM with flags
# matching the xcodebuild recipe (gnu99, sl-compat-prefix.h forced-include,
# x86_64, 10.6 target, SecurityPieces header search paths) and merges the
# resulting objects into sym-ssl/security_ssl via `ar rcs`, reproducing how the
# original patched archive was assembled. Idempotent: re-running recompiles and
# re-merges (ar replaces same-named members).
#
# Run from the repository root with VM set (VM="$(pwd)"), or let it self-locate.

set -uo pipefail

VM_BUILD="${VM:-${VM_BUILD:-$(cd "$(dirname "$0")" && pwd)}}"
PIECES="/usr/local/SecurityPieces"
PREFIX="$VM_BUILD/sl-compat-prefix.h"
SSLSRC=$(ls -d "$VM_BUILD"/libsecurity_ssl-55002 2>/dev/null | head -1)
ARCHIVE="$VM_BUILD/sym-ssl/security_ssl"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}\xe2\x9c\x93 $*${NC}"; }
warn() { echo -e "${YELLOW}\xe2\x9a\xa0 $*${NC}"; }
die()  { echo -e "${RED}\xe2\x9c\x97 $*${NC}"; exit 1; }

echo "=== Merge TLS 1.2 GCM + callouts add-ons into sym-ssl/security_ssl ==="

[ -n "$SSLSRC" ]    || die "libsecurity_ssl source dir not found under $VM_BUILD"
[ -f "$ARCHIVE" ]   || die "archive not found: $ARCHIVE (build ssl first)"
[ -f "$PREFIX" ]    || die "compat prefix header not found: $PREFIX"

LIB="$SSLSRC/lib"

# The add-on translation units. tls12Callouts.c lives outside lib/ (in docs/ on
# the host); on the VM it was staged next to the ssl lib. Locate it flexibly.
ADDON_SRCS=(
    "$LIB/sslGcm.c"
    "$LIB/sslGcmAes.c"
    "$LIB/sslGcmCipher.c"
)
# tls12Callouts.c: prefer lib/, else docs/, else VM_BUILD root.
TLS12CO=""
for cand in "$LIB/tls12Callouts.c" "$SSLSRC/docs/tls12Callouts.c" \
            "$VM_BUILD/tls12Callouts.c" "$VM_BUILD/docs/tls12Callouts.c"; do
    [ -f "$cand" ] && { TLS12CO="$cand"; break; }
done
[ -n "$TLS12CO" ] || die "tls12Callouts.c not found (looked in lib/, docs/, $VM_BUILD)"
ADDON_SRCS+=("$TLS12CO")

# Compile flags mirroring the xcodebuild recipe used by vm-build-subproject.sh.
CFLAGS=(
    -arch x86_64
    -mmacosx-version-min=10.6
    -std=gnu99
    -DNDEBUG -Os -g
    -include "$PREFIX"
    -I"$LIB"
    -I"$PIECES/Headers"
    -I"$PIECES/PrivateHeaders"
    -I"$PIECES/Headers/security_asn1"
    -I"$PIECES/Headers/security_cdsa_utilities"
    -F"$PIECES/Frameworks"
    -F"$PIECES/Components/Security"
    -w
)

WORK="$VM_BUILD/ssl-addons"
rm -rf "$WORK"; mkdir -p "$WORK"

OBJS=()
echo ""
echo "1. Compiling ${#ADDON_SRCS[@]} add-on translation units..."
for src in "${ADDON_SRCS[@]}"; do
    base="$(basename "$src" .c)"
    obj="$WORK/$base.o"
    printf "   %-20s " "$base.c"
    if arch -x86_64 /usr/bin/gcc "${CFLAGS[@]}" -c "$src" -o "$obj" 2> "$WORK/$base.err"; then
        echo "ok"
        OBJS+=("$obj")
    else
        echo "FAILED"
        cat "$WORK/$base.err"
        die "compile failed for $base.c"
    fi
done
ok "compiled ${#OBJS[@]} objects"

echo ""
echo "2. Merging objects into archive (ar rcs)..."
arch -x86_64 /usr/bin/ar rcs "$ARCHIVE" "${OBJS[@]}" || die "ar rcs merge failed"
arch -x86_64 /usr/bin/ranlib "$ARCHIVE" 2>/dev/null || true
ok "merged"

echo ""
echo "3. Verifying merged symbols present in archive..."
for sym in _SSLCipherAES_128_GCM _SSLCipherAES_256_GCM _Tls12Callouts; do
    if arch -x86_64 nm "$ARCHIVE" 2>/dev/null | grep -q " T $sym\$"; then
        echo "   OK  $sym  (defined)"
    else
        warn "   $sym still not defined in archive"
    fi
done

echo ""
echo "   member count: $(ar t "$ARCHIVE" 2>/dev/null | wc -l | tr -d ' ')"
ok "Done. Re-run build-full-security.sh to relink the monolith."
