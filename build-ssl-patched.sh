#!/bin/bash
# build-ssl-patched.sh
# ---------------------------------------------------------------------------
# Recompile the patched appleCdsa.o (NOT_TRUSTED/INVALID_ANCHOR -> libcrypto
# fallback) for both arches and merge into the ssl archives, mirroring the
# merge-ssl-addons.sh recipe (llvm-gcc-4.2, gnu99, sl-compat-prefix.h forced
# include, SecurityPieces header paths). Does NOT install/relink live.
#
# Run from the repository root with VM set (VM="$(pwd)"), or let it self-locate.
# ---------------------------------------------------------------------------
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
SSLSRC=$(ls -d "$VM"/libsecurity_ssl-55002 2>/dev/null | head -1)
LIB="$SSLSRC/lib"
SDK=/Developer/SDKs/MacOSX10.6.sdk
PREFIX="$VM/sl-compat-prefix.h"
GCC=/Developer/usr/bin/llvm-gcc-4.2
OUT=/tmp/build_ssl_patched.txt
: > "$OUT"
log(){ echo "$@" | tee -a "$OUT"; }
die(){ log "FATAL: $*"; exit 1; }

log "=== build-ssl-patched  $(date) ==="

# sanity: patches present
grep -q "recovered RSA peerPubKey via libcrypto" "$LIB/sslCert.c" || \
  die "sslCert.c not patched (no RSA recovery). Run patch-ssl-rsa-pubkey.sh first"
grep -q "tls12ExtractRSAPubKey" "$LIB/tls12_chainverify.c" || \
  die "tls12_chainverify.c not patched (no RSA extractor)"
log "  sslCert.c + tls12_chainverify.c patched: OK"

# common flags (mirror merge-ssl-addons.sh recipe EXACTLY)
PIECES=/usr/local/SecurityPieces
INCS="-I$LIB -I$PIECES/Headers -I$PIECES/PrivateHeaders -I$PIECES/Headers/security_asn1 -I$PIECES/Headers/security_cdsa_utilities"
FRAMEWORKS="-F$PIECES/Frameworks -F$PIECES/Components/Security"
CFLAGS="-mmacosx-version-min=10.6 -std=gnu99 -DNDEBUG -Os -g -include $PREFIX -w"

# objects to rebuild: sslCert.o (RSA recovery) + tls12_chainverify.o (extractor)
OBJS_SRC="sslCert tls12_chainverify"

build_arch() {
  local ARCH="$1" SYMDIR="$2"
  log ""
  log "### ARCH=$ARCH ###"
  local archive="$VM/$SYMDIR/security_ssl"
  [ -f "$archive" ] || { log "  archive not found: $archive"; return 1; }

  cp "$archive" "$archive.pressl.$(date +%s)" && log "  backed up $SYMDIR/security_ssl"

  local objs=""
  for base in $OBJS_SRC; do
    local src="$LIB/$base.c"
    [ -f "$src" ] || { log "  source missing: $src"; return 1; }
    local obj=/tmp/${base}_$ARCH.o
    log "  compiling $base.c ($ARCH)..."
    arch -$ARCH /usr/bin/gcc -arch $ARCH $CFLAGS $INCS $FRAMEWORKS -c "$src" -o "$obj" > "/tmp/ssl_${base}_$ARCH.log" 2>&1
    local rc=$?
    log "    $base.o rc=$rc"
    if [ $rc -ne 0 ]; then
      log "    --- errors (last 20) ---"
      tail -20 "/tmp/ssl_${base}_$ARCH.log" | sed 's/^/      /' | tee -a "$OUT"
      return 1
    fi
    objs="$objs $obj"
  done

  arch -$ARCH /usr/bin/ar r "$archive" $objs 2>>"$OUT"
  arch -$ARCH /usr/bin/ranlib "$archive" 2>/dev/null || true
  log "  merged: $OBJS_SRC into $SYMDIR/security_ssl"
  log "  tls12ExtractRSAPubKey in archive: $(nm "$archive" 2>/dev/null | grep -c tls12ExtractRSAPubKey)"
  return 0
}

build_arch x86_64 sym-ssl;      X=$?
build_arch i386   sym-ssl-i386; I=$?

log ""
log "=== SUMMARY ==="
log "  x86_64: $([ $X -eq 0 ] && echo OK || echo FAILED)"
log "  i386:   $([ $I -eq 0 ] && echo OK || echo FAILED)"
log ""
if [ $X -eq 0 ] && [ $I -eq 0 ]; then
  log "  Both patched. NOW relink: bash link-fat-framework.sh"
  log "  Then restage test fw + retest iTunes handshake path (hstest)."
else
  log "  A build FAILED. Fix errors above before relink."
fi
log "done -> $OUT"
chmod 644 "$OUT" 2>/dev/null
