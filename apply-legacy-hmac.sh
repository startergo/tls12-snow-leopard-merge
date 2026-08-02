#!/bin/bash
# apply-legacy-hmac.sh
# =============================================================================
# Restore the BSAFE-legacy HMAC (CSSM_ALGID_SHA1HMAC_LEGACY) in apple_csp so that
# old (MacOS_10_0-format) keychains -- e.g. login.keychain -- verify correctly.
#
# ROOT CAUSE (fully diagnosed): securityd dbcrypto.cpp verifies old keychain blob
# signatures with CSSM_ALGID_SHA1HMAC_LEGACY, a bug-for-bug-BSAFE-4.0-compatible
# HMAC-SHA1 (its quirk: inner+outer digests are BOTH computed in update(); it
# requires a 20-byte key). apple_csp's real handler, MacLegacyContext, depends on
# CryptKit's HmacSha1Legacy, which is #ifdef CRYPTKIT_CSP_ENABLE. That code was
# NOT built (CryptKit is REDACTED from the Security-55002 open-source drop -- it
# contains Apple's proprietary FEE algorithms), so a prior session rerouted
# SHA1HMAC_LEGACY to the STANDARD MacContext HMAC. Standard HMAC != legacy HMAC,
# so the correct keychain password was rejected with CSSMERR_CSP_VERIFY_FAILED
# ("The user name or passphrase you entered is not correct", exit 51) -- even
# though PBKDF2, 3DES-ECB, and CBC were all proven cryptographically correct.
#
# THE FIX (this script):
#  1. Vendor ONLY the legacy-HMAC pieces of libsecurity_cryptkit (from
#     sources/libsecurity_cryptkit-55002/, taken from Security-55471 -- the
#     HmacSha1Legacy.c is FROZEN 2001 code, byte-behavior-identical across
#     versions, and API-identical to apple_csp-55003). No proprietary FEE code.
#  2. Stage the cryptkit headers under security_cryptkit/ so the
#     <security_cryptkit/HmacSha1Legacy.h> include resolves.
#  3. Unguard MacLegacyContext: MacContext.h / MacContext.cpp
#     '#ifdef CRYPTKIT_CSP_ENABLE' -> '#if 1'.
#  4. Route CSSM_ALGID_SHA1HMAC_LEGACY to the real MacLegacyContext in
#     miscAlgFactory.cpp ('#if CRYPTKIT_CSP_ENABLE' guard before the legacy case
#     -> '#if 1', so the standard-HMAC fallback is excluded).
#
# The build step (compile the 4 legacy .c files with -DCK_SECURITY_BUILD and
# inject the objects into the apple_csp archive) is done by
# build-consistent-framework.sh; this script only prepares the source.
#
# Verified: after this fix + rebuild,  security unlock-keychain -p <pw> login.keychain -> exit 0.
#
# Idempotent. Run where the apple_csp + cryptkit sources live (VM: $VM, or host).
# =============================================================================
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
CSPLIB="${CSPLIB:-$VM/libsecurity_apple_csp-55003/lib}"
CKSRC="${CKSRC:-$VM/cryptkit-vendor}"   # dir holding the vendored cryptkit lib/*.c/.h
PIECES=/usr/local/SecurityPieces
SUDO=""
[ -w "$PIECES/Headers" ] 2>/dev/null || SUDO="sudo -S"

echo "=== 1. vendor the legacy-HMAC cryptkit files into apple_csp/lib ==="
CKFILES="HmacSha1Legacy.c HmacSha1Legacy.h ckSHA1.c ckSHA1.h ckSHA1_priv.c ckSHA1_priv.h ckconfig.h feeTypes.h falloc.c falloc.h platform.h"
for f in $CKFILES; do
  if [ -f "$CKSRC/$f" ]; then
    cp "$CKSRC/$f" "$CSPLIB/$f"
  elif [ -f "$CSPLIB/$f" ]; then
    :  # already present
  else
    echo "  WARN: $f not found in $CKSRC or $CSPLIB"
  fi
done
echo "  cryptkit files present: $(ls "$CSPLIB"/HmacSha1Legacy.c "$CSPLIB"/ckSHA1.c 2>/dev/null | wc -l)/2"

echo "=== 2. stage cryptkit headers under $PIECES/Headers/security_cryptkit ==="
echo "${VM_SUDO_PASS:-}" | $SUDO mkdir -p "$PIECES/Headers/security_cryptkit" 2>/dev/null
for h in HmacSha1Legacy.h ckSHA1.h ckSHA1_priv.h ckconfig.h feeTypes.h falloc.h platform.h; do
  [ -f "$CSPLIB/$h" ] && echo "${VM_SUDO_PASS:-}" | $SUDO cp "$CSPLIB/$h" "$PIECES/Headers/security_cryptkit/" 2>/dev/null
done
echo "  staged: $(ls "$PIECES/Headers/security_cryptkit/" 2>/dev/null | wc -l) headers"

echo "=== 3. unguard MacLegacyContext (#ifdef CRYPTKIT_CSP_ENABLE -> #if 1) ==="
for f in MacContext.h MacContext.cpp; do
  F="$CSPLIB/$f"
  [ -f "$F" ] || { echo "  MISSING $F"; continue; }
  perl -0777 -i -pe 's/#ifdef\s+CRYPTKIT_CSP_ENABLE/#if 1/g' "$F"
  echo "  $f: $(grep -c '#if 1' "$F") '#if 1' guards, $(grep -c '#ifdef CRYPTKIT_CSP_ENABLE' "$F") remaining #ifdef"
done

echo "=== 4. route SHA1HMAC_LEGACY -> real MacLegacyContext in miscAlgFactory.cpp ==="
MAF="$CSPLIB/miscAlgFactory.cpp"
if [ -f "$MAF" ]; then
  perl -0777 -i -pe 's/#if\s+CRYPTKIT_CSP_ENABLE(\s*\n\s*case\s+CSSM_ALGID_SHA1HMAC_LEGACY:)/#if 1$1/g' "$MAF"
  echo "  miscAlgFactory: legacy case guarded by #if 1 = $(grep -B1 'case CSSM_ALGID_SHA1HMAC_LEGACY' "$MAF" | grep -c '#if 1')"
else
  echo "  MISSING $MAF"
fi
echo "done. Rebuild apple_csp with GCC_PREPROCESSOR_DEFINITIONS='CK_SECURITY_BUILD=1',"
echo "compile HmacSha1Legacy.c/ckSHA1.c/ckSHA1_priv.c/falloc.c (-DCK_SECURITY_BUILD) and"
echo "inject the .o's into the apple_csp archive, then relink."
