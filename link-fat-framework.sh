#!/bin/bash
# link-fat-framework.sh — link the i386 and x86_64 Security monoliths (each with
# our EC-chain patch in ssl), then lipo them into one fat framework.
#
# Mirrors build-full-security.sh's link recipe (exported_symbols_list + dead_strip
# + archives-listed-twice + antlr/sqlite/pam/sandbox + CoreFoundation), applied
# once per arch with the matching archive set:
#   x86_64: sym-<short>/security_<short>  (ssl substituted -> sym-ssl-x64patched)
#   i386:   sym-<short>-i386/security_<short>  (patched ssl already there)
#
# Run from the repository root with VM set (VM="$(pwd)"), or let it self-locate.

set +e
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
EXP=$VM/Security.exp
ORDER=$VM/Security-55002/lib/Security.order
INSTALL_NAME=/System/Library/Frameworks/Security.framework/Versions/A/Security

# component order (same 26)
COMPONENTS="ssl codesigning keychain cssm mds apple_x509_tp apple_x509_cl apple_file_dl apple_cspdl apple_csp sd_cspdl filedb cdsa_plugin cdsa_client authorization securityd_client cdsa_utilities utilities checkpw pkcs12 smime manifest asn1 cdsa_utils ocspd cms"

link_arch() {
  arch="$1"; out="$2"; antlr="$3"; symsuffix="$4"
  if [ "$arch" = "i386" ]; then CLIENTONLY="$VM/persist/securityd_client_i386_clientonly"; else CLIENTONLY="$VM/persist/securityd_client_x64_clientonly"; fi
  echo ""
  echo "=========================================================="
  echo "=== LINK $arch monolith -> $out"
  echo "=========================================================="
  ARCHIVES=()
  for short in $COMPONENTS; do
    a=""
    if [ "$arch" = "x86_64" ]; then
      if [ "$short" = "ssl" ]; then
        a="$VM/sym-ssl-x64patched/security_ssl"           # patched x64 ssl
      else
        # prefer security_<short>, else <short>
        [ -f "$VM/sym-$short/security_$short" ] && a="$VM/sym-$short/security_$short"
        [ -z "$a" ] && [ -f "$VM/sym-$short/$short" ] && a="$VM/sym-$short/$short"
      fi
    else # i386
      [ -f "$VM/sym-$short-i386/security_$short" ] && a="$VM/sym-$short-i386/security_$short"
      [ -z "$a" ] && [ -f "$VM/sym-$short-i386/$short" ] && a="$VM/sym-$short-i386/$short"
    fi
    if [ -z "$a" ] || [ ! -f "$a" ]; then
      echo "  !! MISSING $arch archive for $short"; MISSING=1; continue
    fi
    ARCHIVES+=("$a")
  done
  echo "  resolved ${#ARCHIVES[@]}/26 archives for $arch"
  [ "${#ARCHIVES[@]}" -ne 26 ] && { echo "  ABORT $arch: not all 26 archives"; return 1; }

  ORDER_ARG=""
  [ -f "$ORDER" ] && ORDER_ARG="-Wl,-order_file,$ORDER"

  arch -"$arch" /usr/bin/g++ -dynamiclib \
    -arch "$arch" -isysroot / \
    -install_name "$INSTALL_NAME" \
    -compatibility_version 1 -current_version 55002 \
    -exported_symbols_list "$EXP" \
    -Wl,-force_load,"$CLIENTONLY" \
    $ORDER_ARG \
    "${ARCHIVES[@]}" "${ARCHIVES[@]}" \
    -L/usr/local/lib -L"$antlr" -lantlr \
    -lbsm -lstdc++ -lsqlite3 -lpam -lsandbox \
    -framework CoreFoundation \
    -o "$out" 2> "/tmp/link_$arch.log"
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "  LINK FAILED ($arch) rc=$rc — tail:"
    tail -25 "/tmp/link_$arch.log" | sed 's/^/    /'
    return 1
  fi
  echo "  OK -> $out"
  lipo -info "$out" 2>/dev/null | sed 's/^/    /'
  echo "    size: $(ls -la "$out" | awk '{print $5}')"
  echo "    TLS12 markers: $(strings - "$out" 2>/dev/null | grep -c tls12)"
  echo "    our patch (sslVerifyCertChainOpenSSL): $(nm "$out" 2>/dev/null | grep -c sslVerifyCertChainOpenSSL)"
  # SYMBOL GATE -- these are FATAL, not informational.
  #
  # ld only extracts members from a static archive that resolve something either
  # referenced or exported. With -dead_strip + -exported_symbols_list, an archive
  # whose symbols appear in NEITHER list is skipped entirely and the link still
  # succeeds. That happened on the Mac mini (2026-07-20): Security.exp was
  # generated without libsecurity_ssl's 79 _SSL* symbols, so ld silently dropped
  # the WHOLE ssl archive -- "resolved 26/26 archives", "OK", rc=0, and a
  # 9.2MB framework containing no SSL at all. These lines printed XX MISSING and
  # the build carried on to produce an installable, broken framework.
  #
  # A framework missing a component must never be reported as a successful build.
  SYMFAIL=""
  # One representative symbol per critical component/patch. Each would vanish
  # silently if its archive were skipped or its exports omitted:
  #   _SSLHandshake            ssl linked at all
  #   _SSLCopyPeerTrust        ssl's SecureTransport surface
  #   _Tls12Callouts           the TLS 1.2 backport (merge-ssl-addons)
  #   sslVerifyCertChainOpenSSL  EC chain verify, SSL path (build-ssl-patched)
  #   tls12TrustEvaluateOpenSSL  EC chain verify, SecTrust path (keychain inject)
  #   getSessionInfo           ClientSession::getSessionInfo -- absence of this
  #                            is what crashed securityd and blue-screened login
  for s in _SSLHandshake _SSLCopyPeerTrust _Tls12Callouts; do
    if nm "$out" 2>/dev/null | grep -q " $s\$"; then
      echo "    OK sym $s"
    else
      echo "    XX MISSING $s"
      SYMFAIL="$SYMFAIL $s"
    fi
  done
  for s in sslVerifyCertChainOpenSSL tls12TrustEvaluateOpenSSL getSessionInfo; do
    n=$(nm "$out" 2>/dev/null | grep -c -- "$s")
    if [ "$n" -gt 0 ]; then
      echo "    OK sym $s ($n)"
    else
      echo "    XX MISSING $s"
      SYMFAIL="$SYMFAIL $s"
    fi
  done
  if [ -n "$SYMFAIL" ]; then
    echo "  ABORT $arch: required symbol(s) absent from the linked monolith:$SYMFAIL"
    echo "         (an archive was almost certainly skipped -- check Security.exp"
    echo "          covers every component, ssl included)"
    return 1
  fi
  return 0
}

# --- x86_64 ---
# antlr x64 lives in a dir; pass the DIR that contains libantlr.a
link_arch x86_64 "$VM/Security.x86_64.new" "$VM/antlr-cpp" || { echo "x86_64 link failed"; exit 1; }

# --- i386 --- (needs a dir containing libantlr.a that is the i386 one)
# make a dir with libantlr.a -> the i386 archive so -lantlr resolves i386
mkdir -p "$VM/antlr-i386"
cp "$VM/antlr-cpp/libantlr_i386.a" "$VM/antlr-i386/libantlr.a"
link_arch i386 "$VM/Security.i386.new" "$VM/antlr-i386" || { echo "i386 link failed"; exit 1; }

# --- lipo into fat ---
echo ""
echo "=========================================================="
echo "=== LIPO -> fat framework"
echo "=========================================================="
lipo -create "$VM/Security.x86_64.new" "$VM/Security.i386.new" -output "$VM/Security.fat.new"
rc=$?
if [ $rc -ne 0 ]; then echo "lipo failed rc=$rc"; exit 1; fi
echo "fat framework: $VM/Security.fat.new"
lipo -info "$VM/Security.fat.new" | sed 's/^/  /'
echo "  size: $(ls -la "$VM/Security.fat.new" | awk '{print $5}')"
echo ""
echo "=== per-slice verification ==="
for a in x86_64 i386; do
  echo "--- $a slice ---"
  echo "  TLS12: $(lipo -thin $a "$VM/Security.fat.new" -output /tmp/slice_$a 2>/dev/null; strings - /tmp/slice_$a 2>/dev/null | grep -c tls12)"
  echo "  patch: $(nm -arch $a "$VM/Security.fat.new" 2>/dev/null | grep -c sslVerifyCertChainOpenSSL)"
done
echo ""
echo "DONE. Fat patched framework staged at: $VM/Security.fat.new"
echo "NOT installed yet — review verification above first."
