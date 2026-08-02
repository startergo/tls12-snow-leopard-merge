#!/bin/bash
# install-consistent-and-reboot.sh
# =============================================================================
# Install the CF-consistent framework + matched daemon, rebuild the dyld shared
# cache (REQUIRED -- otherwise the old framework loads from cache at boot), stage
# recovery, and reboot to test a full boot with the new framework.
#
# FRAMEWORK AND DAEMON ARE A MATCHED PAIR. They are built from the same component
# set and share the CSSM handle ABI; installing one without the other gives
# CSSMERR_DL_INVALID_DB_HANDLE on keychain unlock (diagnosed 2026-07-21).
#
# ppc7400: our build produces a 2-slice binary (x86_64 + i386) but the stock
# 10.6.8 framework is 3-slice. Installing 2-slice leaves PubSub, WebKit and
# QuickTimeComponents unable to bind in the dyld shared cache. The ppc slice is
# untouched by this project, so it is grafted from the stock framework.
#
# Recovery backups are created automatically on first run (from whatever is
# installed, after verifying it is genuinely stock and not one of our builds).
# If the machine will not boot / SSH does not return, boot to single-user
# (Cmd-S) or a recovery drive and run the two cp lines printed at the end.
#
# Run ON the build host (sudo pw via VM_SUDO_PASS or the default).
# =============================================================================
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
[ -f "$VM/config.sh" ] && . "$VM/config.sh"
SEC=/System/Library/Frameworks/Security.framework/Versions/A/Security
SECDIR=$(dirname "$SEC")
PW="${VM_SUDO_PASS:-}"
FW="${1:-$VM/Security.fat.new}"
DAEMON="${2:-$VM/dst-securityd-fat/securityd}"

STOCK_FW="$SECDIR/Security.stock"
STOCK_DAEMON=/usr/sbin/securityd.stock

sudo_do() { echo "$PW" | sudo -S "$@"; }

[ -f "$FW" ]     || { echo "FATAL: framework not found: $FW"; exit 1; }
[ -f "$DAEMON" ] || { echo "FATAL: daemon not found: $DAEMON"; exit 1; }

# -----------------------------------------------------------------------------
echo "=== preflight: verify all fixes present in $FW ==="
X=$(mktemp -t tls12inst); lipo -thin x86_64 "$FW" -output "$X" 2>/dev/null || cp "$FW" "$X"
echo "  abtd=$(nm "$X" 2>/dev/null|grep -c KeychainImpl15aboutToDestruct)" \
     "gcm=$(nm "$X" 2>/dev/null|grep -c SSLCipherAES_128_GCM)" \
     "getSessionInfo=$(nm "$X" 2>/dev/null|grep -c getSessionInfo)" \
     "tls12=$(nm "$X" 2>/dev/null|grep -c Tls12Callouts)" \
     "hmacLegacy=$(nm "$X" 2>/dev/null|grep -c hmacLegacy)"
rm -f "$X"
D=$(mktemp -t tls12inst); lipo -thin x86_64 "$DAEMON" -output "$D" 2>/dev/null || cp "$DAEMON" "$D"
echo "  daemon getSessionInfo: $(nm "$D" 2>/dev/null | grep -c getSessionInfo)"; rm -f "$D"
echo "  framework slices: $(lipo -info "$FW" | sed 's/.*: //')"
echo "  daemon slices:    $(lipo -info "$DAEMON" | sed 's/.*: //')"

# -----------------------------------------------------------------------------
# Recovery backups. Created on first run from what is currently installed, but
# ONLY if that looks like a genuine stock binary -- otherwise a second run would
# happily record one of our own builds as the recovery target.
echo "=== recovery backups ==="

if [ ! -f "$STOCK_FW" ]; then
  # A stock 10.6.8 framework is 3-slice and has none of our symbols.
  ISTOCK=1
  lipo -info "$SEC" 2>/dev/null | grep -q ppc || ISTOCK=0
  T=$(mktemp -t tls12inst); lipo -thin x86_64 "$SEC" -output "$T" 2>/dev/null || cp "$SEC" "$T"
  [ "$(nm "$T" 2>/dev/null | grep -c 'Tls12Callouts\|hmacLegacy')" != "0" ] && ISTOCK=0
  rm -f "$T"
  if [ "$ISTOCK" = "1" ]; then
    sudo_do cp -p "$SEC" "$STOCK_FW"
    echo "  created $STOCK_FW from the installed framework"
  else
    echo "FATAL: $STOCK_FW missing and the installed framework is NOT stock"
    echo "       (2-slice and/or carries our symbols). Restore a stock 10.6.8"
    echo "       Security.framework binary to $STOCK_FW before installing."
    exit 1
  fi
fi

if [ ! -f "$STOCK_DAEMON" ]; then
  if [ "$(strings /usr/sbin/securityd 2>/dev/null | grep -c getSessionInfo)" = "0" ]; then
    sudo_do cp -p /usr/sbin/securityd "$STOCK_DAEMON"
    echo "  created $STOCK_DAEMON from the installed daemon"
  else
    echo "FATAL: $STOCK_DAEMON missing and the installed daemon is NOT stock"
    echo "       (carries getSessionInfo). Restore a stock 10.6.8 securityd"
    echo "       to $STOCK_DAEMON before installing."
    exit 1
  fi
fi

echo "  stock fw:     $(shasum "$STOCK_FW" | awk '{print $1}')  ($(lipo -info "$STOCK_FW" | sed 's/.*: //'))"
echo "  stock daemon: $(shasum "$STOCK_DAEMON" | awk '{print $1}')"

# -----------------------------------------------------------------------------
# ppc7400 graft. Our link produces x86_64 + i386 only; without the ppc slice the
# shared-cache rebuild drops every ppc-capable consumer of Security.framework.
INSTALL_FW="$FW"
if ! lipo -info "$FW" | grep -q ppc; then
  if lipo -info "$STOCK_FW" | grep -q ppc; then
    echo "=== grafting ppc7400 from $STOCK_FW ==="
    PPC=$(mktemp -t tls12inst); FAT3=$(mktemp -t tls12inst)
    lipo "$STOCK_FW" -thin ppc7400 -output "$PPC" || { echo "FATAL: ppc7400 extract failed"; exit 1; }
    lipo "$FW" "$PPC" -create -output "$FAT3"     || { echo "FATAL: ppc graft failed"; exit 1; }
    rm -f "$PPC"
    INSTALL_FW="$FAT3"
    echo "  grafted: $(lipo -info "$INSTALL_FW" | sed 's/.*: //')"
  else
    echo "  WARN stock framework has no ppc7400 slice -- installing 2-slice."
    echo "       Expect 'no compatible slice found' bind warnings for PubSub,"
    echo "       WebKit and QuickTimeComponents when the cache is rebuilt."
  fi
fi

# -----------------------------------------------------------------------------
echo "=== install framework + daemon (matched pair) ==="
sudo_do cp "$INSTALL_FW" "$SEC"
sudo_do cp "$DAEMON" /usr/sbin/securityd
sudo_do chown root:wheel "$SEC" /usr/sbin/securityd
sudo_do chmod 755 "$SEC" /usr/sbin/securityd
[ "$INSTALL_FW" != "$FW" ] && rm -f "$INSTALL_FW"
sync
echo "  installed fw:     $(shasum "$SEC" | awk '{print $1}')  $(lipo -info "$SEC" | sed 's/.*: //')"
echo "  installed daemon: $(shasum /usr/sbin/securityd | awk '{print $1}')"

# -----------------------------------------------------------------------------
echo "=== rebuild dyld shared cache (REQUIRED so the new framework loads at boot) ==="
sudo_do /usr/bin/update_dyld_shared_cache -force 2>&1 | tail -5
echo ""
echo "  NOTE: any 'could not bind ... no compatible slice found in .../Security'"
echo "        line above means the ppc graft did not take. Do not reboot."

# -----------------------------------------------------------------------------
# In-place verification BEFORE reboot. The dyld cache was rebuilt above, so the
# newly installed framework is already live for freshly launched processes --
# we can exercise it now and decide whether to reboot, rather than rebooting
# blind and risking a machine that does not come back.
echo ""
echo "=== in-place test (new framework is live after the cache rebuild) ==="

KC="$HOME/Library/Keychains/login.keychain"
printf "  keychain unlock: "
if security unlock-keychain -p "${TESTPW:-}" "$KC" 2>/dev/null; then
  echo "PASS (rc=0)"; KC_OK=1
else
  echo "FAIL (rc=$?) -- note: over SSH without a login session this can be a"
  echo "                 false negative; check the HTTPS result and system.log too"
  KC_OK=0
fi

printf "  https fetch:     "
HTTP=$(curl -sS -o /dev/null -w '%{http_code}' https://www.google.com 2>/dev/null || echo "000")
if [ "$HTTP" = "200" ]; then echo "PASS (200)"; NET_OK=1; else echo "FAIL (got $HTTP)"; NET_OK=0; fi

echo ""
echo "  (set TESTPW=<pw> before running to let the keychain test unlock non-interactively)"
echo ""

RESTORE="cp \"$STOCK_FW\" \"$SEC\" ; cp \"$STOCK_DAEMON\" /usr/sbin/securityd ; rm -f /var/db/dyld/dyld_shared_cache_* ; reboot"

if [ "${KC_OK:-0}" = "1" ] && [ "${NET_OK:-0}" = "1" ]; then
  echo "=== both tests PASSED ==="
else
  echo "=== one or more tests FAILED ==="
  echo "The current (stock) framework can be restored WITHOUT rebooting into the"
  echo "new one. To roll back now:"
  echo "  sudo cp \"$STOCK_FW\" \"$SEC\" && sudo cp \"$STOCK_DAEMON\" /usr/sbin/securityd \\"
  echo "    && sudo /usr/bin/update_dyld_shared_cache -force"
fi

echo ""
echo "Recovery if a reboot ever hangs: single-user (Cmd-S) ->"
echo "  $RESTORE"
echo ""
printf "Reboot now to confirm a full boot with the new framework? [y/N] "
read -r ANS
case "$ANS" in
  y|Y|yes|YES) echo "Rebooting..."; sudo_do reboot ;;
  *) echo "Not rebooting. Re-run this script or reboot manually when ready." ;;
esac
