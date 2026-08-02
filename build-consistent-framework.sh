#!/bin/bash
# build-consistent-framework.sh  (UNIVERSAL: x86_64 + i386)
# =============================================================================
# Reproducible pipeline to build the fully CF-layout-consistent, patched, FAT
# (x86_64 + i386) Security framework + FAT securityd daemon for Snow Leopard
# 10.6.8, from source, against the CURRENT headers.
#
# WHY BOTH ARCHES: Snow Leopard runs many system components and apps (iTunes,
# LaunchServices helpers, etc.) as i386. A fat framework whose i386 slice is
# stale/inconsistent crashes those i386 processes (e.g. iTunes:
# GetOurLSSessionIDInit err #1, securitySessionID==0x0). So EVERY component and
# the daemon must be rebuilt for i386 too, consistently.
#
# FIXES BUILT IN (validated this session):
#  1. Keychain crash fix: KeychainImpl::aboutToDestruct (apply-crash-fix.sh)
#  2. TLS 1.2 + AES-GCM in ssl (base build + merge-ssl-addons + build-ssl-patched)
#  3. getSessionInfo MIG RPC restored (ucsp.defs un-skip + securityd handler +
#     MIG regen client+server) -> fixes WindowServer crash-loop (coreservicesd
#     SessionGetInfo was MIG_BAD_ID / Mach 0x10000003) and i386 LaunchServices.
#  4. getSessionInfo daemon handler hardened (no assert-trap; try/catch)
#  5. Trust.cpp CSSM_DL_DB_HANDLE operator== ambiguity -> memcmp
#  6. ALL CF/CSSM/SSL components rebuilt (both arches) against current headers
#     => consistent kAlignedRuntimeSize => no SecCFObject::allocate __HALT.
#
# BUILD DISCIPLINE:
#  - llvm-gcc-4.2 (NOT clang): GCC_VERSION=com.apple.compilers.llvmgcc42
#  - GCC_PREFIX_HEADER=sl-compat-prefix.h, GCC_PRECOMPILE_PREFIX_HEADER=NO
#  - 4x DEPRECATED_IN_MAC_OS_X_VERSION_10_[7-10]... defines empty
#  - ssl needs GCC_C_LANGUAGE_STANDARD=gnu99
#  - relink: NO -dead_strip, force_load client-only securityd_client
#  - sym-<c>/security_<c> is often a symlink; cp-through-symlink updates the real
#    target (fine; relink resolves it). i386 stages to sym-<c>-i386/security_<c>.
#
# USAGE (on VM; sudo pw via VM_SUDO_PASS):
#   bash build-consistent-framework.sh                 # full: both arches + daemon
#   ARCHES="x86_64" bash build-consistent-framework.sh # x64 only (debug)
#   STAGE=daemon bash build-consistent-framework.sh    # daemon only
#
# OUTPUT:
#   $VM/persist/Security.x64  $VM/persist/Security.i386   (per-arch monoliths)
#   $VM/persist/Security.fat.consistent                  (fat framework)
#   $VM/dst-securityd-fat/securityd                      (FAT daemon x64+i386)
# =============================================================================
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
[ -f "$VM/config.sh" ] && . "$VM/config.sh"
PIECES=/usr/local/SecurityPieces
PREFIX="$VM/sl-compat-prefix.h"
SDK=/Developer/SDKs/MacOSX10.6.sdk
GCC=/Developer/usr/bin/llvm-gcc-4.2
STAGE="${STAGE:-all}"
ARCHES="${ARCHES:-x86_64 i386}"
PW="${VM_SUDO_PASS:-}"

# === CORRECT 10.6.8 component versions (mac-os-x-1068 tag) ===
# securityd:    40600 (NOT 55009/Lion) - native SecurityAgent bootstrap launch + getSessionInfo
# utilities:    55010 (NOT 55017)      - has AuditToken::auditSession() that 40600 needs
# libsecurityd: 37613 (NOT 55002)      - mac-os-x-1068 tag == commit fff89928 == 37613 (PROVEN
#                                        via git tag). 37613 has getSessionInfo as a NATIVE
#                                        routine (no un-skip hack needed). 55002 is a later
#                                        (Lion-era) libsecurityd whose server-side session
#                                        code differs; building securityd_server from it is a
#                                        version mismatch vs genuine stock (which uses 37613).
SECURITYD_DIR="${SECURITYD_DIR:-securityd-40600}"
UTILITIES_DIR="${UTILITIES_DIR:-libsecurity_utilities-55010}"
LIBSECURITYD_DIR="${LIBSECURITYD_DIR:-libsecurityd-37613}"
# authorization: 36329 (NOT 55000) - mac-os-x-1068 tag == commit be9e4515 == 36329 (PROVEN via
#   git tag). Contains SessionGetInfo/SessionCreate (the client-side session API). 55000 (what
#   the project had) references AuditInfo::set()/Bootstrap::lookup2() which do NOT exist in
#   utilities-55010 -> x64 framework relink fails. 36329 uses server().getSessionInfo()/
#   setupSession() (ClientSession methods) and is 55010-compatible. SessionGetInfo is the exact
#   function emitting the 'SessionGetInfo(0x..) -> Mach ..' failure, so version-correctness here
#   is the prime suspect for the session bug.
AUTHORIZATION_DIR="${AUTHORIZATION_DIR:-libsecurity_authorization-36329}"
# ocspd: 55004 (NOT 55010) - mac-os-x-1068 tag == 55004. ocspd-55010 (Lion-era) calls
#   MachPlusPlus::Bootstrap::lookup2() which does NOT exist in utilities-55010 (10.6.8 utilities
#   has lookup()/lookupOptional() only, NO lookup2) -> x64 framework relink fails on
#   ocspdGlobals::serverPort(). 55004 uses Bootstrap().lookup() and is 55010-compatible.
OCSPD_DIR="${OCSPD_DIR:-libsecurity_ocspd-55004}"
# codesigning: 55005 (NOT 55032) - mac-os-x-1068 tag == 55005. codesigning-55032 (Lion-era) uses
#   the Security::MachOBase API; 10.6.8 utilities-55010 provides Security::MachO (no MachOBase)
#   -> x64 relink fails with undefined MachOBase::findCommand/findSection/etc. 55005 uses MachO
#   and is 55010-compatible.
CODESIGNING_DIR="${CODESIGNING_DIR:-libsecurity_codesigning-55005}"

DEPR='-DDEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER= -DDEPRECATED_IN_MAC_OS_X_VERSION_10_8_AND_LATER= -DDEPRECATED_IN_MAC_OS_X_VERSION_10_9_AND_LATER= -DDEPRECATED_IN_MAC_OS_X_VERSION_10_10_AND_LATER='
HDRS="$PIECES/Headers $PIECES/PrivateHeaders \$(inherited)"

# components to rebuild for CF-layout consistency (both arches)
# Components rebuilt by STEP 2. MUST cover everything link-fat-framework.sh links
# (see its COMPONENTS line) or an archive stays frozen at whatever headers were
# staged when it was last built -- the exact trap that left the x86_64
# agent_client at Jun 30 with a foreign AuthorizationData.h and SIGSEGV'd
# securityd at every login (2026-07-18).
# asn1/cdsa_utils/manifest/checkpw were added 2026-07-18 after a from-scratch sweep
# (rm -rf cc-build + STAGE=all) left them untouched at Jun 19-Jul 7 dates. They were
# verified inert w.r.t. the AuthItemSet/SecCFObject/MachO layout skew at the time
# (nm found no references), so this is hygiene, not an active bug fix.
# checkpw only builds because comp_ver pins it to 55471 (PAM-based); the 1068-tag
# 36064 needs the private DirectoryServiceMIG.h and cannot compile -- see comp_ver.
COMPS="cdsa_utilities utilities cdsa_client cssm cdsa_plugin codesigning keychain apple_x509_tp apple_x509_cl apple_file_dl apple_cspdl apple_csp sd_cspdl filedb mds ocspd pkcs12 smime cms authorization asn1 cdsa_utils manifest checkpw"

# compile+stage checkpw directly for one arch.
#
# checkpw is the one component we cannot build through xcodebuild:
#   - the 1068-tag 36064 needs the PRIVATE <DirectoryServiceMIG.h> (kDSStdMachPortName),
#     which exists nowhere on the system, in the Security repos, or in the project,
#     and there is no .defs to mig-generate it from -> 24 errors, both arches.
#   - 55471 replaced all that with PAM (pam_appl.h/openpam.h, both present on 10.6)
#     and compiles fine, BUT its xcodeproj wants config/{lib,release}.xcconfig from
#     the later Security tree, and those set GCC_VERSION=clang plus
#     ARCHS_STANDARD_32_64_BIT and warnings-as-errors. Adopting them would build this
#     one archive with a DIFFERENT COMPILER from every other component in the
#     framework -- exactly the sort of inconsistency that produced the AuthItemSet
#     ODR crash. Not worth it for a two-file library.
#
# So: compile the two files directly with the same llvm-gcc-4.2 used everywhere else.
# The only fixup needed is the 10.7-era availability macro in checkpw.h
# (__OSX_AVAILABLE_BUT_DEPRECATED(...__MAC_10_7...)); 10.6's AvailabilityInternal.h
# has __AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_6 but not the _10_7 variant, so
# the declaration breaks and every subsequent system header cascades. Define it to a
# plain deprecated attribute -- same class of workaround as $DEPR above.
#
# Verified: exports are IDENTICAL to the 36064 archive (_checkpw, _checkpw_internal),
# so the ABI the framework links against does not change.
build_checkpw_direct() {
  local arch="$1"
  local ver src symdir out o
  ver=$(comp_ver checkpw); ver="${ver##*-}"
  src=$(ls -d "$VM"/libsecurity_checkpw*-${ver} 2>/dev/null | head -1)
  [ -z "$src" ] && { echo "  (checkpw: no source for version $ver)"; return 0; }
  [ -f "$src/lib/checkpw.c" ] || { echo "  (checkpw: $src/lib/checkpw.c missing)"; return 0; }

  if [ "$arch" = "i386" ]; then symdir="$VM/sym-checkpw-i386"; else symdir="$VM/sym-checkpw"; fi
  mkdir -p "$symdir"
  out="$symdir/security_checkpw"
  o="$VM/cc-build/checkpw-$arch"
  mkdir -p "$o"

  arch -$arch "$GCC" -arch $arch -std=gnu99 -Os -DNDEBUG=1 \
      '-D__AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_7=__attribute__((deprecated))' \
      -I"$src/lib" -I"$PIECES/Headers" -I"$PIECES/PrivateHeaders" \
      -c "$src/lib/checkpw.c" -o "$o/checkpw.o" > "$o/build.log" 2>&1

  if [ ! -f "$o/checkpw.o" ]; then
    echo "  BUILD ISSUE checkpw/$arch (direct compile); log: $o/build.log"
    grep -i 'error' "$o/build.log" | head -3
    return 1
  fi

  # replace the symlink (if any) with a real archive
  rm -f "$out"
  ar qc "$out" "$o/checkpw.o" && ranlib "$out" 2>/dev/null
  echo "  built checkpw/$arch direct -> $out (exports: $(nm "$out" 2>/dev/null | grep -c ' T '))"
  return 0
}

say(){ echo "=== $* ==="; }

# ---------------------------------------------------------------------------
# stage_component_headers <short>
#
# Copy a component's OWN headers (from its version-pinned source, per comp_ver)
# into /usr/local/SecurityPieces/Headers/<dir>/, overwriting whatever is staged.
#
# WHY THIS EXISTS (root cause of the 2026-07-18 securityd segfault):
#   The staged SecurityPieces headers are NOT regenerated when a component's
#   version pin changes, so they can be from a DIFFERENT (newer/foreign) Security
#   release than the archive we build+link. That is an ODR / object-layout
#   violation: a TU compiled against the staged header sees a different class
#   size/members than the linked archive provides.
#   PROVEN instance: staged AuthorizationData.h (Jun 19, foreign) declared
#   AuthItemSet with an EXTRA data member `char *firstItemName` plus a
#   user-defined copy-ctor and operator=, while cdsa_utilities-36658 (what we
#   build) declares neither. securityd compiled against the staged version ->
#   AuthItemSet::operator= walked the std::_Rb_tree with the wrong layout ->
#   dereferenced garbage (rsi=0x0002000000000000) -> SIGSEGV in
#   _Rb_tree::_M_erase inside QueryInvokeMechanism::run during loginwindow's
#   authorizationCopyRights. securityd died at every login => every subsequent
#   SessionGetInfo returned Mach 1102 / securitySessionID == 0x0 => BLUE SCREEN
#   at login and immediate SSH disconnect. The long-hunted "session bug" was a
#   daemon crash from a stale staged header, not a session-protocol defect.
#   (Same disease previously seen as LINK errors: macho++.h MachOBase vs MachO,
#   ssclient.h/eventlistener.h. Runtime-layout skew is the silent variant --
#   it builds clean and crashes later.)
#
# Headers are copied VERBATIM from the pinned source; nothing is hand-edited,
# so this is a staging step, not a patch. Backups kept as .stale-<date>.
# ---------------------------------------------------------------------------
stage_component_headers() {
  local short="$1" ver vernum src dir h b t n=0
  ver=$(comp_ver "$short"); vernum="${ver##*-}"
  if   [ -d "$VM/libsecurity_${short}-${vernum}" ]; then src="$VM/libsecurity_${short}-${vernum}"
  elif [ -d "$VM/libsecurity_${short}-libsecurity_${short}-${vernum}" ]; then src="$VM/libsecurity_${short}-libsecurity_${short}-${vernum}"
  else src=$(ls -d "$VM"/libsecurity_${short}*-${vernum} 2>/dev/null | head -1); fi
  [ -z "$src" ] || [ ! -d "$src/lib" ] && { echo "  (stage-headers: no source for $short)"; return 0; }
  for h in "$src"/lib/*.h; do
    [ -f "$h" ] || continue
    b=$(basename "$h")
    # Stage into EVERY SecurityPieces location carrying this header name --
    # Headers/, PrivateHeaders/ AND Frameworks/*.framework/.../Headers/.
    # CRITICAL: PrivateHeaders/ must be included. securityd includes private SPI
    # headers (e.g. <Security/AuthorizationData.h>) that resolve through
    # PrivateHeaders/Security/. Staging only Headers/ leaves a foreign copy there
    # and the ODR/layout skew persists -- that is exactly what kept the
    # AuthItemSet _Rb_tree corruption alive after the first staging pass
    # (2026-07-18: PrivateHeaders/Security/AuthorizationData.h still had
    # `char *firstItemName` while Headers/ copies were already correct).
    for t in $(find "$PIECES" -name "$b" ! -name "*.stale*" 2>/dev/null); do
      if ! diff -q "$h" "$t" >/dev/null 2>&1; then
        echo "$PW" | sudo -S cp "$t" "$t.stale-$(date +%Y%m%d)" 2>/dev/null
        echo "$PW" | sudo -S cp "$h" "$t" 2>/dev/null
        echo "$PW" | sudo -S chmod 644 "$t" 2>/dev/null
        n=$((n+1))
      fi
    done
  done
  [ "$n" -gt 0 ] && echo "  staged $n header(s) from $(basename "$src") -> SecurityPieces"
  return 0
}

# CORRECT 10.6.8 component version map (mac-os-x-1068 git tag for EVERY component,
# audited 2026-07-17 from Security-55002-full/*/. Prints the version-suffixed source
# folder name build_component should use. Components NOT listed fall back to the glob.
# Rationale: the project accumulated Lion-era (55xxx) versions that reference APIs
# 10.6.8 utilities-55010 lacks (AuditInfo::set, Bootstrap::lookup2, MachOBase, ...),
# breaking the x64 relink. These are the LAST Snow Leopard tags, chosen not guessed.
comp_ver() {
  case "$1" in
    apple_csp)     echo "libsecurity_apple_csp-55003" ;;  # EXCEPTION: the 1068-tag 36859 #includes private CommonCrypto headers (cast.h, aesopt.h, opensslDES.h). CORRECTION 2026-07-21: those headers ARE publicly available -- aosm/CommonCrypto at tag mac-os-x-1068 carries all three under Source/CommonCrypto/ (git fetch the tag; GitHub's svn bridge died Jan 2024). An earlier version of this comment claimed Apple never released them, which is wrong; Netzel's build recipe (sourceforge.net/p/leopard-webkit/wiki/BuildInstructionsSecurity/) stages them via xcodebuild installhdrs + ditto into /usr/local. We stay on 55003 for now because the SL-backport adaptation onto the PUBLIC CommonCryptor.h/CommonDigest.h API lives there, as does the legacy-HMAC keychain-unlock vendoring -- moving to 36859 means re-homing both and staging the CommonCrypto private headers. UNTESTED but plausible; retiring this exception would bring the manifest one step closer to stock 1068.
    apple_cspdl)   echo "libsecurity_apple_cspdl-36064" ;;
    apple_file_dl) echo "libsecurity_apple_file_dl-36064" ;;
    apple_x509_cl) echo "libsecurity_apple_x509_cl-36064" ;;
    apple_x509_tp) echo "libsecurity_apple_x509_tp-55006" ;;
    asn1)          echo "libsecurity_asn1-36064" ;;
    authorization) echo "libsecurity_authorization-36329" ;;
    cdsa_client)   echo "libsecurity_cdsa_client-36213" ;;
    cdsa_plugin)   echo "libsecurity_cdsa_plugin-36327" ;;
    cdsa_utilities)echo "libsecurity_cdsa_utilities-36658" ;;
    cdsa_utils)    echo "libsecurity_cdsa_utils-36064" ;;
    checkpw)       echo "libsecurity_checkpw-55471" ;;  # EXCEPTION (proven): 36064 (1068 tag) #includes the PRIVATE <DirectoryServiceMIG.h> and uses kDSStdMachPortName -- absent from the SDK, the Security repos, the project tree and the whole VM filesystem (find / finds nothing), and there is no .defs in the checkpw project to mig-generate it from. 24 compile errors, both arches. Apple rewrote checkpw onto PAM (pam_appl.h/openpam.h, both present on 10.6) by 55471, which builds clean. Exports are IDENTICAL (_checkpw, _checkpw_internal), so the ABI the framework links against is unchanged. 3rd manifest exception after ssl-55002 and apple_csp-55003 -- all three are the same story: the tag version needs something Apple never shipped publicly, a later version was adapted to public APIs.
    cms)           echo "libsecurity_cms-36064" ;;
    codesigning)   echo "libsecurity_codesigning-55005" ;;
    cssm)          echo "libsecurity_cssm-40418" ;;
    filedb)        echo "libsecurity_filedb-36725" ;;
    keychain)      echo "libsecurity_keychain-55017" ;;
    manifest)      echo "libsecurity_manifest-36064" ;;
    mds)           echo "libsecurity_mds-36495" ;;
    ocspd)         echo "libsecurity_ocspd-55004" ;;
    pkcs12)        echo "libsecurity_pkcs12-40627" ;;
    sd_cspdl)      echo "libsecurity_sd_cspdl-35752" ;;
    smime)         echo "libsecurity_smime-36873" ;;
    ssl)           echo "libsecurity_ssl-55002" ;;  # EXCEPTION (proven): carries the TLS 1.2 patches. Stock 1068 tag is 40581, but our TLS work lives on 55002 and ssl is built+patched separately, not a plain COMPS rebuild. Only deviation from the 1068 manifest.
    utilities)     echo "libsecurity_utilities-55010" ;;
    *)             echo "" ;;
  esac
}

# build one component for one arch, stage to the arch-appropriate sym dir
# args: <short> <arch> [extra xcodebuild args...]
build_component() {
  local short="$1" arch="$2"; shift 2; local extra="$*"
  # checkpw cannot go through xcodebuild (see build_checkpw_direct for the full
  # reason: the 1068 version needs a private header, and the buildable 55471
  # version's xcconfigs would switch this one archive to clang).
  if [ "$short" = "checkpw" ]; then
    build_checkpw_direct "$arch"
    return $?
  fi
  local src proj tgt out new symdir symtarget ver vernum
  # centralized version pin (mac-os-x-1068). comp_ver returns e.g. libsecurity_apple_csp-55003.
  # VM source folders may be named either libsecurity_<short>-<ver> OR the doubled
  # libsecurity_<short>-libsecurity_<short>-<ver> (depending on how they were extracted).
  # So resolve by the VERSION NUMBER: find any folder for this component ending in -<ver>.
  ver=$(comp_ver "$short")
  vernum="${ver##*-}"   # trailing version number, e.g. 55003
  src=""
  if [ -n "$vernum" ]; then
    # exact single-name first, then doubled-name, then any folder ending in that version
    if   [ -d "$VM/libsecurity_${short}-${vernum}" ]; then src="$VM/libsecurity_${short}-${vernum}"
    elif [ -d "$VM/libsecurity_${short}-libsecurity_${short}-${vernum}" ]; then src="$VM/libsecurity_${short}-libsecurity_${short}-${vernum}"
    else src=$(ls -d "$VM"/libsecurity_${short}*-${vernum} 2>/dev/null | head -1); fi
  fi
  if [ -z "$src" ]; then
    src=$(ls -d "$VM"/libsecurity_${short}-* 2>/dev/null | head -1)
    [ -z "$src" ] && src=$(ls -d "$VM"/libsecurity_${short} 2>/dev/null | head -1)
  fi
  [ -z "$src" ] && { echo "  SKIP $short/$arch (no source)"; return 0; }
  proj=$(ls -d "$src"/*.xcodeproj 2>/dev/null | head -1)
  tgt=$(arch -$arch xcodebuild -project "$proj" -list 2>/dev/null | awk '/Targets:/{f=1;next} f&&NF{print $1; exit}')
  out="$VM/cc-build/$short-$arch"; rm -rf "$out"; mkdir -p "$out"
  local xtradef=""
  local xtra_incs=""
  if [ "$short" = "apple_csp" ]; then
    xtradef="GCC_PREPROCESSOR_DEFINITIONS=CK_SECURITY_BUILD=1 NDEBUG"
    xtra_incs="-I$SDK/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/Headers -I$PIECES/Headers/security_cryptkit"
  fi
  say "build $short [$arch] (target $tgt) $extra $xtradef"
  arch -$arch xcodebuild -project "$proj" -target "$tgt" \
    -configuration Deployment -sdk macosx10.6 \
    ARCHS=$arch VALID_ARCHS=$arch ONLY_ACTIVE_ARCH=NO \
    GCC_VERSION=com.apple.compilers.llvmgcc42 \
    GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
    $extra "$xtradef" \
    SYMROOT="$out/sym" OBJROOT="$out/obj" DSTROOT="$out/dst" \
    "HEADER_SEARCH_PATHS=$HDRS" "OTHER_CFLAGS=\$(inherited) $DEPR $xtra_incs" \
    install > "$out/build.log" 2>&1
  local errs=$(grep -c 'error:' "$out/build.log")
  new=$(find "$out/dst" -name "security_$short" -type f 2>/dev/null | head -1)
  if [ -z "$new" ] || [ "$errs" != "0" ]; then
    echo "  BUILD ISSUE $short/$arch: errors=$errs (log: $out/build.log)"
    grep 'error:' "$out/build.log" | head -3
    [ -z "$new" ] && return 1
  fi
  if [ "$arch" = "i386" ]; then symdir="$VM/sym-$short-i386"; else symdir="$VM/sym-$short"; fi
  mkdir -p "$symdir"
  symtarget="$symdir/security_$short"
  cp "$new" "$symtarget"
  echo "  staged $short/$arch -> $(readlink "$symtarget" 2>/dev/null || echo "$symtarget")"

  # cdsa_plugin's generator.pl emits the *abstractsession.h vtable interfaces.
  # STAGE=bootstrap runs it separately (installhdrs) and can emit a DIFFERENT
  # method ORDER than this component build does -- consumers then compile
  # against a vtable layout cdsa_plugin does not implement, and DL dispatch
  # lands in the wrong slot (CSSMERR_DL_INVALID_DB_HANDLE on keychain unlock,
  # diagnosed 2026-07-21). Re-stage the authoritative copies from THIS build so
  # every component compiled after cdsa_plugin sees the implementer's ordering.
  if [ "$short" = "cdsa_plugin" ]; then
    local absdst="$PIECES/Frameworks/security_cdsa_plugin.framework/Versions/A/Headers"
    local absn=0
    for absh in "$out"/sym/derived_src/*abstractsession.h; do
      [ -f "$absh" ] || continue
      cp "$absh" "$absdst/" 2>/dev/null || \
        echo "$PW" | sudo -S cp "$absh" "$absdst/" 2>/dev/null
      absn=$((absn+1))
    done
    [ "$absn" -gt 0 ] && echo "  re-staged $absn abstractsession header(s) from cdsa_plugin/$arch build"
  fi
  return 0
}

# inject keychain tls12_trusteval.o for one arch
# compile+inject the vendored cryptkit legacy-HMAC objects into apple_csp for one arch
inject_legacy_hmac() {
  local arch="$1" cspar o
  local CKV="$VM/cryptkit-vendor"
  local CSPLIB="$VM/libsecurity_apple_csp-55003/lib"
  local CARBON="$SDK/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/Headers"
  if [ "$arch" = "i386" ]; then cspar="$VM/sym-apple_csp-i386/security_apple_csp"; else cspar="$VM/sym-apple_csp/security_apple_csp"; fi
  cspar=$(readlink "$cspar" 2>/dev/null || echo "$cspar")
  [ -f "$cspar" ] || { echo "  (legacy-hmac: apple_csp/$arch archive not found)"; return 0; }
  o="/tmp/ckhmac-$arch"; rm -rf "$o"; mkdir -p "$o"
  local CF="-arch $arch -mmacosx-version-min=10.6 -DCK_SECURITY_BUILD -DNDEBUG -Os -isysroot $SDK -I$CSPLIB -I$PIECES/Headers -I$PIECES/Headers/security_cryptkit -I$PIECES/PrivateHeaders -I$CARBON"
  local rc=0
  for f in HmacSha1Legacy ckSHA1 ckSHA1_priv falloc; do
    arch -$arch /usr/bin/gcc $CF -c "$CSPLIB/$f.c" -o "$o/$f.o" 2>"$o/$f.err" || rc=1
  done
  if [ "$rc" = "0" ]; then
    ar r "$cspar" "$o"/HmacSha1Legacy.o "$o"/ckSHA1.o "$o"/ckSHA1_priv.o "$o"/falloc.o 2>/dev/null
    ranlib "$cspar" 2>/dev/null
    echo "  injected legacy-HMAC into apple_csp/$arch (hmacLegacy syms: $(nm "$cspar" 2>/dev/null | grep -c hmacLegacy))"
  else
    echo "  LEGACY-HMAC BUILD FAILED for $arch (see /tmp/ckhmac-$arch/*.err)"
  fi
}

inject_trusteval() {
  local arch="$1" kcar kcobj
  local KCLIB="$VM/libsecurity_keychain-55017/lib"
  [ -f "$KCLIB/tls12_trusteval.c" ] || return 0
  if [ "$arch" = "i386" ]; then kcar="$VM/sym-keychain-i386/security_keychain"; else kcar="$VM/sym-keychain/security_keychain"; fi
  kcar=$(readlink "$kcar" 2>/dev/null || echo "$kcar")
  [ -f "$kcar" ] || return 0
  arch -$arch "$GCC" -arch $arch -std=gnu99 -c "$KCLIB/tls12_trusteval.c" -o /tmp/tls12_trusteval_$arch.o \
    -isysroot "$SDK" -mmacosx-version-min=10.6 -include "$PREFIX" \
    -I"$PIECES/Headers" -I"$PIECES/PrivateHeaders" -I"$SDK/usr/include" -DNDEBUG 2>/dev/null \
    && ar r "$kcar" /tmp/tls12_trusteval_$arch.o 2>/dev/null \
    && echo "  injected tls12_trusteval.o into keychain/$arch"
}

if [ "$STAGE" = "bootstrap" ]; then
  # =========================================================================
  # STAGE=bootstrap -- populate /usr/local/SecurityPieces on a VIRGIN machine.
  #
  # WHY THIS EXISTS: every other stage READS $PIECES (HEADER_SEARCH_PATHS,
  # FRAMEWORK_SEARCH_PATHS) and stage_component_headers() only CORRECTS headers
  # that are already present -- its inner loop is `find $PIECES -name <hdr>`, so
  # on an empty tree it stages nothing and every compile fails on missing
  # headers. PREREQUISITES.md Stage 2 said to populate it "by installhdrs OR by
  # copying the tree from a known-good VM snapshot", and in practice this project
  # always did the latter -- which is exactly why a foreign AuthorizationData.h
  # could sit in PrivateHeaders/ for weeks and SIGSEGV securityd (2026-07-18).
  # A snapshot-seeded tree is not reproducible and not auditable. This stage
  # builds it from the SAME version-pinned sources the archives are built from.
  #
  # RUN ONCE per machine, before STAGE=all:
  #     STAGE=bootstrap bash build-consistent-framework.sh
  #     STAGE=all       bash build-consistent-framework.sh
  # It is deliberately NOT part of STAGE=all: installhdrs is slow, and re-running
  # it mid-project could re-export headers from a project whose pin later changed.
  #
  # xcodebuild is NOT run as root. Each component exports to a user-writable
  # DSTROOT, then the tree is sudo-copied into $PIECES.
  # =========================================================================
  say "STAGE bootstrap: populate $PIECES from version-pinned sources"
  echo "  headers present before: $(find "$PIECES" -name '*.h' 2>/dev/null | wc -l | tr -d ' ')"

  echo "$PW" | sudo -S mkdir -p "$PIECES/Headers" "$PIECES/PrivateHeaders" \
      "$PIECES/Frameworks" "$PIECES/Components/Security" 2>/dev/null

  BOOT_FAIL=""
  for c in $COMPS ssl; do
    # resolve source the same way build_component does (comp_ver pin, dual naming)
    bver=$(comp_ver "$c"); bvernum="${bver##*-}"
    bsrc=""
    if [ -n "$bvernum" ]; then
      if   [ -d "$VM/libsecurity_${c}-${bvernum}" ]; then bsrc="$VM/libsecurity_${c}-${bvernum}"
      elif [ -d "$VM/libsecurity_${c}-libsecurity_${c}-${bvernum}" ]; then bsrc="$VM/libsecurity_${c}-libsecurity_${c}-${bvernum}"
      else bsrc=$(ls -d "$VM"/libsecurity_${c}*-${bvernum} 2>/dev/null | head -1); fi
    fi
    [ -z "$bsrc" ] && bsrc=$(ls -d "$VM"/libsecurity_${c}-* 2>/dev/null | head -1)
    if [ -z "$bsrc" ]; then echo "  SKIP $c (no source)"; BOOT_FAIL="$BOOT_FAIL $c"; continue; fi

    bproj=$(ls -d "$bsrc"/*.xcodeproj 2>/dev/null | head -1)
    bout="$VM/cc-build/hdrs-$c"; rm -rf "$bout"; mkdir -p "$bout/dst"

    # Copy lib/*.h directly into Headers/security_<short>/.
    # Used when the project has no xcodeproj, when installhdrs exports nothing
    # (CDSA *plugin* projects -- apple_x509_tp/cl, apple_file_dl, apple_cspdl,
    # apple_csp, sd_cspdl -- define no header-install phase but DO have headers
    # other components include), or when the project cannot build at all
    # (checkpw-55471 wants config/*.xcconfig from the later Security tree).
    copy_lib_headers() {
      local c="$1" src="$2" n=0
      [ -d "$src/lib" ] || { echo "  SKIP $c (no lib/)"; return 1; }
      echo "$PW" | sudo -S mkdir -p "$PIECES/Headers/security_$c" 2>/dev/null
      mkdir -p "$PIECES/Headers/security_$c" 2>/dev/null
      for h in "$src"/lib/*.h; do
        [ -f "$h" ] || continue
        cp "$h" "$PIECES/Headers/security_$c/" 2>/dev/null || \
          echo "$PW" | sudo -S cp "$h" "$PIECES/Headers/security_$c/" 2>/dev/null
        n=$((n+1))
      done
      echo "  $c: copied $n header(s) from lib/ directly"
      [ "$n" -gt 0 ]
    }

    # NOTE: an earlier version of this bootstrap ALSO flattened every component's
    # lib/*.h into Headers/Security/ and PrivateHeaders/Security/, on the theory
    # that slqemu's 448-file umbrella dir was "every component's headers".
    # That was WRONG and actively harmful: installhdrs already exports the right
    # files there (keychain's SecItem.h, 33668 bytes, verified byte-identical to
    # both its own lib/ copy AND the 10.6 SDK's), and the flatten then clobbered
    # them in component order with whatever else happened to share a name --
    # leaving a 4100-byte SecItem.h and breaking keychain with
    # "'kSecAttrKeyType' was not declared in this scope".
    # Do not reintroduce it. If a header is genuinely missing, find out which
    # project is supposed to export it rather than copying files around.

    if [ -z "$bproj" ]; then
      copy_lib_headers "$c" "$bsrc" || BOOT_FAIL="$BOOT_FAIL $c"
      continue
    fi

    btgt=$(xcodebuild -project "$bproj" -list 2>/dev/null | awk '/Targets:/{f=1;next} f&&NF{print $1; exit}')
    xcodebuild -project "$bproj" -target "$btgt" \
      -configuration Deployment -sdk macosx10.6 \
      GCC_VERSION=com.apple.compilers.llvmgcc42 \
      GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
      DSTROOT="$bout/dst" OBJROOT="$bout/obj" SYMROOT="$bout/sym" \
      "HEADER_SEARCH_PATHS=$HDRS" \
      installhdrs > "$bout/installhdrs.log" 2>&1

    # installhdrs writes the exported tree under DSTROOT/usr/local/SecurityPieces
    bexp="$bout/dst$PIECES"
    bn=0
    if [ -d "$bexp" ]; then
      bn=$(find "$bexp" -name '*.h' 2>/dev/null | wc -l | tr -d ' ')
    fi
    if [ "$bn" -gt 0 ]; then
      # copy preserving the exported layout (Headers/, PrivateHeaders/,
      # Components/Security/security_<c>.framework/...)
      ( cd "$bexp" && tar cf - . ) | ( cd /tmp && rm -rf bootcopy && mkdir bootcopy && cd bootcopy && tar xf - )
      ( cd /tmp/bootcopy && tar cf - . ) | ( cd "$PIECES" && tar xf - ) 2>/dev/null || \
        echo "$PW" | sudo -S sh -c "cd /tmp/bootcopy && tar cf - . | (cd '$PIECES' && tar xf -)" 2>/dev/null
      rm -rf /tmp/bootcopy
      echo "  $c ($(basename "$bsrc")): exported $bn header(s)"
    else
      # installhdrs produced nothing. CDSA plugin projects define no
      # header-install phase, but their lib/*.h ARE included by other
      # components, so fall back to copying them directly.
      echo "  $c ($(basename "$bsrc")): installhdrs exported 0 -- falling back to lib/"
      copy_lib_headers "$c" "$bsrc" || BOOT_FAIL="$BOOT_FAIL $c"
    fi
  done

  echo "  headers present after:  $(find "$PIECES" -name '*.h' 2>/dev/null | wc -l | tr -d ' ')"
  echo "  umbrella: Headers/Security=$(ls "$PIECES/Headers/Security" 2>/dev/null | wc -l | tr -d ' ') PrivateHeaders/Security=$(ls "$PIECES/PrivateHeaders/Security" 2>/dev/null | wc -l | tr -d ' ')"
  [ -n "$BOOT_FAIL" ] && echo "  COMPONENTS WITH NO HEADERS EXPORTED:$BOOT_FAIL"

  # -----------------------------------------------------------------------
  # Extra headers that no component exports.
  #
  # priv-headers/ : private Apple headers absent from the 10.6 public SDK
  #                 (CFBundlePriv.h, AuthSession.h, CSCommon.h, dtrace glue).
  # stubs/        : shims for things 10.6 genuinely lacks (CFRuntime.h,
  #                 sys/codesign.h, audit_session.h, fileport.h, fsctl.h,
  #                 membershipPriv.h, sandbox_rights_compat.h,
  #                 SecBaseTimestampErrors.h).
  #
  # Until 2026-07-19 these were hand-staged into SecurityPieces once, on one
  # machine, and referenced by nothing -- so a second machine failed with
  # "CoreFoundation/CFRuntime.h: No such file or directory" across
  # utilities/keychain/pkcs12/cms. Layout mirrors slqemu's working tree:
  # everything flat under Headers/<subdir>/.
  # -----------------------------------------------------------------------
  say "STAGE bootstrap: extra headers (priv-headers + stubs)"
  stage_extra() {
    local src="$1" label="$2" n=0 rel d
    [ -d "$src" ] || { echo "  ($label absent: $src)"; return 0; }
    ( cd "$src" && find . -name '*.h' ) | sed 's|^\./||' | while read rel; do
      d=$(dirname "$rel")
      mkdir -p "$PIECES/Headers/$d" 2>/dev/null || \
        echo "$PW" | sudo -S mkdir -p "$PIECES/Headers/$d" 2>/dev/null
      cp "$src/$rel" "$PIECES/Headers/$rel" 2>/dev/null || \
        echo "$PW" | sudo -S cp "$src/$rel" "$PIECES/Headers/$rel" 2>/dev/null
    done
    n=$( ( cd "$src" && find . -name '*.h' ) | wc -l | tr -d ' ' )
    echo "  $label: staged $n header(s)"
  }
  stage_extra "$VM/priv-headers" "priv-headers"
  stage_extra "$VM/stubs" "stubs"

  # Some headers are included under a DIFFERENT directory name than the one the
  # exporting component uses, so stage the extra spellings explicitly:
  #   <Security/AuthSession.h>      (authorization) and <authorization/AuthSession.h>
  #   <Security/checkpw.h>          (cdsa_utilities/AuthorizationData.cpp) --
  #                                 checkpw exports to Headers/security_checkpw/
  if [ -f "$VM/priv-headers/AuthSession.h" ]; then
    for d in Security authorization; do
      mkdir -p "$PIECES/Headers/$d" 2>/dev/null
      cp "$VM/priv-headers/AuthSession.h" "$PIECES/Headers/$d/" 2>/dev/null
    done
    echo "  AuthSession.h staged as Security/ and authorization/"
  fi
  {
    cpwh=$(ls "$VM"/libsecurity_checkpw*/lib/checkpw.h 2>/dev/null | head -1)
    if [ -n "$cpwh" ]; then
      mkdir -p "$PIECES/Headers/Security" 2>/dev/null
      cp "$cpwh" "$PIECES/Headers/Security/" 2>/dev/null
      echo "  checkpw.h staged as Security/checkpw.h"
    fi
  }

  # securityd_client headers: use the REAL ones from libsecurityd, NOT a stub.
  # stubs/securityd_client/ssclient.h is an empty shim from when only
  # dlclientpriv.cpp ("currently empty") included it. apple_cspdl, sd_cspdl, mds
  # and authorization now use real SecurityServer::ClientSession symbols, so the
  # shim produces "'SecurityServer' has not been declared" everywhere. The stub's
  # own header comment says to replace it once that happens -- this is that.
  if [ -d "$VM/$LIBSECURITYD_DIR/lib" ]; then
    mkdir -p "$PIECES/Headers/securityd_client" 2>/dev/null
    for h in "$VM/$LIBSECURITYD_DIR"/lib/*.h; do
      [ -f "$h" ] && cp "$h" "$PIECES/Headers/securityd_client/" 2>/dev/null
    done
    # MIG interface definitions too: SecurityTokend's mig/tokend.defs does
    # `#include <securityd_client/ss_types.defs>`, and mig resolves that through
    # the same header search path. Staging only *.h left tokend_client failing
    # with "ss_types.defs: No such file or directory" on both arches.
    for d in "$VM/$LIBSECURITYD_DIR"/mig/*.defs; do
      [ -f "$d" ] && cp "$d" "$PIECES/Headers/securityd_client/" 2>/dev/null
    done
    echo "  securityd_client: staged $(ls "$VM/$LIBSECURITYD_DIR"/lib/*.h 2>/dev/null | wc -l | tr -d ' ') header(s) + $(ls "$VM/$LIBSECURITYD_DIR"/mig/*.defs 2>/dev/null | wc -l | tr -d ' ') defs from $LIBSECURITYD_DIR"

    # ALSO stage them framework-style. SecurityTokend's mig step resolves
    # <securityd_client/ss_types.defs> through FRAMEWORK_SEARCH_PATHS, i.e.
    # securityd_client.framework/Headers/ss_types.defs -- NOT through
    # Headers/securityd_client/. On slqemu that framework exists only because
    # STEP 4's i386-chain fat_stage created it during earlier builds, so a fresh
    # machine failed with "ss_types.defs: No such file or directory" while the
    # file sat correctly in Headers/securityd_client/.
    SDCFW="$PIECES/Frameworks/securityd_client.framework/Versions/A/Headers"
    mkdir -p "$SDCFW" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$SDCFW" 2>/dev/null
    for f in "$VM/$LIBSECURITYD_DIR"/lib/*.h "$VM/$LIBSECURITYD_DIR"/mig/*.defs; do
      [ -f "$f" ] && { cp "$f" "$SDCFW/" 2>/dev/null || echo "$PW" | sudo -S cp "$f" "$SDCFW/" 2>/dev/null; }
    done
    ( cd "$PIECES/Frameworks/securityd_client.framework" 2>/dev/null && \
      { [ -e Versions/Current ] || ln -s A Versions/Current 2>/dev/null; \
        [ -e Headers ] || ln -s Versions/Current/Headers Headers 2>/dev/null; } )
    echo "  securityd_client.framework/Headers: $(ls "$SDCFW" 2>/dev/null | wc -l | tr -d ' ') file(s)"

    # securityd includes the SAME headers under a securityd_server/ spelling --
    # src/acls.h does #include <securityd_server/sscommon.h>. sscommon.h is a
    # plain source file (libsecurityd-37613/lib/sscommon.h), not generated; only
    # the directory name differs. Without it securityd fails with
    # "'SecurityServer' is not a namespace-name" and a cascade of AclKind /
    # Tokend / QueryPIN errors that look unrelated.
    SDSFW="$PIECES/Frameworks/securityd_server.framework/Versions/A/Headers"
    for d in "$PIECES/Headers/securityd_server" "$SDSFW" \
             "$PIECES/Components/securityd/securityd_server.framework/Versions/A/Headers"; do
      mkdir -p "$d" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$d" 2>/dev/null
      for f in "$VM/$LIBSECURITYD_DIR"/lib/*.h "$VM/$LIBSECURITYD_DIR"/mig/*.defs; do
        [ -f "$f" ] && { cp "$f" "$d/" 2>/dev/null || echo "$PW" | sudo -S cp "$f" "$d/" 2>/dev/null; }
      done
    done
    ( cd "$PIECES/Frameworks/securityd_server.framework" 2>/dev/null && \
      { [ -e Versions/Current ] || ln -s A Versions/Current 2>/dev/null; \
        [ -e Headers ] || ln -s Versions/Current/Headers Headers 2>/dev/null; } )
    echo "  securityd_server: staged $(ls "$PIECES/Headers/securityd_server" 2>/dev/null | wc -l | tr -d ' ') file(s)"
  else
    echo "  WARN $LIBSECURITYD_DIR/lib missing -- securityd_client headers unavailable"
  fi

  # SecurityTokend + libsecurity_agent headers.
  # securityd's src/tokend.h needs the Tokend:: namespace (tokend_types.h,
  # tdclient.h, tdtransit.h, SecTokend.h) or it fails with "'Tokend' has not been
  # declared" / "'Score' in class 'TokenDaemon' does not name a type", which then
  # cascades into unrelated-looking errors like "class QueryPIN has no member
  # named inferHints". libsecurity_agent's headers are needed the same way.
  # Both are plain source headers in lib/ -- nothing generated -- so they can be
  # staged up front. They were hand-staged on slqemu long ago and recorded
  # nowhere, so the Mac mini had no tokend headers at all (2026-07-20).
  # Directory names here are the ones the CONSUMERS spell in their #includes,
  # not the source project names:
  #   securityd's src/tokend.h does #include <security_tokend_client/tdclient.h>
  #   (staging to Headers/SecurityTokend/ resolves nothing -- the include fails
  #   silently as far as the namespace goes and you get
  #   "expected `{' before 'ClientSession'" / "'Score' ... does not name a type")
  for pair in "SecurityTokend:security_tokend_client" "SecurityTokend:SecurityTokend" "libsecurity_agent:security_agent_client"; do
    esrc=$(ls -d "$VM"/${pair%%:*}-* 2>/dev/null | head -1)
    edst="${pair##*:}"
    if [ -n "$esrc" ] && [ -d "$esrc/lib" ]; then
      mkdir -p "$PIECES/Headers/$edst" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$PIECES/Headers/$edst" 2>/dev/null
      for h in "$esrc"/lib/*.h; do
        [ -f "$h" ] && { cp "$h" "$PIECES/Headers/$edst/" 2>/dev/null || \
          echo "$PW" | sudo -S cp "$h" "$PIECES/Headers/$edst/" 2>/dev/null; }
      done
      # framework-style too, matching securityd_client above
      efw="$PIECES/Frameworks/${edst}.framework/Versions/A/Headers"
      mkdir -p "$efw" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$efw" 2>/dev/null
      for h in "$esrc"/lib/*.h; do
        [ -f "$h" ] && { cp "$h" "$efw/" 2>/dev/null || echo "$PW" | sudo -S cp "$h" "$efw/" 2>/dev/null; }
      done
      ( cd "$PIECES/Frameworks/${edst}.framework" 2>/dev/null && \
        { [ -e Versions/Current ] || ln -s A Versions/Current 2>/dev/null; \
          [ -e Headers ] || ln -s Versions/Current/Headers Headers 2>/dev/null; } )
      echo "  $edst: staged $(ls "$esrc"/lib/*.h 2>/dev/null | wc -l | tr -d ' ') header(s) from $(basename "$esrc")"
    else
      echo "  WARN no source for ${pair%%:*} -- $edst headers unavailable"
    fi
  done

  echo "  headers present after extras: $(find "$PIECES" -name '*.h' 2>/dev/null | wc -l | tr -d ' ')"

  # -----------------------------------------------------------------------
  # antlr.jar -- build TOOL, not a header.
  #
  # libsecurity_codesigning's "Requirements Language" aggregate target runs:
  #     antlr=/usr/local/bin/antlr.jar
  #     java -cp "$antlr" antlr.Tool -o $TEMPDIR requirements.grammar
  # to generate RequirementParser/Lexer + RequirementKeywords.h. build_component
  # builds the 'Everything' target (first in xcodebuild -list), which depends on
  # that aggregate -- so WITHOUT the jar the whole codesigning build fails and
  # stages no archive, with errors=0 because there are no compiler errors.
  #
  # slqemu had it at /usr/local/bin/antlr.jar since 2026-06-19; nothing in the
  # project recorded that, so the Mac mini failed here (2026-07-20). ANTLR 2.7.7
  # is BSD-licensed and redistributable, so it is vendored at vendor/antlr.jar.
  # -----------------------------------------------------------------------
  if [ ! -f /usr/local/bin/antlr.jar ]; then
    if [ -f "$VM/vendor/antlr.jar" ]; then
      mkdir -p /usr/local/bin 2>/dev/null || echo "$PW" | sudo -S mkdir -p /usr/local/bin 2>/dev/null
      cp "$VM/vendor/antlr.jar" /usr/local/bin/antlr.jar 2>/dev/null || \
        echo "$PW" | sudo -S cp "$VM/vendor/antlr.jar" /usr/local/bin/antlr.jar 2>/dev/null
      if [ -f /usr/local/bin/antlr.jar ]; then
        echo "  antlr.jar installed to /usr/local/bin (needed by codesigning's Requirements Language target)"
      else
        echo "  WARN could not install antlr.jar -- codesigning will fail to stage an archive"
      fi
    else
      echo "  WARN vendor/antlr.jar missing AND /usr/local/bin/antlr.jar absent --"
      echo "       codesigning's Requirements Language target will fail (ANTLR 2.7.7 needed)"
    fi
  else
    echo "  antlr.jar already present at /usr/local/bin"
  fi

  # -----------------------------------------------------------------------
  # SSL TRUST ANCHORS.
  # ssl_anchors.pem is the anchor bundle the patched SecTrust path evaluates
  # against (217 certs incl. the ISRG/Let's Encrypt roots added by
  # add-isrg-roots.sh). It is NOT generated by any build step -- slqemu had it
  # since 2026-07-18 with no record of where from, so it is vendored at
  # vendor/anchors/ssl_anchors.pem. Without it cert validation has no roots.
  # -----------------------------------------------------------------------
  if [ ! -f "$PIECES/ssl_anchors.pem" ]; then
    if [ -f "$VM/vendor/anchors/ssl_anchors.pem" ]; then
      cp "$VM/vendor/anchors/ssl_anchors.pem" "$PIECES/ssl_anchors.pem" 2>/dev/null || \
        echo "$PW" | sudo -S cp "$VM/vendor/anchors/ssl_anchors.pem" "$PIECES/ssl_anchors.pem" 2>/dev/null
      if [ -f "$PIECES/ssl_anchors.pem" ]; then
        echo "  ssl_anchors.pem staged ($(grep -c 'BEGIN CERTIFICATE' "$PIECES/ssl_anchors.pem" 2>/dev/null | tr -d ' ') certs)"
      else
        echo "  WARN could not stage ssl_anchors.pem -- cert validation will have no anchors"
      fi
    else
      echo "  WARN vendor/anchors/ssl_anchors.pem missing AND $PIECES/ssl_anchors.pem absent"
    fi
  else
    echo "  ssl_anchors.pem already present ($(grep -c 'BEGIN CERTIFICATE' "$PIECES/ssl_anchors.pem" 2>/dev/null | tr -d ' ') certs)"
  fi

  # ANTLR C++ RUNTIME HEADERS.
  # The code antlr.Tool generates (RequirementParser/Lexer.{hpp,cpp}) #includes
  # <antlr/config.hpp>, <antlr/LLkParser.hpp>, <antlr/ASTFactory.hpp> and ~10
  # more. Without them codesigning compiles the generated parser and fails with
  # 32 "antlr/*.hpp: No such file or directory" errors -- which only appear once
  # the jar IS installed, so fixing the jar alone moves the failure rather than
  # removing it. Stock ANTLR 2.7.7 lib/cpp/antlr, same release as the jar.
  # slqemu had them at Headers/antlr/; nothing recorded that either.
  if [ -d "$VM/vendor/antlr-cpp/antlr" ]; then
    mkdir -p "$PIECES/Headers/antlr" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$PIECES/Headers/antlr" 2>/dev/null
    for h in "$VM"/vendor/antlr-cpp/antlr/*.hpp; do
      [ -f "$h" ] && { cp "$h" "$PIECES/Headers/antlr/" 2>/dev/null || \
        echo "$PW" | sudo -S cp "$h" "$PIECES/Headers/antlr/" 2>/dev/null; }
    done
    echo "  antlr C++ runtime: staged $(ls "$PIECES/Headers/antlr"/*.hpp 2>/dev/null | wc -l | tr -d ' ') header(s)"
  elif [ -d "$PIECES/Headers/antlr" ]; then
    echo "  antlr C++ runtime already staged"
  else
    echo "  WARN vendor/antlr-cpp/antlr missing -- codesigning's generated parser will not compile"
  fi

  # -----------------------------------------------------------------------
  # MIG-generated interface headers.
  #
  # codesigning's csgeneric.cpp does #include <securityd_client/cshosting.h>,
  # which is NOT a source file -- mig generates it from libsecurityd's
  # mig/cshosting.defs. Same for ucsp.h / ucspNotify.h. On slqemu these were
  # present because STEP 4 had generated them in earlier runs and the output was
  # staged; on a fresh machine STEP 2 runs first and codesigning fails with
  # "securityd_client/cshosting.h: No such file or directory" (38 errors).
  #
  # libsecurityd has a dedicated 'generate mig' target for exactly this, and it
  # depends on nothing we build (its pbxproj references no libsecurity_*), so it
  # can run here in the bootstrap rather than forcing a build reorder.
  # -----------------------------------------------------------------------
  if [ -f "$VM/$LIBSECURITYD_DIR/libsecurityd.xcodeproj/project.pbxproj" ]; then
    migout="$VM/cc-build/mig-bootstrap"
    rm -rf "$migout"; mkdir -p "$migout"
    ( cd "$VM/$LIBSECURITYD_DIR" && xcodebuild -target 'generate mig' \
        -configuration Deployment -sdk macosx10.6 \
        DSTROOT="$migout/dst" OBJROOT="$migout/obj" SYMROOT="$migout/sym" \
        > "$migout/mig.log" 2>&1 )
    mign=0
    for h in "$migout"/sym/derived_src/*.h; do
      [ -f "$h" ] || continue
      for d in "$PIECES/Headers/securityd_client" \
               "$PIECES/Frameworks/securityd_client.framework/Versions/A/Headers" \
               "$PIECES/Headers/securityd_server" \
               "$PIECES/Frameworks/securityd_server.framework/Versions/A/Headers" \
               "$PIECES/Components/securityd/securityd_server.framework/Versions/A/Headers"; do
        mkdir -p "$d" 2>/dev/null || echo "$PW" | sudo -S mkdir -p "$d" 2>/dev/null
        cp "$h" "$d/" 2>/dev/null || echo "$PW" | sudo -S cp "$h" "$d/" 2>/dev/null
      done
      mign=$((mign+1))
    done
    if [ "$mign" -gt 0 ]; then
      echo "  mig: generated + staged $mign header(s) ($(ls "$migout"/sym/derived_src/*.h 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ' '))"
    else
      echo "  WARN 'generate mig' produced no headers (log: $migout/mig.log)"
      grep -iE 'error' "$migout/mig.log" 2>/dev/null | head -3
    fi
  else
    echo "  WARN $LIBSECURITYD_DIR xcodeproj missing -- cannot generate mig headers"
  fi

  # -----------------------------------------------------------------------
  # ANTLR C++ RUNTIME LIBRARY.
  #
  # link-fat-framework.sh passes -L$VM/antlr-cpp and the codesigning objects
  # reference the ANTLR runtime, so libantlr.a (x86_64) and libantlr_i386.a must
  # exist there. slqemu had them prebuilt since June with no record of where
  # from; we vendor the stock ANTLR 2.7.7 lib/cpp sources instead and compile
  # here, so the library is derived rather than copied between machines.
  # -----------------------------------------------------------------------
  if [ -d "$VM/vendor/antlr-cpp/src" ]; then
    mkdir -p "$VM/antlr-cpp" 2>/dev/null
    for a in x86_64 i386; do
      case "$a" in x86_64) outlib="$VM/antlr-cpp/libantlr.a";; i386) outlib="$VM/antlr-cpp/libantlr_i386.a";; esac
      if [ -f "$outlib" ]; then
        echo "  antlr runtime $a already built ($(basename "$outlib"))"
        continue
      fi
      ao="$VM/cc-build/antlr-$a"; rm -rf "$ao"; mkdir -p "$ao"
      for s in "$VM"/vendor/antlr-cpp/src/*.cpp; do
        [ -f "$s" ] || continue
        case "$(basename "$s")" in dll.cpp) continue;; esac
        arch -$a /Developer/usr/bin/llvm-g++-4.2 -arch $a -Os -DNDEBUG=1 \
          -I"$VM/vendor/antlr-cpp" -I"$PIECES/Headers" \
          -c "$s" -o "$ao/$(basename "${s%.cpp}").o" >> "$ao/build.log" 2>&1
      done
      if ls "$ao"/*.o >/dev/null 2>&1; then
        rm -f "$outlib"; ar qc "$outlib" "$ao"/*.o && ranlib "$outlib" 2>/dev/null
        echo "  antlr runtime $a: built $(ls "$ao"/*.o | wc -l | tr -d ' ') object(s) -> $(basename "$outlib")"
      else
        echo "  WARN antlr runtime $a build produced no objects (log: $ao/build.log)"
        grep -i 'error' "$ao/build.log" 2>/dev/null | head -3
      fi
    done
  else
    echo "  WARN vendor/antlr-cpp/src missing -- cannot build the ANTLR runtime"
  fi

  # -----------------------------------------------------------------------
  # Security.exp -- the framework's exported-symbols list.
  #
  # link-fat-framework.sh passes -exported_symbols_list $VM/Security.exp.
  # slqemu had a 1528-symbol file dated June with no recorded origin. It is
  # DERIVABLE: concatenate the per-component security_*.exp files from the
  # PINNED sources, drop comments and blanks, sort -u.
  #
  # Two gotchas, both found the hard way on the Mac mini (2026-07-20):
  #  - several .exp files have NO trailing newline, so `cat` fuses the last
  #    symbol of one onto the first line of the next -> ld: Undefined symbols
  #    "_MDS_RemoveSubservice#" referenced from -exported_symbol[s_list].
  #  - _CSSM_SPI_Module{Attach,Detach,Load,Unload} appear in some component .exp
  #    files but are compiled HIDDEN in apple_x509_cl (and friends):
  #    "ld: warning: cannot export hidden symbol _CSSM_SPI_ModuleAttach".
  #    slqemu's list omits them. Filter them out.
  # -----------------------------------------------------------------------
  {
    # NOTE: iterate $COMPS *plus ssl*. ssl is deliberately not in COMPS (it is
    # built and patched separately in STEP 3/3b), but its 79 exported symbols
    # (_SSLHandshake, _SSLCopyPeerTrust, _SSLSetPeerDomainName ...) still belong
    # in the framework's export list. Omitting them meant ld had no reason to
    # pull ANY member out of the ssl static archive: with -dead_strip and
    # -exported_symbols_list, an archive whose symbols are neither referenced nor
    # exported is simply skipped. The link then "succeeded" at 26/26 archives
    # while producing a framework with NO SSL at all -- link-fat-framework.sh's
    # own check said "XX MISSING _SSLHandshake" and the build carried on.
    for c in $COMPS ssl; do
      cver=$(comp_ver "$c"); cvernum="${cver##*-}"
      csrc=$(ls -d "$VM"/libsecurity_${c}*-${cvernum} 2>/dev/null | head -1)
      [ -n "$csrc" ] || continue
      for e in "$csrc"/lib/*.exp; do
        # awk (not cat) because several .exp files have NO trailing newline --
        # cat glues their last symbol onto the next file's first line, producing
        # junk like "_MDS_RemoveSubservice#" which ld then reports as an
        # undefined symbol referenced from the -exported_symbols_list option.
        [ -f "$e" ] && awk '{print}' "$e"
      done
    done
  } | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' \
    | grep -vE '^_CSSM_SPI_Module(Attach|Detach|Load|Unload)$' \
    | sort -u > "$VM/Security.exp.new" 2>/dev/null
  if [ -s "$VM/Security.exp.new" ]; then
    mv "$VM/Security.exp.new" "$VM/Security.exp"
    echo "  Security.exp: generated $(wc -l < "$VM/Security.exp" | tr -d ' ') exported symbol(s) from the pinned .exp files"
  else
    rm -f "$VM/Security.exp.new"
    echo "  WARN could not generate Security.exp"
  fi

  # Now correct anything installhdrs exported from a project whose headers differ
  # from the pinned source (belt and braces -- same pass STEP 0 runs).
  say "STAGE bootstrap: sync exported headers to the PINNED versions"
  for c in cdsa_utilities utilities cdsa_client cssm cdsa_plugin authorization; do
    stage_component_headers "$c"
  done

  echo ""
  echo "Bootstrap done. Next: STAGE=all bash build-consistent-framework.sh"
fi

if [ "$STAGE" = "all" ] || [ "$STAGE" = "components" ]; then
  say "STEP 0: sync staged SecurityPieces headers to the PINNED component versions"
  # MUST run before any compile. Stale staged headers from a foreign Security
  # release cause ODR/layout skew against the archives we build -- see the
  # stage_component_headers() comment for the securityd SIGSEGV this caused.
  for c in cdsa_utilities utilities cdsa_client cssm cdsa_plugin authorization; do
    stage_component_headers "$c"
  done

  say "STEP 1: source patches (idempotent)"

  # -----------------------------------------------------------------------
  # STEP 1a: install OUR source files into the (pristine) Apple trees.
  #
  # sources/ holds PRISTINE Apple source only -- verifiable byte-for-byte
  # against opensource.apple.com. Everything we wrote lives in src/ and is
  # copied in here; everything we changed in an Apple file is a patch in
  # patches/. That separation is deliberate: before 2026-07-19 the trees were a
  # mix of pristine and silently-edited files, and answering "is this ours or
  # Apple's?" required diffing against a git tag every time -- which is exactly
  # how a foreign AuthorizationData.h went unnoticed for weeks.
  # -----------------------------------------------------------------------
  install_our_source() {
    local f="$1" dest="$2"
    if [ -f "$VM/src/$f" ]; then
      if [ ! -d "$dest" ]; then echo "  (our-src: $dest missing, skipping $f)"; return 0; fi
      if ! diff -q "$VM/src/$f" "$dest/$f" >/dev/null 2>&1; then
        cp "$VM/src/$f" "$dest/$f"
        echo "  installed src/$f -> $(basename "$dest")"
      fi
    else
      echo "  WARN src/$f MISSING -- build will lack it"
    fi
  }
  install_our_source tls12_trusteval.c   "$VM/libsecurity_keychain-55017/lib"
  # ssl add-on sources. NOTE: none of these are in libsecurity_ssl.xcodeproj --
  # merge-ssl-addons.sh / build-ssl-patched.sh compile them by hand and ar them
  # into the archive, so they must be present in lib/ before STEP 3b runs.
  for f in tls12_chainverify.c tls12Callouts.c \
           sslGcm.c sslGcm.h sslGcmAes.c sslGcmAes.h sslGcmCipher.c sslGcmCipher.h; do
    install_our_source "$f" "$VM/libsecurity_ssl-55002/lib"
  done

  # -----------------------------------------------------------------------
  # STEP 1b: apply patches to Apple files. Each is grep-guarded so a second run
  # is a no-op, and `patch --dry-run` decides before touching anything. -t keeps
  # patch from ever prompting (a bad -p level otherwise hangs the build).
  #
  # apply_patch <patchfile> <workdir> <strip> <guardfile> <guardstring>
  #   workdir  : cd here before patching (the dir the diff paths are relative to)
  #   strip    : -p level. Patches are generated with absolute paths
  #              (diff -u /tmp/<pristine>/lib/X ...), so single-file keychain
  #              patches use -p0 with the target named explicitly, and the ssl
  #              tree patch uses -p4 from inside lib/.
  #   guard*   : if <guardstring> is already in <guardfile>, the patch is done.
  # -----------------------------------------------------------------------
  apply_patch() {
    local pf="$1" wd="$2" strip="$3" gf="$4" gs="$5"
    [ -f "$VM/patches/$pf" ] || { echo "  (patch $pf absent)"; return 0; }
    [ -d "$wd" ] || { echo "  (patch workdir $wd absent)"; return 0; }
    if [ -f "$wd/$gf" ] && grep -q -e "$gs" "$wd/$gf" 2>/dev/null; then
      echo "  $pf already applied"
      return 0
    fi
    if ( cd "$wd" && patch --dry-run -t -p"$strip" < "$VM/patches/$pf" ) >/dev/null 2>&1; then
      ( cd "$wd" && patch -t -p"$strip" < "$VM/patches/$pf" ) >/dev/null 2>&1
      # Verify rather than trust the exit status: a patch can report success
      # while leaving the guarded file untouched if the -p level resolves to a
      # different copy. Confirm the marker is actually present now.
      if [ -f "$wd/$gf" ] && grep -q -e "$gs" "$wd/$gf" 2>/dev/null; then
        echo "  applied $pf"
      else
        echo "  PATCH REPORTED OK BUT GUARD STILL ABSENT: $pf ($gf lacks '$gs')"
      fi
    else
      echo "  PATCH WOULD NOT APPLY: $pf (target not pristine?)"
    fi
  }

  # keychain: EC-leaf SecTrust fallback hook + EV pre-check guard
  apply_patch keychain-55017-Trust.cpp.patch \
              "$VM/libsecurity_keychain-55017/lib" 4 \
              Trust.cpp "tls12TrustEvaluateOpenSSL"
  # keychain: stub out submitDotMac. security_dotmac_tp/dotMacTp.h is not in our
  # source set (the .Mac cert service was decommissioned ~2012), so the pristine
  # file cannot compile here.
  apply_patch keychain-55017-CertificateRequest.cpp.patch \
              "$VM/libsecurity_keychain-55017/lib" 4 \
              CertificateRequest.cpp "decommissioned"
  # ssl: the TLS 1.2 backport across 23 Apple files (cipher specs, handshake,
  # key exchange, digests, HMAC, callouts). Too integrated to express as
  # separate edits -- one tree patch, regenerable with:
  #   diff -ru <pristine>/lib sources/libsecurity_ssl-55002/lib | grep -v '^Only in'
  apply_patch ssl-55002-tls12-backport.patch \
              "$VM/libsecurity_ssl-55002/lib" 4 \
              tls_ssl.h "Tls12Callouts"
  # utilities: three 10.7-only SPIs the 10.6 SDK lacks --
  #   osxcode.cpp  _CFBundleCopyMainBundleExecutableURL (CFBundlePriv.h) -> public
  #                CFBundle API. NOTE this hunk ALSO inverts the SecCodeCopySelf
  #                test: pristine returns OSXCodeWrap when the call FAILS
  #                (OSStatus != 0), which is backwards; ours returns it on
  #                success. That is a real behavioural correction, not a typo.
  #   vproc++.cpp  _vproc_transaction_count (vproc_priv.h) -> return 0; the
  #                accessor is debug-only.
  #   hashing.*    re-adds the Apple license header the 55010 tag is missing.
  apply_patch utilities-55010-sl-compat.patch \
              "$VM/libsecurity_utilities-55010/lib" 4 \
              "vproc++.cpp" "SL-BACKPORT"
  # apple_csp: the SL public-API backport. Both the 1068 tag (36859) and stock
  # 55003 #include private CommonCrypto headers Apple never released
  # (cast.h, aesopt.h, opensslDES.h, CommonCryptorSPI.h). This rewrites the
  # cast/des/rc4/gladman/Mac cipher contexts onto the PUBLIC CommonCryptor.h /
  # CommonDigest.h API so they build against the 10.6 SDK.
  apply_patch apple_csp-55003-sl-backport.patch \
              "$VM/libsecurity_apple_csp-55003/lib" 4 \
              castContext.h "SL-BACKPORT"
  # securityd: make the install rule's chown non-fatal ('-' prefix) so a
  # non-root build does not abort. Two characters; nothing functional.
  apply_patch securityd-40600-startup.mk.patch \
              "$VM/$SECURITYD_DIR/etc" 4 \
              startup.mk "-chown root:wheel"


  # NOTE: every helper below defaults VM to its own directory when VM is unset.
  # Pass VM explicitly or a build anywhere else silently patches nothing --
  # apply-crash-fix.sh did exactly that on the Mac mini ("FATAL:
  # /Users/sl/securitybuild/...Keychains.h not found"), so the aboutToDestruct
  # CF-finalize fix was missing from that build entirely.
  [ -f "$VM/apply-crash-fix.sh" ] && VM="$VM" bash "$VM/apply-crash-fix.sh" || echo "  (apply-crash-fix.sh absent)"
  [ -f "$VM/apply-generator-deterministic.sh" ] && VM="$VM" bash "$VM/apply-generator-deterministic.sh" || echo "  (apply-generator-deterministic.sh absent -- DL vtable will be non-deterministic!)"
  [ -f "$VM/apply-legacy-hmac.sh" ] && VM="$VM" CSPLIB="$VM/libsecurity_apple_csp-55003/lib" CKSRC="$VM/cryptkit-vendor" bash "$VM/apply-legacy-hmac.sh" >/dev/null 2>&1 && echo "  applied legacy-HMAC source prep" || echo "  (apply-legacy-hmac.sh absent -- keychain unlock will fail!)"
  # checkpw-55471 PAM service name: "checkpw" -> "chkpasswd".
  # 55471 does pam_start("checkpw", ...) and expects /etc/pam.d/checkpw, which
  # later OS releases ship. Snow Leopard does NOT have it -- /etc/pam.d has
  # chkpasswd, login, screensaver, sudo, su, passwd... but no checkpw. pam_start
  # therefore fails and checkpw() returns -2 for a CORRECT password (measured on
  # a cold boot: ours -2, stock 0).
  # 10.6's chkpasswd is the equivalent stack and is what the DirectoryService-era
  # checkpw effectively used:
  #     auth    required pam_opendirectory.so
  #     account required pam_opendirectory.so
  # Point our build at it rather than installing a new file under /etc -- adapting
  # our code to the platform beats modifying the platform, and it reuses Apple's
  # own vetted policy.
  CPW="$VM/libsecurity_checkpw-55471/lib/checkpw.c"
  if [ -f "$CPW" ] && grep -q '#define PAM_STACK_NAME[[:space:]]*"checkpw"' "$CPW"; then
    cp "$CPW" "$CPW.pre-pamstack" 2>/dev/null
    perl -i -pe 's{#define PAM_STACK_NAME\s+"checkpw"}{#define PAM_STACK_NAME "chkpasswd"}' "$CPW"
    grep -q '"chkpasswd"' "$CPW" \
      && echo "  checkpw-55471 PAM stack checkpw -> chkpasswd patched" \
      || echo "  WARN checkpw PAM stack patch did not apply"
  fi

  # ssl-55002 appleCdsa.c: widen the libcrypto chain-verify fallback to EC CAs.
  # sslVerifyCertChain() maps SecTrustEvaluate's CSSM error to an SSL error. It routed
  # ONLY CSSMERR_TP_INVALID_CERTIFICATE (EC *leaf* the SL TP can't parse) to
  # sslVerifyCertChainOpenSSL(); chains whose *CA* is EC come back as
  # CSSMERR_APPLETP_INVALID_CA (0x80012115) and fell through to default: ->
  # errSSLXCertChainInvalid (-9807), so the fallback never ran. Measured: google
  # (EC leaf, RSA cross-signed root) worked; cnn (GlobalSign ECC Root R5) and
  # wikipedia (ISRG EC roots) failed at -9807 with ResultType=6. Safari then shows
  # "data does not appear to be a valid certificate". Trust.cpp's SecTrust-side hook
  # was already generalized to (mTpReturn != CSSM_OK); this is its SSL-side twin.
  # Safe: the fallback does a full X509_verify_cert against the anchor bundle plus a
  # SAN hostname check -- no validation is skipped.
  ACD="$VM/libsecurity_ssl-55002/lib/appleCdsa.c"
  if [ -f "$ACD" ] && ! grep -q 'CSSMERR_APPLETP_INVALID_CA' "$ACD"; then
    cp "$ACD" "$ACD.pre-ecca" 2>/dev/null
    perl -i -pe 's{(\t*case CSSMERR_TP_INVALID_CERTIFICATE:\n)}{$1\t\t\tcase CSSMERR_APPLETP_INVALID_CA:\n}' "$ACD"
    grep -q 'CSSMERR_APPLETP_INVALID_CA' "$ACD" \
      && echo "  appleCdsa.c EC-CA fallback (CSSMERR_APPLETP_INVALID_CA) patched" \
      || echo "  WARN appleCdsa.c EC-CA patch did not apply"
  fi

  # Trust.cpp CSSM_DL_DB_HANDLE operator== ambiguity.
  #
  # `handleA == handleB` on CSSM_DL_DB_HANDLE is ambiguous under llvm-gcc-4.2
  # (multiple candidate operator== via implicit conversions), so the comparison
  # has to be spelled out.
  #
  # *** COMPARE THE FIELDS, NOT THE BYTES. ***
  # An earlier version of this patch used
  #     ::memcmp(&a, &b, sizeof(CSSM_DL_DB_HANDLE)) == 0
  # which is WRONG: memcmp compares every byte of the struct including any
  # padding, and padding is not guaranteed initialised. keychain(handle) then
  # fails to find the matching keychain even when DLHandle/DBHandle both match.
  # Symptoms (Mac mini, 2026-07-21): Keychain Access shows the login keychain
  # "(read only)", "Keychain 'login' cannot be found to store 'Safari'", wifi
  # passwords re-prompted, `security unlock-keychain` ->
  # CSSMERR_DL_INVALID_DB_HANDLE, `/usr/libexec/security-checksystem` ->
  # CSSMERR_CSP_FUNCTION_NOT_IMPLEMENTED, and System.keychain repeatedly
  # "recreated because it cannot unlock". slqemu's tree had the field-comparison
  # form and worked; the memcmp form was only ever in the generated patch.
  TF="$VM/libsecurity_keychain-55017/lib/Trust.cpp"
  if [ -f "$TF" ] && ! grep -q 'handle().DLHandle == handle.DLHandle' "$TF"; then
    cp "$TF" "$TF.pre-ambigfix" 2>/dev/null
    perl -i -pe 's{if \(\(\*it\)->database\(\)->handle\(\) == handle\)}{if ((*it)->database()->handle().DLHandle == handle.DLHandle \&\& (*it)->database()->handle().DBHandle == handle.DBHandle)}' "$TF"
    perl -i -pe 's{if\(trustKeychains\(\)\.rootStoreHandle\(\) == handle\)}{if(trustKeychains().rootStoreHandle().DLHandle == handle.DLHandle \&\& trustKeychains().rootStoreHandle().DBHandle == handle.DBHandle)}' "$TF"
    perl -i -pe 's{if\(trustKeychains\(\)\.systemKcHandle\(\) == handle\)}{if(trustKeychains().systemKcHandle().DLHandle == handle.DLHandle \&\& trustKeychains().systemKcHandle().DBHandle == handle.DBHandle)}' "$TF"
    echo "  Trust.cpp operator== ambiguity patched (field comparison)"
  fi

  # NOTE (removed 2026-07-18): a cssm-40418 attachment.{h,cpp} uint32->CSSM_SIZE patch
  # used to live here. It was WRONG -- it was compensating for a STALE staged
  # cssmtype.h (from a foreign Security release) whose CSSM_MALLOC/REALLOC/CALLOC
  # typedefs took CSSM_SIZE(=size_t), while pristine 40418's attachment.cpp uses
  # uint32. cssm-40418 is SELF-CONSISTENT with its OWN headers (both uint32); the
  # only reason it failed was the foreign staged header. STEP 0
  # (stage_component_headers) now syncs the staged headers to the pinned version,
  # so pristine 40418 compiles as-is and no source patch is needed. Do NOT
  # reintroduce it -- with correct headers staged it produces the INVERSE error.

  for A in $ARCHES; do
    say "STEP 2 [$A]: rebuild all CF/CSSM components against current headers"
    for c in $COMPS; do build_component "$c" "$A"; done
    build_component ssl "$A" "GCC_C_LANGUAGE_STANDARD=gnu99"

    # legacy HMAC: compile the vendored cryptkit legacy-HMAC objects for $A and
    # inject them into the apple_csp archive (fixes CSSM_ALGID_SHA1HMAC_LEGACY ->
    # keychain unlock). apple_csp itself must be built with CK_SECURITY_BUILD=1 so
    # MacLegacyContext references hmacLegacy*; these objects satisfy them.
    inject_legacy_hmac "$A"

    say "STEP 3 [$A]: inject keychain tls12_trusteval + merge ssl TLS1.2 add-ons"
    inject_trusteval "$A"
  done

  # ssl add-ons: merge-ssl-addons.sh + build-ssl-patched.sh handle BOTH arches
  # (they build_arch x86_64 sym-ssl / i386 sym-ssl-i386). Run once after both bases staged.
  say "STEP 3b: ssl add-ons (GCM/Callouts + RSA-recovery/chainverify) both arches"
  [ -f "$VM/patch-ssl-rsa-pubkey.sh" ] && ! grep -q "recovered RSA peerPubKey" "$VM/libsecurity_ssl-55002/lib/sslCert.c" 2>/dev/null && VM="$VM" bash "$VM/patch-ssl-rsa-pubkey.sh"
  [ -f "$VM/merge-ssl-addons.sh" ] && VM="$VM" bash "$VM/merge-ssl-addons.sh" >/dev/null 2>&1 && echo "  merged GCM/Callouts"
  [ -f "$VM/build-ssl-patched.sh" ] && VM="$VM" bash "$VM/build-ssl-patched.sh" >/dev/null 2>&1 && echo "  merged RSA-recovery/chainverify"

  # link-fat-framework.sh takes the x86_64 ssl archive from sym-ssl-x64patched/
  # (see its line 34), NOT from sym-ssl/. That directory is a slqemu-only
  # artifact -- nothing creates it -- so a fresh machine reaches STEP 5 with
  # "MISSING x86_64 archive for ssl" and aborts at 25/26 archives, even though
  # the fully patched archive is sitting in sym-ssl/. merge-ssl-addons.sh and
  # build-ssl-patched.sh both patch sym-ssl/security_ssl IN PLACE (hence the
  # .pressl.* backups beside it), so the two are the same content; mirror it.
  if [ -f "$VM/sym-ssl/security_ssl" ]; then
    mkdir -p "$VM/sym-ssl-x64patched" 2>/dev/null
    cp "$VM/sym-ssl/security_ssl" "$VM/sym-ssl-x64patched/security_ssl" 2>/dev/null \
      && echo "  mirrored patched ssl -> sym-ssl-x64patched ($(nm "$VM/sym-ssl-x64patched/security_ssl" 2>/dev/null | grep -c sslVerifyCertChainOpenSSL) chainverify sym)"
  fi
  # i386 ssl add-ons: merge-ssl-addons.sh is x64-only; compile+merge i386 here
  if echo "$ARCHES" | grep -q i386; then
    LIB="$VM/libsecurity_ssl-55002/lib"; IA="$VM/sym-ssl-i386/security_ssl"
    io=/tmp/ssladdons-i386; rm -rf "$io"; mkdir -p "$io"
    ICF="-mmacosx-version-min=10.6 -std=gnu99 -DNDEBUG -Os -include $PREFIX -w"
    IIN="-I$LIB -I$VM/extra-headers -I$PIECES/Headers -I$PIECES/PrivateHeaders -I$PIECES/Headers/security_asn1 -I$PIECES/Headers/security_cdsa_utilities -I$VM/sym-utilities/derived_src"
    IFW="-F$PIECES/Frameworks -F$PIECES/Components/Security"
    for f in sslGcm sslGcmAes sslGcmCipher tls12Callouts sslCert tls12_chainverify; do
      arch -i386 /usr/bin/gcc -arch i386 $ICF $IIN $IFW -isysroot "$SDK" -c "$LIB/$f.c" -o "$io/$f.o" 2>/dev/null
    done
    [ -f "$IA" ] && ar r "$IA" "$io"/*.o 2>/dev/null && ranlib "$IA" 2>/dev/null && echo "  merged i386 ssl add-ons"
  fi
  # stage fully-merged ssl to the relink input dirs
  [ -f "$VM/sym-ssl/security_ssl" ] && cp "$(readlink "$VM/sym-ssl/security_ssl" 2>/dev/null || echo "$VM/sym-ssl/security_ssl")" "$VM/sym-ssl-x64patched/security_ssl" 2>/dev/null
  echo "  ssl x64: GCM=$(nm "$VM/sym-ssl-x64patched/security_ssl" 2>/dev/null | grep -c ' S _SSLCipherAES_128_GCM') Tls12=$(nm "$VM/sym-ssl-x64patched/security_ssl" 2>/dev/null | grep -cE ' [SD] _Tls12Callouts')"
  echo "  ssl i386: GCM=$(nm "$VM/sym-ssl-i386/security_ssl" 2>/dev/null | grep -c ' S _SSLCipherAES_128_GCM') Tls12=$(nm "$VM/sym-ssl-i386/security_ssl" 2>/dev/null | grep -cE ' [SD] _Tls12Callouts')"
fi

if [ "$STAGE" = "all" ] || [ "$STAGE" = "daemon" ]; then
  # Header sync also required on a daemon-only run: securityd compiles against the
  # staged SecurityPieces headers, and stale ones cause the AuthItemSet layout skew
  # that SIGSEGVs the daemon at login (see stage_component_headers()). Idempotent --
  # a no-op if STEP 0 already ran in this invocation.
  if [ "$STAGE" = "daemon" ]; then
    say "STEP 0 (daemon run): sync staged headers to PINNED component versions"
    for c in cdsa_utilities utilities cdsa_client cssm cdsa_plugin authorization; do
      stage_component_headers "$c"
    done
  fi

  say "STEP 4: getSessionInfo MIG restore (ucsp.defs + regen client+server)"
  DEFS="$VM/$LIBSECURITYD_DIR/mig/ucsp.defs"
  # 37613 (correct 10.6.8) has getSessionInfo as a NATIVE routine, so this un-skip
  # is a NO-OP there (the "kept by the kernel" skip line only exists in Lion-era
  # 55002). Kept for safety/back-compat if LIBSECURITYD_DIR is overridden to 55002.
  if grep -q "was getSessionInfo -- now kept by the kernel" "$DEFS"; then
    cp "$DEFS" "$DEFS.pregetsessioninfo.bak"
    perl -0777 -i -pe 's{skip;\s*//\s*was getSessionInfo -- now kept by the kernel}{routine getSessionInfo(UCSP_PORTS; inout session: SecuritySessionId; out attributes: SessionAttributeBits);}' "$DEFS"
    echo "  ucsp.defs getSessionInfo un-skipped (55002 back-compat path)"
  else
    echo "  ucsp.defs getSessionInfo already native in $LIBSECURITYD_DIR (no un-skip needed)"
  fi
  MIGDIR="$VM/$LIBSECURITYD_DIR/mig"; DER="$VM/sym-securityd_server/derived_src"
  ( cd "$MIGDIR" && mig -server "$DER/ucspServer.cpp" -user "$DER/ucspClient.cpp" -header "$DER/ucsp.h" \
      -I"$PIECES/Headers" -I"$MIGDIR" "$MIGDIR/ucsp.defs" >/dev/null 2>&1 \
      && cp "$DER/ucspClient.cpp" "$DER/ucspClientC.c" \
      && echo "  MIG regen: server=$(grep -c getSessionInfo "$DER/ucspServer.cpp") client=$(grep -c getSessionInfo "$DER/ucspClient.cpp")" )
  grep -q "ucsp_server_getSessionInfo" "$VM/$SECURITYD_DIR/src/transition.cpp" && echo "  getSessionInfo: native in $SECURITYD_DIR (good)" || echo "  WARN transition.cpp missing getSessionInfo handler"

  # ===========================================================================
  # STEP 4-i386chain: build the i386 securityd LINK CHAIN + lipo all chain
  # components to FAT frameworks in SecurityPieces, so the i386 daemon link
  # (STEP 4a) can resolve -framework securityd_server/agent_client/etc for i386.
  # Without this the i386 Ld fails: "ignoring file ... not the architecture
  # being linked (i386)" -> Undefined symbols (Child::fork, QueryOld::query).
  # Existing i386 archives (from monolith build): utilities, cdsa_utilities,
  # cdsa_client, securityd_client. MISSING (built here): securityd_server,
  # agent_client, tokend_client.
  # ===========================================================================
  if echo "$ARCHES" | grep -q i386; then
    say "STEP 4-i386chain: build 3 missing i386 link-chain frameworks + fat-stage all"
    LPROJ="$VM/$LIBSECURITYD_DIR/libsecurityd.xcodeproj"
    AGPROJ=$(ls -d "$VM"/libsecurity_agent-*/*.xcodeproj 2>/dev/null | head -1)
    TKPROJ=$(ls -d "$VM"/SecurityTokend-*/*.xcodeproj 2>/dev/null | head -1)

    # helper: build one i386 xcodebuild target, harvest .o's -> archive at $out_ar
    build_i386_archive() {
      local proj="$1" target="$2" out_ar="$3" bdir="$4"
      local o="$VM/cc-build/${target}-i386"; rm -rf "$o"; mkdir -p "$o"
      arch -i386 xcodebuild -project "$proj" -target "$target" \
        -configuration Deployment -sdk macosx10.6 ARCHS=i386 VALID_ARCHS=i386 ONLY_ACTIVE_ARCH=NO \
        GCC_VERSION=com.apple.compilers.llvmgcc42 GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
        SYMROOT="$o/sym" OBJROOT="$o/obj" DSTROOT="$o/dst" \
        "HEADER_SEARCH_PATHS=$HDRS" "OTHER_CFLAGS=\$(inherited) $DEPR" build > "$o/build.log" 2>&1
      local objdir=$(find "$o/obj" -type d -name i386 -path "*${bdir}*Objects-normal*" | head -1)
      if [ -d "$objdir" ] && ls "$objdir"/*.o >/dev/null 2>&1; then
        rm -f "$out_ar"; ar qc "$out_ar" "$objdir"/*.o && ranlib "$out_ar" 2>/dev/null
        echo "  built i386 $target -> $out_ar ($(lipo -info "$out_ar" 2>/dev/null | grep -oE 'i386'))"
        return 0
      fi
      echo "  BUILD ISSUE i386 $target (errors=$(grep -c 'error:' "$o/build.log")); log: $o/build.log"
      grep 'error:' "$o/build.log" | head -3
      return 1
    }

    mkdir -p "$VM/sym-securityd_server-i386" "$VM/sym-agent_client-i386" "$VM/sym-tokend_client-i386"
    # securityd_server MUST be rebuilt for BOTH arches every run: the MIG regen in
    # STEP 4 changes ucspServer (getSessionInfo). A stale x64 securityd_server (e.g.
    # from before the getSessionInfo restore) links a getSessionInfo-less x64 daemon
    # slice -> x64 clients get MIG_BAD_ID. Rebuild x64 into sym-securityd_server
    # (the x64 path fat_stage reads) and i386 into sym-securityd_server-i386.
    build_i386_archive_arch() {
      local arch="$1" proj="$2" target="$3" out_ar="$4" bdir="$5"
      local o="$VM/cc-build/${target}-${arch}"; rm -rf "$o"; mkdir -p "$o"
      arch -$arch xcodebuild -project "$proj" -target "$target" \
        -configuration Deployment -sdk macosx10.6 ARCHS=$arch VALID_ARCHS=$arch ONLY_ACTIVE_ARCH=NO \
        GCC_VERSION=com.apple.compilers.llvmgcc42 GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
        SYMROOT="$o/sym" OBJROOT="$o/obj" DSTROOT="$o/dst" \
        "HEADER_SEARCH_PATHS=$HDRS" "OTHER_CFLAGS=\$(inherited) $DEPR" build > "$o/build.log" 2>&1
      local objdir=$(find "$o/obj" -type d -name "$arch" -path "*${bdir}*Objects-normal*" | head -1)
      if [ -d "$objdir" ] && ls "$objdir"/*.o >/dev/null 2>&1; then
        rm -f "$out_ar"; ar qc "$out_ar" "$objdir"/*.o && ranlib "$out_ar" 2>/dev/null
        echo "  built $arch $target -> $out_ar (getSessionInfo=$(nm "$out_ar" 2>/dev/null | grep -c -i getSessionInfo))"
        return 0
      fi
      echo "  BUILD ISSUE $arch $target (errors=$(grep -c 'error:' "$o/build.log")); log: $o/build.log"
      grep 'error:' "$o/build.log" | head -3; return 1
    }
    # Sym dirs for the link-chain components. The i386 helper only ever creates
    # sym-<c>-i386, so the x86_64 ones are missing on a fresh machine: `ar` then
    # fails with "No such file or directory" and the later fat_stage reports SKIP
    # with an empty x64 side. Invisible on a box where earlier builds made them.
    mkdir -p "$VM/sym-agent_client" "$VM/sym-tokend_client" \
             "$VM/sym-agent_client-i386" "$VM/sym-tokend_client-i386" \
             "$VM/sym-securityd_server" "$VM/sym-securityd_server-i386" 2>/dev/null
    # securityd_server: BOTH arches, fresh from current MIG
    build_i386_archive_arch x86_64 "$LPROJ" libsecurityd_server "$VM/sym-securityd_server/securityd_server"      "libsecurityd_server.build" || I386_CHAIN_FAIL=1
    build_i386_archive_arch i386   "$LPROJ" libsecurityd_server "$VM/sym-securityd_server-i386/securityd_server" "libsecurityd_server.build" || I386_CHAIN_FAIL=1
    # securityd_client likewise. The daemon links -framework securityd_client,_nopic,
    # so fat_stage needs archives in sym-securityd_client{,-i386} -- but nothing
    # populated those: STEP 4b builds the client LATER (into persist/, for the
    # framework's client side) and STEP 4a links the daemon BEFORE that. On slqemu
    # the framework bundle already existed from earlier runs, so the link found it
    # anyway; a fresh machine fails with "ld: framework not found securityd_client".
    # Build it here, symmetric with the server, from the same libsecurityd project.
    mkdir -p "$VM/sym-securityd_client" "$VM/sym-securityd_client-i386" 2>/dev/null
    build_i386_archive_arch x86_64 "$LPROJ" libsecurityd_client "$VM/sym-securityd_client/securityd_client"      "libsecurityd_client.build" || I386_CHAIN_FAIL=1
    build_i386_archive_arch i386   "$LPROJ" libsecurityd_client "$VM/sym-securityd_client-i386/securityd_client" "libsecurityd_client.build" || I386_CHAIN_FAIL=1
    [ -n "$AGPROJ" ] && build_i386_archive "$AGPROJ" libsecurity_agent_client "$VM/sym-agent_client-i386/security_agent_client" "libsecurity_agent_client.build" || { echo "  WARN agent project/target issue"; I386_CHAIN_FAIL=1; }
    # x86_64 agent_client MUST be rebuilt too. It was previously built only for i386,
    # leaving a stale x86_64 archive (Jun 30) compiled against a FOREIGN
    # AuthorizationData.h -- one whose AuthItemSet carried an extra `char *firstItemName`
    # member. agent_client constructs/assigns/destroys AuthItemSet objects at its call
    # sites, so a wrong sizeof there corrupts memory when the freshly-built
    # cdsa_utilities implementation operates on them: the std::set<AuthItemRef>
    # red-black tree ends up with cyclic child pointers and _M_erase recurses until
    # the stack guard page is hit (EXC_BAD_ACCESS at 0x7fff5f3ffff8). That killed
    # securityd on every authorizationCopyRights -> blue screen at login + SSH drop.
    [ -n "$AGPROJ" ] && build_i386_archive_arch x86_64 "$AGPROJ" libsecurity_agent_client "$VM/sym-agent_client/security_agent_client" "libsecurity_agent_client.build" || { echo "  WARN agent x86_64 build issue"; I386_CHAIN_FAIL=1; }
    if [ -n "$TKPROJ" ]; then
      TKTGT=$(arch -i386 xcodebuild -project "$TKPROJ" -list 2>/dev/null | awk '/Targets:/{f=1;next} f&&/client/{print $1; exit}')
      [ -z "$TKTGT" ] && TKTGT=$(arch -i386 xcodebuild -project "$TKPROJ" -list 2>/dev/null | awk '/Targets:/{f=1;next} f&&NF{print $1; exit}')
      build_i386_archive "$TKPROJ" "$TKTGT" "$VM/sym-tokend_client-i386/security_tokend_client" "${TKTGT}.build" || I386_CHAIN_FAIL=1
      # x86_64 tokend_client too -- same staleness trap as agent_client (its x86_64
      # archive was also stuck at Jun 30, built against the foreign headers).
      build_i386_archive_arch x86_64 "$TKPROJ" "$TKTGT" "$VM/sym-tokend_client/security_tokend_client" "${TKTGT}.build" || I386_CHAIN_FAIL=1
    else
      echo "  WARN tokend project not found"; I386_CHAIN_FAIL=1
    fi

    # fat-stage: lipo x64+i386 for each link-chain component into the SecurityPieces
    # framework binary the daemon links (-framework <name>). Both daemon legs then
    # resolve their arch from one fat binary. sudo: SecurityPieces is root-owned.
    say "STEP 4-i386chain: lipo link-chain components to FAT in SecurityPieces"
    # map: <fwname> <x64-archive-or-binary> <i386-archive> <SecurityPieces-subdir>
    fat_stage() {
      local name="$1" x64="$2" i386="$3" dest="$4"
      x64=$(readlink "$x64" 2>/dev/null || echo "$x64")
      i386=$(readlink "$i386" 2>/dev/null || echo "$i386")
      local fw="$PIECES/$dest/$name.framework/Versions/A/$name"
      if [ ! -f "$x64" ] || [ ! -f "$i386" ]; then
        echo "  SKIP $name (x64=$([ -f "$x64" ]&&echo y) i386=$([ -f "$i386" ]&&echo y))"; return 1
      fi
      local tmp=/tmp/fat_$name; lipo -create "$x64" "$i386" -output "$tmp" 2>/tmp/fat_$name.err
      if [ ! -f "$tmp" ]; then echo "  LIPO FAIL $name: $(cat /tmp/fat_$name.err)"; return 1; fi
      echo "$PW" | sudo -S mkdir -p "$PIECES/$dest/$name.framework/Versions/A" 2>/dev/null
      mkdir -p "$PIECES/$dest/$name.framework/Versions/A" 2>/dev/null
      echo "$PW" | sudo -S cp "$tmp" "$fw" 2>/dev/null
      cp "$tmp" "$fw" 2>/dev/null
      # Framework BUNDLE STRUCTURE. `ld -framework <name>` resolves
      # <name>.framework/<name>, which is normally a symlink chain:
      #     <name>.framework/<name>  -> Versions/Current/<name>
      #     <name>.framework/Versions/Current -> A
      # fat_stage only ever wrote Versions/A/<name>; on slqemu the symlinks
      # already existed from earlier manual setup, so this never showed up.
      # Without them a fresh machine fails at the daemon link with
      #     ld: framework not found security_agent_client
      # even though the fat binary is sitting right there in Versions/A.
      ( cd "$PIECES/$dest/$name.framework" 2>/dev/null && {
          [ -e Versions/Current ] || ln -s A Versions/Current 2>/dev/null || \
            ( echo "$PW" | sudo -S ln -s A Versions/Current 2>/dev/null )
          [ -e "$name" ] || ln -s "Versions/Current/$name" "$name" 2>/dev/null || \
            ( echo "$PW" | sudo -S ln -s "Versions/Current/$name" "$name" 2>/dev/null )
          [ -e Headers ] || ln -s Versions/Current/Headers Headers 2>/dev/null || \
            ( echo "$PW" | sudo -S ln -s Versions/Current/Headers Headers 2>/dev/null )
        } )
      # ALSO fat-stage the _nopic (and _debug) variants: the daemon links
      # -framework <name>,_nopic which resolves to the *_nopic binary, a SEPARATE
      # file. If it stays thin x64, the i386 link gets Undefined symbols even
      # though the main binary is fat. These are static archives; same fat content.
      local fwroot="$PIECES/$dest/$name.framework"
      for v in "${name}_nopic" "${name}_debug"; do
        # variant is typically a symlink at Versions/A -> ../../../<variant>; resolve real target(s)
        local made=""
        for vp in "$fwroot/Versions/A/$v" "$fwroot/$v"; do
          if [ -e "$vp" ]; then
            local rvp=$(cd "$(dirname "$vp")" 2>/dev/null && readlink "$(basename "$vp")" 2>/dev/null)
            # write the fat binary to the real file (follow one level of symlink)
            if [ -n "$rvp" ]; then
              ( cd "$(dirname "$vp")" && echo "$PW" | sudo -S cp "$tmp" "$rvp" 2>/dev/null )
            else
              echo "$PW" | sudo -S cp "$tmp" "$vp" 2>/dev/null
            fi
            made=y
          fi
        done
        # Fresh machine: the variant does not exist at all yet. The daemon links
        # -framework <name>,_nopic, which ld resolves as <name>.framework/<name>_nopic,
        # so create it (same fat static archive) plus the Versions/A copy.
        if [ -z "$made" ]; then
          echo "$PW" | sudo -S cp "$tmp" "$fwroot/Versions/A/$v" 2>/dev/null
          cp "$tmp" "$fwroot/Versions/A/$v" 2>/dev/null
          ( cd "$fwroot" 2>/dev/null && { [ -e "$v" ] || ln -s "Versions/Current/$v" "$v" 2>/dev/null || \
              ( echo "$PW" | sudo -S ln -s "Versions/Current/$v" "$v" 2>/dev/null ); } )
        fi
      done
      echo "  fat-staged $name (+_nopic/_debug) -> $dest ($(lipo -info "$fw" 2>/dev/null | grep -oE 'i386|x86_64' | tr '\n' ' '))"
    }
    fat_stage security_utilities        "$VM/sym-utilities/security_utilities"           "$VM/sym-utilities-i386/security_utilities"           Frameworks
    fat_stage security_cdsa_utilities    "$VM/sym-cdsa_utilities/security_cdsa_utilities" "$VM/sym-cdsa_utilities-i386/security_cdsa_utilities" Frameworks
    fat_stage security_cdsa_client       "$VM/sym-cdsa_client/security_cdsa_client"       "$VM/sym-cdsa_client-i386/security_cdsa_client"       Frameworks
    fat_stage securityd_client           "$VM/sym-securityd_client/securityd_client"       "$VM/sym-securityd_client-i386/securityd_client"       Frameworks
    fat_stage securityd_server           "$VM/sym-securityd_server/securityd_server"       "$VM/sym-securityd_server-i386/securityd_server"       Components/securityd
    fat_stage security_agent_client      "$VM/sym-agent_client/security_agent_client"      "$VM/sym-agent_client-i386/security_agent_client"      Frameworks
    fat_stage security_tokend_client     "$VM/sym-tokend_client/security_tokend_client"    "$VM/sym-tokend_client-i386/security_tokend_client"    Components/securityd
    # Security.framework itself must be fat too (-framework Security); slices are in persist.
    if [ -f "$VM/persist/Security.x64" ] && [ -f "$VM/persist/Security.i386" ]; then
      lipo -create "$VM/persist/Security.x64" "$VM/persist/Security.i386" -output /tmp/fat_Security 2>/dev/null
      echo "$PW" | sudo -S cp /tmp/fat_Security "$PIECES/Frameworks/Security.framework/Versions/A/Security" 2>/dev/null
      echo "  fat-staged Security -> Frameworks ($(lipo -info "$PIECES/Frameworks/Security.framework/Versions/A/Security" 2>/dev/null | grep -oE 'i386|x86_64' | tr '\n' ' '))"
    else
      echo "  SKIP Security.framework fat-stage (persist slices missing)"
    fi
    [ -n "${I386_CHAIN_FAIL:-}" ] && echo "  NOTE: one or more i386 chain components failed -- STEP 4a i386 link may still fail (see logs above)"
  fi

  # build FAT daemon: BOTH arches via the SAME xcodebuild path (symmetry is critical --
  # the old x64 path used /tmp/remote-build-securityd.sh which built a DEMUX-LESS daemon
  # (ucsp_server_routine=0, getSessionInfo=0) while i386 built correct -> slice skew ->
  # x64 clients get MIG_BAD_ID. Both legs now seed derived_src from the SAME regenerated
  # $GEN (getSessionInfo-restored ucspServer) and build identically.
  say "STEP 4a: build securityd daemon (x86_64 + i386, symmetric xcodebuild -> fat)"
  SDPROJ="$VM/$SECURITYD_DIR/securityd.xcodeproj"
  GEN="$VM/sym-securityd_server/derived_src"
  build_daemon_arch() {
    local A="$1" oi="$2" obj="$3" sym="$4" log="$5"
    # sudo-clean all three build dirs: prior sudo'd builds leave them root-owned;
    # a plain rm/write fails -> leg never runs -> daemon ships THIN/skewed.
    for d in "$oi" "$sym" "$obj"; do
      echo "$PW" | sudo -S rm -rf "$d" 2>/dev/null; rm -rf "$d" 2>/dev/null
      if [ -e "$d" ]; then echo "  FATAL: cannot clear $d (root-owned, sudo rm failed)"; exit 4; fi
    done
    mkdir -p "$sym/derived_src"
    # seed the getSessionInfo-restored MIG server source both legs share
    cp $GEN/ucsp*.* $GEN/cshosting*.* "$sym/derived_src/" 2>/dev/null
    # ---------------------------------------------------------------------------
    # APPLES-TO-APPLES comparison mode (opt-in via RELEASE_DAEMON=1).
    # Genuine stock securityd (slclean 8be26d8c) is built from the SAME source we
    # use -- git tag mac-os-x-1068 == commit 94f87cfb == securityd-40600 (PROVEN).
    # So the only remaining differences from stock are BUILD TYPE and components.
    # This mode builds our 40600 source with stock's RELEASE build type: -Os,
    # -DNDEBUG, normal variant only, stripped/postprocessed -- matching how Apple
    # shipped it -- to isolate whether the DEBUG build type (secdebug/-O0/asserts)
    # is what breaks the session lookup. Default path (unset) stays the intentional
    # DEBUG build used for diagnosis. Nothing else changes; source patches kept.
    local _cfg="Default" ; local _relflags=""
    if [ "${RELEASE_DAEMON:-0}" = "1" ]; then
      _cfg="Deployment"
      _relflags="BUILD_VARIANTS=normal GCC_OPTIMIZATION_LEVEL=s GCC_PREPROCESSOR_DEFINITIONS=NDEBUG DEPLOYMENT_POSTPROCESSING=YES STRIP_INSTALLED_PRODUCT=YES COPY_PHASE_STRIP=YES"
      echo "  [RELEASE_DAEMON] building $A as stock-matching RELEASE (-Os -DNDEBUG normal stripped)"
    fi
    arch -$A xcodebuild -project "$SDPROJ" -target securityd -configuration $_cfg install \
      DSTROOT="$oi" OBJROOT="$obj" SYMROOT="$sym" \
      ARCHS=$A ONLY_ACTIVE_ARCH=YES MACOSX_DEPLOYMENT_TARGET=10.6 \
      GCC_C_LANGUAGE_STANDARD=gnu99 GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
      "HEADER_SEARCH_PATHS=\$(inherited) $PIECES/Headers $PIECES/PrivateHeaders" \
      "FRAMEWORK_SEARCH_PATHS=\$(inherited) $PIECES/Frameworks $PIECES/Components/Security $PIECES/Components/securityd" \
      $_relflags \
      > "$log" 2>&1
  }
  build_daemon_arch x86_64 "$VM/dst-securityd-x64" "$VM/obj-securityd-x64" "$VM/sym-securityd-x64" /tmp/securityd-x64-build.log
  build_daemon_arch i386   "$VM/dst-securityd-i386" "$VM/obj-securityd-i386" "$VM/sym-securityd-i386" /tmp/securityd-i386-build.log
  SDX64="$VM/dst-securityd-x64/usr/sbin/securityd"
  SDI386="$VM/dst-securityd-i386/usr/sbin/securityd"
  mkdir -p "$VM/dst-securityd-fat"
  # HARD REQUIREMENT: fat (i386 + x86_64), NEVER silently thin.
  if [ ! -f "$SDX64" ]; then
    echo "  FATAL: x86_64 daemon not built. ABORTING (no thin fallback)."
    echo "  --- last 20 lines of x64 build log ---"; tail -20 /tmp/securityd-x64-build.log 2>/dev/null
    exit 5
  fi
  if [ ! -f "$SDI386" ]; then
    echo "  FATAL: i386 daemon not built. ABORTING (no thin fallback)."
    echo "  --- last 20 lines of i386 build log ---"; tail -20 /tmp/securityd-i386-build.log 2>/dev/null
    exit 5
  fi
  # PER-SLICE DEMUX+getSessionInfo GATE (before lipo): each slice MUST carry the
  # ucsp demux and getSessionInfo, or that arch's clients get MIG_BAD_ID. This
  # catches the slice-skew that a lipo/arch-only check misses.
  for pair in "x86_64:$SDX64" "i386:$SDI386"; do
    a="${pair%%:*}"; b="${pair##*:}"
    dmx=$(nm -arch $a "$b" 2>/dev/null | grep -c ucsp_server_routine)
    gsi=$(nm -arch $a "$b" 2>/dev/null | grep -c -i getSessionInfo)
    echo "  slice $a: ucsp_demux=$dmx getSessionInfo=$gsi"
    # RELEASE_DAEMON builds are STRIPPED (like genuine stock 8be26d8c, which has
    # ~1 named symbol) -- nm cannot see getSessionInfo/demux by name even though
    # the code IS present. Skip the name-based skew gate in that mode; the arch
    # gate below still guarantees both slices are present. In default (debug)
    # mode the symbol gate applies as before.
    if [ "${RELEASE_DAEMON:-0}" = "1" ]; then
      echo "  slice $a: (RELEASE_DAEMON: stripped, skipping name-based demux gate)"
      continue
    fi
    if [ "$dmx" -lt 1 ] || [ "$gsi" -lt 1 ]; then
      echo "  FATAL: $a slice missing demux/getSessionInfo (skew). ABORTING before lipo."
      exit 6
    fi
  done
  lipo -create "$SDX64" "$SDI386" -output "$VM/dst-securityd-fat/securityd"
  # ARCH GATE: both slices present in the fat output.
  FATARCHS=$(lipo -info "$VM/dst-securityd-fat/securityd" 2>/dev/null)
  if ! echo "$FATARCHS" | grep -q i386 || ! echo "$FATARCHS" | grep -q x86_64; then
    echo "  FATAL: fat daemon gate FAILED -- not i386+x86_64: $FATARCHS"
    rm -f "$VM/dst-securityd-fat/securityd"
    exit 5
  fi
  echo "  FAT daemon OK (gate passed): $FATARCHS"
  echo "  size: $(stat -f%z "$VM/dst-securityd-fat/securityd" 2>/dev/null) bytes"

  # securityd_client (framework client stub w/ getSessionInfo) for BOTH arches
  say "STEP 4b: securityd_client with getSessionInfo (both arches)"
  # persist/ holds artifacts that outlive a single run (framework slices, the
  # client-only archives). Nothing creates it on a fresh machine, so the cp's
  # below silently failed with "No such file or directory".
  mkdir -p "$VM/persist" 2>/dev/null
  LPROJ="$VM/$LIBSECURITYD_DIR/libsecurityd.xcodeproj"
  for A in $ARCHES; do
    o="$VM/cc-build/libsdclient-$A"; rm -rf "$o"; mkdir -p "$o"
    arch -$A xcodebuild -project "$LPROJ" -target libsecurityd_client \
      -configuration Deployment -sdk macosx10.6 ARCHS=$A VALID_ARCHS=$A ONLY_ACTIVE_ARCH=NO \
      GCC_VERSION=com.apple.compilers.llvmgcc42 GCC_PREFIX_HEADER="$PREFIX" GCC_PRECOMPILE_PREFIX_HEADER=NO \
      SYMROOT="$o/sym" OBJROOT="$o/obj" DSTROOT="$o/dst" \
      "HEADER_SEARCH_PATHS=$HDRS" "OTHER_CFLAGS=\$(inherited) $DEPR" build > "$o/build.log" 2>&1
    OBJDIR=$(find "$o/obj" -type d -name "$A" -path "*libsecurityd_client.build*Objects-normal*" | head -1)
    if [ -d "$OBJDIR" ]; then
      A2=/tmp/sdclient_${A}.a; rm -f "$A2"; ar qc "$A2" "$OBJDIR"/*.o && ranlib "$A2" 2>/dev/null
      if [ "$A" = "i386" ]; then
        cp "$A2" "$(readlink "$VM/sym-securityd_client-i386/securityd_client" 2>/dev/null || echo "$VM/sym-securityd_client-i386/securityd_client")"
        cp "$A2" "$VM/persist/securityd_client_i386_clientonly"; ar d "$VM/persist/securityd_client_i386_clientonly" cshostingServer.o 2>/dev/null; ranlib "$VM/persist/securityd_client_i386_clientonly" 2>/dev/null
      else
        cp "$A2" "$(readlink "$VM/sym-securityd_client/securityd_client" 2>/dev/null || echo "$VM/sym-securityd_client/securityd_client")"
        cp "$A2" "$VM/persist/securityd_client_x64_clientonly"; ar d "$VM/persist/securityd_client_x64_clientonly" cshostingServer.o 2>/dev/null; ranlib "$VM/persist/securityd_client_x64_clientonly" 2>/dev/null
      fi
      echo "  securityd_client/$A getSessionInfo=$(nm "$A2" 2>/dev/null | grep -c getSessionInfo)"
    fi
  done
fi

if [ "$STAGE" = "all" ] || [ "$STAGE" = "relink" ]; then
  say "STEP 5: relink both arch monoliths + lipo fat"
  # link-fat-framework.sh links BOTH arches with the current recipe
  # (no -dead_strip, per-arch force_load of client-ONLY securityd_client, -lbsm)
  VM="$VM" bash "$VM/link-fat-framework.sh"
  cp "$VM/Security.x86_64.new" "$VM/persist/Security.x64" 2>/dev/null
  cp "$VM/Security.i386.new"   "$VM/persist/Security.i386" 2>/dev/null
  X="$VM/persist/Security.x64"; I="$VM/persist/Security.i386"
  echo "  x64:  abtd=$(nm "$X" 2>/dev/null|grep -c KeychainImpl15aboutToDestruct) gcm=$(nm "$X" 2>/dev/null|grep -c SSLCipherAES_128_GCM) tls12=$(nm "$X" 2>/dev/null|grep -c Tls12Callouts) gSI=$(nm "$X" 2>/dev/null|grep -c getSessionInfo)"
  [ -f "$I" ] && echo "  i386: abtd=$(nm -arch i386 "$I" 2>/dev/null|grep -c KeychainImpl15aboutToDestruct) gcm=$(nm -arch i386 "$I" 2>/dev/null|grep -c SSLCipherAES_128_GCM) tls12=$(nm -arch i386 "$I" 2>/dev/null|grep -c Tls12Callouts) gSI=$(nm -arch i386 "$I" 2>/dev/null|grep -c getSessionInfo)"
  if [ -f "$X" ] && [ -f "$I" ]; then
    lipo -create "$X" "$I" -output "$VM/persist/Security.fat.consistent"
    echo "  Security.fat.consistent: $(shasum "$VM/persist/Security.fat.consistent" | awk '{print $1}') ($(lipo -info "$VM/persist/Security.fat.consistent" | grep -oE 'x86_64 i386'))"
  else
    echo "  WARN i386 monolith missing; falling back to known-good i386 slice"
    lipo -create "$X" "$VM/persist/Security.i386.jul6working" -output "$VM/persist/Security.fat.consistent"
  fi
  echo ""
  echo "DONE. Install+reboot: bash install-consistent-and-reboot.sh (daemon: dst-securityd-fat/securityd)"
fi
