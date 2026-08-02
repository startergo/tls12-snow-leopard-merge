/*
 * sl-compat-prefix.h — forced-include (-include) prefix header for building
 * Security-55002 subprojects on the 10.6 SDK with native llvm-gcc-4.2.
 *
 * WHY: several subprojects' headers were tagged at slightly newer versions
 * (cdsa_utilities-55006, cssm-55005.5, authorization-55000, ...) than the
 * 10.6-era Security-55002 baseline. They annotate types with availability /
 * deprecation macros that the 10.6 SDK's <AvailabilityMacros.h> does NOT define
 * (they were introduced for 10.7+). On 10.6 the correct expansion of every one
 * of these is "nothing" (the API is not deprecated until the named version,
 * which is in the future relative to our 10.6 deployment target).
 *
 * This header is force-included ahead of every translation unit (via the
 * -include compiler flag / GCC_PREFIX_HEADER) so the neutralization cannot be
 * bypassed by include order — unlike -D flags routed through xcodebuild build
 * settings, which did not reliably reach the CompileC step (see runbook \u00a72.7).
 *
 * Defining a macro that the SDK MIGHT also define is guarded with #ifndef so we
 * never clobber a real SDK definition; we only fill in the ones the 10.6 SDK
 * leaves undefined.
 */

#ifndef _SL_COMPAT_PREFIX_H_
#define _SL_COMPAT_PREFIX_H_

/* Pull in the SDK's real availability macros first, so our #ifndef guards see
 * whatever the 10.6 SDK does define and only fill the gaps. */
#include <AvailabilityMacros.h>

/* --- DEPRECATED_IN_MAC_OS_X_VERSION_xx_AND_LATER family --- */
#ifndef DEPRECATED_IN_MAC_OS_X_VERSION_10_5_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_5_AND_LATER
#endif
#ifndef DEPRECATED_IN_MAC_OS_X_VERSION_10_6_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_6_AND_LATER
#endif
#ifndef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
#ifndef DEPRECATED_IN_MAC_OS_X_VERSION_10_8_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_8_AND_LATER
#endif

/* --- __AVAILABILITY_INTERNAL__MAC_10_x_DEP__MAC_10_7[ _MSG] family --- *
 * These are the lower-level tokens AvailabilityMacros.h expands the
 * DEPRECATED_* macros into on newer SDKs. On the 10.6 SDK the 10.7-targeted
 * ones don't exist, so headers that reference them directly break. Neutralize
 * the 10.7/10.8 deprecation-internal tokens to nothing. */
#ifndef __AVAILABILITY_INTERNAL__MAC_10_0_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_0_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_2_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_2_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_3_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_3_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_4_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_4_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_5_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_5_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_6_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_6_DEP__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_7_DEP__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_7_DEP__MAC_10_7
#endif

/* _MSG variants (take a string arg) — define as function-like, expand to nothing */
#ifndef __AVAILABILITY_INTERNAL__MAC_10_0_DEP__MAC_10_7_MSG
#define __AVAILABILITY_INTERNAL__MAC_10_0_DEP__MAC_10_7_MSG(_msg)
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_7_MSG
#define __AVAILABILITY_INTERNAL__MAC_10_1_DEP__MAC_10_7_MSG(_msg)
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_5_DEP__MAC_10_7_MSG
#define __AVAILABILITY_INTERNAL__MAC_10_5_DEP__MAC_10_7_MSG(_msg)
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_6_DEP__MAC_10_7_MSG
#define __AVAILABILITY_INTERNAL__MAC_10_6_DEP__MAC_10_7_MSG(_msg)
#endif

/* --- __OSX_AVAILABLE_STARTING introduction tokens for 10.7/10.8 --- *
 * Distinct from the DEPRECATION family above. An API marked
 * `__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_NA)` expands (via the 10.6
 * SDK's AvailabilityInternal.h) to the token `__AVAILABILITY_INTERNAL__MAC_10_7`,
 * which the 10.6 SDK does NOT define (10.7 was the future), so the raw token
 * leaks and breaks the declaration (e.g. CMSEncoder.h:181
 * CMSEncoderSetEncapsulatedContentTypeOID, CMSEncodeContent). On a 10.6
 * deployment target the correct expansion is "nothing" (the symbol is simply
 * declared with no availability attribute; whether a 10.7-only symbol is
 * actually CALLED/linked by the code we compile is a separate question handled
 * per-subproject). Neutralize the introduction tokens for 10.7 and 10.8. */
#ifndef __AVAILABILITY_INTERNAL__MAC_10_7
#define __AVAILABILITY_INTERNAL__MAC_10_7
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_7_AND_LATER
#define __AVAILABILITY_INTERNAL__MAC_10_7_AND_LATER
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_8
#define __AVAILABILITY_INTERNAL__MAC_10_8
#endif
#ifndef __AVAILABILITY_INTERNAL__MAC_10_8_AND_LATER
#define __AVAILABILITY_INTERNAL__MAC_10_8_AND_LATER
#endif

/* --- Proprietary CryptKit / FEE: force OFF --- *
 * libsecurity_apple_csp's project sets CRYPTKIT_CSP_ENABLE in its build
 * settings, which switches in the FEE (Fast Elliptic Encryption) CSP. FEE is
 * Apple's PROPRIETARY elliptic-crypto subproject (`security_cryptkit/*`) and is
 * NOT in the public Apple OSS distribution (confirmed: no libsecurity_cryptkit /
 * security_cryptkit / cryptkit repo with any 55xxx tag) -- so its headers
 * (feeTypes.h, falloc.h, feeFunctions.h, HmacSha1Legacy.h) cannot be staged and
 * the FEE-dependent files (cryptkitcsp.cpp, FEE*.cpp, MacContext's MacLegacyContext)
 * fail to compile. Every one of those files wraps its body in
 * `#ifdef CRYPTKIT_CSP_ENABLE`, so undefining the macro compiles them to nothing
 * -- exactly Apple's intended switch for "build the open CSP without the
 * proprietary CryptKit." The result lacks FEE (a legacy Apple-specific EC system
 * that modern TLS/keychain crypto does NOT use -- standard RSA/DSA/DH/ECDSA come
 * from the OpenSSL paths in apple_csp + the SSL layer's own libcrypto, untouched).
 * This is the \u00a72.1 "from-source CSP is functionally different from Apple's"
 * divergence, made minimal and explicit; the \u00a73 keychain test is the gate that
 * would catch any real regression. Force-undef AFTER the command-line -D so it
 * wins regardless of the project setting. */
#ifdef CRYPTKIT_CSP_ENABLE
#undef CRYPTKIT_CSP_ENABLE
#endif

/* --- Proprietary ComCryption / ASC: force OFF (same situation as CryptKit) --- *
 * libsecurity_apple_csp's project also sets ASC_CSP_ENABLE, switching in the ASC
 * (Apple Secure Compression) CSP, whose engine lives in the `security_comcryption`
 * subproject. That subproject is ALSO absent from public Apple OSS -- it is one of
 * the two repos that returned NO TAGS in the \u00a72.5 batch fetch (obsolete codec).
 * Its header <security_comcryption/comcryption.h> cannot be staged, and the
 * ASC-dependent files (ascContext.cpp/.h, ascFactory.h) fail to compile. They are
 * all wrapped in `#ifdef ASC_CSP_ENABLE`, so undefining it compiles them to
 * nothing -- Apple's intended "build without ASC" switch. ASC is a proprietary
 * compression+encryption codec unrelated to TLS or standard keychain crypto; its
 * absence does not affect RSA/DSA/DH/AES/ECDSA. Same \u00a72.1 divergence class as
 * FEE; \u00a73 keychain test is the gate. */
#ifdef ASC_CSP_ENABLE
#undef ASC_CSP_ENABLE
#endif

/* --- 10.7 Sec* API renames -> 10.6 names --- *
 * A few Security.framework functions were RENAMED in 10.7; the newer-tagged
 * subprojects call the 10.7 name, but only the 10.6 name exists in the 10.6 SDK
 * (same signature). Map the 10.7 name to the 10.6 name. Verified each has an
 * identical-signature 10.6 equivalent in the SDK headers.
 *   SecItemExport (10.7) -> SecKeychainItemExport (10.6)   [SecImportExport.h:214]
 *   SecItemImport (10.7) -> SecKeychainItemImport (10.6)   [same header]
 * Used by: libsecurity_apple_x509_tp TPCertInfo.cpp (encodeIssuers -> PEM export).
 * These are function-name remaps, not attributes, so a plain #define is correct
 * and the call sites need no other change (arg lists already match the 10.6
 * prototype). */
#ifndef SecItemExport
#define SecItemExport SecKeychainItemExport
#endif
#ifndef SecItemImport
#define SecItemImport SecKeychainItemImport
#endif

/* --- 10.7 sandbox SPI flag absent from 10.6 sandbox.h --- *
 * libsecurity_filedb AtomicFile.cpp:342/351 passes SANDBOX_CHECK_NO_REPORT in the
 * sandbox_check() filter-type argument. The 10.6 sandbox.h HAS sandbox_check and
 * SANDBOX_FILTER_PATH but NOT the SANDBOX_CHECK_NO_REPORT flag (added 10.7). That
 * flag only suppresses the system-log entry a denied check would emit -- it does
 * NOT change whether access is granted. Defining it 0 on 10.6 means the check
 * still runs identically; at worst a denied keychain-read is logged (the pre-10.7
 * behavior). Safe and behaviorally correct for 10.6. */
#ifndef SANDBOX_CHECK_NO_REPORT
#define SANDBOX_CHECK_NO_REPORT 0
#endif

/* --- _amkrtemp(): 10.7 private temp-name helper absent from 10.6 --- *
 * libsecurity_filedb AtomicFile.cpp AtomicTempFile::create() calls _amkrtemp(path)
 * to turn a path template into a unique temp filename (malloc'd; caller frees).
 * Verified absent from the 10.6 runtime (nm libSystem.B/libc -> 0) and from every
 * 10.6 SDK header. Apple's _amkrtemp appends a unique suffix to the given path and
 * atomically creates that temp file (mkstemp semantics), returning the final path.
 * Provide a faithful 10.6 shim: append ".XXXXXX" to the template, mkstemp() it (so
 * the name is unique AND the file is created O_EXCL exactly as the caller -- which
 * immediately re-open()s it O_WRONLY|O_CREAT|O_TRUNC -- expects), and return a
 * malloc'd copy of the resulting path. On failure return NULL with errno set, which
 * is exactly the contract the call site checks (`if (temp == NULL) UnixError::throwMe`).
 * static inline so each translation unit that uses it gets its own copy -- no
 * duplicate-symbol clash from the forced-include across filedb's several .o files;
 * unused TUs drop it. Guarded by its own macro so it's defined once per TU. */
#ifndef _SL_HAVE_AMKRTEMP_SHIM
#define _SL_HAVE_AMKRTEMP_SHIM 1
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef __cplusplus
extern "C" {
#endif
static inline char *_amkrtemp(const char *_sl_template)
{
    if (_sl_template == NULL) { errno = EINVAL; return NULL; }
    size_t _sl_len = strlen(_sl_template);
    char *_sl_buf = (char *)malloc(_sl_len + 8); /* + ".XXXXXX" + NUL */
    if (_sl_buf == NULL) { errno = ENOMEM; return NULL; }
    memcpy(_sl_buf, _sl_template, _sl_len);
    memcpy(_sl_buf + _sl_len, ".XXXXXX", 8); /* includes NUL */
    int _sl_fd = mkstemp(_sl_buf);
    if (_sl_fd < 0) { int _sl_e = errno; free(_sl_buf); errno = _sl_e; return NULL; }
    close(_sl_fd); /* caller re-opens by name with O_CREAT|O_TRUNC */
    return _sl_buf;
}
#ifdef __cplusplus
}
#endif
#endif /* _SL_HAVE_AMKRTEMP_SHIM */


/* SL-BACKPORT: codesigning (signer.cpp) references the private CFBundle key
 * _kCFBundleResourceSpecificationKey, which is NOT exported by the 10.6
 * CoreFoundation (nm -> 0) and not declared in any 10.6 SDK header (it lived in
 * the private CFBundlePriv.h). It is a well-known constant whose value is the
 * Info.plist key string "CFBundleResourceSpecification". Define it to the
 * equivalent CFSTR() literal so the one use site (selecting an embedded resource
 * rules file) behaves identically. The macro is only expanded at the use site,
 * where CoreFoundation (hence CFSTR/CFStringRef) is already included. */
#ifndef _kCFBundleResourceSpecificationKey
#define _kCFBundleResourceSpecificationKey CFSTR("CFBundleResourceSpecification")
#endif

/* SL-BACKPORT: csutilities.cpp uses errSecUnknownTag (returned by the CL when a
 * certificate field OID isn't recognized). This error code is absent from the
 * 10.6 SDK's SecBase.h. Define it to its canonical SecBase value (-25304), which
 * is stable across OS versions, so the certificateHasField() switch compiles and
 * matches the runtime's actual return code. Guarded so a real definition (on a
 * newer SDK) is never clobbered. */
#ifndef errSecUnknownTag
#define errSecUnknownTag -25304
#endif

#endif /* _SL_COMPAT_PREFIX_H_ */