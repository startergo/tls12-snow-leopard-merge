# libsecurity_cryptkit-55002 (vendored: legacy HMAC only)

## Why
Stock 10.6.8 Security = Security-55002 (VM framework reports current_version 55002).
Our components (ssl-55002, apple_csp-55003, keychain-55017) match that era.

CryptKit is REDACTED from the Security-55002 open-source drop (proprietary FEE code),
so there is no libsecurity_cryptkit in 55002. But apple_csp-55003 needs CryptKit's
HmacSha1Legacy (CSSM_ALGID_SHA1HMAC_LEGACY) to verify old (MacOS_10_0-format) keychain
signatures like login.keychain. Without it the correct password is rejected
(CSSMERR_CSP_VERIFY_FAILED). A prior session rerouted SHA1HMAC_LEGACY to the standard
HMAC -- wrong for old keychains.

## Vendored from Security-55471 (Mavericks) libsecurity_cryptkit/lib
HmacSha1Legacy.c/.h ckSHA1.c/.h ckSHA1_priv.c/.h ckconfig.h feeTypes.h falloc.c/.h platform.h

Legitimate: HmacSha1Legacy.c is FROZEN, bug-for-bug BSAFE-4.0-compatible (Doug Mitchell,
(C) 2001). It must stay identical across OS versions to keep verifying old keychains, so
the 55471 copy behaves identically to stock 55002. API matches apple_csp-55003 exactly.
NO proprietary FEE code vendored; self-contained via CommonCrypto (ckSHA1 wraps CC_SHA1;
feeTypes.h is typedefs; falloc/platform are util wrappers). Build -DCK_SECURITY_BUILD so
ckconfig.h sets CRYPTKIT_HMAC_LEGACY=1.

## Integration
apple_csp compiles HmacSha1Legacy.c + ckSHA1.c + ckSHA1_priv.c + falloc.c; MacContext.cpp
and miscAlgFactory.cpp route SHA1HMAC_LEGACY to the real MacLegacyContext.
