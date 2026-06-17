/*
 * tls12_trust.c - Trust evaluation overrides for TLS 1.2 backport
 *
 * Named with tls12_ prefix to avoid conflict with Security's exports.
 * The patcher maps these to Security's symbols via explicit name mapping.
 */

#include <Security/SecTrust.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>

/* SecTrustEvaluate — always return kSecTrustResultProceed */
OSStatus tls12_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
    (void)trust;
    if (result)
        *result = kSecTrustResultProceed;
    return noErr;
}

/* SecTrustGetResult — return proceed */
OSStatus tls12_SecTrustGetResult(SecTrustRef trust, SecTrustResultType *result,
                                  CFArrayRef *certChain, void *statusChain)
{
    (void)trust;
    if (result)
        *result = kSecTrustResultProceed;
    if (certChain)
        *certChain = NULL;
    if (statusChain)
        *(void **)statusChain = NULL;
    return noErr;
}

/* SecTrustGetCssmResultCode — return noErr */
OSStatus tls12_SecTrustGetCssmResultCode(SecTrustRef trust, OSStatus *resultCode)
{
    (void)trust;
    if (resultCode)
        *resultCode = noErr;
    return noErr;
}
