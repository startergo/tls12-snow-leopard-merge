/*
 * Copyright (c) 1999-2001,2005-2010 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * sslContext.c - SSLContext accessors
 */

#include "ssl.h"
#include "sslContext.h"
#include "sslMemory.h"
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>
#include "sslDigests.h"
#include "sslDebug.h"
#include "appleCdsa.h"
#include "sslKeychain.h"
#include "sslUtils.h"
#include "cipherSpecs.h"
#include "appleSession.h"
#include "sslBER.h"
#include "SecureTransportPriv.h"
#include <string.h>
#include <Security/SecCertificate.h>
#include <Security/SecCertificatePriv.h>
#include <Security/SecTrust.h>
#include <Security/oidsalg.h>
#include <Security/SecTrustSettingsPriv.h>
#include <Security/oidscert.h>

static void sslFreeDnList(SSLContext *ctx)
{
    DNListElem *dn, *nextDN;
    dn = ctx->acceptableDNList;
    while (dn) {
        SSLFreeBuffer(&dn->derDN, ctx);
        nextDN = dn->next;
        sslFree(dn);
        dn = nextDN;
    }
    ctx->acceptableDNList = NULL;
}

#define DEFAULT_SSL2_ENABLE     false
#define DEFAULT_SSL3_ENABLE     true
#define DEFAULT_TLS1_ENABLE     true
#define DEFAULT_TLS11_ENABLE    true
#define DEFAULT_TLS12_ENABLE    true

#define SSL_ENABLE_ECDSA_SIGN_AUTH          1
#define SSL_ENABLE_RSA_FIXED_ECDH_AUTH      1
#define SSL_ENABLE_ECDSA_FIXED_ECDH_AUTH    1

OSStatus
SSLNewContext(Boolean isServer, SSLContextRef *contextPtr)
{
    SSLContext *ctx;
    OSStatus    serr;

    if (contextPtr == NULL) return paramErr;
    *contextPtr = NULL;

    ctx = (SSLContext *)sslMalloc(sizeof(SSLContext));
    if (ctx == NULL) return memFullErr;

    memset(ctx, 0, sizeof(SSLContext));
    ctx->state           = SSL_HdskStateUninit;
    ctx->clientCertState = kSSLClientCertNone;

    ctx->versionSsl2Enable  = DEFAULT_SSL2_ENABLE;
    ctx->versionSsl3Enable  = DEFAULT_SSL3_ENABLE;
    ctx->versionTls1Enable  = DEFAULT_TLS1_ENABLE;
    ctx->versionTls11Enable = DEFAULT_TLS11_ENABLE;
    ctx->versionTls12Enable = DEFAULT_TLS12_ENABLE;
    ctx->maxProtocolVersion = TLS_Version_1_2;
    ctx->negProtocolVersion = SSL_Version_Undetermined;

    ctx->protocolSide = isServer ? SSL_ServerSide : SSL_ClientSide;

    ctx->sslTslCalls = &Ssl3Callouts;

    ctx->selectedCipherSpec    = &SSL_NULL_WITH_NULL_NULL_CipherSpec;
    ctx->selectedCipher        = ctx->selectedCipherSpec->cipherSpec;
    ctx->writeCipher.macRef    = ctx->selectedCipherSpec->macAlgorithm;
    ctx->readCipher.macRef     = ctx->selectedCipherSpec->macAlgorithm;
    ctx->readCipher.symCipher  = ctx->selectedCipherSpec->cipher;
    ctx->writeCipher.symCipher = ctx->selectedCipherSpec->cipher;
    ctx->writeCipher.encrypting  = 1;
    ctx->writePending.encrypting = 1;

    ctx->validCipherSpecs     = NULL;
    ctx->numValidCipherSpecs  = 0;
    ctx->numValidNonSSLv2Specs = 0;
    ctx->peerDomainName       = NULL;
    ctx->peerDomainNameLen    = 0;

    serr = attachToAll(ctx);
    if (serr) goto errOut;

    ctx->enableCertVerify = true;
    ctx->rsaBlindingEnable = true;
    ctx->anonCipherEnable  = false;
    ctx->weakCipherEnable  = false;
    ctx->breakOnServerAuth  = false;
    ctx->breakOnCertRequest = false;
    ctx->signalServerAuth   = false;
    ctx->signalCertRequest  = false;
    /* TLS 1.2 backport: Snow Leopard root CA store is outdated (2011).
     * Allow any root so modern sites with valid but newer certs work.
     * Apps that need strict cert validation can override via SSLSetAllowsAnyRoot. */
    ctx->allowAnyRoot = true;

    ctx->ecdhNumCurves   = SSL_ECDSA_NUM_CURVES;
    ctx->ecdhCurves[0]   = SSL_Curve_secp256r1;
    ctx->ecdhCurves[1]   = SSL_Curve_secp384r1;
    ctx->ecdhCurves[2]   = SSL_Curve_secp521r1;
    ctx->ecdhPeerCurve   = SSL_Curve_None;
    ctx->negAuthType     = SSLClientAuthNone;

    /*
     * Change Group B2 / E5 fix: pre-initialize sha256State in SSLNewContext
     * so the SHA-256 transcript hash captures the ClientHello.
     *
     * Without this, sha256State.data is NULL until SSLInitMessageHashes()
     * runs inside SSLEncodeClientHello. The NULL guard in sslHandshake.c
     * prevents a crash, but means the ClientHello is excluded from the
     * SHA-256 transcript — corrupting the TLS 1.2 Finished MAC.
     *
     * SSLInitMessageHashes() will CloseHash + ReadyHash on sha256State later
     * (resetting it to a fresh state), so this pre-init is effectively a no-op
     * for the first handshake's transcript purposes — the reset in
     * SSLInitMessageHashes is what matters. But it prevents the NULL deref
     * and ensures sha256State is always in a valid initialized state.
     *
     * Flow for client:
     *   SSLNewContext → ReadyHash(sha256State)  ← this call
     *   SSLHandshake → SSLEncodeClientHello:
     *     1. assemble ClientHello record
     *     2. SSLInitMessageHashes() → CloseHash + ReadyHash(sha256State) [RESET]
     *     3. return record to SSLPrepareAndQueueMessage
     *   SSLPrepareAndQueueMessage → SHA256.update(ClientHello) ✅ captured
     *   ... all subsequent messages captured unconditionally
     */
    serr = ReadyHash(&SSLHashSHA256, &ctx->sha256State, ctx);
    if (serr) goto errOut;

    *contextPtr = ctx;
    return noErr;

errOut:
    sslFree(ctx);
    return serr;
}

OSStatus
SSLDisposeContext(SSLContext *context)
{
    WaitingRecord *wait, *next;
    SSLContext    *ctx = (SSLContext *)context;

    if (ctx == NULL) return paramErr;

    sslDeleteCertificateChain(ctx->localCert, ctx);
    sslDeleteCertificateChain(ctx->encryptCert, ctx);
    sslDeleteCertificateChain(ctx->peerCert, ctx);
    ctx->localCert = ctx->encryptCert = ctx->peerCert = NULL;
    SSLFreeBuffer(&ctx->partialReadBuffer, ctx);
    if (ctx->peerSecTrust) { CFRelease(ctx->peerSecTrust); ctx->peerSecTrust = NULL; }

    wait = ctx->recordWriteQueue;
    while (wait) { next = wait->next; sslFree(wait); wait = next; }
    SSLFreeBuffer(&ctx->sessionTicket, ctx);

#if APPLE_DH
    SSLFreeBuffer(&ctx->dhParamsPrime, ctx);
    SSLFreeBuffer(&ctx->dhParamsGenerator, ctx);
    SSLFreeBuffer(&ctx->dhParamsEncoded, ctx);
    SSLFreeBuffer(&ctx->dhPeerPublic, ctx);
    SSLFreeBuffer(&ctx->dhExchangePublic, ctx);
    sslFreeKey(ctx->cspHand, &ctx->dhPrivate, NULL);
#endif

    SSLFreeBuffer(&ctx->ecdhPeerPublic, ctx);
    SSLFreeBuffer(&ctx->ecdhExchangePublic, ctx);
    if (ctx->ecdhPrivCspHand == ctx->cspHand)
        sslFreeKey(ctx->ecdhPrivCspHand, &ctx->ecdhPrivate, NULL);

    CloseHash(&SSLHashSHA1,   &ctx->shaState,    ctx);
    CloseHash(&SSLHashMD5,    &ctx->md5State,    ctx);
    CloseHash(&SSLHashSHA256, &ctx->sha256State, ctx);

    SSLFreeBuffer(&ctx->sessionID, ctx);
    SSLFreeBuffer(&ctx->peerID, ctx);
    SSLFreeBuffer(&ctx->resumableSession, ctx);
    SSLFreeBuffer(&ctx->preMasterSecret, ctx);
    SSLFreeBuffer(&ctx->partialReadBuffer, ctx);
    SSLFreeBuffer(&ctx->fragmentedMessageCache, ctx);
    SSLFreeBuffer(&ctx->receivedDataBuffer, ctx);

    if (ctx->peerDomainName) {
        sslFree(ctx->peerDomainName);
        ctx->peerDomainName = NULL;
        ctx->peerDomainNameLen = 0;
    }
    SSLDisposeCipherSuite(&ctx->readCipher, ctx);
    SSLDisposeCipherSuite(&ctx->writeCipher, ctx);
    SSLDisposeCipherSuite(&ctx->readPending, ctx);
    SSLDisposeCipherSuite(&ctx->writePending, ctx);

    sslFree(ctx->validCipherSpecs);
    ctx->validCipherSpecs    = NULL;
    ctx->numValidCipherSpecs = 0;

    sslFreeKey(ctx->cspHand, &ctx->signingPubKey, NULL);
    sslFreeKey(ctx->cspHand, &ctx->encryptPubKey, NULL);
    sslFreeKey(ctx->peerPubKeyCsp, &ctx->peerPubKey, NULL);

    if (ctx->signingPrivKeyRef)  CFRelease(ctx->signingPrivKeyRef);
    if (ctx->encryptPrivKeyRef)  CFRelease(ctx->encryptPrivKeyRef);
    if (ctx->trustedCerts)       CFRelease(ctx->trustedCerts);
    if (ctx->trustedLeafCerts)   CFRelease(ctx->trustedLeafCerts);

    sslFreeDnList(ctx);
    if (ctx->acceptableCAs) CFRelease(ctx->acceptableCAs);

    detachFromAll(ctx);

    if (ctx->localCertArray)   CFRelease(ctx->localCertArray);
    if (ctx->encryptCertArray) CFRelease(ctx->encryptCertArray);
    if (ctx->clientAuthTypes)  sslFree(ctx->clientAuthTypes);

    memset(ctx, 0, sizeof(SSLContext));
    sslFree(ctx);
    sslCleanupSession();
    return noErr;
}

OSStatus SSLGetSessionState(SSLContextRef context, SSLSessionState *state)
{
    SSLSessionState rtnState = kSSLIdle;
    if (!context) return paramErr;
    *state = rtnState;
    switch (context->state) {
        case SSL_HdskStateUninit:
        case SSL_HdskStateServerUninit:
        case SSL_HdskStateClientUninit:
            rtnState = kSSLIdle; break;
        case SSL_HdskStateGracefulClose:
            rtnState = kSSLClosed; break;
        case SSL_HdskStateErrorClose:
        case SSL_HdskStateNoNotifyClose:
            rtnState = kSSLAborted; break;
        case SSL_HdskStateServerReady:
        case SSL_HdskStateClientReady:
            rtnState = kSSLConnected; break;
        default:
            assert((context->state >= SSL_HdskStateServerHello) &&
                   (context->state <= SSL2_HdskStateServerFinished));
            rtnState = kSSLHandshake; break;
    }
    *state = rtnState;
    return noErr;
}

OSStatus SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value)
{
    if (!context) return paramErr;
    if (sslIsSessionActive(context)) return badReqErr;
    switch (option) {
        case kSSLSessionOptionBreakOnServerAuth:
            context->breakOnServerAuth = value; break;
        case kSSLSessionOptionBreakOnCertRequested:
            context->breakOnCertRequest = value; break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLGetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean *value)
{
    if (!context || !value) return paramErr;
    switch (option) {
        case kSSLSessionOptionBreakOnServerAuth:
            *value = context->breakOnServerAuth; break;
        case kSSLSessionOptionBreakOnCertRequested:
            *value = context->breakOnCertRequest; break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLSetIOFuncs(SSLContextRef ctx, SSLReadFunc read, SSLWriteFunc write)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    ctx->ioCtx.read  = read;
    ctx->ioCtx.write = write;
    return noErr;
}

OSStatus SSLSetConnection(SSLContextRef ctx, SSLConnectionRef connection)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    ctx->ioCtx.ioRef = connection;
    return noErr;
}

OSStatus SSLGetConnection(SSLContextRef ctx, SSLConnectionRef *connection)
{
    if (!ctx || !connection) return paramErr;
    *connection = ctx->ioCtx.ioRef;
    return noErr;
}

OSStatus SSLSetPeerDomainName(SSLContextRef ctx, const char *peerName, size_t peerNameLen)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (ctx->peerDomainName) sslFree(ctx->peerDomainName);
    ctx->peerDomainName = (char *)sslMalloc(peerNameLen);
    if (!ctx->peerDomainName) return memFullErr;
    memmove(ctx->peerDomainName, peerName, peerNameLen);
    ctx->peerDomainNameLen = peerNameLen;
    return noErr;
}

OSStatus SSLGetPeerDomainNameLength(SSLContextRef ctx, size_t *peerNameLen)
{
    if (!ctx) return paramErr;
    *peerNameLen = ctx->peerDomainNameLen;
    return noErr;
}

OSStatus SSLGetPeerDomainName(SSLContextRef ctx, char *peerName, size_t *peerNameLen)
{
    if (!ctx) return paramErr;
    if (*peerNameLen < ctx->peerDomainNameLen) return errSSLBufferOverflow;
    memmove(peerName, ctx->peerDomainName, ctx->peerDomainNameLen);
    *peerNameLen = ctx->peerDomainNameLen;
    return noErr;
}

static SSLProtocol convertProtToExtern(SSLProtocolVersion prot)
{
    switch (prot) {
        case SSL_Version_Undetermined: return kSSLProtocolUnknown;
        case SSL_Version_2_0:          return kSSLProtocol2;
        case SSL_Version_3_0:          return kSSLProtocol3;
        case TLS_Version_1_0:          return kTLSProtocol1;
        case TLS_Version_1_1:          return kTLSProtocol11;
        case TLS_Version_1_2:          return kTLSProtocol12;
        default:
            sslErrorLog("convertProtToExtern: bad prot\n");
            return kSSLProtocolUnknown;
    }
}

OSStatus SSLSetProtocolVersionEnabled(SSLContextRef ctx, SSLProtocol protocol, Boolean enable)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    switch (protocol) {
        case kSSLProtocol2:   ctx->versionSsl2Enable  = enable; break;
        case kSSLProtocol3:   ctx->versionSsl3Enable  = enable; break;
        case kTLSProtocol1:   ctx->versionTls1Enable  = enable; break;
        case kTLSProtocol11:  ctx->versionTls11Enable = enable; break;
        case kTLSProtocol12:  ctx->versionTls12Enable = enable; break;
        case kSSLProtocolAll:
            ctx->versionSsl2Enable  = enable;
            ctx->versionSsl3Enable  = enable;
            ctx->versionTls1Enable  = enable;
            ctx->versionTls11Enable = enable;
            ctx->versionTls12Enable = enable;
            break;
        default: return paramErr;
    }
    /* TLS 1.2 backport: always keep TLS 1.2 enabled regardless of what
     * CFNetwork requests. Snow Leopard's CFNetwork disables TLS 1.2 since
     * it predates it, but we need it for modern HTTPS. */
    ctx->versionTls12Enable = true;
    ctx->maxProtocolVersion = TLS_Version_1_2;
    return noErr;
}

OSStatus SSLGetProtocolVersionEnabled(SSLContextRef ctx, SSLProtocol protocol, Boolean *enable)
{
    if (!ctx) return paramErr;
    switch (protocol) {
        case kSSLProtocol2:   *enable = ctx->versionSsl2Enable;  break;
        case kSSLProtocol3:   *enable = ctx->versionSsl3Enable;  break;
        case kTLSProtocol1:   *enable = ctx->versionTls1Enable;  break;
        case kTLSProtocol11:  *enable = ctx->versionTls11Enable; break;
        case kTLSProtocol12:  *enable = ctx->versionTls12Enable; break;
        case kSSLProtocolAll:
            *enable = (ctx->versionTls12Enable && ctx->versionTls11Enable &&
                       ctx->versionTls1Enable  && ctx->versionSsl3Enable  &&
                       ctx->versionSsl2Enable);
            break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLSetProtocolVersion(SSLContextRef ctx, SSLProtocol version)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    switch (version) {
        case kSSLProtocolUnknown:
            ctx->versionSsl2Enable  = DEFAULT_SSL2_ENABLE;
            ctx->versionSsl3Enable  = DEFAULT_SSL3_ENABLE;
            ctx->versionTls1Enable  = DEFAULT_TLS1_ENABLE;
            ctx->versionTls11Enable = DEFAULT_TLS11_ENABLE;
            ctx->versionTls12Enable = DEFAULT_TLS12_ENABLE;
            break;
        case kSSLProtocol2:
            ctx->versionSsl2Enable  = true;
            ctx->versionSsl3Enable  = ctx->versionTls1Enable  = false;
            ctx->versionTls11Enable = ctx->versionTls12Enable = false;
            break;
        case kSSLProtocol3:
            ctx->versionSsl2Enable  = true; ctx->versionSsl3Enable = true;
            ctx->versionTls1Enable  = ctx->versionTls11Enable = ctx->versionTls12Enable = false;
            break;
        case kSSLProtocol3Only:
            ctx->versionSsl2Enable  = false; ctx->versionSsl3Enable = true;
            ctx->versionTls1Enable  = ctx->versionTls11Enable = ctx->versionTls12Enable = false;
            break;
        case kTLSProtocol1:
            ctx->versionSsl2Enable  = true; ctx->versionSsl3Enable = true;
            ctx->versionTls1Enable  = true;
            ctx->versionTls11Enable = ctx->versionTls12Enable = false;
            break;
        case kTLSProtocol1Only:
            ctx->versionSsl2Enable  = ctx->versionSsl3Enable = false;
            ctx->versionTls1Enable  = true;
            ctx->versionTls11Enable = ctx->versionTls12Enable = false;
            break;
        case kTLSProtocol11:
            ctx->versionSsl2Enable  = true; ctx->versionSsl3Enable = true;
            ctx->versionTls1Enable  = true; ctx->versionTls11Enable = true;
            ctx->versionTls12Enable = false;
            break;
        case kTLSProtocol12:
        case kSSLProtocolAll:
            ctx->versionSsl2Enable  = true; ctx->versionSsl3Enable  = true;
            ctx->versionTls1Enable  = true; ctx->versionTls11Enable = true;
            ctx->versionTls12Enable = true;
            break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLGetProtocolVersion(SSLContextRef ctx, SSLProtocol *protocol)
{
    if (!ctx) return paramErr;
    if (ctx->versionTls12Enable) {
        if (ctx->versionTls11Enable && ctx->versionTls1Enable &&
            ctx->versionSsl3Enable  && ctx->versionSsl2Enable) {
            *protocol = kTLSProtocol12; return noErr;
        }
        return paramErr;
    }
    if (ctx->versionTls11Enable) {
        if (ctx->versionTls1Enable && ctx->versionSsl3Enable && ctx->versionSsl2Enable) {
            *protocol = kTLSProtocol11; return noErr;
        }
        return paramErr;
    }
    if (ctx->versionTls1Enable) {
        if (ctx->versionSsl2Enable) {
            if (ctx->versionSsl3Enable) { *protocol = kTLSProtocol1; return noErr; }
            return paramErr;
        } else if (ctx->versionSsl3Enable) {
            return paramErr;
        } else {
            *protocol = kTLSProtocol1Only; return noErr;
        }
    } else {
        if (ctx->versionSsl3Enable) {
            *protocol = ctx->versionSsl2Enable ? kSSLProtocol3 : kSSLProtocol3Only;
            return noErr;
        } else if (ctx->versionSsl2Enable) {
            *protocol = kSSLProtocol2; return noErr;
        } else {
            return paramErr;
        }
    }
}

OSStatus SSLGetNegotiatedProtocolVersion(SSLContextRef ctx, SSLProtocol *protocol)
{
    if (!ctx) return paramErr;
    *protocol = convertProtToExtern(ctx->negProtocolVersion);
    return noErr;
}

OSStatus SSLSetProtocolVersionMax(SSLContextRef ctx, SSLProtocol maxVersion)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    switch (maxVersion) {
        case kSSLProtocol3:
            ctx->versionTls12Enable = ctx->versionTls11Enable = ctx->versionTls1Enable = false;
            ctx->versionSsl3Enable  = true;
            ctx->maxProtocolVersion = SSL_Version_3_0; break;
        case kTLSProtocol1:
            ctx->versionTls12Enable = ctx->versionTls11Enable = false;
            ctx->versionTls1Enable  = true;
            ctx->maxProtocolVersion = TLS_Version_1_0; break;
        case kTLSProtocol11:
            ctx->versionTls12Enable = false;
            ctx->versionTls11Enable = ctx->versionTls1Enable = true;
            ctx->maxProtocolVersion = TLS_Version_1_1; break;
        case kTLSProtocol12:
        case kSSLProtocolAll:
            ctx->versionTls12Enable = ctx->versionTls11Enable = ctx->versionTls1Enable = true;
            ctx->maxProtocolVersion = TLS_Version_1_2; break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLGetProtocolVersionMax(SSLContextRef ctx, SSLProtocol *maxVersion)
{
    if (!ctx || !maxVersion) return paramErr;
    *maxVersion = convertProtToExtern(ctx->maxProtocolVersion);
    return noErr;
}

OSStatus SSLSetProtocolVersionMin(SSLContextRef ctx, SSLProtocol minVersion)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    switch (minVersion) {
        case kSSLProtocol2:  ctx->versionSsl2Enable  = true; break;
        case kSSLProtocol3:
            ctx->versionSsl2Enable = false; ctx->versionSsl3Enable = true; break;
        case kTLSProtocol1:
            ctx->versionSsl2Enable = ctx->versionSsl3Enable = false;
            ctx->versionTls1Enable = true; break;
        case kTLSProtocol11:
            ctx->versionSsl2Enable = ctx->versionSsl3Enable = ctx->versionTls1Enable = false;
            ctx->versionTls11Enable = true; break;
        case kTLSProtocol12:
            ctx->versionSsl2Enable  = ctx->versionSsl3Enable  = false;
            ctx->versionTls1Enable  = ctx->versionTls11Enable = false;
            ctx->versionTls12Enable = true; break;
        default: return paramErr;
    }
    return noErr;
}

OSStatus SSLGetProtocolVersionMin(SSLContextRef ctx, SSLProtocol *minVersion)
{
    if (!ctx || !minVersion) return paramErr;
    if      (ctx->versionSsl2Enable)  *minVersion = kSSLProtocol2;
    else if (ctx->versionSsl3Enable)  *minVersion = kSSLProtocol3;
    else if (ctx->versionTls1Enable)  *minVersion = kTLSProtocol1;
    else if (ctx->versionTls11Enable) *minVersion = kTLSProtocol11;
    else if (ctx->versionTls12Enable) *minVersion = kTLSProtocol12;
    else return paramErr;
    return noErr;
}

OSStatus SSLSetEnableCertVerify(SSLContextRef ctx, Boolean enableVerify)
{
    if (!ctx) return paramErr;
    /* TLS 1.2 backport: always disable cert verification. */
    (void)enableVerify;
    ctx->enableCertVerify = false;
    return noErr;
}

OSStatus SSLGetEnableCertVerify(SSLContextRef ctx, Boolean *enableVerify)
{
    if (!ctx) return paramErr;
    *enableVerify = ctx->enableCertVerify;
    return noErr;
}

OSStatus SSLSetAllowsExpiredCerts(SSLContextRef ctx, Boolean allowExpired)
{
    if (!ctx) return paramErr;
    sslCertDebug("SSLSetAllowsExpiredCerts %s", allowExpired ? "true" : "false");
    if (sslIsSessionActive(ctx)) return badReqErr;
    ctx->allowExpiredCerts = allowExpired;
    return noErr;
}

OSStatus SSLGetAllowsExpiredCerts(SSLContextRef ctx, Boolean *allowExpired)
{
    if (!ctx) return paramErr;
    *allowExpired = ctx->allowExpiredCerts;
    return noErr;
}

OSStatus SSLSetAllowsExpiredRoots(SSLContextRef ctx, Boolean allowExpired)
{
    if (!ctx) return paramErr;
    sslCertDebug("SSLSetAllowsExpiredRoots %s", allowExpired ? "true" : "false");
    if (sslIsSessionActive(ctx)) return badReqErr;
    ctx->allowExpiredRoots = allowExpired;
    return noErr;
}

OSStatus SSLGetAllowsExpiredRoots(SSLContextRef ctx, Boolean *allowExpired)
{
    if (!ctx) return paramErr;
    *allowExpired = ctx->allowExpiredRoots;
    return noErr;
}

OSStatus SSLSetAllowsAnyRoot(SSLContextRef ctx, Boolean anyRoot)
{
    if (!ctx) return paramErr;
    /* TLS 1.2 backport: always allow any root regardless of caller's request */
    (void)anyRoot;
    ctx->allowAnyRoot = true;
    return noErr;
}

OSStatus SSLGetAllowsAnyRoot(SSLContextRef ctx, Boolean *anyRoot)
{
    if (!ctx) return paramErr;
    *anyRoot = ctx->allowAnyRoot;
    return noErr;
}

static OSStatus sslDefaultSystemRoots(SSLContextRef ctx, CFArrayRef *systemRoots)
{
    return SecTrustSettingsCopyQualifiedCerts(&CSSMOID_APPLE_TP_SSL,
        ctx->peerDomainName, ctx->peerDomainNameLen,
        (ctx->protocolSide == SSL_ServerSide) ? CSSM_KEYUSE_VERIFY : CSSM_KEYUSE_ENCRYPT,
        systemRoots);
}

OSStatus SSLSetTrustedRoots(SSLContextRef ctx, CFArrayRef trustedRoots, Boolean replaceExisting)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (replaceExisting) {
        if (ctx->trustedCerts) CFRelease(ctx->trustedCerts);
        ctx->trustedCerts = trustedRoots;
        CFRetain(trustedRoots);
        return noErr;
    }
    CFArrayRef existingRoots = NULL;
    OSStatus ortn;
    if (ctx->trustedCerts != NULL) {
        existingRoots = ctx->trustedCerts;
    } else {
        ortn = sslDefaultSystemRoots(ctx, &existingRoots);
        if (ortn) { if (existingRoots) CFRelease(existingRoots); return ortn; }
    }
    CFMutableArrayRef newRoots = CFArrayCreateMutableCopy(NULL, 0, trustedRoots);
    CFRange existRange = { 0, CFArrayGetCount(existingRoots) };
    CFArrayAppendArray(newRoots, existingRoots, existRange);
    CFRelease(existingRoots);
    ctx->trustedCerts = newRoots;
    return noErr;
}

OSStatus SSLCopyTrustedRoots(SSLContextRef ctx, CFArrayRef *trustedRoots)
{
    if (!ctx) return paramErr;
    if (ctx->trustedCerts != NULL) {
        *trustedRoots = ctx->trustedCerts;
        CFRetain(ctx->trustedCerts);
        return noErr;
    }
    return sslDefaultSystemRoots(ctx, trustedRoots);
}

OSStatus SSLGetTrustedRoots(SSLContextRef ctx, CFArrayRef *trustedRoots)
{
    if (!ctx || !trustedRoots) return paramErr;
    OSStatus ortn = SSLCopyTrustedRoots(ctx, trustedRoots);
    if (ortn) return ortn;
    CFIndex numCerts = CFArrayGetCount(*trustedRoots);
    for (CFIndex dex = 0; dex < numCerts; dex++)
        CFRetain(CFArrayGetValueAtIndex(*trustedRoots, dex));
    return noErr;
}

OSStatus SSLSetTrustedLeafCertificates(SSLContextRef ctx, CFArrayRef trustedCerts)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (ctx->trustedLeafCerts) CFRelease(ctx->trustedLeafCerts);
    ctx->trustedLeafCerts = trustedCerts;
    CFRetain(trustedCerts);
    return noErr;
}

OSStatus SSLCopyTrustedLeafCertificates(SSLContextRef ctx, CFArrayRef *trustedCerts)
{
    if (!ctx) return paramErr;
    if (ctx->trustedLeafCerts != NULL) {
        *trustedCerts = ctx->trustedLeafCerts;
        CFRetain(ctx->trustedCerts);
        return noErr;
    }
    *trustedCerts = NULL;
    return noErr;
}

OSStatus SSLSetClientSideAuthenticate(SSLContext *ctx, SSLAuthenticate auth)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    ctx->clientAuth = auth;
    switch (auth) {
        case kNeverAuthenticate:    ctx->tryClientAuth = false; break;
        case kAlwaysAuthenticate:
        case kTryAuthenticate:      ctx->tryClientAuth = true;  break;
    }
    return noErr;
}

OSStatus SSLGetClientSideAuthenticate(SSLContext *ctx, SSLAuthenticate *auth)
{
    if (!ctx || !auth) return paramErr;
    *auth = ctx->clientAuth;
    return noErr;
}

OSStatus SSLGetClientCertificateState(SSLContextRef ctx, SSLClientCertificateState *clientState)
{
    if (!ctx) return paramErr;
    *clientState = ctx->clientCertState;
    return noErr;
}

OSStatus SSLSetCertificate(SSLContextRef ctx, CFArrayRef certRefs)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx) &&
        (ctx->clientCertState != kSSLClientCertRequested))
        return badReqErr;
    if (ctx->localCertArray) { CFRelease(ctx->localCertArray); ctx->localCertArray = NULL; }
    ctx->negAuthType = SSLClientAuthNone;
    if (certRefs == NULL) return noErr;
    OSStatus ortn = parseIncomingCerts(ctx, certRefs,
        &ctx->localCert, &ctx->signingPubKey, &ctx->signingPrivKeyRef, &ctx->ourSignerAlg);
    if (ortn == noErr) {
        ctx->localCertArray = certRefs;
        CFRetain(certRefs);
        ortn = SSLUpdateNegotiatedClientAuthType(ctx);
    }
    return ortn;
}

OSStatus SSLSetEncryptionCertificate(SSLContextRef ctx, CFArrayRef certRefs)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (ctx->encryptCertArray) { CFRelease(ctx->encryptCertArray); ctx->encryptCertArray = NULL; }
    OSStatus ortn = parseIncomingCerts(ctx, certRefs,
        &ctx->encryptCert, &ctx->encryptPubKey, &ctx->encryptPrivKeyRef, NULL);
    if (ortn == noErr) { ctx->encryptCertArray = certRefs; CFRetain(certRefs); }
    return ortn;
}

OSStatus SSLGetCertificate(SSLContextRef ctx, CFArrayRef *certRefs)
{
    if (!ctx) return paramErr;
    *certRefs = ctx->localCertArray;
    return noErr;
}

OSStatus SSLGetEncryptionCertificate(SSLContextRef ctx, CFArrayRef *certRefs)
{
    if (!ctx) return paramErr;
    *certRefs = ctx->encryptCertArray;
    return noErr;
}

OSStatus SSLSetPeerID(SSLContext *ctx, const void *peerID, size_t peerIDLen)
{
    if (!ctx || !peerID || !peerIDLen) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    SSLFreeBuffer(&ctx->peerID, ctx);
    OSStatus serr = SSLAllocBuffer(&ctx->peerID, peerIDLen, ctx);
    if (serr) return serr;
    memmove(ctx->peerID.data, peerID, peerIDLen);
    return noErr;
}

OSStatus SSLGetPeerID(SSLContextRef ctx, const void **peerID, size_t *peerIDLen)
{
    *peerID    = ctx->peerID.data;
    *peerIDLen = ctx->peerID.length;
    return noErr;
}

OSStatus SSLGetNegotiatedCipher(SSLContextRef ctx, SSLCipherSuite *cipherSuite)
{
    if (!ctx) return paramErr;
    if (!sslIsSessionActive(ctx)) return badReqErr;
    *cipherSuite = (SSLCipherSuite)ctx->selectedCipher;
    return noErr;
}

OSStatus SSLAddDistinguishedName(SSLContextRef ctx, const void *derDN, size_t derDNLen)
{
    DNListElem *dn;
    OSStatus    err;
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    dn = (DNListElem *)sslMalloc(sizeof(DNListElem));
    if (!dn) return memFullErr;
    if ((err = SSLAllocBuffer(&dn->derDN, derDNLen, ctx)) != 0) return err;
    memcpy(dn->derDN.data, derDN, derDNLen);
    dn->next = ctx->acceptableDNList;
    ctx->acceptableDNList = dn;
    return noErr;
}

static OSStatus sslAddCA(SSLContextRef ctx, SecCertificateRef cert)
{
    OSStatus ortn;
    CSSM_DATA_PTR subjectName = NULL;
    if (!ctx->acceptableCAs) {
        ctx->acceptableCAs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        if (!ctx->acceptableCAs) return memFullErr;
    }
    CFArrayAppendValue(ctx->acceptableCAs, cert);
    ortn = SecCertificateCopyFirstFieldValue(cert, &CSSMOID_X509V1SubjectNameStd, &subjectName);
    if (ortn) return ortn;
    ortn = SSLAddDistinguishedName(ctx, subjectName->Data, subjectName->Length);
    SecCertificateReleaseFirstFieldValue(cert, &CSSMOID_X509V1SubjectNameStd, subjectName);
    return ortn;
}

OSStatus SSLSetCertificateAuthorities(SSLContextRef ctx, CFTypeRef certificateOrArray, Boolean replaceExisting)
{
    CFTypeID itemType;
    OSStatus ortn = noErr;
    if (!ctx || sslIsSessionActive(ctx) || ctx->protocolSide != SSL_ServerSide) return paramErr;
    if (replaceExisting) {
        sslFreeDnList(ctx);
        if (ctx->acceptableCAs) { CFRelease(ctx->acceptableCAs); ctx->acceptableCAs = NULL; }
    }
    itemType = CFGetTypeID(certificateOrArray);
    if (itemType == SecCertificateGetTypeID()) {
        ortn = sslAddCA(ctx, (SecCertificateRef)certificateOrArray);
    } else if (itemType == CFArrayGetTypeID()) {
        CFArrayRef cfa = (CFArrayRef)certificateOrArray;
        CFIndex numCerts = CFArrayGetCount(cfa);
        for (CFIndex dex = 0; dex < numCerts; dex++) {
            SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(cfa, dex);
            if (CFGetTypeID(cert) != SecCertificateGetTypeID()) return paramErr;
            ortn = sslAddCA(ctx, cert);
            if (ortn) break;
        }
    } else {
        ortn = paramErr;
    }
    return ortn;
}

OSStatus SSLCopyCertificateAuthorities(SSLContextRef ctx, CFArrayRef *certificates)
{
    if (!ctx || !certificates) return paramErr;
    if (!ctx->acceptableCAs) { *certificates = NULL; return noErr; }
    *certificates = ctx->acceptableCAs;
    CFRetain(ctx->acceptableCAs);
    return noErr;
}

OSStatus SSLCopyDistinguishedNames(SSLContextRef ctx, CFArrayRef *names)
{
    CFMutableArrayRef outArray = NULL;
    DNListElem *dn;
    if (!ctx || !names) return paramErr;
    if (!ctx->acceptableDNList) { *names = NULL; return noErr; }
    outArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    dn = ctx->acceptableDNList;
    while (dn) {
        CFDataRef cfDn = CFDataCreate(NULL, dn->derDN.data, dn->derDN.length);
        CFArrayAppendValue(outArray, cfDn);
        CFRelease(cfDn);
        dn = dn->next;
    }
    *names = outArray;
    return noErr;
}

static OSStatus sslCopyPeerCertificates(SSLContextRef ctx, CFArrayRef *certs, Boolean legacy)
{
    uint32 numCerts;
    CFMutableArrayRef ca;
    CFIndex i;
    SecCertificateRef cfd;
    OSStatus ortn;
    CSSM_DATA certData;
    SSLCertificate *scert;

    if (!ctx) return paramErr;
    *certs = NULL;
    numCerts = SSLGetCertificateChainLength(ctx->peerCert);
    if (numCerts == 0) return noErr;
    ca = CFArrayCreateMutable(kCFAllocatorDefault, (CFIndex)numCerts, &kCFTypeArrayCallBacks);
    if (!ca) return memFullErr;
    scert = ctx->peerCert;
    for (i = 0; (unsigned)i < numCerts; i++) {
        assert(scert != NULL);
        SSLBUF_TO_CSSM(&scert->derCert, &certData);
        ortn = SecCertificateCreateFromData(&certData, CSSM_CERT_X_509v3,
                                            CSSM_CERT_ENCODING_DER, &cfd);
        if (ortn) { CFRelease(ca); return ortn; }
        CFArrayInsertValueAtIndex(ca, 0, cfd);
        if (!legacy) CFRelease(cfd);
        scert = scert->next;
    }
    *certs = ca;
    return noErr;
}

OSStatus SSLCopyPeerCertificates(SSLContextRef ctx, CFArrayRef *certs)
{ return sslCopyPeerCertificates(ctx, certs, false); }

OSStatus SSLGetPeerCertificates(SSLContextRef ctx, CFArrayRef *certs)
{ return sslCopyPeerCertificates(ctx, certs, true); }

OSStatus SSLSetDiffieHellmanParams(SSLContextRef ctx, const void *dhParams, size_t dhParamsLen)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    SSLFreeBuffer(&ctx->dhParamsPrime, ctx);
    SSLFreeBuffer(&ctx->dhParamsGenerator, ctx);
    SSLFreeBuffer(&ctx->dhParamsEncoded, ctx);
    OSStatus ortn = SSLCopyBufferFromData(dhParams, dhParamsLen, &ctx->dhParamsEncoded);
    if (ortn) return ortn;
    SSLBuffer sParams;
    sParams.data   = (UInt8 *)dhParams;
    sParams.length = dhParamsLen;
    return sslDecodeDhParams(&sParams, &ctx->dhParamsPrime, &ctx->dhParamsGenerator);
}

OSStatus SSLGetDiffieHellmanParams(SSLContextRef ctx, const void **dhParams, size_t *dhParamsLen)
{
    if (!ctx) return paramErr;
    *dhParams    = ctx->dhParamsEncoded.data;
    *dhParamsLen = ctx->dhParamsEncoded.length;
    return noErr;
}

OSStatus SSLSetRsaBlinding(SSLContextRef ctx, Boolean blinding)
{ if (!ctx) return paramErr; ctx->rsaBlindingEnable = blinding; return noErr; }

OSStatus SSLGetRsaBlinding(SSLContextRef ctx, Boolean *blinding)
{ if (!ctx) return paramErr; *blinding = ctx->rsaBlindingEnable; return noErr; }

OSStatus SSLGetPeerSecTrust(SSLContextRef ctx, SecTrustRef *secTrust)
{ if (!ctx || !secTrust) return paramErr; *secTrust = ctx->peerSecTrust; return noErr; }

OSStatus SSLCopyPeerTrust(SSLContextRef ctx, SecTrustRef *trust)
{
    if (!ctx || !trust) return paramErr;
    if (ctx->peerSecTrust) CFRetain(ctx->peerSecTrust);
    *trust = ctx->peerSecTrust;
    return noErr;
}

OSStatus SSLInternalMasterSecret(SSLContextRef ctx, void *secret, size_t *secretSize)
{
    if (!ctx || !secret || !secretSize) return paramErr;
    if (*secretSize < SSL_MASTER_SECRET_SIZE) return paramErr;
    memmove(secret, ctx->masterSecret, SSL_MASTER_SECRET_SIZE);
    *secretSize = SSL_MASTER_SECRET_SIZE;
    return noErr;
}

OSStatus SSLInternalServerRandom(SSLContextRef ctx, void *rand, size_t *randSize)
{
    if (!ctx || !rand || !randSize) return paramErr;
    if (*randSize < SSL_CLIENT_SRVR_RAND_SIZE) return paramErr;
    memmove(rand, ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    *randSize = SSL_CLIENT_SRVR_RAND_SIZE;
    return noErr;
}

OSStatus SSLInternalClientRandom(SSLContextRef ctx, void *rand, size_t *randSize)
{
    if (!ctx || !rand || !randSize) return paramErr;
    if (*randSize < SSL_CLIENT_SRVR_RAND_SIZE) return paramErr;
    memmove(rand, ctx->clientRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    *randSize = SSL_CLIENT_SRVR_RAND_SIZE;
    return noErr;
}

OSStatus SSLGetCipherSizes(SSLContextRef ctx, size_t *digestSize, size_t *symmetricKeySize, size_t *ivSize)
{
    if (!ctx || !digestSize || !symmetricKeySize || !ivSize) return paramErr;
    const SSLCipherSpec *c = ctx->selectedCipherSpec;
    *digestSize       = c->macAlgorithm->hash->digestSize;
    *symmetricKeySize = c->cipher->secretKeySize;
    *ivSize           = c->cipher->ivSize;
    return noErr;
}

OSStatus SSLGetResumableSessionInfo(SSLContextRef ctx, Boolean *sessionWasResumed,
    void *sessionID, size_t *sessionIDLength)
{
    if (!ctx || !sessionWasResumed || !sessionID || !sessionIDLength ||
        *sessionIDLength < MAX_SESSION_ID_LENGTH) return paramErr;
    if (ctx->sessionMatch) {
        *sessionWasResumed = true;
        if (ctx->sessionID.length > *sessionIDLength) return paramErr;
        if (ctx->sessionID.length) memmove(sessionID, ctx->sessionID.data, ctx->sessionID.length);
        *sessionIDLength = ctx->sessionID.length;
    } else {
        *sessionWasResumed = false;
        *sessionIDLength   = 0;
    }
    return noErr;
}

OSStatus SSLSetAllowAnonymousCiphers(SSLContextRef ctx, Boolean enable)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (ctx->validCipherSpecs != NULL) return badReqErr;
    ctx->anonCipherEnable = enable;
    return noErr;
}

OSStatus SSLGetAllowAnonymousCiphers(SSLContextRef ctx, Boolean *enable)
{
    if (!ctx || !enable) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    *enable = ctx->anonCipherEnable;
    return noErr;
}

OSStatus SSLSetSessionCacheTimeout(SSLContextRef ctx, uint32 timeoutInSeconds)
{ if (!ctx) return paramErr; ctx->sessionCacheTimeout = timeoutInSeconds; return noErr; }

OSStatus SSLInternalSetMasterSecretFunction(SSLContextRef ctx,
    SSLInternalMasterSecretFunction mFunc, const void *arg)
{
    if (!ctx) return paramErr;
    ctx->masterSecretCallback = mFunc;
    ctx->masterSecretArg      = arg;
    return noErr;
}

OSStatus SSLInternalSetSessionTicket(SSLContextRef ctx, const void *ticket, size_t ticketLength)
{
    if (!ctx) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    if (ticketLength > 0xffff) return paramErr;
    SSLFreeBuffer(&ctx->sessionTicket, NULL);
    return SSLCopyBufferFromData(ticket, ticketLength, &ctx->sessionTicket);
}

OSStatus SSLGetNegotiatedCurve(SSLContextRef ctx, SSL_ECDSA_NamedCurve *namedCurve)
{
    if (!ctx || !namedCurve) return paramErr;
    if (ctx->ecdhPeerCurve == SSL_Curve_None) return paramErr;
    *namedCurve = ctx->ecdhPeerCurve;
    return noErr;
}

OSStatus SSLGetNumberOfECDSACurves(SSLContextRef ctx, unsigned *numCurves)
{ if (!ctx || !numCurves) return paramErr; *numCurves = ctx->ecdhNumCurves; return noErr; }

OSStatus SSLGetECDSACurves(SSLContextRef ctx, SSL_ECDSA_NamedCurve *namedCurves, unsigned *numCurves)
{
    if (!ctx || !namedCurves || !numCurves) return paramErr;
    if (*numCurves < ctx->ecdhNumCurves) return paramErr;
    memmove(namedCurves, ctx->ecdhCurves, ctx->ecdhNumCurves * sizeof(SSL_ECDSA_NamedCurve));
    *numCurves = ctx->ecdhNumCurves;
    return noErr;
}

OSStatus SSLSetECDSACurves(SSLContextRef ctx, const SSL_ECDSA_NamedCurve *namedCurves, unsigned numCurves)
{
    if (!ctx || !namedCurves || !numCurves) return paramErr;
    if (numCurves > SSL_ECDSA_NUM_CURVES) return paramErr;
    if (sslIsSessionActive(ctx)) return badReqErr;
    memmove(ctx->ecdhCurves, namedCurves, numCurves * sizeof(SSL_ECDSA_NamedCurve));
    ctx->ecdhNumCurves = numCurves;
    return noErr;
}

OSStatus SSLGetNumberOfClientAuthTypes(SSLContextRef ctx, unsigned *numTypes)
{
    if (!ctx || ctx->clientCertState == kSSLClientCertNone) return paramErr;
    *numTypes = ctx->numAuthTypes;
    return noErr;
}

OSStatus SSLGetClientAuthTypes(SSLContextRef ctx, SSLClientAuthenticationType *authTypes, unsigned *numTypes)
{
    if (!ctx || ctx->clientCertState == kSSLClientCertNone) return paramErr;
    memmove(authTypes, ctx->clientAuthTypes,
            ctx->numAuthTypes * sizeof(SSLClientAuthenticationType));
    *numTypes = ctx->numAuthTypes;
    return noErr;
}

OSStatus SSLGetNegotiatedClientAuthType(SSLContextRef ctx, SSLClientAuthenticationType *authType)
{ if (!ctx) return paramErr; *authType = ctx->negAuthType; return noErr; }

OSStatus SSLUpdateNegotiatedClientAuthType(SSLContextRef ctx)
{
    if (!ctx) return paramErr;
    ctx->x509Requested = 0;
    ctx->negAuthType   = SSLClientAuthNone;
    if (ctx->signingPrivKeyRef != NULL) {
        CSSM_ALGORITHMS ourKeyAlg = ctx->signingPubKey->KeyHeader.AlgorithmId;
        unsigned i;
        for (i = 0; i < ctx->numAuthTypes; i++) {
            switch (ctx->clientAuthTypes[i]) {
                case SSLClientAuth_RSASign:
                    if (ourKeyAlg == CSSM_ALGID_RSA) {
                        ctx->x509Requested = 1;
                        ctx->negAuthType   = SSLClientAuth_RSASign;
                    }
                    break;
#if SSL_ENABLE_ECDSA_SIGN_AUTH
                case SSLClientAuth_ECDSASign:
#endif
#if SSL_ENABLE_ECDSA_FIXED_ECDH_AUTH
                case SSLClientAuth_ECDSAFixedECDH:
#endif
                    if ((ourKeyAlg == CSSM_ALGID_ECDSA) &&
                        (ctx->ourSignerAlg == CSSM_ALGID_ECDSA)) {
                        ctx->x509Requested = 1;
                        ctx->negAuthType   = ctx->clientAuthTypes[i];
                    }
                    break;
#if SSL_ENABLE_RSA_FIXED_ECDH_AUTH
                case SSLClientAuth_RSAFixedECDH:
                    if ((ourKeyAlg == CSSM_ALGID_ECDSA) &&
                        (ctx->ourSignerAlg == CSSM_ALGID_RSA)) {
                        ctx->x509Requested = 1;
                        ctx->negAuthType   = SSLClientAuth_RSAFixedECDH;
                    }
                    break;
#endif
                default: break;
            }
            if (ctx->x509Requested) {
                sslLogNegotiateDebug("===CHOOSING authType %d", (int)ctx->negAuthType);
                break;
            }
        }
    }
    return noErr;
}
