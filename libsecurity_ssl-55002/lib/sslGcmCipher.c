/*
 * sslGcmCipher.c — TLS 1.2 AES-GCM cipher-spec callouts (Snow Leopard backport).
 *
 * Bridges the SSLSymmetricCipher `initialize`/`finish` vtable slots to the
 * validated GCM core (sslGcm.c) + libcrypto AES backend (sslGcmAes.c).
 *
 * Key-material handoff (from SSLInitPendingCiphers, NotExportable path):
 *   initialize(keyPtr, ivPtr, cipherCtx, ctx)
 *     keyPtr -> this direction's AES key   (secretKeySize bytes: 16 or 32)
 *     ivPtr  -> this direction's fixed IV  (ivSize bytes: 4)
 * We heap-allocate an SslGcmCtx, run sslGcmInit (builds the AES key schedule
 * via libcrypto and stores the 4-byte fixed IV), and stash the pointer in
 * cipherCtx->cc.aes — a void* union member unused by the CBC AES path
 * (which uses cc.cryptorRef). This avoids growing CipherContext, which is
 * embedded 4x in SSLContext.
 *
 * The actual record sealing/opening happens in tls12Callouts.c, which detects
 * the GCM sentinel mode and calls sslGcmEncrypt/Decrypt with the stored ctx.
 */

#include "sslContext.h"
#include "cryptType.h"
#include "sslGcmCipher.h"
#include "sslGcmAes.h"
#include "sslMemory.h"
#include "sslDebug.h"
#include <string.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>

/*
 * initialize callout. keyBits is derived from the spec's secretKeySize so a
 * single function serves both AES-128 and AES-256 GCM.
 */
static OSStatus sslGcmCipherInit(
    uint8 *key, uint8 *iv, CipherContext *cipherCtx, SSLContext *ctx)
{
    SslGcmCtx *gcm;
    int        keyBits;

    (void)ctx;
    if (cipherCtx == NULL || cipherCtx->symCipher == NULL) {
        return errSSLInternal;
    }
    if (key == NULL || iv == NULL) {
        sslErrorLog("sslGcmCipherInit: NULL key or iv\n");
        return errSSLInternal;
    }

    keyBits = (int)cipherCtx->symCipher->secretKeySize * 8;   /* 128 or 256 */

    /* Free any previously-allocated context (re-key / renegotiation). */
    if (cipherCtx->cc.aes != NULL) {
        sslFree(cipherCtx->cc.aes);
        cipherCtx->cc.aes = NULL;
    }

    gcm = (SslGcmCtx *)sslMalloc(sizeof(SslGcmCtx));
    if (gcm == NULL) {
        return memFullErr;
    }
    memset(gcm, 0, sizeof(*gcm));

    if (sslGcmInit(gcm, key, keyBits, iv) != 0) {
        sslErrorLog("sslGcmCipherInit: sslGcmInit failed (keyBits=%d)\n", keyBits);
        sslFree(gcm);
        return errSSLCrypto;
    }

    cipherCtx->cc.aes = gcm;
    return noErr;
}

/* finish callout: release the GCM context. */
static OSStatus sslGcmCipherFinish(CipherContext *cipherCtx, SSLContext *ctx)
{
    (void)ctx;
    if (cipherCtx == NULL) {
        return noErr;
    }
    if (cipherCtx->cc.aes != NULL) {
        sslFree(cipherCtx->cc.aes);
        cipherCtx->cc.aes = NULL;
    }
    return noErr;
}

/*
 * AEAD stubs for the encrypt/decrypt vtable slots. These must never be invoked:
 * the record layer (tls12WriteRecord / tls12DecryptRecord) detects the GCM
 * sentinel mode and calls sslGcmEncrypt/Decrypt directly, bypassing these.
 * Present only so the function pointers are non-NULL and to fail loudly if the
 * dispatch is ever wrong.
 */
static OSStatus sslGcmCipherCryptStub(
    SSLBuffer src, SSLBuffer dest, CipherContext *cipherCtx, SSLContext *ctx)
{
    (void)src; (void)dest; (void)cipherCtx; (void)ctx;
    sslErrorLog("sslGcmCipherCryptStub: AEAD cipher reached CBC crypt path!\n");
    return errSSLInternal;
}

/*
 * GCM cipher specs.
 *
 * Field meanings for the AEAD case:
 *   keySize        = secretKeySize (no separate "key size" distinction here)
 *   secretKeySize  = 16 (AES-128) or 32 (AES-256)
 *   ivSize         = 4  -> the implicit/fixed IV length; SSLInitPendingCiphers
 *                          extracts this many bytes per direction from the key
 *                          block and hands them to initialize() as `iv`.
 *   blockSize      = 0  -> disables the CBC explicit-IV + padding logic in the
 *                          record layer (GCM frames its own 8-byte explicit
 *                          nonce instead).
 *   encrMode       = SSL_CSSM_ALGMODE_GCM -> the AEAD sentinel the record
 *                          layer branches on.
 */
const SSLSymmetricCipher SSLCipherAES_128_GCM = {
    16,                      /* keySize        */
    16,                      /* secretKeySize  */
    4,                       /* ivSize (fixed IV) */
    0,                       /* blockSize (0 => AEAD, no CBC padding) */
    CSSM_ALGID_AES,          /* keyAlg  */
    CSSM_ALGID_AES,          /* encrAlg */
    SSL_CSSM_ALGMODE_GCM,    /* encrMode = AEAD sentinel */
    CSSM_PADDING_NONE,       /* encrPad */
    sslGcmCipherInit,        /* initialize */
    sslGcmCipherCryptStub,   /* encrypt (unused; AEAD path bypasses) */
    sslGcmCipherCryptStub,   /* decrypt (unused; AEAD path bypasses) */
    sslGcmCipherFinish       /* finish */
};

const SSLSymmetricCipher SSLCipherAES_256_GCM = {
    32,                      /* keySize        */
    32,                      /* secretKeySize  */
    4,                       /* ivSize (fixed IV) */
    0,                       /* blockSize (0 => AEAD) */
    CSSM_ALGID_AES,          /* keyAlg  */
    CSSM_ALGID_AES,          /* encrAlg */
    SSL_CSSM_ALGMODE_GCM,    /* encrMode = AEAD sentinel */
    CSSM_PADDING_NONE,       /* encrPad */
    sslGcmCipherInit,        /* initialize */
    sslGcmCipherCryptStub,   /* encrypt (unused) */
    sslGcmCipherCryptStub,   /* decrypt (unused) */
    sslGcmCipherFinish       /* finish */
};
