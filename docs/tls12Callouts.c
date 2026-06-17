/*
 * tls12Callouts.c — TLS 1.2 SslTlsCallouts implementation
 * Source-merge into Apple libsecurity_ssl-55002 (Snow Leopard 10.6.8 x86_64)
 */

#include "tls_ssl.h"
#include "sslMemory.h"
#include "sslUtils.h"
#include "sslDigests.h"
#include "sslAlertMessage.h"
#include "sslDebug.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <strings.h>

/* ─── PRF label strings ─────────────────────────────────────────────── */
#define PLS12_MASTER_SECRET             "master secret"
#define PLS12_MASTER_SECRET_LEN         13
#define PLS12_KEY_EXPAND                "key expansion"
#define PLS12_KEY_EXPAND_LEN            13
#define PLS12_CLIENT_FINISH             "client finished"
#define PLS12_CLIENT_FINISH_LEN         15
#define PLS12_SERVER_FINISH             "server finished"
#define PLS12_SERVER_FINISH_LEN         15
#define PLS12_EXPORT_CLIENT_WRITE       "client write key"
#define PLS12_EXPORT_CLIENT_WRITE_LEN   16
#define PLS12_EXPORT_SERVER_WRITE       "server write key"
#define PLS12_EXPORT_SERVER_WRITE_LEN   16
#define PLS12_EXPORT_IV_BLOCK           "IV block"
#define PLS12_EXPORT_IV_BLOCK_LEN       8

#define TLS12_PRF_HMAC              (&TlsHmacSHA256)
#define TLS12_FINISHED_HASH         (&SSLHashSHA256)
#define TLS12_FINISHED_DIGEST_LEN   CC_SHA256_DIGEST_LENGTH   /* 32 */

#define TLS12_HDR_LENGTH    (8 + 1 + 2 + 2)   /* seqNo+type+version+length */

#pragma mark *** P_SHA256 PRF ***

static OSStatus tls12PHash(
    SSLContext          *ctx,
    const HMACReference *hmac,
    const unsigned char *secret,
    unsigned             secretLen,
    unsigned char       *seed,
    unsigned             seedLen,
    unsigned char       *out,
    unsigned             outLen)
{
    unsigned char   aSubI[TLS_HMAC_MAX_SIZE];
    unsigned char   digest[TLS_HMAC_MAX_SIZE];
    HMACContextRef  hmacCtx;
    OSStatus        serr;
    unsigned        digestLen = hmac->macSize;

    serr = hmac->alloc(hmac, ctx, secret, secretLen, &hmacCtx);
    if (serr) return serr;

    serr = hmac->hmac(hmacCtx, seed, seedLen, aSubI, &digestLen);
    if (serr) goto fail;
    assert(digestLen == hmac->macSize);

    for (;;) {
        serr = hmac->init(hmacCtx);                          if (serr) break;
        serr = hmac->update(hmacCtx, aSubI, digestLen);      if (serr) break;
        serr = hmac->update(hmacCtx, seed, seedLen);         if (serr) break;
        serr = hmac->final(hmacCtx, digest, &digestLen);     if (serr) break;
        assert(digestLen == hmac->macSize);
        if (outLen <= digestLen) { memmove(out, digest, outLen); break; }
        memmove(out, digest, digestLen);
        out    += digestLen;
        outLen -= digestLen;
        serr = hmac->hmac(hmacCtx, aSubI, digestLen, aSubI, &digestLen);
        if (serr) break;
        assert(digestLen == hmac->macSize);
    }
fail:
    hmac->free(hmacCtx);
    memset(aSubI,  0, sizeof aSubI);
    memset(digest, 0, sizeof digest);
    return serr;
}

static OSStatus tls12_PRF(
    SSLContext  *ctx,
    const void  *vsecret, size_t secretLen,
    const void  *label,   size_t labelLen,
    const void  *seed,    size_t seedLen,
    void        *vout,    size_t outLen)
{
    unsigned char  *labelSeed = NULL;
    unsigned        labelSeedLen;
    OSStatus        serr;

    if (label != NULL) {
        labelSeedLen = (unsigned)(labelLen + seedLen);
        labelSeed = (unsigned char *)sslMalloc(labelSeedLen);
        if (labelSeed == NULL) return memFullErr;
        memmove(labelSeed, label, labelLen);
        memmove(labelSeed + labelLen, seed, seedLen);
    } else {
        labelSeed    = (unsigned char *)seed;
        labelSeedLen = (unsigned)seedLen;
    }
    serr = tls12PHash(ctx, TLS12_PRF_HMAC,
        (const unsigned char *)vsecret, (unsigned)secretLen,
        labelSeed, labelSeedLen,
        (unsigned char *)vout, (unsigned)outLen);
    if (label != NULL && labelSeed != NULL) sslFree(labelSeed);
    return serr;
}

#pragma mark *** record write — explicit IV ***

/*
 * tls12WriteRecord: like ssl3WriteRecord but prepends a random explicit IV
 * (blockSize bytes) before the plaintext for CBC cipher suites (RFC 5246 §6.2.3.2).
 * For stream ciphers or null cipher (blockSize == 0) the layout is identical
 * to TLS 1.0.
 */
OSStatus tls12WriteRecord(SSLRecord rec, SSLContext *ctx)
{
    OSStatus        err;
    int             padding = 0, i;
    WaitingRecord  *out = NULL, *queue;
    SSLBuffer       payload, mac;
    UInt8          *charPtr;
    UInt16          payloadSize, blockSize;
    UInt16          explicitIVLen = 0;

    assert(rec.contents.length <= 16384);

    blockSize = ctx->writeCipher.symCipher->blockSize;

    /* Explicit IV only for CBC ciphers under TLS 1.1+ */
    if (blockSize > 0 && ctx->negProtocolVersion >= TLS_Version_1_1) {
        explicitIVLen = blockSize;
    }

    payloadSize = (UInt16)(explicitIVLen +
                           rec.contents.length +
                           ctx->writeCipher.macRef->hash->digestSize);
    if (blockSize > 0) {
        padding = blockSize - (payloadSize % blockSize) - 1;
        payloadSize += padding + 1;
    }

    out = (WaitingRecord *)sslMalloc(offsetof(WaitingRecord, data) + 5 + payloadSize);
    if (out == NULL) return memFullErr;
    out->next   = NULL;
    out->sent   = 0;
    out->length = 5 + payloadSize;

    charPtr = out->data;
    *(charPtr++) = rec.contentType;
    charPtr = SSLEncodeInt(charPtr, rec.protocolVersion, 2);
    charPtr = SSLEncodeInt(charPtr, payloadSize, 2);

    /* Random explicit IV */
    if (explicitIVLen > 0) {
        SSLBuffer ivBuf;
        ivBuf.data   = charPtr;
        ivBuf.length = explicitIVLen;
        err = sslRand(ctx, &ivBuf);
        if (err) goto fail;
        charPtr += explicitIVLen;
    }

    /* Plaintext */
    memcpy(charPtr, rec.contents.data, rec.contents.length);
    payload.data   = charPtr;
    payload.length = rec.contents.length;
    charPtr += rec.contents.length;

    /* MAC (covers plaintext only, not explicit IV) */
    mac.data   = charPtr;
    mac.length = ctx->writeCipher.macRef->hash->digestSize;
    charPtr += mac.length;

    if (mac.length > 0) {
        assert(ctx->sslTslCalls != NULL);
        err = ctx->sslTslCalls->computeMac(rec.contentType,
                  payload, mac, &ctx->writeCipher,
                  ctx->writeCipher.sequenceNum, ctx);
        if (err) goto fail;
    }

    /* Full encrypted payload: explicitIV + plaintext + MAC + padding */
    payload.data   = out->data + 5;
    payload.length = payloadSize;

    /* Padding bytes */
    if (blockSize > 0) {
        for (i = 1; i <= padding + 1; ++i)
            payload.data[payload.length - i] = (UInt8)padding;
    }

    /* Encrypt in place */
    err = ctx->writeCipher.symCipher->encrypt(payload, payload, &ctx->writeCipher, ctx);
    if (err) goto fail;

    /* Enqueue */
    if (ctx->recordWriteQueue == NULL) {
        ctx->recordWriteQueue = out;
    } else {
        queue = ctx->recordWriteQueue;
        while (queue->next != NULL) queue = queue->next;
        queue->next = out;
    }

    IncrementUInt64(&ctx->writeCipher.sequenceNum);
    return noErr;

fail:
    sslFree(out);
    return err;
}

#pragma mark *** record decryption — explicit IV strip ***

static OSStatus tls12DecryptRecord(
    UInt8        type,
    SSLBuffer   *payload,
    SSLContext  *ctx)
{
    OSStatus    err;
    SSLBuffer   content;
    UInt8       blockSize = ctx->readCipher.symCipher->blockSize;

    if (blockSize > 0 && (payload->length % blockSize) != 0) {
        SSLFatalSessionAlert(SSL_AlertRecordOverflow, ctx);
        return errSSLRecordOverflow;
    }

    /* Decrypt in place */
    if ((err = ctx->readCipher.symCipher->decrypt(*payload, *payload,
             &ctx->readCipher, ctx)) != 0) {
        SSLFatalSessionAlert(SSL_AlertDecryptError, ctx);
        return errSSLDecryptionFail;
    }

    content.data   = payload->data;
    content.length = payload->length - ctx->readCipher.macRef->hash->digestSize;

    if (blockSize > 0) {
        /* TLS 1.1/1.2: strip explicit IV */
        if (ctx->negProtocolVersion >= TLS_Version_1_1) {
            if (payload->length < (size_t)(blockSize + 1 +
                    ctx->readCipher.macRef->hash->digestSize)) {
                SSLFatalSessionAlert(SSL_AlertDecodeError, ctx);
                return errSSLDecryptionFail;
            }
            content.data   += blockSize;
            content.length -= blockSize;
        }

        /* TLS padding check */
        UInt8  padSize  = payload->data[payload->length - 1];
        UInt8 *padChars;
        if (padSize > payload->length) {
            SSLFatalSessionAlert(SSL_AlertDecodeError, ctx);
            sslErrorLog("tls12DecryptRecord: bad padding (%d)\n", (unsigned)padSize);
            return errSSLDecryptionFail;
        }
        padChars = payload->data + payload->length - padSize;
        while (padChars < (payload->data + payload->length)) {
            if (*padChars++ != padSize) {
                SSLFatalSessionAlert(SSL_AlertDecodeError, ctx);
                return errSSLDecryptionFail;
            }
        }
        content.length -= (1 + padSize);
    }

    if (ctx->readCipher.macRef->hash->digestSize > 0) {
        /* MAC immediately follows the content. content.data already includes
         * the explicit-IV shift, so the MAC pointer must be relative to
         * content.data, NOT payload->data (which would land blockSize bytes
         * short, inside the ciphertext, and fail verification). */
        if ((err = SSLVerifyMac(type, &content,
                 content.data + content.length, ctx)) != 0) {
            SSLFatalSessionAlert(SSL_AlertBadRecordMac, ctx);
            return errSSLBadRecordMac;
        }
    }

    *payload = content;
    return noErr;
}

#pragma mark *** MAC init / free ***

static OSStatus tls12InitMac(CipherContext *cipherCtx, SSLContext *ctx)
{
    const HMACReference *hmac;
    OSStatus serr;

    assert(cipherCtx->macRef != NULL);
    hmac = cipherCtx->macRef->hmac;
    /* hmac is NULL for the null cipher — nothing to initialize */
    if (hmac == NULL) return noErr;
    if (cipherCtx->macCtx.hmacCtx != NULL) {
        hmac->free(cipherCtx->macCtx.hmacCtx);
        cipherCtx->macCtx.hmacCtx = NULL;
    }
    serr = hmac->alloc(hmac, ctx, cipherCtx->macSecret,
        cipherCtx->macRef->hash->digestSize, &cipherCtx->macCtx.hmacCtx);
    memset(cipherCtx->macSecret, 0, sizeof(cipherCtx->macSecret));
    return serr;
}

static OSStatus tls12FreeMac(CipherContext *cipherCtx)
{
    if (cipherCtx->macRef == NULL) return noErr;
    if (cipherCtx->macRef->hmac == NULL) return noErr;   /* null cipher */
    if (cipherCtx->macCtx.hmacCtx != NULL) {
        cipherCtx->macRef->hmac->free(cipherCtx->macCtx.hmacCtx);
        cipherCtx->macCtx.hmacCtx = NULL;
    }
    return noErr;
}

#pragma mark *** record MAC ***

static OSStatus tls12ComputeMac(
    UInt8 type, SSLBuffer data, SSLBuffer mac,
    CipherContext *cipherCtx, sslUint64 seqNo, SSLContext *ctx)
{
    unsigned char        hdr[TLS12_HDR_LENGTH];
    unsigned char       *p;
    HMACContextRef       hmacCtx;
    OSStatus             serr;
    const HMACReference *hmac;
    unsigned             macLength;
    SSLProtocolVersion   vers = ctx->negProtocolVersion;

    assert(cipherCtx != NULL && cipherCtx->macRef != NULL);
    hmac = cipherCtx->macRef->hmac;
    /* null cipher: no MAC */
    if (hmac == NULL) return noErr;
    hmacCtx = cipherCtx->macCtx.hmacCtx;

    serr = hmac->init(hmacCtx);
    if (serr) goto fail;

    p    = SSLEncodeUInt64(hdr, seqNo);
    *p++ = type;
    *p++ = (unsigned char)(vers >> 8);
    *p++ = (unsigned char)(vers & 0xff);
    *p++ = (unsigned char)(data.length >> 8);
    *p   = (unsigned char)(data.length & 0xff);

    serr = hmac->update(hmacCtx, hdr, TLS12_HDR_LENGTH); if (serr) goto fail;
    serr = hmac->update(hmacCtx, data.data, data.length); if (serr) goto fail;
    macLength = mac.length;
    serr = hmac->final(hmacCtx, mac.data, &macLength);
    if (serr) goto fail;
    mac.length = macLength;
fail:
    return serr;
}

#pragma mark *** key derivation ***

#define TLS12_GKM_SEED_LEN  (PLS12_KEY_EXPAND_LEN + 2 * SSL_CLIENT_SRVR_RAND_SIZE)

static OSStatus tls12GenerateKeyMaterial(SSLBuffer key, SSLContext *ctx)
{
    unsigned char seedBuf[TLS12_GKM_SEED_LEN];
    memmove(seedBuf, PLS12_KEY_EXPAND, PLS12_KEY_EXPAND_LEN);
    memmove(seedBuf + PLS12_KEY_EXPAND_LEN,
            ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    memmove(seedBuf + PLS12_KEY_EXPAND_LEN + SSL_CLIENT_SRVR_RAND_SIZE,
            ctx->clientRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    return tls12_PRF(ctx,
        ctx->masterSecret, SSL_MASTER_SECRET_SIZE,
        NULL, 0, seedBuf, TLS12_GKM_SEED_LEN,
        key.data, key.length);
}

static OSStatus tls12GenerateExportKeyAndIv(
    SSLContext *ctx,
    const SSLBuffer clientWriteKey, const SSLBuffer serverWriteKey,
    SSLBuffer finalClientWriteKey,  SSLBuffer finalServerWriteKey,
    SSLBuffer finalClientIV,        SSLBuffer finalServerIV)
{
    /* TLS 1.2 forbids export suites — dead code for vtable completeness */
    unsigned char  randBuf[2 * SSL_CLIENT_SRVR_RAND_SIZE];
    unsigned char *ivBlock;
    char          *nullKey = "";
    OSStatus       serr;

    memmove(randBuf, ctx->clientRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    memmove(randBuf + SSL_CLIENT_SRVR_RAND_SIZE, ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);

    serr = tls12_PRF(ctx, clientWriteKey.data, clientWriteKey.length,
        PLS12_EXPORT_CLIENT_WRITE, PLS12_EXPORT_CLIENT_WRITE_LEN,
        randBuf, 2 * SSL_CLIENT_SRVR_RAND_SIZE,
        finalClientWriteKey.data, finalClientWriteKey.length);
    if (serr) return serr;
    serr = tls12_PRF(ctx, serverWriteKey.data, serverWriteKey.length,
        PLS12_EXPORT_SERVER_WRITE, PLS12_EXPORT_SERVER_WRITE_LEN,
        randBuf, 2 * SSL_CLIENT_SRVR_RAND_SIZE,
        finalServerWriteKey.data, finalServerWriteKey.length);
    if (serr) return serr;
    if (!finalClientIV.length && !finalServerIV.length) return noErr;
    ivBlock = (unsigned char *)sslMalloc(finalClientIV.length + finalServerIV.length);
    if (!ivBlock) return memFullErr;
    serr = tls12_PRF(ctx, (const unsigned char *)nullKey, 0,
        PLS12_EXPORT_IV_BLOCK, PLS12_EXPORT_IV_BLOCK_LEN,
        randBuf, 2 * SSL_CLIENT_SRVR_RAND_SIZE,
        ivBlock, finalClientIV.length + finalServerIV.length);
    if (!serr) {
        memmove(finalClientIV.data, ivBlock, finalClientIV.length);
        memmove(finalServerIV.data, ivBlock + finalClientIV.length, finalServerIV.length);
    }
    sslFree(ivBlock);
    return serr;
}

static OSStatus tls12GenerateMasterSecret(SSLContext *ctx)
{
    unsigned char randBuf[2 * SSL_CLIENT_SRVR_RAND_SIZE];
    memmove(randBuf, ctx->clientRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    memmove(randBuf + SSL_CLIENT_SRVR_RAND_SIZE, ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);
    return tls12_PRF(ctx,
        ctx->preMasterSecret.data, ctx->preMasterSecret.length,
        PLS12_MASTER_SECRET, PLS12_MASTER_SECRET_LEN,
        randBuf, 2 * SSL_CLIENT_SRVR_RAND_SIZE,
        ctx->masterSecret, SSL_MASTER_SECRET_SIZE);
}

#pragma mark *** Finished / CertVfy ***

static OSStatus tls12ComputeFinishedMac(
    SSLContext *ctx, SSLBuffer finished,
    SSLBuffer shaMsgState, SSLBuffer md5MsgState, Boolean isServer)
{
    unsigned char  digest[TLS12_FINISHED_DIGEST_LEN];
    SSLBuffer      digBuf;
    SSLBuffer      sha256Clone = {0, NULL};
    OSStatus       serr;
    const char    *finLabel    = isServer ? PLS12_SERVER_FINISH : PLS12_CLIENT_FINISH;
    unsigned       finLabelLen = isServer ? PLS12_SERVER_FINISH_LEN : PLS12_CLIENT_FINISH_LEN;

    (void)shaMsgState; (void)md5MsgState;

    serr = CloneHashState(TLS12_FINISHED_HASH, &ctx->sha256State, &sha256Clone, ctx);
    if (serr) return serr;
    digBuf.data   = digest;
    digBuf.length = TLS12_FINISHED_DIGEST_LEN;
    serr = TLS12_FINISHED_HASH->final(&sha256Clone, &digBuf);
    if (serr) goto done;
    serr = tls12_PRF(ctx,
        ctx->masterSecret, SSL_MASTER_SECRET_SIZE,
        finLabel, finLabelLen,
        digest, TLS12_FINISHED_DIGEST_LEN,
        finished.data, finished.length);
done:
    SSLFreeBuffer(&sha256Clone, ctx);
    return serr;
}

static OSStatus tls12ComputeCertVfyMac(
    SSLContext *ctx, SSLBuffer finished,
    SSLBuffer shaMsgState, SSLBuffer md5MsgState)
{
    SSLBuffer sha256Clone = {0, NULL};
    SSLBuffer digBuf;
    OSStatus  serr;

    (void)shaMsgState; (void)md5MsgState;
    assert(finished.length == TLS12_FINISHED_DIGEST_LEN);

    serr = CloneHashState(TLS12_FINISHED_HASH, &ctx->sha256State, &sha256Clone, ctx);
    if (serr) return serr;
    digBuf.data   = finished.data;
    digBuf.length = TLS12_FINISHED_DIGEST_LEN;
    serr = TLS12_FINISHED_HASH->final(&sha256Clone, &digBuf);
    SSLFreeBuffer(&sha256Clone, ctx);
    return serr;
}

#pragma mark *** dispatch table ***

const SslTlsCallouts Tls12Callouts = {
    tls12DecryptRecord,
    tls12WriteRecord,
    tls12InitMac,
    tls12FreeMac,
    tls12ComputeMac,
    tls12GenerateKeyMaterial,
    tls12GenerateExportKeyAndIv,
    tls12GenerateMasterSecret,
    tls12ComputeFinishedMac,
    tls12ComputeCertVfyMac
};
