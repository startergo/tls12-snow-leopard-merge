/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All Rights Reserved.
 * 
 * The contents of this file constitute Original Code as defined in and are
 * subject to the Apple Public Source License Version 1.2 (the 'License').
 * You may not use this file except in compliance with the License. Please obtain
 * a copy of the License at http://www.apple.com/publicsource and read it before
 * using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS
 * OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see the License for the
 * specific language governing rights and limitations under the License.
 */


/*
	File:		sslKeyExchange.c

	Contains:	Support for key exchange and server key exchange

	Written by:	Doug Mitchell

	Copyright: (c) 1999 by Apple Computer, Inc., all rights reserved.

*/

#include "sslContext.h"
#include "sslHandshake.h"
#include "sslMemory.h"
#include "sslDebug.h"
#include "sslUtils.h"
#include "appleCdsa.h"
#include "sslDigests.h"
#include "ModuleAttacher.h"
#include "sslBER.h"

#include <assert.h>

/* cubic PR #5 P1: route our libcrypto usage through tls12_chainverify.c's
 * process-wide once-init, which installs OpenSSL 0.9.8's required locking
 * callbacks before any libcrypto call. The static-dlopen pattern this file
 * used previously could fire before the chain/trust path triggered the init,
 * leaving RSA_verify / ECDSA_verify running without locks under concurrent
 * handshakes. */
extern void *tls12_libcrypto_handle(void);
#include <string.h>
#include <dlfcn.h>

#include <Security/cssmapi.h>
#include <Security/SecKeyPriv.h>
#include <pthread.h>

/*
 * TLS 1.2 backport: -dead_strip defect workaround.
 *
 * The monolith relink runs llvm-gcc-4.2 + ld64 with -dead_strip. That toolchain
 * incorrectly strips `static` functions that are reachable ONLY through a
 * multi-level static call chain within a single .o — even when the chain is
 * rooted at an exported function. Concretely, the public (exported)
 * SSLProcessServerKeyExchange calls the static SSLDecodeSignedServerKeyExchange,
 * which calls the static sslVerifyTLS12ECDSA / sslVerifyTLS12SHA256/384/512/SHA1;
 * ld64 dead-stripped that whole sub-tree, so at runtime the ECDSA-GCM (and RSA
 * SHA-2) ServerKeyExchange verification simply was not present -> handshake died
 * after the server flight with cipher=0x0000 / errSSLProtocol.
 *
 * KEEP_USED marks each verify function __attribute__((used)), which forces the
 * compiler to emit the symbol and forbids dead-strip from removing it. This is
 * the minimal, local fix and matches how the original working monolith retained
 * these functions. Applied to SSLDecodeSignedServerKeyExchange and every static
 * verify helper it dispatches to.
 */
#define KEEP_USED __attribute__((used))

/* TLS 1.2 HashAlgorithm values (RFC 5246 §7.4.1.4.1) */
#define TLS12_HASH_ALG_SHA256   4
#define TLS12_HASH_ALG_SHA384   5
#define TLS12_HASH_ALG_SHA512   6

/*
 * DER DigestInfo prefix for SHA-256 (PKCS#1 v2.1 §9.2):
 *   30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
 * The server signs DigestInfo(SHA256(data)), not raw SHA256(data).
 * We prepend this to our 32-byte hash before sslRawVerify (CSSM raw RSA)
 * so the byte comparison against the decrypted signature succeeds.
 */
static const uint8 kSHA256DigestInfoPrefix[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20
};
#define kSHA256DiPfxLen  (sizeof(kSHA256DigestInfoPrefix))
#define kSHA256DiLen     (kSHA256DiPfxLen + SSL_SHA256_DIGEST_LEN)  /* 19+32=51 */

/*
 * DER DigestInfo prefix for SHA-1 (PKCS#1 v2.1 §9.2):
 *   30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
 * In TLS 1.2, even SHA-1 signatures use DigestInfo wrapping.
 */
static const uint8 kSHA1DigestInfoPrefix[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
    0x2b, 0x0e, 0x03, 0x02, 0x1a,
    0x05, 0x00, 0x04, 0x14
};
#define kSHA1DiPfxLen  (sizeof(kSHA1DigestInfoPrefix))
#define kSHA1DiLen     (kSHA1DiPfxLen + SSL_SHA1_DIGEST_LEN)  /* 15+20=35 */

static OSStatus KEEP_USED
sslVerifyTLS12SHA256(SSLContext *ctx, const CSSM_KEY *pubKey,
    CSSM_CSP_HANDLE cspHand, const uint8 *hash32,
    const uint8 *sig, size_t sigLen)
{
    uint8 di[kSHA256DiLen];
    memcpy(di, kSHA256DigestInfoPrefix, kSHA256DiPfxLen);
    memcpy(di + kSHA256DiPfxLen, hash32, SSL_SHA256_DIGEST_LEN);
    return sslRawVerify(ctx, pubKey, cspHand, di, kSHA256DiLen, sig, sigLen);
}

/*
 * DER DigestInfo prefix for SHA-384 (PKCS#1 v2.1 §9.2):
 *   30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
 * Used to verify a SHA-384 RSA-signed ServerKeyExchange (the 256-bit GCM
 * suites sign the SKE with SHA-384). 48-byte digest.
 */
static const uint8 kSHA384DigestInfoPrefix[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30
};
#define kSHA384DiPfxLen  (sizeof(kSHA384DigestInfoPrefix))
#define kSHA384DiLen     (kSHA384DiPfxLen + SSL_SHA384_DIGEST_LEN)  /* 19+48=67 */

static OSStatus KEEP_USED
sslVerifyTLS12SHA384(SSLContext *ctx, const CSSM_KEY *pubKey,
    CSSM_CSP_HANDLE cspHand, const uint8 *hash48,
    const uint8 *sig, size_t sigLen)
{
    uint8 di[kSHA384DiLen];
    memcpy(di, kSHA384DigestInfoPrefix, kSHA384DiPfxLen);
    memcpy(di + kSHA384DiPfxLen, hash48, SSL_SHA384_DIGEST_LEN);
    return sslRawVerify(ctx, pubKey, cspHand, di, kSHA384DiLen, sig, sigLen);
}

/*
 * DER DigestInfo prefix for SHA-512 (PKCS#1 v2.1 §9.2):
 *   30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
 * Used to verify a SHA-512 RSA-signed ServerKeyExchange. Some servers (e.g.
 * tls12.badssl.com) sign the SKE with SHA-512 once SHA512+RSA is advertised in
 * signature_algorithms. 64-byte digest.
 */
static const uint8 kSHA512DigestInfoPrefix[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40
};
#define kSHA512DiPfxLen  (sizeof(kSHA512DigestInfoPrefix))
#define kSHA512DiLen     (kSHA512DiPfxLen + SSL_SHA512_DIGEST_LEN)  /* 19+64=83 */

static OSStatus KEEP_USED
sslVerifyTLS12SHA512(SSLContext *ctx, const CSSM_KEY *pubKey,
    CSSM_CSP_HANDLE cspHand, const uint8 *hash64,
    const uint8 *sig, size_t sigLen)
{
    uint8 di[kSHA512DiLen];
    memcpy(di, kSHA512DigestInfoPrefix, kSHA512DiPfxLen);
    memcpy(di + kSHA512DiPfxLen, hash64, SSL_SHA512_DIGEST_LEN);
    return sslRawVerify(ctx, pubKey, cspHand, di, kSHA512DiLen, sig, sigLen);
}

static OSStatus KEEP_USED
sslVerifyTLS12SHA1(SSLContext *ctx, const CSSM_KEY *pubKey,
    CSSM_CSP_HANDLE cspHand, const uint8 *sha1Hash,
    const uint8 *sig, size_t sigLen)
{
    uint8 di[kSHA1DiLen];
    memcpy(di, kSHA1DigestInfoPrefix, kSHA1DiPfxLen);
    memcpy(di + kSHA1DiPfxLen, sha1Hash, SSL_SHA1_DIGEST_LEN);
    return sslRawVerify(ctx, pubKey, cspHand, di, kSHA1DiLen, sig, sigLen);
}

/*
 * Phase 3: ECDSA ServerKeyExchange signature verification via libcrypto.
 *
 * The ECDHE_ECDSA suites (e.g. 0xC02B, used by google/youtube/wikipedia) sign
 * the ServerKeyExchange with the leaf certificate's ECDSA key. Apple's CSSM EC
 * path crashes on Snow Leopard (the same reason ECDHE key exchange was moved to
 * libcrypto), so we verify with libcrypto's ECDSA_verify, dlsym'd from
 * /usr/lib/libcrypto.0.9.8.dylib.
 *
 * We get the server's EC public key by handing the leaf certificate's raw DER
 * straight to libcrypto (d2i_X509 -> X509_get_pubkey -> EVP_PKEY_get1_EC_KEY),
 * sidestepping CSSM entirely. ECDSA_verify takes the RAW hash (not DigestInfo-
 * wrapped) and the DER-encoded ECDSA-Sig-Value exactly as it appears on the
 * wire, so we pass the SKE signature bytes through unmodified.
 *
 * Returns noErr on a good signature, errSSLCrypto / errSSLDecryptionFail
 * otherwise. Never asserts; any missing symbol or parse failure is an error.
 */
/* sslVerifyTLS12RSA - i386 libcrypto RSA-PKCS1 SKE-signature verify.
 * On Snow Leopard i386 CSSM cannot extract or rebuild the leaf RSA key
 * (CSSM_CL_CertGetKeyInfo fails; sslGetPubKeyFromBits bus-errors), so
 * ctx->peerPubKey is NULL for ECDHE_RSA. We verify the ServerKeyExchange
 * signature directly with libcrypto RSA_verify, mirroring sslVerifyTLS12ECDSA.
 * RSA_verify takes the RAW digest + NID and builds/compares DigestInfo itself. */
static OSStatus KEEP_USED
sslVerifyTLS12RSA(SSLContext *ctx, int nid, const uint8 *hash, size_t hashLen,
    const uint8 *sig, size_t sigLen)
{
    typedef void *(*d2i_X509_fn)(void **px, const unsigned char **in, long len);
    typedef void  (*X509_free_fn)(void *x);
    typedef void *(*X509_get_pubkey_fn)(void *x);
    typedef void  (*EVP_PKEY_free_fn)(void *pkey);
    typedef void *(*EVP_PKEY_get1_RSA_fn)(void *pkey);
    typedef void  (*RSA_free_fn)(void *rsa);
    typedef int   (*RSA_verify_fn)(int type, const unsigned char *m, unsigned int m_len,
                                   const unsigned char *sigbuf, unsigned int siglen, void *rsa);
    SSLCertificate *leaf;
    const unsigned char *p;
    void *x = NULL, *pkey = NULL, *rsa = NULL;
    int rc;
    OSStatus ortn = errSSLCrypto;

    void *libcrypto_rsa = tls12_libcrypto_handle();
    if (!libcrypto_rsa) {
        sslErrorLog("sslVerifyTLS12RSA: can't open libcrypto\n");
        return errSSLCrypto;
    }
    d2i_X509_fn          pd2i = (d2i_X509_fn)dlsym(libcrypto_rsa, "d2i_X509");
    X509_free_fn         pxf  = (X509_free_fn)dlsym(libcrypto_rsa, "X509_free");
    X509_get_pubkey_fn   pgp  = (X509_get_pubkey_fn)dlsym(libcrypto_rsa, "X509_get_pubkey");
    EVP_PKEY_free_fn     ppf  = (EVP_PKEY_free_fn)dlsym(libcrypto_rsa, "EVP_PKEY_free");
    EVP_PKEY_get1_RSA_fn pgr  = (EVP_PKEY_get1_RSA_fn)dlsym(libcrypto_rsa, "EVP_PKEY_get1_RSA");
    RSA_free_fn          prf  = (RSA_free_fn)dlsym(libcrypto_rsa, "RSA_free");
    RSA_verify_fn        prv  = (RSA_verify_fn)dlsym(libcrypto_rsa, "RSA_verify");
    if (!pd2i || !pxf || !pgp || !ppf || !pgr || !prf || !prv) {
        sslErrorLog("sslVerifyTLS12RSA: missing libcrypto symbols\n");
        return errSSLCrypto;
    }
    { FILE*_f=fopen("/tmp/nine808b.log","a"); if(_f){fprintf(_f,"RSAV enter nid=%d hashLen=%d sigLen=%d\n",nid,(int)hashLen,(int)sigLen);fclose(_f);} }

    leaf = ctx->peerCert;
    if (leaf == NULL) { sslErrorLog("sslVerifyTLS12RSA: no peer cert\n"); return errSSLCrypto; }
    while (leaf->next != NULL) leaf = leaf->next;

    p = (const unsigned char *)leaf->derCert.data;
    x = pd2i(NULL, &p, (long)leaf->derCert.length);
    if (x == NULL) { sslErrorLog("sslVerifyTLS12RSA: d2i_X509 failed\n"); return errSSLCrypto; }
    pkey = pgp(x);
    if (pkey == NULL) { sslErrorLog("sslVerifyTLS12RSA: X509_get_pubkey failed\n"); goto out; }
    rsa = pgr(pkey);
    if (rsa == NULL) { sslErrorLog("sslVerifyTLS12RSA: not an RSA key\n"); goto out; }

    rc = prv(nid, hash, (unsigned int)hashLen, sig, (unsigned int)sigLen, rsa);
    { FILE*_f=fopen("/tmp/nine808b.log","a"); if(_f){fprintf(_f,"RSAV RSA_verify rc=%d\n",rc);fclose(_f);} }
    if (rc == 1) ortn = noErr;
    else { sslErrorLog("sslVerifyTLS12RSA: RSA_verify rc=%d\n", rc); ortn = errSSLDecryptionFail; }

out:
    if (rsa)  prf(rsa);
    if (pkey) ppf(pkey);
    if (x)    pxf(x);
    return ortn;
}

static OSStatus KEEP_USED
sslVerifyTLS12ECDSA(SSLContext *ctx, const uint8 *hash, size_t hashLen,
    const uint8 *sig, size_t sigLen)
{
    typedef void *(*d2i_X509_fn)(void **px, const unsigned char **in, long len);
    typedef void  (*X509_free_fn)(void *x);
    typedef void *(*X509_get_pubkey_fn)(void *x);
    typedef void  (*EVP_PKEY_free_fn)(void *pkey);
    typedef void *(*EVP_PKEY_get1_EC_KEY_fn)(void *pkey);
    typedef void  (*EC_KEY_free_fn)(void *key);
    typedef int   (*ECDSA_verify_fn)(int type, const unsigned char *dgst, int dgstlen,
                                     const unsigned char *sig, int siglen, void *eckey);

    SSLCertificate *leaf;
    const unsigned char *p;
    void *x = NULL, *pkey = NULL, *ecKey = NULL;
    int   rc;
    OSStatus ortn = errSSLCrypto;

    void *libcrypto_ecdsa = tls12_libcrypto_handle();
    if (!libcrypto_ecdsa) {
        sslErrorLog("sslVerifyTLS12ECDSA: can't open libcrypto\n");
        return errSSLCrypto;
    }

    d2i_X509_fn             pd2i_X509            = (d2i_X509_fn)dlsym(libcrypto_ecdsa, "d2i_X509");
    X509_free_fn            pX509_free           = (X509_free_fn)dlsym(libcrypto_ecdsa, "X509_free");
    X509_get_pubkey_fn      pX509_get_pubkey     = (X509_get_pubkey_fn)dlsym(libcrypto_ecdsa, "X509_get_pubkey");
    EVP_PKEY_free_fn        pEVP_PKEY_free       = (EVP_PKEY_free_fn)dlsym(libcrypto_ecdsa, "EVP_PKEY_free");
    EVP_PKEY_get1_EC_KEY_fn pEVP_PKEY_get1_EC_KEY= (EVP_PKEY_get1_EC_KEY_fn)dlsym(libcrypto_ecdsa, "EVP_PKEY_get1_EC_KEY");
    EC_KEY_free_fn          pEC_KEY_free         = (EC_KEY_free_fn)dlsym(libcrypto_ecdsa, "EC_KEY_free");
    ECDSA_verify_fn         pECDSA_verify        = (ECDSA_verify_fn)dlsym(libcrypto_ecdsa, "ECDSA_verify");

    if (!pd2i_X509 || !pX509_free || !pX509_get_pubkey || !pEVP_PKEY_free ||
        !pEVP_PKEY_get1_EC_KEY || !pEC_KEY_free || !pECDSA_verify) {
        sslErrorLog("sslVerifyTLS12ECDSA: missing libcrypto symbols\n");
        return errSSLCrypto;
    }

    /* Leaf cert is the TAIL of the peerCert list (list is built root-first). */
    leaf = ctx->peerCert;
    if (leaf == NULL) {
        sslErrorLog("sslVerifyTLS12ECDSA: no peer cert\n");
        return errSSLCrypto;
    }
    while (leaf->next != NULL) leaf = leaf->next;

    /* Parse the leaf cert DER -> X509 -> EVP_PKEY -> EC_KEY. */
    p = (const unsigned char *)leaf->derCert.data;
    x = pd2i_X509(NULL, &p, (long)leaf->derCert.length);
    if (x == NULL) {
        sslErrorLog("sslVerifyTLS12ECDSA: d2i_X509 failed\n");
        return errSSLCrypto;
    }
    pkey = pX509_get_pubkey(x);
    if (pkey == NULL) {
        sslErrorLog("sslVerifyTLS12ECDSA: X509_get_pubkey failed\n");
        goto out;
    }
    ecKey = pEVP_PKEY_get1_EC_KEY(pkey);
    if (ecKey == NULL) {
        sslErrorLog("sslVerifyTLS12ECDSA: not an EC key\n");
        goto out;
    }

    /* ECDSA_verify: type ignored, raw hash, DER sig. rc==1 means valid. */
    rc = pECDSA_verify(0, hash, (int)hashLen, sig, (int)sigLen, ecKey);
    if (rc == 1) {
        ortn = noErr;
    } else {
        sslErrorLog("sslVerifyTLS12ECDSA: ECDSA_verify rc=%d\n", rc);
        ortn = errSSLDecryptionFail;
    }

out:
    if (ecKey) pEC_KEY_free(ecKey);
    if (pkey)  pEVP_PKEY_free(pkey);
    if (x)     pX509_free(x);
    return ortn;
}

#pragma mark -
#pragma mark *** forward static declarations ***
static OSStatus SSLGenServerDHParamsAndKey(SSLContext *ctx);
static OSStatus SSLEncodeDHKeyParams(SSLContext *ctx, uint8 *charPtr);
static OSStatus SSLDecodeDHKeyParams(SSLContext *ctx, uint8 **charPtr,
	UInt32 length);
static OSStatus SSLDecodeECDHKeyParams(SSLContext *ctx, uint8 **charPtr,
	UInt32 length);

#define DH_PARAM_DUMP		0
#if 	DH_PARAM_DUMP
static void dumpBuf(const char *name, SSLBuffer *buf)
{
	printf("%s:\n", name);
	uint8 *cp = buf->data;
	uint8 *endCp = cp + buf->length;
	do {
		unsigned i;
		for(i=0; i<16; i++) {
			printf("%02x ", *cp++);
			if(cp == endCp) break;
		}
		if(cp == endCp) break;
		printf("\n");
	} while(cp < endCp);
	printf("\n");
}
#else
#define dumpBuf(n, b)
#endif

#if 	APPLE_DH

#pragma mark -
#pragma mark *** local D-H parameter generator ***
struct ServerDhParams {
	SSLBuffer		prime;		
	SSLBuffer		generator;
	SSLBuffer		paramBlock;
};

static pthread_once_t serverDhParamsControl = PTHREAD_ONCE_INIT;
static struct ServerDhParams serverDhParams = {};

static void SSLInitServerDHParams(void) {
	CSSM_CSP_HANDLE cspHand;
	CSSM_CL_HANDLE  clHand;
	CSSM_TP_HANDLE  tpHand;
	CSSM_RETURN     crtn;
	crtn = attachToModules(&cspHand, &clHand, &tpHand);
	if(crtn) return;
	CSSM_CC_HANDLE 	ccHandle;
	CSSM_DATA cParams = {0, NULL};
	crtn = CSSM_CSP_CreateKeyGenContext(cspHand, CSSM_ALGID_DH,
		SSL_DH_DEFAULT_PRIME_SIZE, NULL, NULL, NULL, NULL, &cParams, &ccHandle);
	if(crtn) { stPrintCdsaError("ServerDhParams CSSM_CSP_CreateKeyGenContext", crtn); return; }
	sslDhDebug("^^^generating Diffie-Hellman parameters...");
	crtn = CSSM_GenerateAlgorithmParams(ccHandle, SSL_DH_DEFAULT_PRIME_SIZE, &cParams);
	if(crtn) {
		stPrintCdsaError("ServerDhParams CSSM_GenerateAlgorithmParams", crtn);
		CSSM_DeleteContext(ccHandle); return;
	}
	CSSM_TO_SSLBUF(&cParams, &serverDhParams.paramBlock);
	OSStatus ortn = sslDecodeDhParams(&serverDhParams.paramBlock,
        &serverDhParams.prime, &serverDhParams.generator);
	if(ortn) { sslErrorLog("ServerDhParams: param decode error\n"); return; }
	CSSM_DeleteContext(ccHandle);
}

#endif	/* APPLE_DH */

#pragma mark -
#pragma mark *** RSA key exchange ***

#define RSA_CLIENT_KEY_ADD_LENGTH		1

typedef	CSSM_KEY_PTR	SSLRSAPrivateKey;

static OSStatus
SSLEncodeRSAKeyParams(SSLBuffer *keyParams, SSLRSAPrivateKey *key, SSLContext *ctx)
{
	OSStatus    err;
    SSLBuffer   modulus, exponent;
    uint8       *charPtr;

	if(err = attachToCsp(ctx)) return err;
	assert((*key)->KeyHeader.BlobType == CSSM_KEYBLOB_RAW);
	err = sslGetPubKeyBits(ctx, *key, ctx->cspHand, &modulus, &exponent);
	if(err) {
		SSLFreeBuffer(&modulus, ctx);
		SSLFreeBuffer(&exponent, ctx);
		return err;
	}
    if ((err = SSLAllocBuffer(keyParams, modulus.length + exponent.length + 4, ctx)) != 0)
        return err;
    charPtr = keyParams->data;
    charPtr = SSLEncodeInt(charPtr, modulus.length, 2);
    memcpy(charPtr, modulus.data, modulus.length);
    charPtr += modulus.length;
    charPtr = SSLEncodeInt(charPtr, exponent.length, 2);
    memcpy(charPtr, exponent.data, exponent.length);
	SSLFreeBuffer(&modulus, ctx);
	SSLFreeBuffer(&exponent, ctx);
    return noErr;
}

static OSStatus
SSLEncodeRSAPremasterSecret(SSLContext *ctx)
{
	SSLBuffer           randData;
    OSStatus            err;
    SSLProtocolVersion	maxVersion;
	
    if ((err = SSLAllocBuffer(&ctx->preMasterSecret, SSL_RSA_PREMASTER_SECRET_SIZE, ctx)) != 0)
        return err;
	sslGetMaxProtVersion(ctx, &maxVersion);
    SSLEncodeInt(ctx->preMasterSecret.data, maxVersion, 2);
    randData.data = ctx->preMasterSecret.data+2;
    randData.length = SSL_RSA_PREMASTER_SECRET_SIZE - 2;
    if ((err = sslRand(ctx, &randData)) != 0)
        return err;
    return noErr;
}

static OSStatus
SSLEncodeSignedServerKeyExchange(SSLRecord *keyExch, SSLContext *ctx)
{
	OSStatus        err;
    uint8           *charPtr;
    size_t          outputLen;
    uint8           hashes[SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN];
    SSLBuffer       exchangeParams,clientRandom,serverRandom,hashCtx, hash;
	uint8			*dataToSign;
	size_t			dataToSignLen;
	bool			isRsa = true;
    uint32 			maxSigLen;
    size_t	    	actSigLen;
	SSLBuffer		signature;
	const CSSM_KEY	*cssmKey;
	
    assert(ctx->protocolSide == SSL_ServerSide);
	assert(ctx->signingPubKey != NULL);
    exchangeParams.data = 0;
    hashCtx.data = 0;
	signature.data = 0;
	
	switch(ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA:
        case SSL_RSA_EXPORT:
			if(ctx->encryptPubKey == NULL) {
				sslErrorLog("RSAServerKeyExchange: no encrypt cert\n");
				return errSSLBadConfiguration;
			}
			err = SSLEncodeRSAKeyParams(&exchangeParams, &ctx->encryptPubKey, ctx);
			break;
		#if 	APPLE_DH
		case SSL_DHE_DSS:
		case SSL_DHE_DSS_EXPORT:
			isRsa = false;
		case SSL_DHE_RSA:
		case SSL_DHE_RSA_EXPORT:
		{
			err = SSLGenServerDHParamsAndKey(ctx);
			if(err) return err;
			UInt32 len = ctx->dhParamsPrime.length + 
				ctx->dhParamsGenerator.length + ctx->dhExchangePublic.length + 6;
			err = SSLAllocBuffer(&exchangeParams, len, ctx);
			if(err) goto fail;
			err = SSLEncodeDHKeyParams(ctx, exchangeParams.data);
			break;
		}
		#endif
		default:
			assert(0);
			return errSSLInternal;
	}
	if(err) goto fail;
			    
    clientRandom.data   = ctx->clientRandom;
    clientRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    serverRandom.data   = ctx->serverRandom;
    serverRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    
	if(isRsa) {
		dataToSign = hashes;
		dataToSignLen = SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN;
		hash.data = &hashes[0];
		hash.length = SSL_MD5_DIGEST_LEN;
		if ((err = ReadyHash(&SSLHashMD5, &hashCtx, ctx)) != 0) goto fail;
		if ((err = SSLHashMD5.update(&hashCtx, &clientRandom)) != 0) goto fail;
		if ((err = SSLHashMD5.update(&hashCtx, &serverRandom)) != 0) goto fail;
		if ((err = SSLHashMD5.update(&hashCtx, &exchangeParams)) != 0) goto fail;
		if ((err = SSLHashMD5.final(&hashCtx, &hash)) != 0) goto fail;
		if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;
    } else {
		dataToSign = &hashes[SSL_MD5_DIGEST_LEN];
		dataToSignLen = SSL_SHA1_DIGEST_LEN;
	}
    hash.data = &hashes[SSL_MD5_DIGEST_LEN];
    hash.length = SSL_SHA1_DIGEST_LEN;
    if ((err = ReadyHash(&SSLHashSHA1, &hashCtx, ctx)) != 0) goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0) goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0) goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &exchangeParams)) != 0) goto fail;
    if ((err = SSLHashSHA1.final(&hashCtx, &hash)) != 0) goto fail;
    if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;
    
	err = SecKeyGetCSSMKey(ctx->signingPrivKeyRef, &cssmKey);
	if(err) goto fail;
	err = sslGetMaxSigSize(cssmKey, &maxSigLen);
	if(err) goto fail;
	err = SSLAllocBuffer(&signature, maxSigLen, ctx);
	if(err) goto fail;
	
	err = sslRawSign(ctx, ctx->signingPrivKeyRef,
		dataToSign, dataToSignLen,
		signature.data, maxSigLen, &actSigLen);
	if(err) goto fail;
	assert(actSigLen <= maxSigLen);
	
    outputLen = exchangeParams.length + 2 + actSigLen;
    keyExch->protocolVersion = ctx->negProtocolVersion;
    keyExch->contentType = SSL_RecordTypeHandshake;
    if ((err = SSLAllocBuffer(&keyExch->contents, outputLen+4, ctx)) != 0) goto fail;
    
    charPtr = keyExch->contents.data;
    *charPtr++ = SSL_HdskServerKeyExchange;
    charPtr = SSLEncodeInt(charPtr, outputLen, 3);
    memcpy(charPtr, exchangeParams.data, exchangeParams.length);
    charPtr += exchangeParams.length;
    charPtr = SSLEncodeInt(charPtr, actSigLen, 2);
	memcpy(charPtr, signature.data, actSigLen);
    err = noErr;
    
fail:
    SSLFreeBuffer(&hashCtx, ctx);
    SSLFreeBuffer(&exchangeParams, ctx);
    SSLFreeBuffer(&signature, ctx);
    return err;
}

/*
 * Decode and verify a server key exchange message signed by server's public key.
 *
 * Change Group D3 / TLS 1.2:
 *
 * In TLS 1.2 (RFC 5246 §7.4.3), the ServerKeyExchange signature is prefixed
 * with a 2-byte SignatureAndHashAlgorithm field before the signature length:
 *
 *   TLS 1.2:   [hash_alg:1][sig_alg:1][sig_len:2][signature:sig_len]
 *   TLS 1.0/1: [sig_len:2][signature:sig_len]
 *
 * When negProtocolVersion == TLS_Version_1_2 we:
 *   1. Read the hash_alg byte to determine which hash the server used.
 *   2. Skip sig_alg (we only support RSA signing keys in Phase 1).
 *   3. Hash signedParams with the indicated algorithm:
 *      - SHA-256 (hash_alg=4): hash = SHA256(clientRandom+serverRandom+params)
 *      - SHA-384 (hash_alg=5): fall through to SHA-256 (best effort)
 *      - other: fall back to MD5+SHA1
 *   4. Verify via sslRawVerify (PKCS#1 v1.5, which handles DigestInfo wrapping).
 *
 * The CSSM sslRawVerify function passes the hash directly to CSSM_SignVerify
 * with CSSM_PADDING_PKCS1 which handles DigestInfo wrapping automatically
 * based on the data length — for 32-byte input it infers SHA-256, for 36-byte
 * input it uses the MD5+SHA1 concatenation format.
 */
static OSStatus KEEP_USED
SSLDecodeSignedServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{   
	OSStatus        err;
    SSLBuffer       hashOut, hashCtx, clientRandom, serverRandom;
    UInt16          modulusLen = 0, exponentLen = 0, signatureLen;
    uint8           *modulus = NULL, *exponent = NULL, *signature;
    uint8           hashes[SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN];
    uint8           sha256Digest[SSL_SHA256_DIGEST_LEN];
    SSLBuffer       signedHashes;
 	uint8			*dataToSign;
	size_t			dataToSignLen;
	bool			isRsa = true;
	uint8			tls12HashAlg = 0;   /* hash algorithm byte from SignatureAndHashAlgorithm */
	
	assert(ctx->protocolSide == SSL_ClientSide);
	signedHashes.data = 0;
    hashCtx.data = 0;
    
    if (message.length < 2) {
    	sslErrorLog("SSLDecodeSignedServerKeyExchange: msg len error 1\n");
        return errSSLProtocol;
    }
	
    uint8 *charPtr = message.data;
	uint8 *endCp = charPtr + message.length;

	switch(ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA:
        case SSL_RSA_EXPORT:
			modulusLen = SSLDecodeInt(charPtr, 2);
			charPtr += 2;
			if((charPtr + modulusLen) > endCp) {
				sslErrorLog("signedServerKeyExchange: msg len error 2\n");
				return errSSLProtocol;
			}
			modulus = charPtr;
			charPtr += modulusLen;
			exponentLen = SSLDecodeInt(charPtr, 2);
			charPtr += 2;
			if((charPtr + exponentLen) > endCp) {
				sslErrorLog("signedServerKeyExchange: msg len error 3\n");
				return errSSLProtocol;
			}
			exponent = charPtr;
			charPtr += exponentLen;
			break;
		#if		APPLE_DH
		case SSL_DHE_DSS:
		case SSL_DHE_DSS_EXPORT:
			isRsa = false;
		case SSL_DHE_RSA:
		case SSL_DHE_RSA_EXPORT:
			err = SSLDecodeDHKeyParams(ctx, &charPtr, message.length);
			if(err) return err;
			break;
		#endif
		case SSL_ECDHE_ECDSA:
			isRsa = false;
		case SSL_ECDHE_RSA:
			err = SSLDecodeECDHKeyParams(ctx, &charPtr, message.length);
			if(err) return err;
			break;
		default:
			assert(0);
			return errSSLInternal;
	}
	
	/* signedParams covers the key exchange params (EC curve + pubkey, or DH params) */
	SSLBuffer signedParams;
	signedParams.data = message.data;
	signedParams.length = charPtr - message.data;

	/*
	 * TLS 1.2: parse and skip the 2-byte SignatureAndHashAlgorithm prefix,
	 * saving the hash algorithm byte for use in digest selection below.
	 */
	if (ctx->negProtocolVersion == TLS_Version_1_2) {
		if ((charPtr + 4) > endCp) {   /* need at least hash(1)+sig(1)+len(2) */
			sslErrorLog("signedServerKeyExchange: TLS1.2 sig prefix truncated\n");
			return errSSLProtocol;
		}
		tls12HashAlg = charPtr[0];     /* e.g. 4=sha256, 5=sha384, 2=sha1 */
		/* charPtr[1] is sig_alg (1=rsa, 3=ecdsa) */
		charPtr += 2;
	}

	signatureLen = SSLDecodeInt(charPtr, 2);
	charPtr += 2;
	if((charPtr + signatureLen) != endCp) {
		sslErrorLog("signedServerKeyExchange: msg len error 4 "
			"(sigLen=%u remaining=%d)\n",
			(unsigned)signatureLen, (int)(endCp - charPtr));
		return errSSLProtocol;
	}
	signature = charPtr;
	
    clientRandom.data = ctx->clientRandom;
    clientRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    serverRandom.data = ctx->serverRandom;
    serverRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;

	if (ctx->negProtocolVersion == TLS_Version_1_2 && !isRsa) {
		/*
		 * Phase 3: TLS 1.2 ECDSA-signed ServerKeyExchange (ECDHE_ECDSA suites,
		 * e.g. google/youtube/wikipedia on 0xC02B). Hash with the algorithm the
		 * server indicated (SHA-256 for hashAlg=4, SHA-384 for hashAlg=5; we
		 * advertised only those two ECDSA pairs), then ECDSA-verify the raw hash
		 * against the leaf cert's EC public key via libcrypto.
		 */
		uint8     ecHash[SSL_SHA512_DIGEST_LEN];   /* max 64 (SHA-512) */
		SSLBuffer ecHashBuf;
		const HashReference *hashRef;
		unsigned  ecHashLen;

		if (tls12HashAlg == TLS12_HASH_ALG_SHA512) {
			hashRef   = &SSLHashSHA512;
			ecHashLen = SSL_SHA512_DIGEST_LEN;
		} else if (tls12HashAlg == TLS12_HASH_ALG_SHA384) {
			hashRef   = &SSLHashSHA384;
			ecHashLen = SSL_SHA384_DIGEST_LEN;
		} else {
			/* default to SHA-256 (hashAlg=4); covers the common ECDSA case */
			hashRef   = &SSLHashSHA256;
			ecHashLen = SSL_SHA256_DIGEST_LEN;
		}
		ecHashBuf.data   = ecHash;
		ecHashBuf.length = ecHashLen;

		if ((err = ReadyHash(hashRef, &hashCtx, ctx)) != 0) goto fail;
		if ((err = hashRef->update(&hashCtx, &clientRandom)) != 0) goto fail;
		if ((err = hashRef->update(&hashCtx, &serverRandom)) != 0) goto fail;
		if ((err = hashRef->update(&hashCtx, &signedParams)) != 0) goto fail;
		if ((err = hashRef->final(&hashCtx, &ecHashBuf)) != 0) goto fail;
		if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;

		err = sslVerifyTLS12ECDSA(ctx, ecHash, ecHashLen, signature, signatureLen);
		if (err) {
			sslErrorLog("SSLDecodeSignedServerKeyExchange: ECDSA verify "
				"err %d (hashAlg=%u)\n", (int)err, (unsigned)tls12HashAlg);
			goto fail;
		}
	} else if (ctx->negProtocolVersion == TLS_Version_1_2 &&
	    tls12HashAlg == TLS12_HASH_ALG_SHA512) {
		/*
		 * TLS 1.2 SHA-512 RSA-signed ServerKeyExchange. Some servers (e.g.
		 * tls12.badssl.com) sign the SKE with SHA-512 once we advertise
		 * SHA512+RSA in signature_algorithms. Hash = SHA512(clientRandom ||
		 * serverRandom || signedParams), then RSA-verify against
		 * DigestInfo(SHA512(...)). RSA only; ECDSA+SHA512 is handled in the
		 * !isRsa branch above.
		 */
		uint8 sha512Digest[SSL_SHA512_DIGEST_LEN];
		SSLBuffer sha512Buf;
		sha512Buf.data   = sha512Digest;
		sha512Buf.length = SSL_SHA512_DIGEST_LEN;

		if ((err = ReadyHash(&SSLHashSHA512, &hashCtx, ctx)) != 0) goto fail;
		if ((err = SSLHashSHA512.update(&hashCtx, &clientRandom)) != 0) goto fail;
		if ((err = SSLHashSHA512.update(&hashCtx, &serverRandom)) != 0) goto fail;
		if ((err = SSLHashSHA512.update(&hashCtx, &signedParams)) != 0) goto fail;
		if ((err = SSLHashSHA512.final(&hashCtx, &sha512Buf)) != 0) goto fail;
		if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;

		if (ctx->peerPubKey == NULL)
			err = sslVerifyTLS12RSA(ctx, 674, sha512Digest, SSL_SHA512_DIGEST_LEN, signature, signatureLen);
		else
		err = sslVerifyTLS12SHA512(ctx, ctx->peerPubKey, ctx->peerPubKeyCsp,
			sha512Digest, signature, signatureLen);
		if(err) {
			sslErrorLog("SSLDecodeSignedServerKeyExchange: SHA512 verify "
				"err %d (hashAlg=%u)\n", (int)err, (unsigned)tls12HashAlg);
			goto fail;
		}
	} else if (ctx->negProtocolVersion == TLS_Version_1_2 &&
	    tls12HashAlg == TLS12_HASH_ALG_SHA384) {
		/*
		 * TLS 1.2 SHA-384 signature path (AES-256-GCM-SHA384 suites).
		 * Hash = SHA384(clientRandom || serverRandom || signedParams), then
		 * RSA-verify against DigestInfo(SHA384(...)). Only the RSA case is
		 * handled here; ECDSA SKE verification is not implemented (isRsa is
		 * false for SSL_ECDHE_ECDSA, handled in the else-branch fallback).
		 */
		uint8 sha384Digest[SSL_SHA384_DIGEST_LEN];
		SSLBuffer sha384Buf;
		sha384Buf.data   = sha384Digest;
		sha384Buf.length = SSL_SHA384_DIGEST_LEN;

		if ((err = ReadyHash(&SSLHashSHA384, &hashCtx, ctx)) != 0) goto fail;
		if ((err = SSLHashSHA384.update(&hashCtx, &clientRandom)) != 0) goto fail;
		if ((err = SSLHashSHA384.update(&hashCtx, &serverRandom)) != 0) goto fail;
		if ((err = SSLHashSHA384.update(&hashCtx, &signedParams)) != 0) goto fail;
		if ((err = SSLHashSHA384.final(&hashCtx, &sha384Buf)) != 0) goto fail;
		if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;

		if (ctx->peerPubKey == NULL)
			err = sslVerifyTLS12RSA(ctx, 673, sha384Digest, SSL_SHA384_DIGEST_LEN, signature, signatureLen);
		else
		err = sslVerifyTLS12SHA384(ctx, ctx->peerPubKey, ctx->peerPubKeyCsp,
			sha384Digest, signature, signatureLen);
		if(err) {
			sslErrorLog("SSLDecodeSignedServerKeyExchange: SHA384 verify "
				"err %d (hashAlg=%u)\n", (int)err, (unsigned)tls12HashAlg);
			goto fail;
		}
	} else if (ctx->negProtocolVersion == TLS_Version_1_2 &&
	    tls12HashAlg >= TLS12_HASH_ALG_SHA256) {
		/*
		 * TLS 1.2 SHA-256 (or higher) signature path.
		 *
		 * Hash = SHA256(clientRandom || serverRandom || signedParams)
		 * The server signed this hash with PKCS#1 v1.5 RSA + SHA256.
		 *
		 * sslRawVerify sends our 32-byte hash to CSSM with CSSM_PADDING_PKCS1.
		 * CSSM infers SHA-256 DigestInfo from the 32-byte length and verifies.
		 */
		SSLBuffer sha256Buf;
		sha256Buf.data   = sha256Digest;
		sha256Buf.length = SSL_SHA256_DIGEST_LEN;

		if ((err = ReadyHash(&SSLHashSHA256, &hashCtx, ctx)) != 0) goto fail;
		if ((err = SSLHashSHA256.update(&hashCtx, &clientRandom)) != 0) goto fail;
		if ((err = SSLHashSHA256.update(&hashCtx, &serverRandom)) != 0) goto fail;
		if ((err = SSLHashSHA256.update(&hashCtx, &signedParams)) != 0) goto fail;
		if ((err = SSLHashSHA256.final(&hashCtx, &sha256Buf)) != 0) goto fail;
		if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;

		/*
		 * SHA-256 path: use sslVerifyTLS12SHA256 which prepends the
		 * DER DigestInfo prefix before calling sslRawVerify. The server
		 * RSA-signed DigestInfo(SHA256(data)), not raw SHA256(data).
		 */
		if (ctx->peerPubKey == NULL)
			err = sslVerifyTLS12RSA(ctx, 672, sha256Digest, SSL_SHA256_DIGEST_LEN, signature, signatureLen);
		else
		err = sslVerifyTLS12SHA256(ctx, ctx->peerPubKey, ctx->peerPubKeyCsp,
			sha256Digest, signature, signatureLen);
		if(err) {
			sslErrorLog("SSLDecodeSignedServerKeyExchange: SHA256 verify "
				"err %d (hashAlg=%u)\n", (int)err, (unsigned)tls12HashAlg);
			goto fail;
		}
	} else {
		/*
		 * TLS 1.0/1.1: use MD5+SHA1 concatenation (no DigestInfo).
		 * TLS 1.2 with SHA-1 (hash_alg=2): compute only SHA-1 and wrap
		 * in SHA-1 DigestInfo before calling sslRawVerify.
		 */
		if (ctx->negProtocolVersion == TLS_Version_1_2) {
			/* TLS 1.2 SHA-1 path: hash only with SHA-1, then DigestInfo-wrap */
			hashOut.data = hashes + SSL_MD5_DIGEST_LEN;
			hashOut.length = SSL_SHA1_DIGEST_LEN;
			if ((err = ReadyHash(&SSLHashSHA1, &hashCtx, ctx)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0) goto fail;
			if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0) goto fail;
			if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;
			err = sslVerifyTLS12SHA1(ctx, ctx->peerPubKey, ctx->peerPubKeyCsp,
				hashes + SSL_MD5_DIGEST_LEN, signature, signatureLen);
			if (err) {
				sslErrorLog("SSLDecodeSignedServerKeyExchange: TLS1.2/SHA1 verify "
					"err %d\n", (int)err);
				goto fail;
			}
		} else {
			/* TLS 1.0/1.1: MD5+SHA1 raw (no DigestInfo) */
			if(isRsa) {
				dataToSign = hashes;
				dataToSignLen = SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN;
				hashOut.data = hashes;
				hashOut.length = SSL_MD5_DIGEST_LEN;
				if ((err = ReadyHash(&SSLHashMD5, &hashCtx, ctx)) != 0) goto fail;
				if ((err = SSLHashMD5.update(&hashCtx, &clientRandom)) != 0) goto fail;
				if ((err = SSLHashMD5.update(&hashCtx, &serverRandom)) != 0) goto fail;
				if ((err = SSLHashMD5.update(&hashCtx, &signedParams)) != 0) goto fail;
				if ((err = SSLHashMD5.final(&hashCtx, &hashOut)) != 0) goto fail;
				if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;
			} else {
				dataToSign = &hashes[SSL_MD5_DIGEST_LEN];
				dataToSignLen = SSL_SHA1_DIGEST_LEN;
			}
			hashOut.data = hashes + SSL_MD5_DIGEST_LEN;
			hashOut.length = SSL_SHA1_DIGEST_LEN;
			if ((err = ReadyHash(&SSLHashSHA1, &hashCtx, ctx)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0) goto fail;
			if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0) goto fail;
			if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0) goto fail;
			if ((err = SSLFreeBuffer(&hashCtx, ctx)) != 0) goto fail;
			err = sslRawVerify(ctx,
				ctx->peerPubKey, ctx->peerPubKeyCsp,
				dataToSign, dataToSignLen,
				signature, signatureLen);
			if(err) {
				sslErrorLog("SSLDecodeSignedServerKeyExchange: MD5/SHA1 verify "
					"err %d\n", (int)err);
				goto fail;
			}
		}
	}
    
	switch(ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA:
        case SSL_RSA_EXPORT:
		{
			SSLBuffer modBuf, expBuf;
			sslFreeKey(ctx->peerPubKeyCsp, &ctx->peerPubKey, NULL);
			modBuf.data = modulus; modBuf.length = modulusLen;
			expBuf.data = exponent; expBuf.length = exponentLen;
			err = sslGetPubKeyFromBits(ctx, &modBuf, &expBuf,
				&ctx->peerPubKey, &ctx->peerPubKeyCsp);
			break;
		}
		case SSL_DHE_RSA: case SSL_DHE_RSA_EXPORT:
		case SSL_DHE_DSS: case SSL_DHE_DSS_EXPORT:
		case SSL_ECDHE_ECDSA: case SSL_ECDHE_RSA:
			break;
		default:
			assert(0);		
	}
fail:
    SSLFreeBuffer(&signedHashes, ctx);
    SSLFreeBuffer(&hashCtx, ctx);
    return err;
}

static OSStatus
SSLDecodeRSAKeyExchange(SSLBuffer keyExchange, SSLContext *ctx)
{
	OSStatus            err;
    size_t        		outputLen, localKeyModulusLen;
    SSLProtocolVersion  version;
    Boolean				useEncryptKey = false;
	uint8				*src = NULL;
	SecKeyRef			keyRef = NULL;
    const CSSM_KEY		*cssmKey;
		
	assert(ctx->protocolSide == SSL_ServerSide);
	
	#if		SSL_SERVER_KEYEXCH_HACK
		if((ctx->selectedCipherSpec->keyExchangeMethod == SSL_RSA_EXPORT) &&
			(ctx->encryptPrivKey != NULL)) {
			useEncryptKey = true;
		}
	#else
		if (ctx->encryptPrivKeyRef) useEncryptKey = true;
	#endif
	keyRef = useEncryptKey ? ctx->encryptPrivKeyRef : ctx->signingPrivKeyRef;
	err = SecKeyGetCSSMKey(keyRef, &cssmKey);
	if(err) return err;
    
	localKeyModulusLen = sslKeyLengthInBytes(cssmKey);

    if (keyExchange.length == localKeyModulusLen) {
		src = keyExchange.data;
	} else if((keyExchange.length == (localKeyModulusLen + 2)) &&
		(ctx->negProtocolVersion >= TLS_Version_1_0)) {
		src = keyExchange.data + 2;
	} else {
    	sslErrorLog("SSLDecodeRSAKeyExchange: length error (exp %u got %u)\n",
			(unsigned)localKeyModulusLen, (unsigned)keyExchange.length);
        return errSSLProtocol;
	}
    err = SSLAllocBuffer(&ctx->preMasterSecret, SSL_RSA_PREMASTER_SECRET_SIZE, ctx);
	if(err != 0) return err;

	err = sslRsaDecrypt(ctx, keyRef, CSSM_PADDING_PKCS1,
		src, localKeyModulusLen,
		ctx->preMasterSecret.data, SSL_RSA_PREMASTER_SECRET_SIZE, &outputLen);
    
	if(err != noErr) {
		sslLogNegotiateDebug("SSLDecodeRSAKeyExchange: RSA decrypt fail");
	} else if(outputLen != SSL_RSA_PREMASTER_SECRET_SIZE) {
    	err = errSSLProtocol;
    }
    
	if(err == noErr) {
		version = (SSLProtocolVersion)SSLDecodeInt(ctx->preMasterSecret.data, 2);
		if((version != ctx->negProtocolVersion) &&
		   (version != ctx->clientReqProtocol)) {
			sslLogNegotiateDebug("SSLDecodeRSAKeyExchange: version error");
			err = errSSLProtocol;
		}
    }
	if(err != noErr) {
		SSLEncodeInt(ctx->preMasterSecret.data, ctx->negProtocolVersion, 2);
		SSLBuffer tmpBuf;
		tmpBuf.data   = ctx->preMasterSecret.data + 2;
		tmpBuf.length = SSL_RSA_PREMASTER_SECRET_SIZE - 2;
		sslRand(ctx, &tmpBuf);
	}
    return noErr;
}

static OSStatus
SSLEncodeRSAKeyExchange(SSLRecord *keyExchange, SSLContext *ctx)
{
	OSStatus            err;
    size_t        		outputLen, peerKeyModulusLen;
    size_t				bufLen;
	uint8				*dst;
	bool				encodeLen = false;
	
	assert(ctx->protocolSide == SSL_ClientSide);
    if ((err = SSLEncodeRSAPremasterSecret(ctx)) != 0)
        return err;
    
    keyExchange->contentType = SSL_RecordTypeHandshake;
    keyExchange->protocolVersion = ctx->negProtocolVersion;
        
	peerKeyModulusLen = sslKeyLengthInBytes(ctx->peerPubKey);
	bufLen = peerKeyModulusLen + 4;
	#if 	RSA_CLIENT_KEY_ADD_LENGTH
	if(ctx->negProtocolVersion >= TLS_Version_1_0) {
		bufLen += 2;
		encodeLen = true;
	}
	#endif
    if ((err = SSLAllocBuffer(&keyExchange->contents, bufLen, ctx)) != 0)
        return err;
	dst = keyExchange->contents.data + 4;
	if(encodeLen) dst += 2;
    keyExchange->contents.data[0] = SSL_HdskClientKeyExchange;
    SSLEncodeInt(keyExchange->contents.data + 1, bufLen - 4, 3);
	if(encodeLen) {
		SSLEncodeInt(keyExchange->contents.data + 4, peerKeyModulusLen, 2);
	}
	err = errSSLCrypto;  /* use OpenSSL for raw blob keys; CDSA path crashes */
	if (ctx->peerPubKey->KeyHeader.BlobType != CSSM_KEYBLOB_RAW) {
		/* Reference key: use CDSA path (works for keychain-backed keys) */
		err = sslRsaEncrypt(ctx, ctx->peerPubKey, ctx->peerPubKeyCsp,
			CSSM_PADDING_PKCS1,
			ctx->preMasterSecret.data, SSL_RSA_PREMASTER_SECRET_SIZE,
			dst, peerKeyModulusLen, &outputLen);
	}
	if (err != noErr) {
		/*
		 * TLS 1.2: Apple CDSA RSA encrypt crashes with raw PKCS1 blob keys on
		 * Snow Leopard. Fall back to libcrypto RSA_public_encrypt via dlsym.
		 */
		typedef void * (*BN_bin2bn_fn)(const unsigned char *s, int len, void *ret);
		typedef void   (*BN_free_fn)(void *a);
		typedef void * (*RSA_new_fn)(void);
		typedef void   (*RSA_free_fn)(void *rsa);
		typedef int    (*RSA_public_encrypt_fn)(int flen, const unsigned char *from,
									unsigned char *to, void *rsa, int padding);
		/* RSA struct offset for n and e on OpenSSL 0.9.8 (Snow Leopard):
		 * struct rsa_st { ... BIGNUM *n; BIGNUM *e; ... } — set via direct field assign.
		 * Instead use RSA_new + set n,e via BN_bin2bn + RSA struct layout.
		 * Simpler: use the 3-arg form by setting members at known offsets.
		 *
		 * OpenSSL 0.9.8 RSA struct (rsa_st) on x86_64:
		 *   pad(4), version(8), meth(ptr), engine(ptr), n(ptr), e(ptr), ...
		 * Offsets: n=32, e=40 bytes from struct start.
		 */
		#define RSA_OFFSET_N  32
		#define RSA_OFFSET_E  40
		#define RSA_PKCS1_PADDING 1

		void *libcrypto = tls12_libcrypto_handle();
		if (libcrypto) {
			BN_bin2bn_fn          pBN_bin2bn          = (BN_bin2bn_fn)dlsym(libcrypto, "BN_bin2bn");
			BN_free_fn            pBN_free            = (BN_free_fn)dlsym(libcrypto, "BN_free");
			RSA_new_fn            pRSA_new            = (RSA_new_fn)dlsym(libcrypto, "RSA_new");
			RSA_free_fn           pRSA_free           = (RSA_free_fn)dlsym(libcrypto, "RSA_free");
			RSA_public_encrypt_fn pRSA_public_encrypt = (RSA_public_encrypt_fn)dlsym(libcrypto, "RSA_public_encrypt");
			if (pBN_bin2bn && pBN_free && pRSA_new && pRSA_free && pRSA_public_encrypt) {
				/* Extract modulus and exponent from our PKCS1 key */
				SSLBuffer modulus = {0, NULL}, exponent = {0, NULL};
				OSStatus bitsErr = sslGetPubKeyBits(ctx, ctx->peerPubKey,
					ctx->peerPubKeyCsp, &modulus, &exponent);
				if (bitsErr == noErr && modulus.data && exponent.data) {
					void *rsa = pRSA_new();
					if (rsa) {
						/* Set n and e in the RSA struct at known 0.9.8 offsets */
						void *bn_n = pBN_bin2bn(modulus.data, (int)modulus.length, NULL);
						void *bn_e = pBN_bin2bn(exponent.data, (int)exponent.length, NULL);
						*(void **)((char*)rsa + RSA_OFFSET_N) = bn_n;
						*(void **)((char*)rsa + RSA_OFFSET_E) = bn_e;
						int rc = pRSA_public_encrypt(
							(int)SSL_RSA_PREMASTER_SECRET_SIZE,
							(const unsigned char *)ctx->preMasterSecret.data,
							(unsigned char *)dst,
							rsa, RSA_PKCS1_PADDING);
						if (rc == (int)peerKeyModulusLen) {
						err = noErr;
						} else {
							err = errSSLCrypto;
						}
						/* Zero out n and e before free to prevent double-free on rsa_st */
						*(void **)((char*)rsa + RSA_OFFSET_N) = NULL;
						*(void **)((char*)rsa + RSA_OFFSET_E) = NULL;
						if (bn_n) pBN_free(bn_n);
						if (bn_e) pBN_free(bn_e);
						pRSA_free(rsa);
					} else {
						err = errSSLCrypto;
					}
				}
				SSLFreeBuffer(&modulus, ctx);
				SSLFreeBuffer(&exponent, ctx);
			}
		} else {
			fprintf(stderr, "  [rsakex-ossl] dlopen libcrypto failed\n");
		}
	}
	if(err) return err;
    return noErr;
}


#if APPLE_DH

#pragma mark -
#pragma mark *** Diffie-Hellman key exchange ***

static OSStatus
SSLGenServerDHParamsAndKey(SSLContext *ctx)
{
	OSStatus ortn;
    assert(ctx->protocolSide == SSL_ServerSide);
	if(ctx->dhParamsPrime.data == NULL) {
		assert(ctx->dhParamsGenerator.data == NULL);
        int prtn = pthread_once(&serverDhParamsControl, SSLInitServerDHParams);
        if (prtn) return errSSLInternal;
		ortn = SSLCopyBuffer(&serverDhParams.prime, &ctx->dhParamsPrime);
		if(ortn) return ortn;
		ortn = SSLCopyBuffer(&serverDhParams.generator, &ctx->dhParamsGenerator);
		if(ortn) return ortn;
		ortn = SSLCopyBuffer(&serverDhParams.paramBlock, &ctx->dhParamsEncoded);
		if(ortn) return ortn;
	}
	sslFreeKey(ctx->cspHand, &ctx->dhPrivate, NULL);
	SSLFreeBuffer(&ctx->dhExchangePublic, ctx);
	ctx->dhPrivate = (CSSM_KEY *)sslMalloc(sizeof(CSSM_KEY));
	CSSM_KEY pubKey;
	ortn = sslDhGenerateKeyPair(ctx, &ctx->dhParamsEncoded,
		ctx->dhParamsPrime.length * 8, &pubKey, ctx->dhPrivate);
	if(ortn) return ortn;
	CSSM_TO_SSLBUF(&pubKey.KeyData, &ctx->dhExchangePublic);
	return noErr;
} 

static OSStatus 
SSLEncodeDHKeyParams(SSLContext *ctx, uint8 *charPtr)
{
    assert(ctx->protocolSide == SSL_ServerSide);
	charPtr = SSLEncodeInt(charPtr, ctx->dhParamsPrime.length, 2);
	memcpy(charPtr, ctx->dhParamsPrime.data, ctx->dhParamsPrime.length);
	charPtr += ctx->dhParamsPrime.length;
	charPtr = SSLEncodeInt(charPtr, ctx->dhParamsGenerator.length, 2);
	memcpy(charPtr, ctx->dhParamsGenerator.data, ctx->dhParamsGenerator.length);
	charPtr += ctx->dhParamsGenerator.length;
	charPtr = SSLEncodeInt(charPtr, ctx->dhExchangePublic.length, 2);
	memcpy(charPtr, ctx->dhExchangePublic.data, ctx->dhExchangePublic.length);
	dumpBuf("server prime", &ctx->dhParamsPrime);
	dumpBuf("server generator", &ctx->dhParamsGenerator);
	dumpBuf("server pub key", &ctx->dhExchangePublic);
	return noErr;
}

static OSStatus
SSLDecodeDHKeyParams(SSLContext *ctx, uint8 **charPtr, UInt32 length)
{   
	OSStatus err = noErr;
	assert(ctx->protocolSide == SSL_ClientSide);
    uint8 *endCp = *charPtr + length;
    SSLFreeBuffer(&ctx->dhParamsPrime, ctx);
    SSLFreeBuffer(&ctx->dhParamsGenerator, ctx);
	SSLFreeBuffer(&ctx->dhPeerPublic, ctx);
	
	UInt32 len = SSLDecodeInt(*charPtr, 2); (*charPtr) += 2;
	if((*charPtr + len) > endCp) return errSSLProtocol;
	err = SSLAllocBuffer(&ctx->dhParamsPrime, len, ctx); if(err) return err;
	memmove(ctx->dhParamsPrime.data, *charPtr, len); (*charPtr) += len;
	
	len = SSLDecodeInt(*charPtr, 2); (*charPtr) += 2;
	if((*charPtr + len) > endCp) return errSSLProtocol;
	err = SSLAllocBuffer(&ctx->dhParamsGenerator, len, ctx); if(err) return err;
	memmove(ctx->dhParamsGenerator.data, *charPtr, len); (*charPtr) += len;
	
	len = SSLDecodeInt(*charPtr, 2); (*charPtr) += 2;
	err = SSLAllocBuffer(&ctx->dhPeerPublic, len, ctx); if(err) return err;
	memmove(ctx->dhPeerPublic.data, *charPtr, len); (*charPtr) += len;
	
	dumpBuf("client peer pub", &ctx->dhPeerPublic);
	dumpBuf("client prime", &ctx->dhParamsPrime);
	dumpBuf("client generator", &ctx->dhParamsGenerator);
	return err;	
}

static OSStatus
SSLGenClientDHKeyAndExchange(SSLContext *ctx)
{   
	OSStatus ortn;
    assert(ctx->protocolSide == SSL_ClientSide);
	if((ctx->dhParamsPrime.data == NULL) ||
	   (ctx->dhParamsGenerator.data == NULL) ||
	   (ctx->dhPeerPublic.data == NULL)) {
	   sslErrorLog("SSLGenClientDHKeyAndExchange: incomplete server params\n");
	   return errSSLProtocol;
	}
	CSSM_KEY pubKey;
	ctx->dhPrivate = (CSSM_KEY *)sslMalloc(sizeof(CSSM_KEY));
	ortn = sslDhGenKeyPairClient(ctx, &ctx->dhParamsPrime, &ctx->dhParamsGenerator,
		&pubKey, ctx->dhPrivate);
	if(ortn) { sslFree(ctx->dhPrivate); ctx->dhPrivate = NULL; return ortn; }
	ortn = sslDhKeyExchange(ctx, ctx->dhParamsPrime.length * 8, &ctx->preMasterSecret);
	if(ortn) return ortn;
	CSSM_TO_SSLBUF(&pubKey.KeyData, &ctx->dhExchangePublic);
	return noErr;
}

static OSStatus
SSLEncodeDHanonServerKeyExchange(SSLRecord *keyExch, SSLContext *ctx)
{   
	OSStatus ortn = noErr;
	assert(ctx->protocolSide == SSL_ServerSide);
	ortn = SSLGenServerDHParamsAndKey(ctx);
	if(ortn) return ortn;
	UInt32 length = 6 + ctx->dhParamsPrime.length + 
		ctx->dhParamsGenerator.length + ctx->dhExchangePublic.length;
	keyExch->protocolVersion = ctx->negProtocolVersion;
	keyExch->contentType = SSL_RecordTypeHandshake;
	if ((ortn = SSLAllocBuffer(&keyExch->contents, length+4, ctx)) != 0)
		return ortn;
	uint8 *charPtr = keyExch->contents.data;
	*charPtr++ = SSL_HdskServerKeyExchange;
	charPtr = SSLEncodeInt(charPtr, length, 3);
	return SSLEncodeDHKeyParams(ctx, charPtr);
}

static OSStatus
SSLDecodeDHanonServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{   
	OSStatus err = noErr;
	assert(ctx->protocolSide == SSL_ClientSide);
    if (message.length < 6) return errSSLProtocol;
    uint8 *charPtr = message.data;
	err = SSLDecodeDHKeyParams(ctx, &charPtr, message.length);
	if(err == noErr) {
		if((message.data + message.length) != charPtr) err = errSSLProtocol;
	}
	return err;
}

static OSStatus
SSLDecodeDHClientKeyExchange(SSLBuffer keyExchange, SSLContext *ctx)
{   
	OSStatus ortn = noErr;
    unsigned int publicLen;
	assert(ctx->protocolSide == SSL_ServerSide);
	if(ctx->dhParamsPrime.data == NULL) { assert(0); return errSSLInternal; }
	uint8 *charPtr = keyExchange.data;
    publicLen = SSLDecodeInt(charPtr, 2); charPtr += 2;
	if((keyExchange.length != publicLen + 2) ||
	   (publicLen > ctx->dhParamsPrime.length)) return errSSLProtocol;
	SSLFreeBuffer(&ctx->dhPeerPublic, ctx);
	ortn = SSLAllocBuffer(&ctx->dhPeerPublic, publicLen, ctx);
	if(ortn) return ortn;
	memmove(ctx->dhPeerPublic.data, charPtr, publicLen);
	SSLFreeBuffer(&ctx->preMasterSecret, ctx);
	ortn = sslDhKeyExchange(ctx, ctx->dhParamsPrime.length * 8, &ctx->preMasterSecret);
	dumpBuf("server peer pub", &ctx->dhPeerPublic);
	dumpBuf("server premaster", &ctx->preMasterSecret);
	return ortn;
}

static OSStatus
SSLEncodeDHClientKeyExchange(SSLRecord *keyExchange, SSLContext *ctx)
{
	OSStatus err;
    size_t   outputLen;
	assert(ctx->protocolSide == SSL_ClientSide);
    if ((err = SSLGenClientDHKeyAndExchange(ctx)) != 0) return err;
    outputLen = ctx->dhExchangePublic.length + 2;
    keyExchange->contentType = SSL_RecordTypeHandshake;
    keyExchange->protocolVersion = ctx->negProtocolVersion;
    if ((err = SSLAllocBuffer(&keyExchange->contents, outputLen + 4, ctx)) != 0) return err;
    keyExchange->contents.data[0] = SSL_HdskClientKeyExchange;
    SSLEncodeInt(keyExchange->contents.data+1, ctx->dhExchangePublic.length+2, 3);
    SSLEncodeInt(keyExchange->contents.data+4, ctx->dhExchangePublic.length, 2);
    memcpy(keyExchange->contents.data+6, ctx->dhExchangePublic.data, ctx->dhExchangePublic.length);
	dumpBuf("client pub key", &ctx->dhExchangePublic);
	dumpBuf("client premaster", &ctx->preMasterSecret);
    return noErr;
}

#endif	/* APPLE_DH */

#pragma mark -
#pragma mark *** ECDSA key exchange ***

static OSStatus
SSLGenClientECDHKeyAndExchange(SSLContext *ctx)
{   
	OSStatus ortn;
    assert(ctx->protocolSide == SSL_ClientSide);
	switch(ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_ECDHE_ECDSA: case SSL_ECDHE_RSA:
			if(ctx->ecdhPeerPublic.data == NULL) {
			   sslErrorLog("SSLGenClientECDHKeyAndExchange: incomplete server params\n");
			   return errSSLProtocol;
			}
			break;
		case SSL_ECDH_ECDSA: case SSL_ECDH_RSA:
		{
			if(ctx->peerPubKey == NULL) return errSSLInternal;
			ortn = sslEcdsaPeerCurve(ctx->peerPubKey, &ctx->ecdhPeerCurve);
			if(ortn) return ortn;
			sslEcdsaDebug("SSLGenClientECDHKeyAndExchange: derived peerCurve %u",
				(unsigned)ctx->ecdhPeerCurve);
			break;
		}
		default: assert(0); return errSSLInternal;
	}
	if((ctx->negAuthType == SSLClientAuth_RSAFixedECDH) ||
	   (ctx->negAuthType == SSLClientAuth_ECDSAFixedECDH)) {
		assert(ctx->signingPrivKeyRef != NULL);
		assert(ctx->cspHand != 0);
		sslFreeKey(ctx->cspHand, &ctx->ecdhPrivate, NULL);
		SSLFreeBuffer(&ctx->ecdhExchangePublic, ctx);
		ortn = SecKeyGetCSSMKey(ctx->signingPrivKeyRef, (const CSSM_KEY **)&ctx->ecdhPrivate);
		if(ortn) return ortn;
		ortn = SecKeyGetCSPHandle(ctx->signingPrivKeyRef, &ctx->ecdhPrivCspHand);
		if(ortn) return ortn;
		sslEcdsaDebug("+++ Extracted ECDH private key");
		ortn = sslEcdhKeyExchange(ctx, &ctx->preMasterSecret);
		if(ortn) return ortn;
		return noErr;
	}

	/*
	 * Phase 2: OpenSSL-based ECDHE key generation and exchange.
	 * CDSA sslEcdhGenerateKeyPair/sslEcdhKeyExchange crash on Snow Leopard.
	 * Use libcrypto EC functions via dlsym instead.
	 *
	 * NID values for OpenSSL 0.9.8:
	 *   NID_X9_62_prime256v1 = 415 (secp256r1 / P-256)
	 *   NID_secp384r1        = 715
	 *   NID_secp521r1        = 716
	 */
	#define NID_secp256r1  415
	#define NID_secp384r1  715
	#define NID_secp521r1  716
	#define POINT_CONVERSION_UNCOMPRESSED  4

	typedef void*  (*EC_KEY_new_by_curve_name_fn)(int nid);
	typedef void   (*EC_KEY_free_fn)(void *key);
	typedef int    (*EC_KEY_generate_key_fn)(void *key);
	typedef void*  (*EC_KEY_get0_public_key_fn)(const void *key);
	typedef void*  (*EC_KEY_get0_private_key_fn)(const void *key);
	typedef void*  (*EC_KEY_get0_group_fn)(const void *key);
	typedef size_t (*EC_POINT_point2oct_fn)(const void *group, const void *point,
										int form, unsigned char *buf, size_t len, void *ctx);
	typedef int    (*EC_POINT_oct2point_fn)(const void *group, void *point,
										const unsigned char *buf, size_t len, void *ctx);
	typedef void*  (*EC_POINT_new_fn)(const void *group);
	typedef void   (*EC_POINT_free_fn)(void *point);
	typedef int    (*ECDH_compute_key_fn)(void *out, size_t outlen,
										const void *pub_key, void *ecdh,
										void *(*KDF)(const void *in, size_t inlen,
											void *out, size_t *outlen));

	void *libcrypto_ec = tls12_libcrypto_handle();
	if (!libcrypto_ec) {
		sslErrorLog("SSLGenClientECDHKeyAndExchange: can't open libcrypto\n");
		return errSSLCrypto;
	}

	EC_KEY_new_by_curve_name_fn  pEC_KEY_new_by_curve_name  =
		(EC_KEY_new_by_curve_name_fn)dlsym(libcrypto_ec, "EC_KEY_new_by_curve_name");
	EC_KEY_free_fn               pEC_KEY_free               =
		(EC_KEY_free_fn)dlsym(libcrypto_ec, "EC_KEY_free");
	EC_KEY_generate_key_fn       pEC_KEY_generate_key       =
		(EC_KEY_generate_key_fn)dlsym(libcrypto_ec, "EC_KEY_generate_key");
	EC_KEY_get0_public_key_fn    pEC_KEY_get0_public_key    =
		(EC_KEY_get0_public_key_fn)dlsym(libcrypto_ec, "EC_KEY_get0_public_key");
	EC_KEY_get0_group_fn         pEC_KEY_get0_group         =
		(EC_KEY_get0_group_fn)dlsym(libcrypto_ec, "EC_KEY_get0_group");
	EC_POINT_point2oct_fn        pEC_POINT_point2oct        =
		(EC_POINT_point2oct_fn)dlsym(libcrypto_ec, "EC_POINT_point2oct");
	EC_POINT_oct2point_fn        pEC_POINT_oct2point        =
		(EC_POINT_oct2point_fn)dlsym(libcrypto_ec, "EC_POINT_oct2point");
	EC_POINT_new_fn              pEC_POINT_new              =
		(EC_POINT_new_fn)dlsym(libcrypto_ec, "EC_POINT_new");
	EC_POINT_free_fn             pEC_POINT_free             =
		(EC_POINT_free_fn)dlsym(libcrypto_ec, "EC_POINT_free");
	ECDH_compute_key_fn          pECDH_compute_key          =
		(ECDH_compute_key_fn)dlsym(libcrypto_ec, "ECDH_compute_key");

	if (!pEC_KEY_new_by_curve_name || !pEC_KEY_free || !pEC_KEY_generate_key ||
		!pEC_KEY_get0_public_key || !pEC_KEY_get0_group ||
		!pEC_POINT_point2oct || !pEC_POINT_oct2point ||
		!pEC_POINT_new || !pEC_POINT_free || !pECDH_compute_key) {
		sslErrorLog("SSLGenClientECDHKeyAndExchange: missing EC symbols in libcrypto\n");
		return errSSLCrypto;
	}

	/* Map SSL named curve to OpenSSL NID */
	int nid;
	switch (ctx->ecdhPeerCurve) {
		case SSL_Curve_secp256r1: nid = NID_secp256r1; break;
		case SSL_Curve_secp384r1: nid = NID_secp384r1; break;
		case SSL_Curve_secp521r1: nid = NID_secp521r1; break;
		default:
			sslErrorLog("SSLGenClientECDHKeyAndExchange: unknown curve %u\n",
				(unsigned)ctx->ecdhPeerCurve);
			return errSSLCrypto;
	}

	/* Generate ephemeral ECDH key pair */
	void *ecKey = pEC_KEY_new_by_curve_name(nid);
	if (!ecKey) return errSSLCrypto;

	if (!pEC_KEY_generate_key(ecKey)) {
		pEC_KEY_free(ecKey);
		return errSSLCrypto;
	}

	/* Serialize our public key as uncompressed ECPoint (04 || x || y) */
	const void *group  = pEC_KEY_get0_group(ecKey);
	const void *pubPt  = pEC_KEY_get0_public_key(ecKey);
	size_t pubLen = pEC_POINT_point2oct(group, pubPt,
		POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (pubLen == 0) { pEC_KEY_free(ecKey); return errSSLCrypto; }

	ortn = SSLAllocBuffer(&ctx->ecdhExchangePublic, pubLen, ctx);
	if (ortn) { pEC_KEY_free(ecKey); return ortn; }
	pEC_POINT_point2oct(group, pubPt, POINT_CONVERSION_UNCOMPRESSED,
		ctx->ecdhExchangePublic.data, pubLen, NULL);

	/* Deserialize server's public key from ecdhPeerPublic */
	void *peerPt = pEC_POINT_new(group);
	if (!peerPt) { pEC_KEY_free(ecKey); return errSSLCrypto; }

	if (!pEC_POINT_oct2point(group, peerPt,
		ctx->ecdhPeerPublic.data, ctx->ecdhPeerPublic.length, NULL)) {
		pEC_POINT_free(peerPt);
		pEC_KEY_free(ecKey);
		sslErrorLog("SSLGenClientECDHKeyAndExchange: bad peer public key\n");
		return errSSLProtocol;
	}

	/* Compute shared secret: ECDH(our_private, peer_public) */
	/* Secret length = curve size in bytes */
	size_t secretLen;
	switch (ctx->ecdhPeerCurve) {
		case SSL_Curve_secp256r1: secretLen = 32; break;
		case SSL_Curve_secp384r1: secretLen = 48; break;
		case SSL_Curve_secp521r1: secretLen = 66; break;
		default: secretLen = 32; break;
	}

	ortn = SSLAllocBuffer(&ctx->preMasterSecret, secretLen, ctx);
	if (ortn) {
		pEC_POINT_free(peerPt);
		pEC_KEY_free(ecKey);
		return ortn;
	}

	int rc = pECDH_compute_key(
		ctx->preMasterSecret.data, secretLen,
		peerPt, ecKey, NULL  /* no KDF — raw shared secret */
	);

	pEC_POINT_free(peerPt);
	pEC_KEY_free(ecKey);

	if (rc <= 0) {
		sslErrorLog("SSLGenClientECDHKeyAndExchange: ECDH_compute_key failed\n");
		SSLFreeBuffer(&ctx->preMasterSecret, ctx);
		return errSSLCrypto;
	}
	/* Trim preMasterSecret to actual computed length (rc may be < secretLen for P-521) */
	ctx->preMasterSecret.length = rc;

	return noErr;
}

static OSStatus
SSLDecodeECDHKeyParams(SSLContext *ctx, uint8 **charPtr, UInt32 length)
{   
	OSStatus err = noErr;
	sslEcdsaDebug("+++ Decoding ECDH Server Key Exchange");
	assert(ctx->protocolSide == SSL_ClientSide);
    uint8 *endCp = *charPtr + length;
	SSLFreeBuffer(&ctx->ecdhPeerPublic, ctx);
	
	uint8 curveType = **charPtr;
	if(curveType != SSL_CurveTypeNamed) return errSSLProtocol;
	(*charPtr)++;
	if(*charPtr > endCp) return errSSLProtocol;
	
	ctx->ecdhPeerCurve = SSLDecodeInt(*charPtr, 2); (*charPtr) += 2;
	if(*charPtr > endCp) return errSSLProtocol;
	switch(ctx->ecdhPeerCurve) {
		case SSL_Curve_secp256r1: case SSL_Curve_secp384r1: case SSL_Curve_secp521r1: break;
		default: return errSSLProtocol;
	}
	sslEcdsaDebug("+++ SSLDecodeECDHKeyParams: ecdhPeerCurve %u", (unsigned)ctx->ecdhPeerCurve);
	
	UInt32 len = SSLDecodeInt(*charPtr, 1); (*charPtr)++;
	if((*charPtr + len) > endCp) return errSSLProtocol;
	err = SSLAllocBuffer(&ctx->ecdhPeerPublic, len, ctx);
	if(err) return err;
	memmove(ctx->ecdhPeerPublic.data, *charPtr, len);
	(*charPtr) += len;
	dumpBuf("client peer pub", &ctx->ecdhPeerPublic);
	return err;	
}

static OSStatus
SSLEncodeECDHClientKeyExchange(SSLRecord *keyExchange, SSLContext *ctx)
{
	OSStatus err;
    size_t   outputLen;
	assert(ctx->protocolSide == SSL_ClientSide);
    if ((err = SSLGenClientECDHKeyAndExchange(ctx)) != 0) return err;
	bool emptyMsg = false;
	switch(ctx->negAuthType) {
		case SSLClientAuth_RSAFixedECDH: case SSLClientAuth_ECDSAFixedECDH:
			emptyMsg = true; break;
		default: break;
	}
	outputLen = emptyMsg ? 0 : ctx->ecdhExchangePublic.length + 1;
    keyExchange->contentType = SSL_RecordTypeHandshake;
    keyExchange->protocolVersion = ctx->negProtocolVersion;
    if ((err = SSLAllocBuffer(&keyExchange->contents, outputLen + 4, ctx)) != 0) return err;
    keyExchange->contents.data[0] = SSL_HdskClientKeyExchange;
	if(emptyMsg) {
		SSLEncodeInt(keyExchange->contents.data+1, 0, 3);
		sslEcdsaDebug("+++ Sending EMPTY ECDH Client Key Exchange");
	} else {
		SSLEncodeInt(keyExchange->contents.data+1, ctx->ecdhExchangePublic.length+1, 3);
		SSLEncodeInt(keyExchange->contents.data+4, ctx->ecdhExchangePublic.length, 1);
		memcpy(keyExchange->contents.data+5, ctx->ecdhExchangePublic.data,
			ctx->ecdhExchangePublic.length);
		sslEcdsaDebug("+++ Encoded ECDH Client Key Exchange");
	}
	dumpBuf("client pub key", &ctx->ecdhExchangePublic);
	dumpBuf("client premaster", &ctx->preMasterSecret);
    return noErr;
}

#pragma mark -
#pragma mark *** Public Functions ***

OSStatus
SSLEncodeServerKeyExchange(SSLRecord *keyExch, SSLContext *ctx)
{   
	OSStatus err;
    switch (ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA: case SSL_RSA_EXPORT:
		#if		APPLE_DH
		case SSL_DHE_RSA: case SSL_DHE_RSA_EXPORT:
		case SSL_DHE_DSS: case SSL_DHE_DSS_EXPORT:
		#endif
            if ((err = SSLEncodeSignedServerKeyExchange(keyExch, ctx)) != 0) return err;
            break;
        #if		APPLE_DH
        case SSL_DH_anon: case SSL_DH_anon_EXPORT:
            if ((err = SSLEncodeDHanonServerKeyExchange(keyExch, ctx)) != 0) return err;
            break;
        #endif
        default: return unimpErr;
    }
    return noErr;
}

OSStatus
SSLProcessServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{   
	OSStatus err;
    switch (ctx->selectedCipherSpec->keyExchangeMethod) {   
		case SSL_RSA: case SSL_RSA_EXPORT:
		#if		APPLE_DH
		case SSL_DHE_RSA: case SSL_DHE_RSA_EXPORT:
		case SSL_DHE_DSS: case SSL_DHE_DSS_EXPORT:
		#endif
		case SSL_ECDHE_ECDSA: case SSL_ECDHE_RSA:
            err = SSLDecodeSignedServerKeyExchange(message, ctx);
            break;
        #if		APPLE_DH
        case SSL_DH_anon: case SSL_DH_anon_EXPORT:
            err = SSLDecodeDHanonServerKeyExchange(message, ctx);
            break;
        #endif
        default: err = unimpErr; break;
    }
    return err;
}

OSStatus
SSLEncodeKeyExchange(SSLRecord *keyExchange, SSLContext *ctx)
{   
	OSStatus err;
    assert(ctx->protocolSide == SSL_ClientSide);
    switch (ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA: case SSL_RSA_EXPORT:
            err = SSLEncodeRSAKeyExchange(keyExchange, ctx);
            break;
        #if		APPLE_DH
		case SSL_DHE_RSA: case SSL_DHE_RSA_EXPORT:
		case SSL_DHE_DSS: case SSL_DHE_DSS_EXPORT:
        case SSL_DH_anon: case SSL_DH_anon_EXPORT:
            err = SSLEncodeDHClientKeyExchange(keyExchange, ctx);
            break;
        #endif
		case SSL_ECDH_ECDSA: case SSL_ECDHE_ECDSA:
		case SSL_ECDH_RSA:   case SSL_ECDHE_RSA:
		case SSL_ECDH_anon:
			err = SSLEncodeECDHClientKeyExchange(keyExchange, ctx);
            break;
        default: err = unimpErr;
    }
    return err;
}

OSStatus
SSLProcessKeyExchange(SSLBuffer keyExchange, SSLContext *ctx)
{   
	OSStatus err;
    switch (ctx->selectedCipherSpec->keyExchangeMethod) {
		case SSL_RSA: case SSL_RSA_EXPORT:
            if ((err = SSLDecodeRSAKeyExchange(keyExchange, ctx)) != 0) return err;
            break;
		#if		APPLE_DH
        case SSL_DH_anon:
		case SSL_DHE_DSS: case SSL_DHE_DSS_EXPORT:
		case SSL_DHE_RSA: case SSL_DHE_RSA_EXPORT:
		case SSL_DH_anon_EXPORT:
            if ((err = SSLDecodeDHClientKeyExchange(keyExchange, ctx)) != 0) return err;
            break;
        #endif
        default: return unimpErr;
    }
    return noErr;
}

OSStatus
SSLInitPendingCiphers(SSLContext *ctx)
{
	OSStatus        err;
    SSLBuffer       key;
    uint8           *keyDataProgress, *keyPtr, *ivPtr;
    int             keyDataLen;
    CipherContext   *serverPending, *clientPending;
        
    key.data = 0;
    
    ctx->readPending.macRef = ctx->selectedCipherSpec->macAlgorithm;
    ctx->writePending.macRef = ctx->selectedCipherSpec->macAlgorithm;
    ctx->readPending.symCipher = ctx->selectedCipherSpec->cipher;
    ctx->writePending.symCipher = ctx->selectedCipherSpec->cipher;
    ctx->readPending.sequenceNum.high = ctx->readPending.sequenceNum.low = 0;
    ctx->writePending.sequenceNum.high = ctx->writePending.sequenceNum.low = 0;
    
    keyDataLen = ctx->selectedCipherSpec->macAlgorithm->hash->digestSize +
                     ctx->selectedCipherSpec->cipher->secretKeySize;
    if (ctx->selectedCipherSpec->isExportable == NotExportable)
        keyDataLen += ctx->selectedCipherSpec->cipher->ivSize;
    keyDataLen *= 2;
    
    if ((err = SSLAllocBuffer(&key, keyDataLen, ctx)) != 0) return err;
	assert(ctx->sslTslCalls != NULL);
    if ((err = ctx->sslTslCalls->generateKeyMaterial(key, ctx)) != 0) goto fail;
    
    if (ctx->protocolSide == SSL_ServerSide) {
		serverPending = &ctx->writePending;
		clientPending = &ctx->readPending;
    } else {
		serverPending = &ctx->readPending;
		clientPending = &ctx->writePending;
    }
    
    keyDataProgress = key.data;
    memcpy(clientPending->macSecret, keyDataProgress,
		ctx->selectedCipherSpec->macAlgorithm->hash->digestSize);
    keyDataProgress += ctx->selectedCipherSpec->macAlgorithm->hash->digestSize;
    memcpy(serverPending->macSecret, keyDataProgress,
		ctx->selectedCipherSpec->macAlgorithm->hash->digestSize);
    keyDataProgress += ctx->selectedCipherSpec->macAlgorithm->hash->digestSize;
    
	err = ctx->sslTslCalls->initMac(clientPending, ctx);
	if(err) goto fail;
	err = ctx->sslTslCalls->initMac(serverPending, ctx);
	if(err) goto fail;
	
    if (ctx->selectedCipherSpec->isExportable == NotExportable) {
		keyPtr = keyDataProgress;
        keyDataProgress += ctx->selectedCipherSpec->cipher->secretKeySize;
		UInt8 ivSize = ctx->selectedCipherSpec->cipher->ivSize;
		ivPtr = (ivSize == 0) ? NULL :
			keyDataProgress + ctx->selectedCipherSpec->cipher->secretKeySize;
        if ((err = ctx->selectedCipherSpec->cipher->initialize(keyPtr, ivPtr,
                                    clientPending, ctx)) != 0) goto fail;
        keyPtr = keyDataProgress;
        keyDataProgress += ctx->selectedCipherSpec->cipher->secretKeySize;
		ivPtr = (ivSize == 0) ? NULL :
			keyDataProgress + ctx->selectedCipherSpec->cipher->ivSize;
        if ((err = ctx->selectedCipherSpec->cipher->initialize(keyPtr, ivPtr,
                                    serverPending, ctx)) != 0) goto fail;
    } else {
        uint8		clientExportKey[16], serverExportKey[16], 
					clientExportIV[16],  serverExportIV[16];
        SSLBuffer   clientWrite, serverWrite;
        SSLBuffer	finalClientWrite, finalServerWrite;
		SSLBuffer	finalClientIV, finalServerIV;
		
        assert(ctx->selectedCipherSpec->cipher->keySize <= 16);
        assert(ctx->selectedCipherSpec->cipher->ivSize <= 16);
        
        clientWrite.data = keyDataProgress;
        clientWrite.length = ctx->selectedCipherSpec->cipher->secretKeySize;
        serverWrite.data = keyDataProgress + clientWrite.length;
        serverWrite.length = ctx->selectedCipherSpec->cipher->secretKeySize;
		finalClientWrite.data = clientExportKey;
		finalServerWrite.data   = serverExportKey;
		finalClientIV.data      = clientExportIV;
		finalServerIV.data      = serverExportIV;
		finalClientWrite.length = 16;
		finalServerWrite.length = 16;
		finalClientIV.length    = ctx->selectedCipherSpec->cipher->ivSize;
		finalServerIV.length    = ctx->selectedCipherSpec->cipher->ivSize;

		assert(ctx->sslTslCalls != NULL);
		err = ctx->sslTslCalls->generateExportKeyAndIv(ctx, clientWrite, serverWrite,
			finalClientWrite, finalServerWrite, finalClientIV, finalServerIV);
		if(err) goto fail;
        if ((err = ctx->selectedCipherSpec->cipher->initialize(clientExportKey, 
				clientExportIV, clientPending, ctx)) != 0) goto fail;
        if ((err = ctx->selectedCipherSpec->cipher->initialize(serverExportKey, 
				serverExportIV, serverPending, ctx)) != 0) goto fail;
    }
    
    ctx->writePending.ready = 1;
    ctx->readPending.ready = 1;
    err = noErr;
fail:
    SSLFreeBuffer(&key, ctx);
    return err;
}
