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
	File:		cipherSpecs.c

	Contains:	SSLCipherSpec declarations

	Written by:	Doug Mitchell

	Copyright: (c) 1999 by Apple Computer, Inc., all rights reserved.

*/

#include "CipherSuite.h"
#include "sslContext.h"
#include "cryptType.h"
#include "symCipher.h"
#include "cipherSpecs.h"
#include "sslGcmCipher.h"   /* AES-GCM cipher specs (AEAD) */
#include "sslDebug.h"
#include "sslMemory.h"
#include "sslDebug.h"
#include "sslUtils.h"
#include "sslPriv.h"
#include "appleCdsa.h"
#include <string.h>
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>

#define ENABLE_3DES			1		/* normally enabled */
#define ENABLE_RC4			1		/* normally enabled */
#define ENABLE_DES			1		/* normally enabled */
#define ENABLE_RC2			1		/* normally enabled */
#define ENABLE_AES			1		/* normally enabled, our first preference */
/* Phase 2: ECDHE enabled — using OpenSSL libcrypto EC functions via dlsym.
 * CDSA sslEcdhGenerateKeyPair crashes on SL, replaced with EC_KEY_generate_key. */
#define ENABLE_ECDHE		1
#define ENABLE_ECDHE_RSA	1
#define ENABLE_ECDH			0	/* static ECDH not needed for Phase 2 */
#define ENABLE_ECDH_RSA		0

#define ENABLE_RSA_DES_SHA_NONEXPORT		ENABLE_DES	
#define ENABLE_RSA_DES_MD5_NONEXPORT		ENABLE_DES
#define ENABLE_RSA_DES_SHA_EXPORT			ENABLE_DES
#define ENABLE_RSA_RC4_MD5_EXPORT			ENABLE_RC4	/* the most common one */
#define ENABLE_RSA_RC4_MD5_NONEXPORT		ENABLE_RC4 
#define ENABLE_RSA_RC4_SHA_NONEXPORT		ENABLE_RC4
#define ENABLE_RSA_RC2_MD5_EXPORT			ENABLE_RC2
#define ENABLE_RSA_RC2_MD5_NONEXPORT		ENABLE_RC2
#define ENABLE_RSA_3DES_SHA					ENABLE_3DES 
#define ENABLE_RSA_3DES_MD5					ENABLE_3DES	

#if 	APPLE_DH
/* Phase 1: DHE also disabled — Snow Leopard DH keygen unstable with some servers.
 * Pure RSA suites (0x003C, 0x003D, TLS_RSA_WITH_AES_*) are sufficient for Phase 1. */
#define ENABLE_DH_ANON		0
#define ENABLE_DH_EPHEM_RSA	0
#define ENABLE_DH_EPHEM_DSA	0
#else
#define ENABLE_DH_ANON		0
#define ENABLE_DH_EPHEM_RSA	0
#define ENABLE_DH_EPHEM_DSA	0
#endif	/* APPLE_DH */

/*
 * Change Group G — TLS 1.2 SHA-256 cipher suite wire values.
 * The 10.6 SDK CipherSuite.h enum ends at 0xC019; these are not present.
 * Note: SSLCipherSuite is UInt32 (not UInt16) in the 10.6 SDK.
 */
#define TLS_RSA_WITH_AES_128_CBC_SHA256			0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256			0x003D
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256		0x0067
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256		0x006B
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	0xC027
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	0xC023

/*
 * AES-GCM (AEAD) suites — RFC 5288 / RFC 5289.
 * 128-bit GCM suites use the SHA-256 PRF; 256-bit GCM suites use the SHA-384
 * PRF and transcript hash. tls12Callouts.c selects the PRF/Finished hash per
 * suite wire value (Phase 3), so both can coexist in this table.
 */
#define TLS_RSA_WITH_AES_128_GCM_SHA256			0x009C
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	0xC02B
/* Phase 3: AES-256-GCM-SHA384 suites */
#define TLS_RSA_WITH_AES_256_GCM_SHA384			0x009D
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	0xC02C

extern const SSLSymmetricCipher SSLCipherNull;		/* in sslNullCipher.c */

/*
 * The symmetric ciphers currently supported (in addition to the
 * NULL cipher in nullciph.c).
 */
#if	ENABLE_DES
static const SSLSymmetricCipher SSLCipherDES_CBC = {
    8, 8, 8, 8,
    CSSM_ALGID_DES, CSSM_ALGID_DES,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};

static const SSLSymmetricCipher SSLCipherDES40_CBC = {
    8, 5, 8, 8,
    CSSM_ALGID_DES, CSSM_ALGID_DES,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};
#endif	/* ENABLE_DES */

#if	ENABLE_3DES
static const SSLSymmetricCipher SSLCipher3DES_CBC = {
    24, 24, 8, 8,
    CSSM_ALGID_3DES_3KEY, CSSM_ALGID_3DES_3KEY_EDE,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};
#endif	/* ENABLE_3DES */

#if		ENABLE_RC4
static const SSLSymmetricCipher SSLCipherRC4_40 = {
    16, 5, 0, 0,
    CSSM_ALGID_RC4, CSSM_ALGID_RC4,
    CSSM_ALGMODE_NONE, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};

static const SSLSymmetricCipher SSLCipherRC4_128 = {
    16, 16, 0, 0,
    CSSM_ALGID_RC4, CSSM_ALGID_RC4,
    CSSM_ALGMODE_NONE, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};
#endif	/* ENABLE_RC4 */

#if		ENABLE_RC2
static const SSLSymmetricCipher SSLCipherRC2_40 = {
    16, 5, 8, 8,
    CSSM_ALGID_RC2, CSSM_ALGID_RC2,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CDSASymmInit, CDSASymmEncrypt, CDSASymmDecrypt, CDSASymmFinish
};

static const SSLSymmetricCipher SSLCipherRC2_128 = {
    16, 16, 8, 8,
    CSSM_ALGID_RC2, CSSM_ALGID_RC2,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CDSASymmInit, CDSASymmEncrypt, CDSASymmDecrypt, CDSASymmFinish
};
#endif	/* ENABLE_RC2 */

#if		ENABLE_AES
static const SSLSymmetricCipher SSLCipherAES_128 = {
    16, 16, 16, 16,
    CSSM_ALGID_AES, CSSM_ALGID_AES,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};

static const SSLSymmetricCipher SSLCipherAES_256 = {
    32, 32, 16, 16,
    CSSM_ALGID_AES, CSSM_ALGID_AES,
    CSSM_ALGMODE_CBC_IV8, CSSM_PADDING_NONE,
    CCSymmInit, CCSymmEncryptDecrypt, CCSymmEncryptDecrypt, CCSymmFinish
};
#endif	/* ENABLE_AES */

const SSLCipherSpec SSL_NULL_WITH_NULL_NULL_CipherSpec =
{   SSL_NULL_WITH_NULL_NULL, Exportable, SSL_NULL_auth, &HashHmacNull, &SSLCipherNull };

/*
 * List of all CipherSpecs we implement.
 *
 * Change Group G: RSA SHA-256 suites come FIRST (positions 0-1), before all
 * ECDHE entries. This forces servers to select RSA key exchange with SHA-256
 * HMAC for TLS 1.2, avoiding the ECDHE ServerKeyExchange signature path
 * which requires Phase 2 changes to sslCert.c. ECDHE SHA-256 suites follow
 * immediately after so servers that prefer ECDHE can still use them once
 * Phase 2 is complete.
 */
static const SSLCipherSpec KnownCipherSpecs[] =
{
	/* ── TLS 1.2: AES-256-GCM (AEAD, SHA-384 PRF) — Phase 3, highest preference ── */
	#if ENABLE_ECDHE_RSA
	    {   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacNull, &SSLCipherAES_256_GCM },
	#endif
	#if ENABLE_ECDHE
	    {   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacNull, &SSLCipherAES_256_GCM },
	#endif
	#if ENABLE_AES
	    {   TLS_RSA_WITH_AES_256_GCM_SHA384, NotExportable, SSL_RSA,
	    	&HashHmacNull, &SSLCipherAES_256_GCM },
	#endif
	/* ── TLS 1.2: AES-128-GCM (AEAD, SHA-256 PRF) ── */
	#if ENABLE_AES
	    {   TLS_RSA_WITH_AES_128_GCM_SHA256, NotExportable, SSL_RSA,
	    	&HashHmacNull, &SSLCipherAES_128_GCM },
	#endif
	#if ENABLE_ECDHE_RSA
	    {   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacNull, &SSLCipherAES_128_GCM },
	#endif
	#if ENABLE_ECDHE
	    {   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacNull, &SSLCipherAES_128_GCM },
	#endif
	/* ── TLS 1.2: RSA + SHA-256 (Phase 1 safe — no ECDHE key exchange) ── */
	#if ENABLE_AES
	    {   TLS_RSA_WITH_AES_128_CBC_SHA256, NotExportable, SSL_RSA,
	    	&HashHmacSHA256, &SSLCipherAES_128 },
	    {   TLS_RSA_WITH_AES_256_CBC_SHA256, NotExportable, SSL_RSA,
	    	&HashHmacSHA256, &SSLCipherAES_256 },
	#endif
	/* ── TLS 1.2: ECDHE + SHA-256 (Phase 2 — ECDHE key exchange path) ── */
	#if ENABLE_ECDHE_RSA
	    {   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacSHA256, &SSLCipherAES_128 },
	#endif
	#if ENABLE_ECDHE
	    {   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacSHA256, &SSLCipherAES_128 },
	#endif
	/* ── TLS 1.2: DHE + SHA-256 ─────────────────────────────────────── */
	#if ENABLE_AES && ENABLE_DH_EPHEM_RSA
	    {   TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, NotExportable, SSL_DHE_RSA,
	    	&HashHmacSHA256, &SSLCipherAES_128 },
	    {   TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, NotExportable, SSL_DHE_RSA,
	    	&HashHmacSHA256, &SSLCipherAES_256 },
	#endif
	/* ── Existing SHA-1 suites ───────────────────────────────────────── */
	#if ENABLE_ECDHE
	    {   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacSHA1, &SSLCipherAES_256 },
	    {   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacSHA1, &SSLCipherAES_128 },
	    {   TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacSHA1, &SSLCipherRC4_128 },
	    {   TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, NotExportable, SSL_ECDHE_ECDSA,
	    	&HashHmacSHA1, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_ECDHE_RSA
	    {   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_128 },
	    {   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_256 },
	    {   TLS_ECDHE_RSA_WITH_RC4_128_SHA, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacSHA1, &SSLCipherRC4_128 },
	    {   TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, NotExportable, SSL_ECDHE_RSA,
	    	&HashHmacSHA1, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_ECDH
	    {   TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, NotExportable, SSL_ECDH_ECDSA,
	    	&HashHmacSHA1, &SSLCipherAES_128 },
	    {   TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, NotExportable, SSL_ECDH_ECDSA,
	    	&HashHmacSHA1, &SSLCipherAES_256 },
	    {   TLS_ECDH_ECDSA_WITH_RC4_128_SHA, NotExportable, SSL_ECDH_ECDSA,
	    	&HashHmacSHA1, &SSLCipherRC4_128 },
	    {   TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, NotExportable, SSL_ECDH_ECDSA,
	    	&HashHmacSHA1, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_ECDH_RSA
	    {   TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, NotExportable, SSL_ECDH_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_128 },
	    {   TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, NotExportable, SSL_ECDH_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_256 },
	    {   TLS_ECDH_RSA_WITH_RC4_128_SHA, NotExportable, SSL_ECDH_RSA,
	    	&HashHmacSHA1, &SSLCipherRC4_128 },
	    {   TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, NotExportable, SSL_ECDH_RSA,
	    	&HashHmacSHA1, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_AES
	    {   TLS_RSA_WITH_AES_128_CBC_SHA, NotExportable, SSL_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_128 },
	#endif
	#if ENABLE_RSA_RC4_SHA_NONEXPORT
	    {   SSL_RSA_WITH_RC4_128_SHA, NotExportable, SSL_RSA,
	    	&HashHmacSHA1, &SSLCipherRC4_128 },
	#endif
	#if ENABLE_RSA_RC4_MD5_NONEXPORT
	    {   SSL_RSA_WITH_RC4_128_MD5, NotExportable, SSL_RSA,
	    	&HashHmacMD5, &SSLCipherRC4_128 },
	#endif
	#if ENABLE_AES
	    {   TLS_RSA_WITH_AES_256_CBC_SHA, NotExportable, SSL_RSA,
	    	&HashHmacSHA1, &SSLCipherAES_256 },
	#endif
	#if ENABLE_RSA_3DES_SHA
	    {   SSL_RSA_WITH_3DES_EDE_CBC_SHA, NotExportable, SSL_RSA,
	    	&HashHmacSHA1, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_RSA_3DES_MD5
	    {   SSL_RSA_WITH_3DES_EDE_CBC_MD5, NotExportable, SSL_RSA,
	    	&HashHmacMD5, &SSLCipher3DES_CBC },
	#endif
	#if ENABLE_RSA_DES_SHA_NONEXPORT
	    {   SSL_RSA_WITH_DES_CBC_SHA, NotExportable, SSL_RSA,
	    	&HashHmacSHA1, &SSLCipherDES_CBC },
	#endif
	#if ENABLE_RSA_DES_MD5_NONEXPORT
	    {   SSL_RSA_WITH_DES_CBC_MD5, NotExportable, SSL_RSA,
	    	&HashHmacMD5, &SSLCipherDES_CBC },
	#endif
	/* exportable */
	#if ENABLE_RSA_RC4_MD5_EXPORT
	    {   SSL_RSA_EXPORT_WITH_RC4_40_MD5, Exportable, SSL_RSA_EXPORT,
	    	&HashHmacMD5, &SSLCipherRC4_40 },
	#endif
	#if ENABLE_RSA_DES_SHA_EXPORT
	    {   SSL_RSA_EXPORT_WITH_DES40_CBC_SHA, Exportable, SSL_RSA_EXPORT,
	    	&HashHmacSHA1, &SSLCipherDES40_CBC },
	#endif
	#if ENABLE_RSA_RC2_MD5_EXPORT
	    {   SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5, Exportable, SSL_RSA_EXPORT,
	    	&HashHmacMD5, &SSLCipherRC2_40 },
	#endif
	#if ENABLE_RSA_RC2_MD5_NONEXPORT
	    {   SSL_RSA_WITH_RC2_CBC_MD5, NotExportable, SSL_RSA,
	    	&HashHmacMD5, &SSLCipherRC2_128 },
	#endif
	    {   SSL_RSA_WITH_NULL_MD5, Exportable, SSL_RSA,
	    	&HashHmacMD5, &SSLCipherNull },
};

static const unsigned CipherSpecCount = sizeof(KnownCipherSpecs) / sizeof(SSLCipherSpec);

static void sslAnalyzeCipherSpecs(SSLContext *ctx)
{
	unsigned dex;
	SSLCipherSpec *cipherSpec;
	ctx->numValidNonSSLv2Specs = 0;
	cipherSpec = &ctx->validCipherSpecs[0];
	for (dex = 0; dex < ctx->numValidCipherSpecs; dex++, cipherSpec++) {
		if (!CIPHER_SUITE_IS_SSLv2(cipherSpec->cipherSpec))
			ctx->numValidNonSSLv2Specs++;
		switch (cipherSpec->keyExchangeMethod) {
			case SSL_ECDH_ECDSA: case SSL_ECDHE_ECDSA:
			case SSL_ECDH_RSA:   case SSL_ECDHE_RSA:
			case SSL_ECDH_anon:
				ctx->ecdsaEnable = true; break;
			default: break;
		}
	}
}

OSStatus sslBuildCipherSpecArray(SSLContext *ctx)
{
	unsigned dex, size;
	assert(ctx != NULL);
	assert(ctx->validCipherSpecs == NULL);

	ctx->numValidCipherSpecs = CipherSpecCount;
	size = CipherSpecCount * sizeof(SSLCipherSpec);
	ctx->validCipherSpecs = (SSLCipherSpec *)sslMalloc(size);
	if (ctx->validCipherSpecs == NULL) { ctx->numValidCipherSpecs = 0; return memFullErr; }

	SSLCipherSpec *dst = ctx->validCipherSpecs;
	const SSLCipherSpec *src = KnownCipherSpecs;

	bool trimECDSA = false;
	if ((ctx->protocolSide == SSL_ServerSide) && !SSL_ECDSA_SERVER) trimECDSA = true;
	if (ctx->versionSsl2Enable || !ctx->versionTls1Enable) trimECDSA = true;

	for (dex = 0; dex < CipherSpecCount; dex++) {
		switch (src->keyExchangeMethod) {
			case SSL_ECDH_ECDSA: case SSL_ECDHE_ECDSA:
			case SSL_ECDH_RSA:   case SSL_ECDHE_RSA:
			case SSL_ECDH_anon:
				if (trimECDSA) { ctx->numValidCipherSpecs--; src++; continue; }
				break;
			default: break;
		}
		if (!ctx->anonCipherEnable) {
			if (src->cipher == &SSLCipherNull) { ctx->numValidCipherSpecs--; src++; continue; }
			switch (src->keyExchangeMethod) {
				case SSL_DH_anon: case SSL_DH_anon_EXPORT: case SSL_ECDH_anon:
					ctx->numValidCipherSpecs--; src++; continue;
				default: break;
			}
		}
		if (!ctx->weakCipherEnable) {
			if (src->cipher == &SSLCipherRC2_40  || src->cipher == &SSLCipherRC4_40 ||
			    src->cipher == &SSLCipherDES40_CBC || src->cipher == &SSLCipherDES_CBC) {
				ctx->numValidCipherSpecs--; src++; continue;
			}
		}
		if (ctx->protocolSide == SSL_ServerSide && ctx->signingPrivKeyRef != NULL) {
			if (sslVerifySelectedCipher(ctx, src) != noErr) {
				ctx->numValidCipherSpecs--; src++; continue;
			}
		}
		*dst++ = *src++;
	}
	sslAnalyzeCipherSpecs(ctx);
	return noErr;
}

static OSStatus cipherSpecsToCipherSuites(
	UInt32 numCipherSpecs, const SSLCipherSpec *cipherSpecs,
	SSLCipherSuite *ciphers, size_t *numCiphers)
{
	unsigned dex;
	if (*numCiphers < numCipherSpecs) return errSSLBufferOverflow;
	for (dex = 0; dex < numCipherSpecs; dex++) ciphers[dex] = cipherSpecs[dex].cipherSpec;
	*numCiphers = numCipherSpecs;
	return noErr;
}

OSStatus SSLGetNumberSupportedCiphers(SSLContextRef ctx, size_t *numCiphers)
{
	if (!ctx || !numCiphers) return paramErr;
	*numCiphers = CipherSpecCount;
	return noErr;
}

OSStatus SSLGetSupportedCiphers(SSLContextRef ctx, SSLCipherSuite *ciphers, size_t *numCiphers)
{
	if (!ctx || !ciphers || !numCiphers) return paramErr;
	return cipherSpecsToCipherSuites(CipherSpecCount, KnownCipherSpecs, ciphers, numCiphers);
}

OSStatus SSLSetEnabledCiphers(SSLContextRef ctx, const SSLCipherSuite *ciphers, size_t numCiphers)
{
	unsigned size, callerDex, tableDex;
	if (!ctx || !ciphers || !numCiphers) return paramErr;
	if (sslIsSessionActive(ctx)) return badReqErr;
	size = numCiphers * sizeof(SSLCipherSpec);
	ctx->validCipherSpecs = (SSLCipherSpec *)sslMalloc(size);
	if (!ctx->validCipherSpecs) { ctx->numValidCipherSpecs = 0; return memFullErr; }
	for (callerDex = 0; callerDex < numCiphers; callerDex++) {
		int foundOne = 0;
		for (tableDex = 0; tableDex < CipherSpecCount; tableDex++) {
			if (ciphers[callerDex] == KnownCipherSpecs[tableDex].cipherSpec) {
				ctx->validCipherSpecs[callerDex] = KnownCipherSpecs[tableDex];
				foundOne = 1; break;
			}
		}
		if (!foundOne) {
			sslFree(ctx->validCipherSpecs); ctx->validCipherSpecs = NULL;
			return errSSLBadCipherSuite;
		}
	}
	ctx->numValidCipherSpecs = numCiphers;
	sslAnalyzeCipherSpecs(ctx);
	return noErr;
}

OSStatus SSLGetNumberEnabledCiphers(SSLContextRef ctx, size_t *numCiphers)
{
	if (!ctx || !numCiphers) return paramErr;
	if (!ctx->validCipherSpecs) {
		OSStatus s = sslBuildCipherSpecArray(ctx);
		if (!s) {
			*numCiphers = ctx->numValidCipherSpecs;
			sslFree(ctx->validCipherSpecs); ctx->validCipherSpecs = NULL; ctx->numValidCipherSpecs = 0;
		} else { *numCiphers = CipherSpecCount; }
	} else { *numCiphers = ctx->numValidCipherSpecs; }
	return noErr;
}

OSStatus SSLGetEnabledCiphers(SSLContextRef ctx, SSLCipherSuite *ciphers, size_t *numCiphers)
{
	if (!ctx || !ciphers || !numCiphers) return paramErr;
	if (!ctx->validCipherSpecs) {
		OSStatus s = sslBuildCipherSpecArray(ctx);
		if (!s) {
			s = cipherSpecsToCipherSuites(ctx->numValidCipherSpecs, ctx->validCipherSpecs, ciphers, numCiphers);
			sslFree(ctx->validCipherSpecs); ctx->validCipherSpecs = NULL; ctx->numValidCipherSpecs = 0;
		} else {
			s = cipherSpecsToCipherSuites(CipherSpecCount, KnownCipherSpecs, ciphers, numCiphers);
		}
		return s;
	}
	return cipherSpecsToCipherSuites(ctx->numValidCipherSpecs, ctx->validCipherSpecs, ciphers, numCiphers);
}

OSStatus FindCipherSpec(SSLContext *ctx)
{
	unsigned i;
	assert(ctx && ctx->validCipherSpecs);
	ctx->selectedCipherSpec = NULL;
	for (i = 0; i < ctx->numValidCipherSpecs; i++) {
		if (ctx->validCipherSpecs[i].cipherSpec == ctx->selectedCipher) {
			ctx->selectedCipherSpec = &ctx->validCipherSpecs[i]; break;
		}
	}
	if (!ctx->selectedCipherSpec) return errSSLNegotiation;
	return sslVerifySelectedCipher(ctx, ctx->selectedCipherSpec);
}
