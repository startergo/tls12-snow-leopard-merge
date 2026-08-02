/*
 * Copyright (c) 2000-2007 Apple Inc. All Rights Reserved.
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
	File:		SecureTransportPriv.h
	Contains:	Apple-private exported routines
	Copyright:	(c) 2000-2007 Apple Inc., all rights reserved.
*/

#ifndef	_SECURE_TRANSPORT_PRIV_H_
#define _SECURE_TRANSPORT_PRIV_H_	1

#include <Security/SecureTransport.h>
#include <Security/SecTrust.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Change Group A2: TLS 1.1 and 1.2 SSLProtocol extensions.
 *
 * The 10.6 SDK SSLProtocol enum implicit values:
 *   kSSLProtocolUnknown=0, kSSLProtocol2=1, kSSLProtocol3=2,
 *   kSSLProtocol3Only=3, kTLSProtocol1=4, kTLSProtocol1Only=5,
 *   kSSLProtocolAll=6
 * We extend with 7 and 8 as #defines so switch/case compiles cleanly.
 */
#define kTLSProtocol11	((SSLProtocol)7)	/* TLS 1.1, lower versions OK */
#define kTLSProtocol12	((SSLProtocol)8)	/* TLS 1.2, lower versions OK */

/*
 * New API bodies added in sslContext.c (Change Groups B/C4).
 * Declared here so callers can use them once the dylib is in place.
 */
OSStatus SSLSetProtocolVersionMax(SSLContextRef ctx, SSLProtocol maxVersion);
OSStatus SSLGetProtocolVersionMax(SSLContextRef ctx, SSLProtocol *maxVersion);	/* RETURNED */
OSStatus SSLSetProtocolVersionMin(SSLContextRef ctx, SSLProtocol minVersion);
OSStatus SSLGetProtocolVersionMin(SSLContextRef ctx, SSLProtocol *minVersion);	/* RETURNED */

/* The size of client- and server-generated random numbers in hello messages. */
#define SSL_CLIENT_SRVR_RAND_SIZE		32

/* The size of the pre-master and master secrets. */
#define SSL_RSA_PREMASTER_SECRET_SIZE	48
#define SSL_MASTER_SECRET_SIZE			48

OSStatus SSLInternalMasterSecret(
   SSLContextRef context,
   void *secret,         /* mallocd by caller, SSL_MASTER_SECRET_SIZE */
   size_t *secretSize);  /* in/out */

OSStatus SSLInternalServerRandom(
   SSLContextRef context,
   void *rand,			/* mallocd by caller, SSL_CLIENT_SRVR_RAND_SIZE */
   size_t *randSize);	/* in/out */

OSStatus SSLInternalClientRandom(
   SSLContextRef context,
   void *rand,			/* mallocd by caller, SSL_CLIENT_SRVR_RAND_SIZE */
   size_t *randSize);	/* in/out */

OSStatus SSLGetCipherSizes(
	SSLContextRef context,
	size_t *digestSize,
	size_t *symmetricKeySize,
	size_t *ivSize);

OSStatus SSLInternal_PRF(
   SSLContextRef context,
   const void *secret,
   size_t secretLen,
   const void *label,
   size_t labelLen,
   const void *seed,
   size_t seedLen,
   void *out,			/* mallocd by caller, length >= outLen */
   size_t outLen);

OSStatus SSLGetPeerSecTrust(
	SSLContextRef context,
	SecTrustRef *secTrust);	/* RETURNED */

#define MAX_SESSION_ID_LENGTH	32

OSStatus SSLGetResumableSessionInfo(
	SSLContextRef context,
	Boolean *sessionWasResumed,		/* RETURNED */
	void *sessionID,				/* RETURNED, mallocd by caller */
	size_t *sessionIDLength);		/* IN/OUT */

OSStatus SSLGetCertificate(
	SSLContextRef context,
	CFArrayRef *certRefs);			/* RETURNED, not retained */

OSStatus SSLGetEncryptionCertificate(
	SSLContextRef context,
	CFArrayRef *certRefs);			/* RETURNED, not retained */

OSStatus SSLGetClientSideAuthenticate(
	SSLContextRef context,
	SSLAuthenticate *auth);			/* RETURNED */

OSStatus SSLSetTrustedLeafCertificates(
	SSLContextRef context,
	CFArrayRef certRefs);

OSStatus SSLCopyTrustedLeafCertificates(
	SSLContextRef context,
	CFArrayRef *certRefs);			/* RETURNED, caller must release */

OSStatus SSLSetAllowAnonymousCiphers(
	SSLContextRef context,
	Boolean enable);

OSStatus SSLGetAllowAnonymousCiphers(
	SSLContextRef context,
	Boolean *enable);

OSStatus SSLSetSessionCacheTimeout(
	SSLContextRef context,
	uint32 timeoutInSeconds);

typedef void (*SSLInternalMasterSecretFunction)(
	SSLContextRef ctx,
	const void *arg,		/* opaque to SecureTransport; app-specific */
	void *secret,			/* mallocd by caller, SSL_MASTER_SECRET_SIZE */
	size_t *secretLength);	/* in/out */

OSStatus SSLInternalSetMasterSecretFunction(
	SSLContextRef ctx,
	SSLInternalMasterSecretFunction mFunc,
	const void *arg);		/* opaque to SecureTransport; app-specific */

OSStatus SSLInternalSetSessionTicket(
   SSLContextRef ctx,
   const void *ticket,
   size_t ticketLength);

/* ECDH named curves */
typedef enum {
	SSL_Curve_None      = -1,
	SSL_Curve_secp256r1 = 23,
	SSL_Curve_secp384r1 = 24,
	SSL_Curve_secp521r1 = 25
} SSL_ECDSA_NamedCurve;

extern OSStatus SSLGetNegotiatedCurve(
   SSLContextRef ctx,
   SSL_ECDSA_NamedCurve *namedCurve);	/* RETURNED */

extern OSStatus SSLGetNumberOfECDSACurves(
   SSLContextRef ctx,
   unsigned *numCurves);				/* RETURNED */

extern OSStatus SSLGetECDSACurves(
   SSLContextRef ctx,
   SSL_ECDSA_NamedCurve *namedCurves,	/* RETURNED */
   unsigned *numCurves);				/* IN/OUT */

extern OSStatus SSLSetECDSACurves(
   SSLContextRef ctx,
   const SSL_ECDSA_NamedCurve *namedCurves,
   unsigned numCurves);

/* Client authentication types */
typedef enum {
	SSLClientAuthNone        = -1,
	SSLClientAuth_RSASign    =  1,
	SSLClientAuth_DSSSign    =  2,
	SSLClientAuth_RSAFixedDH =  3,
	SSLClientAuth_DSS_FixedDH = 4,
	/* RFC 4492 */
	SSLClientAuth_ECDSASign      = 64,
	SSLClientAuth_RSAFixedECDH   = 65,
	SSLClientAuth_ECDSAFixedECDH = 66
} SSLClientAuthenticationType;

extern OSStatus SSLGetNumberOfClientAuthTypes(
	SSLContextRef ctx,
	unsigned *numTypes);

extern OSStatus SSLGetClientAuthTypes(
   SSLContextRef ctx,
   SSLClientAuthenticationType *authTypes,	/* RETURNED */
   unsigned *numTypes);						/* IN/OUT */

extern OSStatus SSLGetNegotiatedClientAuthType(
   SSLContextRef ctx,
   SSLClientAuthenticationType *authType);	/* RETURNED */

#ifdef __cplusplus
}
#endif

#endif	/* _SECURE_TRANSPORT_PRIV_H_ */
