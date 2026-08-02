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
	File:		sslHandshakeHello.c

	Contains:	Support for client hello and server hello messages. 

	Written by:	Doug Mitchell

	Copyright: (c) 1999 by Apple Computer, Inc., all rights reserved.

*/

#include "sslContext.h"
#include "sslHandshake.h"
#include "sslMemory.h"
#include "sslSession.h"
#include "sslUtils.h"
#include "sslDebug.h"
#include "appleCdsa.h"
#include "sslDigests.h"
#include "cipherSpecs.h"

#include <string.h>

/* IE treats null session id as valid; two consecutive sessions with NULL ID
 * are considered a match. Workaround: when resumable sessions are disabled, 
 * send a random session ID. */
#define SSL_IE_NULL_RESUME_BUG		1
#if		SSL_IE_NULL_RESUME_BUG
#define SSL_NULL_ID_LEN				32	/* length of bogus session ID */
#endif

OSStatus
SSLEncodeServerHello(SSLRecord *serverHello, SSLContext *ctx)
{   OSStatus        err;
    UInt8           *charPtr;
    int             sessionIDLen;
    
    sessionIDLen = 0;
    if (ctx->sessionID.data != 0)
        sessionIDLen = (UInt8)ctx->sessionID.length;
	#if 	SSL_IE_NULL_RESUME_BUG
	if(sessionIDLen == 0) {
		sessionIDLen = SSL_NULL_ID_LEN;
	}	
	#endif	/* SSL_IE_NULL_RESUME_BUG */
		
	/* this was set to a known quantity in SSLProcessClientHello */
	assert(ctx->negProtocolVersion != SSL_Version_Undetermined);
	/* should not be here in this case */
	assert(ctx->negProtocolVersion != SSL_Version_2_0);
	sslLogNegotiateDebug("===SSL3 server: sending version %d_%d",
		ctx->negProtocolVersion >> 8, ctx->negProtocolVersion & 0xff);
	sslLogNegotiateDebug("...sessionIDLen = %d", sessionIDLen);
    serverHello->protocolVersion = ctx->negProtocolVersion;
    serverHello->contentType = SSL_RecordTypeHandshake;
    if ((err = SSLAllocBuffer(&serverHello->contents, 42 + sessionIDLen, ctx)) != 0)
        return err;
    
    charPtr = serverHello->contents.data;
    *charPtr++ = SSL_HdskServerHello;
    charPtr = SSLEncodeInt(charPtr, 38 + sessionIDLen, 3);
    charPtr = SSLEncodeInt(charPtr, serverHello->protocolVersion, 2);
	#if		SSL_PAC_SERVER_ENABLE
	if(!ctx->serverRandomValid) {
    	if ((err = SSLEncodeRandom(ctx->serverRandom, ctx)) != 0) {
       		return err;
		}
	}
	#else
    if ((err = SSLEncodeRandom(ctx->serverRandom, ctx)) != 0)
        return err;
	#endif	/* SSL_PAC_SERVER_ENABLE */
    
	memcpy(charPtr, ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);

    charPtr += SSL_CLIENT_SRVR_RAND_SIZE;
	*(charPtr++) = (UInt8)sessionIDLen;
	#if 	SSL_IE_NULL_RESUME_BUG
	if(ctx->sessionID.data != NULL) {
		memcpy(charPtr, ctx->sessionID.data, sessionIDLen);
	}
	else {
		SSLBuffer rb;
		rb.data = charPtr;
		rb.length = SSL_NULL_ID_LEN;
		sslRand(ctx, &rb);
	}
	#else	
    if (sessionIDLen > 0)
        memcpy(charPtr, ctx->sessionID.data, sessionIDLen);
	#endif	/* SSL_IE_NULL_RESUME_BUG */
	charPtr += sessionIDLen;
    charPtr = SSLEncodeInt(charPtr, ctx->selectedCipher, 2);
    *(charPtr++) = 0;      /* Null compression */

    sslLogNegotiateDebug("ssl3: server specifying cipherSuite 0x%lx", 
		(UInt32)ctx->selectedCipher);
	
    assert(charPtr == serverHello->contents.data + serverHello->contents.length);
    
    return noErr;
}

OSStatus
SSLProcessServerHello(SSLBuffer message, SSLContext *ctx)
{   OSStatus            err;
    SSLProtocolVersion  protocolVersion, negVersion;
    unsigned int        sessionIDLen;
    UInt8               *p;
    
    assert(ctx->protocolSide == SSL_ClientSide);
    
    if (message.length < 38) {
    	sslErrorLog("SSLProcessServerHello: msg len error\n");
        return errSSLProtocol;
    }
    p = message.data;
    
    protocolVersion = (SSLProtocolVersion)SSLDecodeInt(p, 2);
    p += 2;
	err = sslVerifyProtVersion(ctx, protocolVersion, &negVersion);
	if(err) {
		return err;
	}
    ctx->negProtocolVersion = negVersion;
	/* Change Group D3: extend callout switch to add TLS 1.1 and 1.2 */
	switch(negVersion) {
		case SSL_Version_3_0:
			ctx->sslTslCalls = &Ssl3Callouts;
			break;
		case TLS_Version_1_0:
 			ctx->sslTslCalls = &Tls1Callouts;
			break;
		case TLS_Version_1_1:
			ctx->sslTslCalls = &Tls1Callouts;	/* ADD: 1.1 reuses 1.0 callouts */
			break;
		case TLS_Version_1_2:
			ctx->sslTslCalls = &Tls12Callouts;	/* ADD: the new table */
			break;
		default:
			return errSSLNegotiation;
	}
    sslLogNegotiateDebug("===SSL3 client: negVersion is %d_%d",
		(negVersion >> 8) & 0xff, negVersion & 0xff);
    
    memcpy(ctx->serverRandom, p, 32);
    p += 32;
    
    sessionIDLen = *p++;
    if (message.length < (38 + sessionIDLen)) {
    	sslErrorLog("SSLProcessServerHello: msg len error 2\n");
        return errSSLProtocol;
    }
    if (sessionIDLen > 0 && ctx->peerID.data != 0)
    {   err = SSLAllocBuffer(&ctx->sessionID, sessionIDLen, ctx);
        if (err == 0)
            memcpy(ctx->sessionID.data, p, sessionIDLen);
    }
    p += sessionIDLen;
    
    ctx->selectedCipher = (UInt16)SSLDecodeInt(p,2);
    sslLogNegotiateDebug("===ssl3: server requests cipherKind %x", 
    	(unsigned)ctx->selectedCipher);
    p += 2;
    if ((err = FindCipherSpec(ctx)) != 0) {
        return err;
    }
    
    if (*p++ != 0)      /* Compression */
        return unimpErr;
    
	/* any remaining data is server hello extensions, none of which we deal with */
    return noErr;
}

OSStatus
SSLEncodeClientHello(SSLRecord *clientHello, SSLContext *ctx)
{   
	unsigned		length, i;
    OSStatus        err;
    unsigned char   *p;
    SSLBuffer       sessionIdentifier = { 0, NULL };
    UInt16          sessionIDLen;
	UInt32			sessionTicketLen = 0;
	UInt32			serverNameLen = 0;
	UInt32			pointFormatLen = 0;
	UInt32			suppCurveLen = 0;
	UInt32			sigAlgsLen = 0;
	UInt32			totalExtenLen = 0;
	
    assert(ctx->protocolSide == SSL_ClientSide);
	
	clientHello->contents.length = 0;
	clientHello->contents.data = NULL;
	
    sessionIDLen = 0;
    if (ctx->resumableSession.data != 0)
    {   if ((err = SSLRetrieveSessionID(ctx->resumableSession,
				&sessionIdentifier, ctx)) != 0)
        {   return err;
        }
        sessionIDLen = sessionIdentifier.length;
    }
    
    length = 39 + 2*(ctx->numValidNonSSLv2Specs) + sessionIDLen;
    
	err = sslGetMaxProtVersion(ctx, &clientHello->protocolVersion);
	if(err) {
		goto err_exit;
	}

	/* D-FINDING-1: extension gate uses >= TLS_Version_1_0; auto-activates for 1.1/1.2 */
	if((clientHello->protocolVersion >= TLS_Version_1_0) &&
	   (ctx->peerDomainName != NULL) &&
	   (ctx->peerDomainNameLen != 0)) {
		serverNameLen = 2 +	/* extension type */
						2 + /* 2-byte vector length, extension_data */
						2 + /* length of server_name_list */
						1 +	/* length of name_type */
						2 + /* length of HostName */
						ctx->peerDomainNameLen;
		totalExtenLen += serverNameLen;
	}
	/* TLS 1.2 backport: guard against an uninitialized/garbage sessionTicket.
	 * On the CFNetwork path the context is not created by our SSLNewContext,
	 * and ctx->sessionTicket.length can read as junk (e.g. 0x10100), which
	 * inflated totalExtenLen past 0xffff and tripped the overflow reset that
	 * silently dropped ALL extensions (SNI, supported_curves, sig_algs).
	 * A real session ticket is always <= 0xffff (see SSLInternalSetSessionTicket).
	 * Only honor the ticket if it is both non-zero AND sanely bounded with a
	 * non-NULL data pointer. */
	if((ctx->sessionTicket.length != 0) &&
	   (ctx->sessionTicket.length <= 0xffff) &&
	   (ctx->sessionTicket.data != NULL)) {
		sessionTicketLen = 2 +	/* extension type */
						   2 + /* 2-byte vector length, extension_data */
						   ctx->sessionTicket.length;
		totalExtenLen += sessionTicketLen;
	}
	if((clientHello->protocolVersion >= TLS_Version_1_0) &&
	(ctx->ecdsaEnable)) {
	pointFormatLen = 2 +	/* extension type */
	2 +	/* 2-byte vector length, extension_data */
	1 +    /* length of the ec_point_format_list */
	1;		/* the single format we support */
	suppCurveLen   = 2 +	/* extension type */
	2 +	/* 2-byte vector length, extension_data */
	2 +    /* length of the elliptic_curve_list */
	(2 * ctx->ecdhNumCurves);
	totalExtenLen += (pointFormatLen + suppCurveLen);
	}
	/* TLS 1.2: signature_algorithms extension (RFC 5246 §7.4.1.4.1).
	 * Required for ECDHE handshakes — servers use it to select the
	 * ServerKeyExchange signature algorithm. Without it (or without a pair the
	 * server's cert can use), strict TLS 1.2 servers send handshake_failure.
	 *
	 * Phase 3: advertise a fuller set so AES-256-GCM-SHA384 servers (which sign
	 * the SKE with SHA-384) and ECDSA-cert servers (google/youtube/wikipedia)
	 * have a usable option. 6 pairs:
	 *   SHA256+RSA(4,1) SHA384+RSA(5,1) SHA512+RSA(6,1)
	 *   SHA256+ECDSA(4,3) SHA384+ECDSA(5,3)
	 *   SHA1+RSA(2,1)
	 */
	if(clientHello->protocolVersion >= TLS_Version_1_2) {
		/* type(2) + ext_len(2) + list_len(2) + 6 pairs * 2 bytes each = 20 */
		sigAlgsLen = 2 + 2 + 2 + (6 * 2);
		totalExtenLen += sigAlgsLen;
	}
	if(totalExtenLen != 0) {
		if(totalExtenLen > 0xffff) {
			sslErrorLog("Total extensions length EXCEEDED\n");
			totalExtenLen = 0;
			sessionTicketLen = 0;
			serverNameLen = 0;
			pointFormatLen = 0;
			suppCurveLen = 0;
			sigAlgsLen = 0;   /* FIX: was omitted; left the sig_algs writer
			                   * armed while the allocation dropped extension
			                   * space -> 10-byte heap overflow on CFNetwork. */
		}
		else {
			length += (totalExtenLen + 2);
		}
	}
		
    clientHello->contentType = SSL_RecordTypeHandshake;
    if ((err = SSLAllocBuffer(&clientHello->contents, length + 4, ctx)) != 0)
        goto err_exit;
    
    p = clientHello->contents.data;
    *p++ = SSL_HdskClientHello;
    p = SSLEncodeInt(p, length, 3);
    p = SSLEncodeInt(p, clientHello->protocolVersion, 2);
	sslLogNegotiateDebug("===SSL3 client: proclaiming max protocol "
		"%d_%d capable ONLY",
		clientHello->protocolVersion >> 8, clientHello->protocolVersion & 0xff);
   if ((err = SSLEncodeRandom(p, ctx)) != 0)
    {   goto err_exit;
    }
    memcpy(ctx->clientRandom, p, SSL_CLIENT_SRVR_RAND_SIZE);
    p += 32;
    *p++ = sessionIDLen;
    if (sessionIDLen > 0)
    {   memcpy(p, sessionIdentifier.data, sessionIDLen);
    }
    p += sessionIDLen;
    p = SSLEncodeInt(p, 2*(ctx->numValidNonSSLv2Specs), 2);
    for (i = 0; i<ctx->numValidCipherSpecs; ++i) {
		if(CIPHER_SUITE_IS_SSLv2(ctx->validCipherSpecs[i].cipherSpec)) {
			continue;
		}
		sslLogNegotiateDebug("ssl3EncodeClientHello sending spec %x", 
					(unsigned)ctx->validCipherSpecs[i].cipherSpec);		
        p = SSLEncodeInt(p, ctx->validCipherSpecs[i].cipherSpec, 2);
	}
    *p++ = 1;                               /* 1 byte long vector */
    *p++ = 0;                               /* null compression */
 
	if(totalExtenLen != 0) {
   		p = SSLEncodeInt(p, totalExtenLen, 2);
	}
	if(sessionTicketLen) {
		sslEapDebug("Adding %lu bytes of sessionTicket to ClientHello",
			(unsigned long)ctx->sessionTicket.length);
   		p = SSLEncodeInt(p, SSL_HE_SessionTicket, 2);
		p = SSLEncodeInt(p, ctx->sessionTicket.length, 2);
		memcpy(p, ctx->sessionTicket.data, ctx->sessionTicket.length);
		p += ctx->sessionTicket.length;
	}
	if(serverNameLen) {
		sslEapDebug("Specifying ServerNameIndication");
		p = SSLEncodeInt(p, SSL_HE_ServerName, 2);
		p = SSLEncodeInt(p, ctx->peerDomainNameLen + 5, 2);
		p = SSLEncodeInt(p, ctx->peerDomainNameLen + 3, 2);
		p = SSLEncodeInt(p, SSL_NT_HostName, 1);
		p = SSLEncodeInt(p, ctx->peerDomainNameLen, 2);
		memcpy(p, ctx->peerDomainName, ctx->peerDomainNameLen);
		p += ctx->peerDomainNameLen;
	}
	if(suppCurveLen) {
		UInt32 len = 2 * ctx->ecdhNumCurves;
		unsigned dex;
		p = SSLEncodeInt(p, SSL_HE_EllipticCurves, 2);
		p = SSLEncodeInt(p, len+2, 2);
		p = SSLEncodeInt(p, len, 2);
		for(dex=0; dex<ctx->ecdhNumCurves; dex++) {
			sslEcdsaDebug("+++ adding supported curves %u to ClientHello", 
				(unsigned)ctx->ecdhCurves[dex]);
			p = SSLEncodeInt(p, ctx->ecdhCurves[dex], 2);	
		}
	}
	if(pointFormatLen) {
		sslEcdsaDebug("+++ adding point format to ClientHello");
		p = SSLEncodeInt(p, SSL_HE_EC_PointFormats, 2);
		p = SSLEncodeInt(p, 2, 2);
		p = SSLEncodeInt(p, 1, 1);
		p = SSLEncodeInt(p, SSL_PointFormatUncompressed, 1);	
	}
	if(sigAlgsLen) {
		/* signature_algorithms extension type = 0x000d */
		p = SSLEncodeInt(p, 0x000d, 2);
		/* extension data length = list_len(2) + 6 pairs * 2 = 14 */
		p = SSLEncodeInt(p, 14, 2);
		/* supported_signature_algs list length in bytes = 6 pairs * 2 = 12 */
		p = SSLEncodeInt(p, 12, 2);
		/* (hash, signature) pairs, server preference order.
		 * hash: 2=SHA1 4=SHA256 5=SHA384 6=SHA512; sig: 1=RSA 3=ECDSA */
		p = SSLEncodeInt(p, 4, 1); p = SSLEncodeInt(p, 1, 1);  /* SHA256+RSA   */
		p = SSLEncodeInt(p, 5, 1); p = SSLEncodeInt(p, 1, 1);  /* SHA384+RSA   */
		p = SSLEncodeInt(p, 6, 1); p = SSLEncodeInt(p, 1, 1);  /* SHA512+RSA   */
		p = SSLEncodeInt(p, 4, 1); p = SSLEncodeInt(p, 3, 1);  /* SHA256+ECDSA */
		p = SSLEncodeInt(p, 5, 1); p = SSLEncodeInt(p, 3, 1);  /* SHA384+ECDSA */
		p = SSLEncodeInt(p, 2, 1); p = SSLEncodeInt(p, 1, 1);  /* SHA1+RSA     */
		sslEcdsaDebug("+++ added signature_algorithms to ClientHello");
	}
    assert(p == clientHello->contents.data + clientHello->contents.length);
    
    if ((err = SSLInitMessageHashes(ctx)) != 0)
        goto err_exit;

err_exit:
	if (err != 0) {
		SSLFreeBuffer(&clientHello->contents, ctx);
	}
	SSLFreeBuffer(&sessionIdentifier, ctx);

	return err;
}

OSStatus
SSLProcessClientHello(SSLBuffer message, SSLContext *ctx)
{   OSStatus            err;
    SSLProtocolVersion  negVersion;
    UInt16              cipherListLen, cipherCount, desiredSpec, cipherSpec;
    UInt8               sessionIDLen, compressionCount;
    UInt8               *charPtr;
    unsigned            i;
    UInt8				*eom;

    if (message.length < 41) {
    	sslErrorLog("SSLProcessClientHello: msg len error 1\n");
        return errSSLProtocol;
    }
    charPtr = message.data;
	eom = charPtr + message.length;
    ctx->clientReqProtocol = (SSLProtocolVersion)SSLDecodeInt(charPtr, 2);
    charPtr += 2;
	err = sslVerifyProtVersion(ctx, ctx->clientReqProtocol, &negVersion);
	if(err) {
		return err;
	}
	/* Change Group D3: extend callout switch (server side copy) */
	switch(negVersion) {
		case SSL_Version_3_0:
			ctx->sslTslCalls = &Ssl3Callouts;
			break;
		case TLS_Version_1_0:
 			ctx->sslTslCalls = &Tls1Callouts;
			break;
		case TLS_Version_1_1:
			ctx->sslTslCalls = &Tls1Callouts;	/* ADD: 1.1 reuses 1.0 callouts */
			break;
		case TLS_Version_1_2:
			ctx->sslTslCalls = &Tls12Callouts;	/* ADD: the new table */
			break;
		default:
			return errSSLNegotiation;
	}
	ctx->negProtocolVersion = negVersion;
    sslLogNegotiateDebug("===SSL3 server: negVersion is %d_%d",
		negVersion >> 8, negVersion & 0xff);
    
    memcpy(ctx->clientRandom, charPtr, SSL_CLIENT_SRVR_RAND_SIZE);
    charPtr += 32;
    sessionIDLen = *(charPtr++);
    if (message.length < (unsigned)(41 + sessionIDLen)) {
    	sslErrorLog("SSLProcessClientHello: msg len error 2\n");
        return errSSLProtocol;
    }
    if (sessionIDLen > 0 && ctx->peerID.data != 0) 
    {   err = SSLAllocBuffer(&ctx->sessionID, sessionIDLen, ctx);
        if (err == 0)
            memcpy(ctx->sessionID.data, charPtr, sessionIDLen);
    }
    charPtr += sessionIDLen;
    
    cipherListLen = (UInt16)SSLDecodeInt(charPtr, 2);
    charPtr += 2;
	if((charPtr + cipherListLen) > eom) {
    	sslErrorLog("SSLProcessClientHello: msg len error 5\n");
        return errSSLProtocol;
	}
    if ((cipherListLen & 1) || 
	    (cipherListLen < 2) || 
		(message.length < (unsigned)(39 + sessionIDLen + cipherListLen))) {
    	sslErrorLog("SSLProcessClientHello: msg len error 3\n");
        return errSSLProtocol;
    }
    cipherCount = cipherListLen/2;
    cipherSpec = 0xFFFF;
    while (cipherSpec == 0xFFFF && cipherCount--)
    {   desiredSpec = (UInt16)SSLDecodeInt(charPtr, 2);
        charPtr += 2;
        for (i = 0; i <ctx->numValidCipherSpecs; i++)
        {   if (ctx->validCipherSpecs[i].cipherSpec == desiredSpec)
            {   cipherSpec = desiredSpec;
                break;
            }
        }
    }
    
    if (cipherSpec == 0xFFFF)
        return errSSLNegotiation;
    charPtr += 2 * cipherCount;
    ctx->selectedCipher = cipherSpec;
    
    compressionCount = *(charPtr++);
    if ((compressionCount < 1) || 
	    (message.length < 
		    (unsigned)(38 + sessionIDLen + cipherListLen + compressionCount))) {
    	sslErrorLog("SSLProcessClientHello: msg len error 4\n");
        return errSSLProtocol;
    }
    
	#if		SSL_PAC_SERVER_ENABLE
	charPtr += compressionCount;
	if(charPtr < eom) {
		unsigned remLen = eom - charPtr;
		UInt32 totalExtensLen;
		UInt32 extenType;
		UInt32 extenLen;
		if(remLen < 6) {
			sslEapDebug("SSLProcessClientHello: too small for any extension");
			goto proceed;	
		}
		totalExtensLen = SSLDecodeInt(charPtr, 2);
		charPtr += 2;
		if((charPtr + totalExtensLen) > eom) {
			sslEapDebug("SSLProcessClientHello: too small for specified total_extension_length");
			goto proceed;	
		}
		while(charPtr < eom) {
			extenType = SSLDecodeInt(charPtr, 2);
			charPtr += 2;
			extenLen = SSLDecodeInt(charPtr, 2);
			charPtr += 2;
			if((charPtr + extenLen) > eom) {
				sslEapDebug("SSLProcessClientHello: too small for specified extension_length");
				break;	
			}
			switch(extenType) {
				case SSL_HE_SessionTicket:
					SSLFreeBuffer(&ctx->sessionTicket, NULL);
					SSLCopyBufferFromData(charPtr, extenLen, &ctx->sessionTicket);
					sslEapDebug("Saved %lu bytes of sessionTicket from ClientHello",
						(unsigned long)extenLen);
					break;
				case SSL_HE_ServerName:
				{
					UInt8 *cp = charPtr;
					UInt32 v = SSLDecodeInt(cp, 2);
					cp += 2;
					sslEapDebug("SSL_HE_ServerName: length of server_name_list %lu",
						(unsigned long)v);
					v = SSLDecodeInt(cp, 1);
					cp++;
					sslEapDebug("SSL_HE_ServerName: name_type %lu", (unsigned long)v);
					v = SSLDecodeInt(cp, 2);
					cp += 2;
					sslEapDebug("SSL_HE_ServerName: length of HostName %lu",
						(unsigned long)v);
					char hostString[v + 1];
					memmove(hostString, cp, v);
					hostString[v] = '\0';
					sslEapDebug("SSL_HE_ServerName: ServerName '%s'", hostString);
					break;
				}
				default:
					sslEapDebug("SSLProcessClientHello: unknown extenType (%lu)",
						(unsigned long)extenType);
					break;
			}
			charPtr += extenLen;
		}
	}
proceed:
	#endif
    if ((err = FindCipherSpec(ctx)) != 0) {
        return err;
    }
    sslLogNegotiateDebug("ssl3 server: selecting cipherKind 0x%x", (unsigned)ctx->selectedCipher);
    if ((err = SSLInitMessageHashes(ctx)) != 0)
        return err;
    
    return noErr;
}

OSStatus
SSLEncodeRandom(unsigned char *p, SSLContext *ctx)
{   SSLBuffer   randomData;
    OSStatus    err;
    UInt32      time;
    
    if ((err = sslTime(&time)) != 0)
        return err;
    SSLEncodeInt(p, time, 4);
    randomData.data = p+4;
    randomData.length = 28;
   	if((err = sslRand(ctx, &randomData)) != 0)
        return err;
    return noErr;
}

/*
 * Change Group D-FINDING-2 / E5: add SHA-256 init alongside SHA-1 and MD5.
 * SHA-256 must run unconditionally from the first handshake message —
 * the version may not be locked yet when these are called, and TLS 1.2's
 * Finished hashes ALL prior messages including the ClientHello.
 */
OSStatus
SSLInitMessageHashes(SSLContext *ctx)
{   OSStatus          err;

    if ((err = CloseHash(&SSLHashSHA1,   &ctx->shaState,    ctx)) != 0)
        return err;
    if ((err = CloseHash(&SSLHashMD5,    &ctx->md5State,    ctx)) != 0)
        return err;
    if ((err = CloseHash(&SSLHashSHA256, &ctx->sha256State, ctx)) != 0)	/* ADD */
        return err;
    if ((err = CloseHash(&SSLHashSHA384, &ctx->sha384State, ctx)) != 0)	/* Phase 3 */
        return err;
    if ((err = ReadyHash(&SSLHashSHA1,   &ctx->shaState,    ctx)) != 0)
        return err;
    if ((err = ReadyHash(&SSLHashMD5,    &ctx->md5State,    ctx)) != 0)
        return err;
    if ((err = ReadyHash(&SSLHashSHA256, &ctx->sha256State, ctx)) != 0)	/* ADD */
        return err;
    if ((err = ReadyHash(&SSLHashSHA384, &ctx->sha384State, ctx)) != 0)	/* Phase 3 */
        return err;
    return noErr;
}
