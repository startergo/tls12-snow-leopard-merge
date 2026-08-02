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
	File:		sslutils.c

	Contains:	Misc. SSL utility functions

	Written by:	Doug Mitchell

	Copyright: (c) 1999 by Apple Computer, Inc., all rights reserved.

*/

#include "sslContext.h"
#include "sslUtils.h"
#include "sslMemory.h"
#include "sslDebug.h"

#include <sys/time.h>

#include <fcntl.h> // for open
#include <unistd.h> // for read

UInt32
SSLDecodeInt(const unsigned char *p, int length)
{   UInt32  val = 0;
    while (length--)
        val = (val << 8) | *p++;
    return val;
}

unsigned char *
SSLEncodeInt(unsigned char *p, UInt32 value, int length)
{   unsigned char   *retVal = p + length;       /* Return pointer to char after int */
    assert(length > 0 && length <= 4);
    while (length--)                /* Assemble backwards */
    {   p[length] = (uint8)value;   /* Implicit masking to low byte */
        value >>= 8;
    }
    return retVal;
}

uint8*
SSLEncodeUInt64(uint8 *p, sslUint64 value)
{   p = SSLEncodeInt(p, value.high, 4);
    return SSLEncodeInt(p, value.low, 4);
}


void
IncrementUInt64(sslUint64 *v)
{   if (++v->low == 0)          /* Must have just rolled over */
        ++v->high;
}

UInt32
SSLGetCertificateChainLength(const SSLCertificate *c)
{   
	UInt32 rtn = 0;
	
    while (c)
    {   
    	rtn++;
        c = c->next;
    }
    return rtn;
}

Boolean sslIsSessionActive(const SSLContext *ctx)
{
	assert(ctx != NULL);
	switch(ctx->state) {
		case SSL_HdskStateUninit:
		case SSL_HdskStateServerUninit:
		case SSL_HdskStateClientUninit:
		case SSL_HdskStateGracefulClose:
		case SSL_HdskStateErrorClose:
			return false;
		default:
			return true;
	}
}

OSStatus sslDeleteCertificateChain(
    SSLCertificate		*certs,
	SSLContext 			*ctx)
{	
	SSLCertificate		*cert;
	SSLCertificate		*nextCert;
	
	assert(ctx != NULL);
	cert=certs;
	while(cert != NULL) {
		nextCert = cert->next;
		SSLFreeBuffer(&cert->derCert, ctx);
		sslFree(cert);
		cert = nextCert;
	}
	return noErr;
}

#if	SSL_DEBUG

/* Change Group D-FINDING-3: add 1.1/1.2 strings (cosmetic, debug only) */
const char *protocolVersStr(SSLProtocolVersion prot)
{
	switch(prot) {
 	case SSL_Version_Undetermined: return "SSL_Version_Undetermined";
 	case SSL_Version_2_0: return "SSL_Version_2_0";
 	case SSL_Version_3_0: return "SSL_Version_3_0";
 	case TLS_Version_1_0: return "TLS_Version_1_0";
 	case TLS_Version_1_1: return "TLS_Version_1_1";		/* ADD */
 	case TLS_Version_1_2: return "TLS_Version_1_2";		/* ADD */
 	default: sslErrorLog("protocolVersStr: bad prot\n"); return "BAD PROTOCOL";
 	}
 	return NULL;	/* NOT REACHED */
}

#endif	/* SSL_DEBUG */

/*
 * Redirect SSLBuffer-based I/O call to user-supplied I/O. 
 */ 
OSStatus sslIoRead(
 	SSLBuffer 		buf, 
 	size_t 			*actualLength, 
 	SSLContext 		*ctx)
{
 	size_t 		dataLength = buf.length;
 	OSStatus	ortn;
 		
	*actualLength = 0;
	ortn = (ctx->ioCtx.read)(ctx->ioCtx.ioRef,
		buf.data,
		&dataLength);
	*actualLength = dataLength;
	return ortn;
}
 
OSStatus sslIoWrite(
 	SSLBuffer 		buf, 
 	size_t 			*actualLength, 
 	SSLContext 		*ctx)
{
 	size_t 			dataLength = buf.length;
 	OSStatus		ortn;
 		
	*actualLength = 0;
	ortn = (ctx->ioCtx.write)(ctx->ioCtx.ioRef,
		buf.data,
		&dataLength);
	*actualLength = dataLength;
	return ortn;
}

OSStatus sslTime(UInt32 *tim)
{
	time_t t;
	time(&t);
	*tim = (UInt32)t;
	return noErr;
}

/*
 * Common RNG function.  @@@ Factor this into a common crypto lib
 */
OSStatus sslRand(SSLContext *ctx, SSLBuffer *buf)
{
	static int random_fd = -1;

	OSStatus		serr = noErr;
	
	assert(ctx != NULL);
	assert(buf != NULL);
	assert(buf->data != NULL);
	
	if(buf->length == 0) {
		sslErrorLog("sslRand: zero buf->length\n");
		return noErr;
	}

	if (random_fd == -1) {
		random_fd = open("/dev/random", O_RDONLY);
		if (random_fd == -1) {
			sslErrorLog("sslRand: error opening /dev/random: %s\n",
				strerror(errno));
			return errSSLCrypto;
		}
	}

    ssize_t bytesRead = read(random_fd, buf->data, buf->length);
	if (bytesRead != buf->length) {
		sslErrorLog("sslRand: error reading %lu bytes from /dev/random: %s\n",
			buf->length, strerror(errno));
		serr = errSSLCrypto;
	}

	return serr;
}

/*
 * Given a protocol version sent by peer, determine if we accept that version
 * and downgrade if appropriate (which can not be done for the client side).
 *
 * Change Group D2: add TLS 1.1 and TLS 1.2 cases following the identical
 * downgrade-ladder pattern as TLS 1.0.
 */
OSStatus sslVerifyProtVersion(
	SSLContext 			*ctx,
	SSLProtocolVersion	peerVersion,	// sent by peer
	SSLProtocolVersion 	*negVersion)	// final negotiated version if return success
{
	OSStatus ortn = noErr;
	
	switch(peerVersion) {
		case SSL_Version_2_0:
			if(ctx->versionSsl2Enable) {
				*negVersion = SSL_Version_2_0;
			}
			else {
				ortn = errSSLNegotiation;
			}
			break;
		case SSL_Version_3_0:
			if(ctx->versionSsl3Enable) {
				*negVersion = SSL_Version_3_0;
			}
			else if(ctx->protocolSide == SSL_ClientSide) {
				ortn = errSSLNegotiation;
			}
			else if(ctx->versionSsl2Enable) {
				*negVersion = SSL_Version_2_0;
			}
			else {
				ortn = errSSLNegotiation;
			}
			break;
		case TLS_Version_1_0:
			if(ctx->versionTls1Enable) {
				*negVersion = TLS_Version_1_0;
			}
			else if(ctx->protocolSide == SSL_ClientSide) {
				ortn = errSSLNegotiation;
			}
			else if(ctx->versionSsl3Enable) {
				*negVersion = SSL_Version_3_0;
			}
			else if(ctx->versionSsl2Enable) {
				*negVersion = SSL_Version_2_0;
			}
			else {
				sslErrorLog("sslVerifyProtVersion: no protocols supported\n");
				ortn = errSSLNegotiation;
			}
			break;
		/* Change Group D2: TLS 1.1 — ADD */
		case TLS_Version_1_1:
			if(ctx->versionTls11Enable) {
				*negVersion = TLS_Version_1_1;
			}
			else if(ctx->protocolSide == SSL_ClientSide) {
				ortn = errSSLNegotiation;
			}
			else if(ctx->versionTls1Enable) {
				*negVersion = TLS_Version_1_0;
			}
			else if(ctx->versionSsl3Enable) {
				*negVersion = SSL_Version_3_0;
			}
			else if(ctx->versionSsl2Enable) {
				*negVersion = SSL_Version_2_0;
			}
			else {
				ortn = errSSLNegotiation;
			}
			break;
		/* Change Group D2: TLS 1.2 — ADD */
		case TLS_Version_1_2:
			if(ctx->versionTls12Enable) {
				*negVersion = TLS_Version_1_2;
			}
			else if(ctx->protocolSide == SSL_ClientSide) {
				ortn = errSSLNegotiation;
			}
			else if(ctx->versionTls11Enable) {
				*negVersion = TLS_Version_1_1;
			}
			else if(ctx->versionTls1Enable) {
				*negVersion = TLS_Version_1_0;
			}
			else if(ctx->versionSsl3Enable) {
				*negVersion = SSL_Version_3_0;
			}
			else if(ctx->versionSsl2Enable) {
				*negVersion = SSL_Version_2_0;
			}
			else {
				ortn = errSSLNegotiation;
			}
			break;
		default:
			ortn = errSSLNegotiation;
			break;
		
	}
	return ortn;
}

/*
 * Determine max enabled protocol, i.e., the one we try to negotiate for.
 *
 * Change Group D1: prepend TLS 1.2 and 1.1 — highest-first is the existing
 * convention. With both enabled by default (B2), client offers 0x0303.
 */
OSStatus sslGetMaxProtVersion(
	SSLContext 			*ctx,
	SSLProtocolVersion	*version)	// RETURNED
{
	OSStatus ortn = noErr;
	if(ctx->versionTls12Enable) {				/* ADD — checked first */
		*version = TLS_Version_1_2;
	}
	else if(ctx->versionTls11Enable) {			/* ADD */
		*version = TLS_Version_1_1;
	}
	else if(ctx->versionTls1Enable) {
		*version = TLS_Version_1_0;
	}
	else if(ctx->versionSsl3Enable) {
		*version =  SSL_Version_3_0;
	}
	else if(ctx->versionSsl2Enable) {
		*version =  SSL_Version_2_0;
	}
	else {
		ortn = paramErr;
	}
	return ortn;
}
