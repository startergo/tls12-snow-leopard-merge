/*
 * Copyright (c) 2000-2009 Apple, Inc. All Rights Reserved.
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
	File:		sslHandshake.c

	Contains:	SSL 3.0 handshake state machine. 

	Written by:	Doug Mitchell

	Copyright: (c) 1999-2009 Apple, Inc. All Rights Reserved.

*/

#include "sslContext.h"
#include "sslHandshake.h"
#include "sslMemory.h"
#include "sslAlertMessage.h"
#include "sslSession.h"
#include "sslUtils.h"
#include "sslDebug.h"
#include "appleCdsa.h"
#include "sslDigests.h"
#include "cipherSpecs.h"

#include <string.h>
#include <assert.h>

#define REQUEST_CERT_CORRECT        0

static OSStatus SSLProcessHandshakeMessage(SSLHandshakeMsg message, SSLContext *ctx);

OSStatus
SSLProcessHandshakeRecord(SSLRecord rec, SSLContext *ctx)
{   OSStatus        err;
    sint32          remaining;
    UInt8           *p;
	UInt8			*startingP;
    SSLHandshakeMsg message = {};
    SSLBuffer       messageData;
    
    if (ctx->fragmentedMessageCache.data != 0)
    {   
		UInt32 origLen = ctx->fragmentedMessageCache.length;
		if ((err = SSLReallocBuffer(&ctx->fragmentedMessageCache,
                    ctx->fragmentedMessageCache.length + rec.contents.length,
                    ctx)) != 0)
        {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
            return err;
        }
        memcpy(ctx->fragmentedMessageCache.data + origLen,
            rec.contents.data, rec.contents.length);
        remaining = ctx->fragmentedMessageCache.length;
        p = ctx->fragmentedMessageCache.data;
    }
    else
    {   remaining = rec.contents.length;
        p = rec.contents.data;
    }
	startingP = p;
	
    while (remaining > 0)
    {   if (remaining < 4)
            break;
        
        messageData.data = p;
        message.type = (SSLHandshakeType)*p++;
        message.contents.length = SSLDecodeInt(p, 3);
        if (((int)(message.contents.length + 4)) > remaining)
            break;
        
        p += 3;
        message.contents.data = p;
        p += message.contents.length;
        messageData.length = 4 + message.contents.length;
        assert(p == messageData.data + messageData.length);
        
        remaining -= messageData.length;
        if ((err = SSLProcessHandshakeMessage(message, ctx)) != 0)
            return err;
        
        if (message.type != SSL_HdskHelloRequest)
        {
			/*
			 * E5 Site 1 — incoming handshake messages.
			 * SHA-256 is guarded: sha256State.data is NULL until
			 * SSLInitMessageHashes() runs (inside SSLEncodeClientHello /
			 * SSLProcessClientHello). Calling update on a NULL buffer crashes.
			 */
            if ((err = SSLHashSHA1.update(&ctx->shaState, &messageData)) != 0 ||
                (err = SSLHashMD5.update(&ctx->md5State, &messageData)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                return err;
            }
            if (ctx->sha256State.data != NULL) {
                if ((err = SSLHashSHA256.update(&ctx->sha256State, &messageData)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
            }
        }
        
        if ((err = SSLAdvanceHandshake(message.type, ctx)) != 0)
            return err;
    }
    
    if (remaining > 0)
    {   if (ctx->fragmentedMessageCache.data == 0)
        {   if ((err = SSLAllocBuffer(&ctx->fragmentedMessageCache, remaining, ctx)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                return err;
            }
        }
        if (startingP != ctx->fragmentedMessageCache.data)
        {   memcpy(ctx->fragmentedMessageCache.data, startingP, remaining);
            ctx->fragmentedMessageCache.length = remaining;
        }
    }
    else if (ctx->fragmentedMessageCache.data != 0)
    {   if ((err = SSLFreeBuffer(&ctx->fragmentedMessageCache, ctx)) != 0)
        {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
            return err;
        }
    }
	
    return noErr;
}

static OSStatus
SSLProcessHandshakeMessage(SSLHandshakeMsg message, SSLContext *ctx)
{   OSStatus      err;
    
    err = noErr;
    SSLLogHdskMsg(message.type, 0);
    switch (message.type)
    {   case SSL_HdskHelloRequest:
            if (ctx->protocolSide != SSL_ClientSide)
                goto wrongMessage;
            if (message.contents.length > 0)
                err = errSSLProtocol;
            break;
        case SSL_HdskClientHello:
            if (ctx->state != SSL_HdskStateServerUninit)
                goto wrongMessage;
            err = SSLProcessClientHello(message.contents, ctx);
            break;
        case SSL_HdskServerHello:
            if (ctx->state != SSL_HdskStateServerHello &&
                ctx->state != SSL_HdskStateServerHelloUnknownVersion)
                goto wrongMessage;
            err = SSLProcessServerHello(message.contents, ctx);
            break;
        case SSL_HdskCert:
            if (ctx->state != SSL_HdskStateCert &&
                ctx->state != SSL_HdskStateClientCert)
                goto wrongMessage;
			err = SSLProcessCertificate(message.contents, ctx);
            break;
        case SSL_HdskCertRequest:
            if (((ctx->state != SSL_HdskStateHelloDone) && 
			     (ctx->state != SSL_HdskStateKeyExchange))
                 || ctx->certRequested)
                goto wrongMessage;
            err = SSLProcessCertificateRequest(message.contents, ctx);
            /* TLS 1.2 backport: always signal the cert request back to the
             * caller (CFNetwork) so SSLHandshakeProceed returns
             * errSSLClientCertRequested cleanly at the TOP of the next call,
             * before any write-queue flush. This reproduces the "dialog shown,
             * no crash" behavior. Auto-advancing into SSL_HdskServerHelloDone
             * (the empty-cert path) is what corrupts the write queue, so we
             * must stop here and hand control back. */
            ctx->signalCertRequest = true;
            break;
        case SSL_HdskServerKeyExchange:
        	switch(ctx->state) {
        		case SSL_HdskStateKeyExchange:
        		case SSL_HdskStateHelloDone:
        			break;
        		default:
                	goto wrongMessage;
        	}
            err = SSLProcessServerKeyExchange(message.contents, ctx);
            break;
        case SSL_HdskServerHelloDone:
            if (ctx->state != SSL_HdskStateHelloDone)
                goto wrongMessage;
            err = SSLProcessServerHelloDone(message.contents, ctx);
            break;
        case SSL_HdskCertVerify:
            if (ctx->state != SSL_HdskStateClientCertVerify)
                goto wrongMessage;
            err = SSLProcessCertificateVerify(message.contents, ctx);
			assert(ctx->protocolSide == SSL_ServerSide);
			if(err) {
				ctx->clientCertState = kSSLClientCertRejected;
			}
            break;
        case SSL_HdskClientKeyExchange:
            if (ctx->state != SSL_HdskStateClientKeyExchange)
                goto wrongMessage;
            err = SSLProcessKeyExchange(message.contents, ctx);
            break;
        case SSL_HdskFinished:
            if (ctx->state != SSL_HdskStateFinished)
                goto wrongMessage;
            err = SSLProcessFinished(message.contents, ctx);
            break;
        default:
            goto wrongMessage;
            break;
    }
    
    if (err && !ctx->sentFatalAlert) 
    {   if (err == errSSLProtocol)
            SSLFatalSessionAlert(SSL_AlertIllegalParam, ctx);
        else if (err == errSSLNegotiation)
            SSLFatalSessionAlert(SSL_AlertHandshakeFail, ctx);
        else if (err != errSSLWouldBlock &&
				 err != errSSLServerAuthCompleted &&
				 err != errSSLClientCertRequested)
            SSLFatalSessionAlert(SSL_AlertCloseNotify, ctx);
    }
    return err;
    
wrongMessage:
    SSLFatalSessionAlert(SSL_AlertUnexpectedMsg, ctx);
    return errSSLProtocol;
}

static OSStatus
SSLResumeServerSide(
	SSLContext *ctx)
{
	OSStatus err;
	if ((err = SSLPrepareAndQueueMessage(SSLEncodeServerHello, ctx)) != 0)
		return err;
	if ((err = SSLInitPendingCiphers(ctx)) != 0)
	{   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
		return err;
	}
	if ((err = SSLPrepareAndQueueMessage(SSLEncodeChangeCipherSpec,
				ctx)) != 0)
		return err;
	if ((err = SSLDisposeCipherSuite(&ctx->writeCipher, ctx)) != 0)
	{   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
		return err;
	}
	ctx->writeCipher = ctx->writePending;
	ctx->writeCipher.ready = 0;
	memset(&ctx->writePending, 0, sizeof(CipherContext));
	if ((err = SSLPrepareAndQueueMessage(SSLEncodeFinishedMessage, 
			ctx)) != 0)
		return err;
	ctx->writeCipher.ready = 1;
	SSLChangeHdskState(ctx, SSL_HdskStateChangeCipherSpec);
	return noErr;
}

OSStatus
SSLAdvanceHandshake(SSLHandshakeType processed, SSLContext *ctx)
{   OSStatus        err;
    SSLBuffer       sessionIdentifier;
    
    switch (processed)
    {   case SSL_HdskHelloRequest:
			ctx->certRequested = 0;
			ctx->certSent = 0;
			ctx->certReceived = 0;
			ctx->x509Requested = 0;
			ctx->clientCertState = kSSLClientCertNone;
			ctx->readCipher.ready = 0;
			ctx->writeCipher.ready = 0;
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeClientHello, ctx)) != 0)
                return err;
            SSLChangeHdskState(ctx, SSL_HdskStateServerHello);
            break;
        case SSL_HdskClientHello:
            assert(ctx->protocolSide == SSL_ServerSide);
			ctx->sessionMatch = 0;
			#if 	SSL_PAC_SERVER_ENABLE
			if((ctx->sessionTicket.data != NULL) && 
			   (ctx->masterSecretCallback != NULL)) {
				size_t secretLen = SSL_MASTER_SECRET_SIZE;
				sslEapDebug("Server side resuming based on masterSecretCallback");
			    if ((err = SSLEncodeRandom(ctx->serverRandom, ctx)) != 0)
       				 return err;
				ctx->serverRandomValid = 1;
				ctx->masterSecretCallback(ctx, ctx->masterSecretArg,
					ctx->masterSecret, &secretLen);
				ctx->sessionMatch = 1;
				if ((err = FindCipherSpec(ctx)) != 0) {
					return err;
				}
				if((err = SSLResumeServerSide(ctx)) != 0) 
					return err;
				break;
			}
			#endif	/* SSL_PAC_SERVER_ENABLE */
            if (ctx->sessionID.data != 0)
            {   if (ctx->resumableSession.data != 0)
                {   
					SSLProtocolVersion sessionProt;
					if ((err = SSLRetrieveSessionID(ctx->resumableSession, 
								&sessionIdentifier, ctx)) != 0)
                        return err;
					if ((err = SSLRetrieveSessionProtocolVersion(ctx->resumableSession, 
							&sessionProt, ctx)) != 0)
					{   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
						return err;
					}
					if ((sessionIdentifier.length == ctx->sessionID.length) &&
                        (memcmp(sessionIdentifier.data, ctx->sessionID.data, 
							ctx->sessionID.length) == 0) &&
					    (sessionProt == ctx->negProtocolVersion)) 
                    {
						sslLogResumSessDebug("===RESUMING SSL3 server-side session");
                        if ((err = SSLInstallSessionFromData(ctx->resumableSession,
								ctx)) != 0)
                        {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                            return err;
                        }
						ctx->sessionMatch = 1;
						SSLFreeBuffer(&sessionIdentifier, ctx);
						if((err = SSLResumeServerSide(ctx)) != 0) 
							return err;
                        break;
                    }
					else {
						sslLogResumSessDebug(
							"===FAILED TO RESUME SSL3 server-side session");
					}
                    if ((err = SSLFreeBuffer(&sessionIdentifier, ctx)) != 0 ||
                        (err = SSLDeleteSessionData(ctx)) != 0)
                    {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                        return err;
                    }
                }
                if ((err = SSLFreeBuffer(&ctx->sessionID, ctx)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
            }
            
            if (ctx->peerID.data != 0)
            {   assert(ctx->sessionID.data == 0);
                err = SSLAllocBuffer(&ctx->sessionID, SSL_SESSION_ID_LEN, ctx);
                if (err == 0)
                {   
                	if((err = sslRand(ctx, &ctx->sessionID)) != 0)
                    {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                        return err;
                    }
                }
            }
            
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeServerHello, ctx)) != 0)
                return err;
            switch (ctx->selectedCipherSpec->keyExchangeMethod)
            {   case SSL_NULL_auth:
            	#if		APPLE_DH
                case SSL_DH_anon:
                case SSL_DH_anon_EXPORT:
                	if(ctx->clientAuth == kAlwaysAuthenticate) {
                		SSLFatalSessionAlert(SSL_AlertHandshakeFail, ctx);
                		return errSSLNegotiation;
                	}
                	ctx->tryClientAuth = false;
                    break;
                #endif	/* APPLE_DH */
                default:
					if(ctx->localCert == NULL) {
						sslErrorLog("SSLAdvanceHandshake: No server key!\n");
						return errSSLBadConfiguration;
					}
                    if ((err = SSLPrepareAndQueueMessage(SSLEncodeCertificate, 
							ctx)) != 0)
                        return err;
                    break;
            }
			{
				bool doServerKeyExch = false;
				switch(ctx->selectedCipherSpec->keyExchangeMethod) {
					case SSL_RSA_EXPORT:
					#if !SSL_SERVER_KEYEXCH_HACK
					case SSL_RSA:
					#endif
						if(ctx->encryptPrivKeyRef != NULL) {
							doServerKeyExch = true;
						}
						break;
					case SSL_DH_anon:
					case SSL_DH_anon_EXPORT:
					case SSL_DHE_RSA:
					case SSL_DHE_RSA_EXPORT:
					case SSL_DHE_DSS:
					case SSL_DHE_DSS_EXPORT:
						doServerKeyExch = true;
						break;
					default:
						break;
				}
				if(doServerKeyExch) {
					err = SSLPrepareAndQueueMessage(SSLEncodeServerKeyExchange, ctx);
					if(err) {
						return err;
					}
				}
			}
            if (ctx->tryClientAuth)
            {   if ((err = SSLPrepareAndQueueMessage(SSLEncodeCertificateRequest, 
						ctx)) != 0)
                    return err;
                ctx->certRequested = 1;
				ctx->clientCertState = kSSLClientCertRequested;
            }
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeServerHelloDone, ctx)) != 0)
                return err;
            if (ctx->certRequested) {
                SSLChangeHdskState(ctx, SSL_HdskStateClientCert);
            }
            else {
                SSLChangeHdskState(ctx, SSL_HdskStateClientKeyExchange);
            }
            break;
        case SSL_HdskServerHello:
			ctx->sessionMatch = 0;
            if (ctx->resumableSession.data != 0 && ctx->sessionID.data != 0)
            {   
				SSLProtocolVersion sessionProt;
				if ((err = SSLRetrieveSessionID(ctx->resumableSession, 
						&sessionIdentifier, ctx)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
				if ((err = SSLRetrieveSessionProtocolVersion(ctx->resumableSession, 
						&sessionProt, ctx)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
                if ((sessionIdentifier.length == ctx->sessionID.length) &&
                    (memcmp(sessionIdentifier.data, ctx->sessionID.data, 
							ctx->sessionID.length) == 0) &&
					(sessionProt == ctx->negProtocolVersion)) 
                {
					sslLogResumSessDebug("===RESUMING SSL3 client-side session");
                    if ((err = SSLInstallSessionFromData(ctx->resumableSession,
							ctx)) != 0 ||
                        (err = SSLInitPendingCiphers(ctx)) != 0 ||
                        (err = SSLFreeBuffer(&sessionIdentifier, ctx)) != 0)
                    {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                        return err;
                    }
					ctx->sessionMatch = 1;
                    SSLChangeHdskState(ctx, SSL_HdskStateChangeCipherSpec);
                    break;
                }
				else {
					sslLogResumSessDebug("===FAILED TO RESUME SSL3 client-side "
							"session");
				}
                if ((err = SSLFreeBuffer(&sessionIdentifier, ctx)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
            }
            switch (ctx->selectedCipherSpec->keyExchangeMethod)
            {   
            	case SSL_NULL_auth:
                case SSL_DH_anon:
                case SSL_DH_anon_EXPORT:
                    SSLChangeHdskState(ctx, SSL_HdskStateKeyExchange);
                    break;
                case SSL_RSA:
                case SSL_DH_DSS:
                case SSL_DH_DSS_EXPORT:
                case SSL_DH_RSA:
                case SSL_DH_RSA_EXPORT:
                case SSL_RSA_EXPORT:
                case SSL_DHE_DSS:
                case SSL_DHE_DSS_EXPORT:
                case SSL_DHE_RSA:
                case SSL_DHE_RSA_EXPORT:
                case SSL_Fortezza:
				case SSL_ECDH_ECDSA:
				case SSL_ECDHE_ECDSA:
				case SSL_ECDH_RSA:
				case SSL_ECDHE_RSA:
                    SSLChangeHdskState(ctx, SSL_HdskStateCert);
                    break;
                default:
                    assert("Unknown key exchange method");
                    break;
            }
            break;
        case SSL_HdskCert:
            if (ctx->state == SSL_HdskStateCert)
                switch (ctx->selectedCipherSpec->keyExchangeMethod)
                {   case SSL_RSA:
                	case SSL_RSA_EXPORT:
                    case SSL_DH_DSS:
                    case SSL_DH_DSS_EXPORT:
                    case SSL_DH_RSA:
                    case SSL_DH_RSA_EXPORT:
					case SSL_ECDH_ECDSA:
					case SSL_ECDH_RSA:
                        SSLChangeHdskState(ctx, SSL_HdskStateHelloDone);
                        break;
                    case SSL_DHE_DSS:
                    case SSL_DHE_DSS_EXPORT:
                    case SSL_DHE_RSA:
                    case SSL_DHE_RSA_EXPORT:
                    case SSL_Fortezza:
					case SSL_ECDHE_ECDSA:
					case SSL_ECDHE_RSA:
                        SSLChangeHdskState(ctx, SSL_HdskStateKeyExchange);
                        break;
                    default:
                        assert("Unknown or unexpected key exchange method");
                        break;
                }
            else if (ctx->state == SSL_HdskStateClientCert)
            {   SSLChangeHdskState(ctx, SSL_HdskStateClientKeyExchange);
                if (ctx->peerCert != 0)
                    ctx->certReceived = 1;
            }
            break;
        case SSL_HdskCertRequest:
            if (ctx->peerCert == 0)
            {   SSLFatalSessionAlert(SSL_AlertHandshakeFail, ctx);
                return errSSLProtocol;
            }
            assert(ctx->protocolSide == SSL_ClientSide);
            ctx->certRequested = 1;
            ctx->clientCertState = kSSLClientCertRequested;
            break;
        case SSL_HdskServerKeyExchange:
            SSLChangeHdskState(ctx, SSL_HdskStateHelloDone);
            break;
        case SSL_HdskServerHelloDone:
            if (ctx->state == SSL_HdskStateClientCert) {
                SSLChangeHdskState(ctx, SSL_HdskServerHelloDone);
            } else { 
                if (ctx->signalServerAuth) {
                    ctx->signalServerAuth = false;
                    SSLChangeHdskState(ctx, SSL_HdskStateClientCert);
                    return errSSLServerAuthCompleted;
                } else if (ctx->signalCertRequest) {
                    ctx->signalCertRequest = false;
                    SSLChangeHdskState(ctx, SSL_HdskStateClientCert);
                    return errSSLClientCertRequested;
                }
            }
            
			if (ctx->clientCertState == kSSLClientCertRequested) {
                if (ctx->localCert != 0 && ctx->x509Requested) {
					if ((err = SSLPrepareAndQueueMessage(SSLEncodeCertificate,
							ctx)) != 0) {
						return err;
					}
                }
                else {
					if(ctx->negProtocolVersion >= TLS_Version_1_0) {
						if ((err = SSLPrepareAndQueueMessage(SSLEncodeCertificate,
								ctx)) != 0) {
							return err;
						}
					}
					else {
						if ((err = SSLSendAlert(SSL_AlertLevelWarning, SSL_AlertNoCert,
								ctx)) != 0) {
							return err;
						}
					}
                }
            }
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeKeyExchange, ctx)) != 0)
                return err;
			assert(ctx->sslTslCalls != NULL);
            if ((err = ctx->sslTslCalls->generateMasterSecret(ctx)) != 0 ||
                (err = SSLInitPendingCiphers(ctx)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                return err;
            }
			memset(ctx->preMasterSecret.data, 0, ctx->preMasterSecret.length);
            if ((err = SSLFreeBuffer(&ctx->preMasterSecret, ctx)) != 0) {
                return err;
			}
            if (ctx->certSent) {
				switch(ctx->negAuthType) {
					case SSLClientAuth_RSASign:
					case SSLClientAuth_ECDSASign:
						if ((err = SSLPrepareAndQueueMessage(SSLEncodeCertificateVerify, 
								ctx)) != 0) {
							return err;
						}
						break;
					default:
						break;
				}
			}
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeChangeCipherSpec, 
					ctx)) != 0) {
                return err;
			}
            if ((err = SSLDisposeCipherSuite(&ctx->writeCipher, ctx)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                return err;
            }
            ctx->writeCipher = ctx->writePending;
            ctx->writeCipher.ready = 0;
            memset(&ctx->writePending, 0, sizeof(CipherContext));
			ctx->writePending.encrypting = 1;   
            if ((err = SSLPrepareAndQueueMessage(SSLEncodeFinishedMessage, ctx)) != 0)
                return err;
            ctx->writeCipher.ready = 1;
            SSLChangeHdskState(ctx, SSL_HdskStateChangeCipherSpec);
            break;
        case SSL_HdskCertVerify:
            SSLChangeHdskState(ctx, SSL_HdskStateChangeCipherSpec);
            break;
        case SSL_HdskClientKeyExchange:
 			assert(ctx->sslTslCalls != NULL);
			if ((err = ctx->sslTslCalls->generateMasterSecret(ctx)) != 0 ||
                (err = SSLInitPendingCiphers(ctx)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                return err;
            }
			memset(ctx->preMasterSecret.data, 0, ctx->preMasterSecret.length);
            if ((err = SSLFreeBuffer(&ctx->preMasterSecret, ctx)) != 0)
                return err;
            if (ctx->certReceived) {
                SSLChangeHdskState(ctx, SSL_HdskStateClientCertVerify);
            }
            else {
                SSLChangeHdskState(ctx, SSL_HdskStateChangeCipherSpec);
            }
            break;
        case SSL_HdskFinished:
            ctx->readCipher.ready = 1;
            if (ctx->writePending.ready != 0)
            {   if ((err = SSLPrepareAndQueueMessage(SSLEncodeChangeCipherSpec, 
						ctx)) != 0)
                    return err;
                if ((err = SSLDisposeCipherSuite(&ctx->writeCipher, ctx)) != 0)
                {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                    return err;
                }
                ctx->writeCipher = ctx->writePending;
                ctx->writeCipher.ready = 0;
                memset(&ctx->writePending, 0, sizeof(CipherContext));
                if ((err = SSLPrepareAndQueueMessage(SSLEncodeFinishedMessage, 
							ctx)) != 0)
                    return err;
                ctx->writeCipher.ready = 1;
            }
            if (ctx->protocolSide == SSL_ServerSide) {
                SSLChangeHdskState(ctx, SSL_HdskStateServerReady);
            }
            else {
                SSLChangeHdskState(ctx, SSL_HdskStateClientReady);
            }
            if ((ctx->peerID.data != 0) && (ctx->sessionTicket.data == NULL)) {
                SSLAddSessionData(ctx);
			}
            break;
        default:
            assert("Unknown State");
            break;
    }
    
    return noErr;
}

OSStatus
SSLPrepareAndQueueMessage(EncodeMessageFunc msgFunc, SSLContext *ctx)
{   OSStatus        err;
    SSLRecord       rec = {0, 0, {0, NULL}};
    
    if ((err = msgFunc(&rec, ctx)) != 0)
    {   SSLFatalSessionAlert(SSL_AlertCloseNotify, ctx);
        goto fail;
    }
    
    if (rec.contentType == SSL_RecordTypeHandshake)
    {
		/*
		 * E5 Site 2 — outgoing handshake messages.
		 * SHA-256 is guarded: sha256State.data is NULL on the first ClientHello
		 * because SSLInitMessageHashes is called at the END of SSLEncodeClientHello,
		 * after the record is assembled and returned here for hashing.
		 */
        if ((err = SSLHashSHA1.update(&ctx->shaState, &rec.contents)) != 0 ||
            (err = SSLHashMD5.update(&ctx->md5State, &rec.contents)) != 0)
        {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
            goto fail;
        }
        if (ctx->sha256State.data != NULL) {
            if ((err = SSLHashSHA256.update(&ctx->sha256State, &rec.contents)) != 0)
            {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
                goto fail;
            }
        }
        SSLLogHdskMsg((SSLHandshakeType)rec.contents.data[0], 1);
    }
    
	assert(ctx->sslTslCalls != NULL);
    if ((err = ctx->sslTslCalls->writeRecord(rec, ctx)) != 0)
        goto fail;
    
    err = noErr;
fail:
    SSLFreeBuffer(&rec.contents, ctx);
    
    return err;
}

OSStatus
SSL3ReceiveSSL2ClientHello(SSLRecord rec, SSLContext *ctx)
{   OSStatus      err;
    
    if ((err = SSLInitMessageHashes(ctx)) != 0)
        return err;
    
	/*
	 * E5 Site 3 — SSL2-format ClientHello path.
	 * SSLInitMessageHashes() called just above, so sha256State is valid.
	 * Guard kept for safety.
	 */
    if ((err = SSLHashSHA1.update(&ctx->shaState, &rec.contents)) != 0 ||
        (err = SSLHashMD5.update(&ctx->md5State, &rec.contents)) != 0)
    {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
        return err;
    }
    if (ctx->sha256State.data != NULL) {
        if ((err = SSLHashSHA256.update(&ctx->sha256State, &rec.contents)) != 0)
        {   SSLFatalSessionAlert(SSL_AlertInternalError, ctx);
            return err;
        }
    }
    
    if ((err = SSLAdvanceHandshake(SSL_HdskClientHello, ctx)) != 0)
        return err;
    
    return noErr;
}

/* log changes in handshake state */
#ifndef	NDEBUG
#include <stdio.h>

char *hdskStateToStr(SSLHandshakeState state)
{
	static char badStr[100];
	
	switch(state) {
		case SSL_HdskStateUninit:           return "Uninit";
		case SSL_HdskStateServerUninit:     return "ServerUninit";
		case SSL_HdskStateClientUninit:     return "ClientUninit";
		case SSL_HdskStateGracefulClose:    return "GracefulClose";
		case SSL_HdskStateErrorClose:       return "ErrorClose";
		case SSL_HdskStateNoNotifyClose:    return "NoNotifyClose";
		case SSL_HdskStateServerHello:      return "ServerHello";
		case SSL_HdskStateServerHelloUnknownVersion: return "ServerHelloUnknownVersion";
		case SSL_HdskStateKeyExchange:      return "KeyExchange";
		case SSL_HdskStateCert:             return "Cert";
		case SSL_HdskStateHelloDone:        return "HelloDone";
		case SSL_HdskStateClientCert:       return "ClientCert";
		case SSL_HdskStateClientKeyExchange: return "ClientKeyExchange";
		case SSL_HdskStateClientCertVerify: return "ClientCertVerify";
		case SSL_HdskStateChangeCipherSpec: return "ChangeCipherSpec";
		case SSL_HdskStateFinished:         return "Finished";
		case SSL2_HdskStateClientMasterKey: return "SSL2_ClientMasterKey";
		case SSL2_HdskStateClientFinished:  return "SSL2_ClientFinished";
		case SSL2_HdskStateServerHello:     return "SSL2_ServerHello";
		case SSL2_HdskStateServerVerify:    return "SSL2_ServerVerify";
		case SSL2_HdskStateServerFinished:  return "SSL2_ServerFinished";
		case SSL_HdskStateServerReady:      return "SSL_ServerReady";
		case SSL_HdskStateClientReady:      return "SSL_ClientReady";
		default:
			sprintf(badStr, "Unknown state (%d(d)", state);
			return badStr;
	}
}

void SSLChangeHdskState(SSLContext *ctx, SSLHandshakeState newState)
{
	#ifndef	NDEBUG
	sslHdskStateDebug("...hdskState = %s", hdskStateToStr(newState));
	#endif
	ctx->state = newState;
}

static char *hdskMsgToStr(SSLHandshakeType msg)
{
	static char badStr[100];
	switch(msg) {
		case SSL_HdskHelloRequest:      return "SSL_HdskHelloRequest";
		case SSL_HdskClientHello:       return "SSL_HdskClientHello";
		case SSL_HdskServerHello:       return "SSL_HdskServerHello";
		case SSL_HdskCert:              return "SSL_HdskCert";
		case SSL_HdskServerKeyExchange: return "SSL_HdskServerKeyExchange";
		case SSL_HdskCertRequest:       return "SSL_HdskCertRequest";
		case SSL_HdskServerHelloDone:   return "SSL_HdskServerHelloDone";
		case SSL_HdskCertVerify:        return "SSL_HdskCertVerify";
		case SSL_HdskClientKeyExchange: return "SSL_HdskClientKeyExchange";
		case SSL_HdskFinished:          return "SSL_HdskFinished";
		case SSL_HdskNoCertAlert:       return "SSL_HdskNoCertAlert";
		default:
			sprintf(badStr, "Unknown msg (%d(d))", msg);
			return badStr;
	}
}

void SSLLogHdskMsg(SSLHandshakeType msg, char sent)
{
	sslHdskMsgDebug("---%s handshake msg %s", 
		hdskMsgToStr(msg), (sent ? "sent" : "recv"));
}

#endif	/* NDEBUG */
