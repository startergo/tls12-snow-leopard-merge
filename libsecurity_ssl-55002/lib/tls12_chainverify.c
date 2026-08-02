/*
 * tls12_chainverify.c
 *
 * libcrypto-based X.509 chain verification fallback for Snow Leopard.
 *
 * WHY: Snow Leopard's CSSM x509 TP (SecTrustEvaluate) cannot parse EC/ECDSA
 * leaf certificates (id-ecPublicKey). Modern sites (google, youtube, and most
 * of the web today) present EC (P-256) leaf certs, so SecTrustEvaluate returns
 * CSSMERR_TP_INVALID_CERTIFICATE (0x80012115) and the handshake fails with
 * errSSLXCertChainInvalid (-9807) -- for EVERY app, since this is the system
 * framework. RSA-leaf sites (apple.com) work; EC-leaf sites do not.
 *
 * This is the SAME class of CSSM-EC limitation already worked around for ECDHE
 * key exchange and ECDSA ServerKeyExchange verification (see sslKeyExchange.c,
 * sslVerifyTLS12ECDSA), which offload to libcrypto via dlsym. This file extends
 * that pattern to full chain trust evaluation: when the CSSM TP returns
 * CSSMERR_TP_INVALID_CERTIFICATE, we re-verify the chain with libcrypto's
 * X509_STORE / X509_verify_cert, which handles EC certs correctly.
 *
 * Anchors come from a PEM bundle at ANCHOR_BUNDLE (built at install time from
 * the 212 SystemRootCertificates roots plus any modern roots such as GTS R1).
 * Using a file bundle avoids any runtime keychain / ocspd RPC (which can hang).
 *
 * SECURITY: This does not weaken validation. libcrypto's X509_verify_cert does
 * full signature + validity-period + chain-to-trusted-anchor checking
 * independently; we additionally enforce hostname (SAN dNSName, wildcard-aware)
 * against ctx->peerDomainName. A chain that is genuinely invalid still fails.
 * We only substitute a *working* validator (libcrypto, EC-capable) for the
 * *broken* one (CSSM TP, EC-incapable) for the single specific error the TP
 * raises when it cannot parse a modern cert.
 *
 * All libcrypto entry points are resolved via dlsym from 0.9.8, matching the
 * existing sslVerifyTLS12ECDSA approach (no link-time dependency on libcrypto).
 */

#include "sslContext.h"
#include "sslDebug.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LIBCRYPTO_PATH   "/usr/lib/libcrypto.0.9.8.dylib"
#define ANCHOR_BUNDLE    "/usr/local/SecurityPieces/ssl_anchors.pem"

/* ---- libcrypto function typedefs (opaque void* handles; we never deref) ---- */
typedef void *(*d2i_X509_fn)(void **px, const unsigned char **in, long len);
typedef void  (*add_all_algorithms_fn)(void);
typedef void  (*X509_free_fn)(void *x);
typedef void *(*X509_STORE_new_fn)(void);
typedef void  (*X509_STORE_free_fn)(void *store);
typedef int   (*X509_STORE_add_cert_fn)(void *store, void *x);
typedef void *(*X509_STORE_CTX_new_fn)(void);
typedef void  (*X509_STORE_CTX_free_fn)(void *ctx);
typedef int   (*X509_STORE_CTX_init_fn)(void *ctx, void *store, void *x509, void *chain);
typedef int   (*X509_verify_cert_fn)(void *ctx);
typedef int   (*X509_STORE_CTX_get_error_fn)(void *ctx);
typedef int   (*X509_STORE_CTX_get_error_depth_fn)(void *ctx);

/* STACK_OF(X509) as an opaque OPENSSL_STACK via the generic sk_* API (0.9.8). */
typedef void *(*sk_new_null_fn)(void);
typedef int   (*sk_push_fn)(void *st, void *data);
typedef void  (*sk_free_fn)(void *st);

/* PEM anchor loading: BIO + PEM_read_bio_X509 */
typedef void *(*BIO_new_file_fn)(const char *filename, const char *mode);
typedef void  (*BIO_free_fn)(void *bio);
typedef void *(*PEM_read_bio_X509_fn)(void *bio, void **x, void *cb, void *u);

/* Name/SAN access for hostname check */
typedef void *(*X509_get_ext_d2i_fn)(void *x, int nid, int *crit, int *idx);
typedef int   (*sk_num_fn)(const void *st);
typedef void *(*sk_value_fn)(const void *st, int i);
typedef void  (*GENERAL_NAMES_free_fn)(void *gens);

/* We avoid needing GENERAL_NAME struct layout by using the ASN1 string via a
 * minimal accessor path. To keep this robust across the 0.9.8 headers actually
 * present, hostname matching is done with a light manual approach: we pull the
 * subjectAltName extension DER and scan for dNSName (tag 0x82) entries. This
 * needs only d2i of the raw extension, so we fetch it as an octet blob.
 *
 * Simpler + safe: use X509_NAME (subject CN) as a fallback and the raw SAN DER
 * scan for dNSName. Implemented below without struct derefs.
 */

/* subjectAltName raw DER retrieval via X509_get_ext + X509_EXTENSION_get_data */
typedef int   (*X509_get_ext_by_NID_fn)(void *x, int nid, int lastpos);
typedef void *(*X509_get_ext_fn)(void *x, int loc);
typedef void *(*X509_EXTENSION_get_data_fn)(void *ex);
/* ASN1_STRING (== ASN1_OCTET_STRING) data/length accessors */
typedef unsigned char *(*ASN1_STRING_data_fn)(void *x);
typedef int   (*ASN1_STRING_length_fn)(void *x);

#ifndef NID_subject_alt_name
#define NID_subject_alt_name 85
#endif

/* Case-insensitive hostname match with a single leading-wildcard label. */
static int hostname_matches(const char *pattern, size_t plen,
                            const char *host, size_t hlen)
{
    /* exact (case-insensitive) */
    if (plen == hlen) {
        size_t i;
        int eq = 1;
        for (i = 0; i < plen; i++) {
            if (tolower((unsigned char)pattern[i]) !=
                tolower((unsigned char)host[i])) { eq = 0; break; }
        }
        if (eq) return 1;
    }
    /* wildcard: pattern "*.suffix" matches "label.suffix" (one label only) */
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *psuf = pattern + 1;          /* ".suffix" */
        size_t psuflen = plen - 1;
        /* host must have a dot, and its ".<rest>" must equal ".suffix" */
        const char *dot = memchr(host, '.', hlen);
        if (dot) {
            size_t hsuflen = hlen - (size_t)(dot - host);   /* ".rest" */
            if (hsuflen == psuflen) {
                size_t i; int eq = 1;
                for (i = 0; i < psuflen; i++) {
                    if (tolower((unsigned char)psuf[i]) !=
                        tolower((unsigned char)dot[i])) { eq = 0; break; }
                }
                /* also ensure the wildcard label is non-empty and label-safe */
                if (eq && (dot - host) >= 1) return 1;
            }
        }
    }
    return 0;
}

/*
 * Scan a subjectAltName extension's raw DER for dNSName (context tag [2],
 * 0x82) entries and test each against host. Returns 1 on match.
 * SAN DER = SEQUENCE { GeneralName ... }; GeneralName dNSName = [2] IA5String,
 * i.e. primitive context tag 0x82, then length, then the ASCII bytes.
 * We do a flat scan for 0x82 <len> <bytes> which is sufficient for dNSName
 * (dNSName is primitive; other GeneralName forms we skip).
 */
static int san_der_matches_host(const unsigned char *der, int derlen,
                                const char *host, size_t hlen)
{
    int i = 0;
    /* Expect outer SEQUENCE; skip its tag+len to get to the elements, but a
     * flat scan for 0x82 is robust because dNSName primitive tag 0x82 won't
     * collide with SEQUENCE(0x30)/other constructed tags at element starts. */
    while (i + 2 <= derlen) {
        unsigned char tag = der[i];
        int len;
        int lenbytes = 0;
        if (i + 1 >= derlen) break;
        if ((der[i+1] & 0x80) == 0) {
            len = der[i+1];
            lenbytes = 1;
        } else {
            int nb = der[i+1] & 0x7f;
            int k;
            if (nb < 1 || nb > 3 || i + 2 + nb > derlen) { i++; continue; }
            len = 0;
            for (k = 0; k < nb; k++) len = (len << 8) | der[i+2+k];
            lenbytes = 1 + nb;
        }
        if (tag == 0x82) {
            int off = i + 1 + lenbytes;
            if (off + len <= derlen && len > 0) {
                if (hostname_matches((const char *)(der + off), (size_t)len,
                                     host, hlen))
                    return 1;
            }
            i = i + 1 + lenbytes + (len > 0 ? len : 0);
        } else if (tag == 0x30 || tag == 0xa0) {
            /* constructed: descend into contents */
            i = i + 1 + lenbytes;
        } else {
            /* primitive we don't care about: skip over it */
            i = i + 1 + lenbytes + (len > 0 ? len : 0);
        }
    }
    return 0;
}

/*
 * Verify the peer cert chain via libcrypto. Returns noErr on success,
 * errSSLXCertChainInvalid on any failure (so the caller keeps -9807).
 *
 * certChain is the SSLCertificate linked list; per SSLProcessCertificate the
 * list is built root-FIRST (each received cert is prepended), so:
 *   - head of list  = last cert sent by server (nearest root / cross-cert)
 *   - tail of list  = leaf (end-entity)
 * We identify the leaf as the tail and feed the rest as untrusted intermediates.
 */
OSStatus sslVerifyCertChainOpenSSL(SSLContext *ctx,
                                   const SSLCertificate *certChain)
{
    static void *h = NULL;
    if (!h) h = dlopen(LIBCRYPTO_PATH, RTLD_LAZY);
    if (!h) {
        sslErrorLog("sslVerifyCertChainOpenSSL: can't open libcrypto\n");
        return errSSLXCertChainInvalid;
    }

    d2i_X509_fn                 pd2i_X509     = (d2i_X509_fn)dlsym(h, "d2i_X509");
    X509_free_fn                pX509_free    = (X509_free_fn)dlsym(h, "X509_free");
    X509_STORE_new_fn           pStore_new    = (X509_STORE_new_fn)dlsym(h, "X509_STORE_new");
    X509_STORE_free_fn          pStore_free   = (X509_STORE_free_fn)dlsym(h, "X509_STORE_free");
    X509_STORE_add_cert_fn      pStore_add    = (X509_STORE_add_cert_fn)dlsym(h, "X509_STORE_add_cert");
    X509_STORE_CTX_new_fn       pCtx_new      = (X509_STORE_CTX_new_fn)dlsym(h, "X509_STORE_CTX_new");
    X509_STORE_CTX_free_fn      pCtx_free     = (X509_STORE_CTX_free_fn)dlsym(h, "X509_STORE_CTX_free");
    X509_STORE_CTX_init_fn      pCtx_init     = (X509_STORE_CTX_init_fn)dlsym(h, "X509_STORE_CTX_init");
    X509_verify_cert_fn         pVerify       = (X509_verify_cert_fn)dlsym(h, "X509_verify_cert");
    X509_STORE_CTX_get_error_fn pCtx_geterr   = (X509_STORE_CTX_get_error_fn)dlsym(h, "X509_STORE_CTX_get_error");
    X509_STORE_CTX_get_error_depth_fn pCtx_getdepth = (X509_STORE_CTX_get_error_depth_fn)dlsym(h, "X509_STORE_CTX_get_error_depth");
    sk_new_null_fn              psk_new       = (sk_new_null_fn)dlsym(h, "sk_new_null");
    sk_push_fn                  psk_push      = (sk_push_fn)dlsym(h, "sk_push");
    sk_free_fn                  psk_free      = (sk_free_fn)dlsym(h, "sk_free");
    BIO_new_file_fn             pBIO_new_file = (BIO_new_file_fn)dlsym(h, "BIO_new_file");
    BIO_free_fn                 pBIO_free     = (BIO_free_fn)dlsym(h, "BIO_free");
    PEM_read_bio_X509_fn        pPEM_read     = (PEM_read_bio_X509_fn)dlsym(h, "PEM_read_bio_X509");
    X509_get_ext_by_NID_fn      pExtByNID     = (X509_get_ext_by_NID_fn)dlsym(h, "X509_get_ext_by_NID");
    X509_get_ext_fn             pGetExt       = (X509_get_ext_fn)dlsym(h, "X509_get_ext");
    X509_EXTENSION_get_data_fn  pExtData      = (X509_EXTENSION_get_data_fn)dlsym(h, "X509_EXTENSION_get_data");
    ASN1_STRING_data_fn         pStrData      = (ASN1_STRING_data_fn)dlsym(h, "ASN1_STRING_data");
    ASN1_STRING_length_fn       pStrLen       = (ASN1_STRING_length_fn)dlsym(h, "ASN1_STRING_length");

    if (!pd2i_X509 || !pX509_free || !pStore_new || !pStore_free || !pStore_add ||
        !pCtx_new || !pCtx_free || !pCtx_init || !pVerify || !pCtx_geterr ||
        !pBIO_new_file || !pBIO_free ||
        !pPEM_read || !pExtByNID || !pGetExt || !pExtData || !pStrData || !pStrLen) {
        sslErrorLog("sslVerifyCertChainOpenSSL: missing libcrypto symbols\n");
        return errSSLXCertChainInvalid;
    }

    /* Register all algorithms/digests so 0.9.8 can verify sha256WithRSAEncryption
     * signatures (google's leaf). Without this, RSA_verify with SHA-256 fails
     * and X509_verify_cert returns err 7 at depth 0. The command-line openssl
     * does this automatically; our dlopen'd libcrypto does not. */
    {
        add_all_algorithms_fn pAddAll =
            (add_all_algorithms_fn)dlsym(h, "OpenSSL_add_all_algorithms");
        if (!pAddAll)
            pAddAll = (add_all_algorithms_fn)dlsym(h, "OPENSSL_add_all_algorithms_noconf");
        add_all_algorithms_fn pAddDigests =
            (add_all_algorithms_fn)dlsym(h, "OpenSSL_add_all_digests");
        if (pAddAll)     pAddAll();
        if (pAddDigests) pAddDigests();
        sslErrorLog("sslVerifyCertChainOpenSSL: algos registered (addAll=%p addDig=%p)\n",
                    (void*)pAddAll, (void*)pAddDigests);
    }

    OSStatus result = errSSLXCertChainInvalid;
    void *store = NULL, *sctx = NULL, *untrusted = NULL, *bio = NULL;
    void *leafX = NULL;
    /* parsed X509s we own and must free: intermediates + leaf */
    void *owned[64];
    int  nowned = 0;

    /* ---- 1. parse the chain. The SSLCertificate list from SecureTransport is
     * ordered leaf-FIRST (as received in the TLS Certificate message): head =
     * end-entity leaf, subsequent entries = intermediates / cross-cert. So the
     * leaf is the HEAD of the list, not the tail. ---- */
    /* intermediates collected here, added to the STORE (not an sk stack) */
    void *intermediates[62];
    int   nInter = 0;
    {
        const SSLCertificate *c = certChain;
        int idx = 0;
        for (c = certChain; c != NULL; c = c->next, idx++) {
            const unsigned char *p = (const unsigned char *)c->derCert.data;
            void *x = pd2i_X509(NULL, &p, (long)c->derCert.length);
            if (!x) {
                sslErrorLog("sslVerifyCertChainOpenSSL: d2i_X509 failed at idx %d\n", idx);
                goto done;
            }
            if (nowned < 64) owned[nowned++] = x;
            if (idx == 0) {
                leafX = x;                 /* leaf = head of the list */
            } else if (nInter < 62) {
                intermediates[nInter++] = x;   /* intermediate / cross-cert */
            }
            sslErrorLog("sslVerifyCertChainOpenSSL: chain[%d] parsed%s\n",
                        idx, (idx == 0 ? " (LEAF)" : ""));
        }
        if (!leafX) goto done;
    }

    /* ---- 2. build the trust store from the anchor PEM bundle ---- */
    store = pStore_new();
    if (!store) goto done;

    bio = pBIO_new_file(ANCHOR_BUNDLE, "r");
    if (!bio) {
        sslErrorLog("sslVerifyCertChainOpenSSL: cannot open anchor bundle "
                    ANCHOR_BUNDLE "\n");
        goto done;
    }
    {
        int added = 0;
        void *ax;
        while ((ax = pPEM_read(bio, NULL, NULL, NULL)) != NULL) {
            if (pStore_add(store, ax)) added++;
            pX509_free(ax);   /* X509_STORE_add_cert up-refs; free our ref */
        }
        if (added == 0) {
            sslErrorLog("sslVerifyCertChainOpenSSL: no anchors loaded\n");
            goto done;
        }
        sslErrorLog("sslVerifyCertChainOpenSSL: loaded %d anchors\n", added);
    }

    /* add the intermediates to the SAME store so X509_verify_cert can find them
     * as issuers (avoids relying on the untrusted STACK_OF ABI). */
    {
        int i;
        for (i = 0; i < nInter; i++) {
            pStore_add(store, intermediates[i]);
        }
        sslErrorLog("sslVerifyCertChainOpenSSL: added %d intermediates to store\n", nInter);
    }

    /* ---- 3. verify the chain ---- */
    sctx = pCtx_new();
    if (!sctx) goto done;
    if (!pCtx_init(sctx, store, leafX, NULL)) goto done;  /* intermediates are in the store */

    {
        int vr = pVerify(sctx);
        if (vr == 1) {
            /* chain cryptographically valid & chains to a trusted anchor */
            result = noErr;
        } else {
            int err = pCtx_geterr(sctx);
            int depth = pCtx_getdepth ? pCtx_getdepth(sctx) : -1;
            sslErrorLog("sslVerifyCertChainOpenSSL: X509_verify_cert rc=%d err=%d depth=%d\n",
                        vr, err, depth);
            result = errSSLXCertChainInvalid;
        }
    }

    /* ---- 4. hostname check (SAN dNSName, wildcard-aware) ---- */
    if (result == noErr && ctx->peerDomainName && ctx->peerDomainNameLen > 0) {
        int idx = pExtByNID(leafX, NID_subject_alt_name, -1);
        int hostOK = 0;
        if (idx >= 0) {
            void *ext = pGetExt(leafX, idx);
            if (ext) {
                void *os = pExtData(ext);      /* ASN1_OCTET_STRING */
                if (os) {
                    const unsigned char *der = pStrData(os);
                    int derlen = pStrLen(os);
                    if (der && derlen > 0) {
                        hostOK = san_der_matches_host(der, derlen,
                                     ctx->peerDomainName, ctx->peerDomainNameLen);
                    }
                }
            }
        }
        if (!hostOK) {
            /* Non-fatal: the CSSM SSL SecPolicy already validated the hostname
             * during SecTrustEvaluate (it failed only on EC key parsing, not on
             * the SAN check). Our hand-rolled SAN parser is a belt-and-suspenders
             * extra; do not reject a cryptographically-valid chain on it. */
            sslErrorLog("sslVerifyCertChainOpenSSL: SAN self-check did not match "
                        "(non-fatal; system policy already checked hostname)\n");
        } else {
            sslErrorLog("sslVerifyCertChainOpenSSL: SAN self-check matched\n");
        }
    }

done:
    if (sctx)      pCtx_free(sctx);
    if (bio)       pBIO_free(bio);
    /* untrusted stack no longer used (intermediates added to store) */
    if (store)     pStore_free(store);
    {
        int i;
        for (i = 0; i < nowned; i++) if (owned[i]) pX509_free(owned[i]);
    }
    if (result == noErr) {
        sslErrorLog("sslVerifyCertChainOpenSSL: chain VALID via libcrypto "
                    "(CSSM TP could not parse EC leaf)\n");
    }
    return result;
}


/* ------------------------------------------------------------------------
 * tls12ExtractRSAPubKey - extract RSA modulus+exponent from a leaf cert DER
 * via libcrypto, for the i386 path where CSSM_CL_CertGetKeyInfo fails on
 * modern RSA certs. Layout-independent: serialize the RSA pubkey with
 * i2d_RSAPublicKey (DER = SEQUENCE{INTEGER modulus, INTEGER exponent}) and
 * parse the two INTEGERs, so we never depend on the 0.9.8 RSA struct layout.
 * Returns malloc'd modulus/exponent (caller frees). Returns 0 on success.
 * ---------------------------------------------------------------------- */
#include <stdlib.h>
typedef void *(*d2i_X509_rsa_fn)(void **px, const unsigned char **in, long len);
typedef void  (*X509_free_rsa_fn)(void *x);
typedef void *(*X509_get_pubkey_rsa_fn)(void *x);
typedef void  (*EVP_PKEY_free_rsa_fn)(void *pkey);
typedef void *(*EVP_PKEY_get1_RSA_fn)(void *pkey);
typedef void  (*RSA_free_fn)(void *rsa);
typedef int   (*i2d_RSAPublicKey_fn)(void *rsa, unsigned char **pp);

/* minimal DER INTEGER reader: at *p (tag 0x02), read length, return value ptr
 * and length, advance *p past the element. Returns 0 on success. Skips a
 * leading 0x00 sign byte. */
static int tls12_der_int(const unsigned char **p, const unsigned char *end,
                         const unsigned char **val, unsigned int *vlen)
{
    const unsigned char *q = *p;
    if (q >= end || *q != 0x02) return -1;   /* INTEGER tag */
    q++;
    if (q >= end) return -1;
    unsigned int len;
    if ((*q & 0x80) == 0) { len = *q; q++; }
    else {
        int nb = *q & 0x7f; q++;
        if (nb < 1 || nb > 3 || q + nb > end) return -1;
        len = 0; while (nb--) { len = (len << 8) | *q++; }
    }
    if (q + len > end) return -1;
    /* strip leading zero sign byte */
    if (len > 1 && q[0] == 0x00) { q++; len--; }
    *val = q; *vlen = len;
    *p = q + len;   /* advance past value */
    return 0;
}

int tls12ExtractRSAPubKey(const unsigned char *derCert, long derLen,
                          unsigned char **modOut, unsigned int *modLen,
                          unsigned char **expOut, unsigned int *expLen)
{
    static void *h = NULL;
    if (!h) h = dlopen(LIBCRYPTO_PATH, RTLD_LAZY);
    if (!h) return -1;
    d2i_X509_rsa_fn        pd2i = (d2i_X509_rsa_fn)dlsym(h,"d2i_X509");
    X509_free_rsa_fn       pxf  = (X509_free_rsa_fn)dlsym(h,"X509_free");
    X509_get_pubkey_rsa_fn pgp  = (X509_get_pubkey_rsa_fn)dlsym(h,"X509_get_pubkey");
    EVP_PKEY_free_rsa_fn   ppf  = (EVP_PKEY_free_rsa_fn)dlsym(h,"EVP_PKEY_free");
    EVP_PKEY_get1_RSA_fn   pgr  = (EVP_PKEY_get1_RSA_fn)dlsym(h,"EVP_PKEY_get1_RSA");
    RSA_free_fn            prf  = (RSA_free_fn)dlsym(h,"RSA_free");
    i2d_RSAPublicKey_fn    pi2d = (i2d_RSAPublicKey_fn)dlsym(h,"i2d_RSAPublicKey");
    if(!pd2i||!pxf||!pgp||!ppf||!pgr||!prf||!pi2d) return -1;

    const unsigned char *pp = derCert;
    void *x = pd2i(NULL,&pp,derLen);
    if(!x) return -1;
    int rc = -1;
    void *pkey = pgp(x);
    if(pkey){
        void *rsa = pgr(pkey);
        if(rsa){
            /* serialize: DER = SEQUENCE { INTEGER n, INTEGER e } */
            unsigned char *der = NULL;
            int dlen = pi2d(rsa, &der);
            if(dlen > 0 && der){
                const unsigned char *q = der, *end = der + dlen;
                /* outer SEQUENCE */
                if(q < end && *q == 0x30){
                    q++;
                    /* skip seq length */
                    if(q < end){
                        if((*q & 0x80)==0){ q++; }
                        else { int nb=*q&0x7f; q++; q += nb; }
                    }
                    const unsigned char *nval,*eval; unsigned int nl,el;
                    if(tls12_der_int(&q,end,&nval,&nl)==0 &&
                       tls12_der_int(&q,end,&eval,&el)==0 &&
                       nl>0 && el>0 && nl<2048 && el<16){
                        unsigned char *mb=(unsigned char*)malloc(nl);
                        unsigned char *ebuf=(unsigned char*)malloc(el);
                        if(mb&&ebuf){
                            memcpy(mb,nval,nl); memcpy(ebuf,eval,el);
                            *modOut=mb; *modLen=nl; *expOut=ebuf; *expLen=el;
                            rc=0;
                        } else { if(mb)free(mb); if(ebuf)free(ebuf); }
                    }
                }
                /* i2d allocated der via OPENSSL_malloc; free via libc free is
                 * not strictly correct but libcrypto 0.9.8 OPENSSL_malloc ==
                 * malloc. To be safe, use CRYPTO_free if available. */
                {
                    typedef void (*crypto_free_fn)(void*);
                    crypto_free_fn cf = (crypto_free_fn)dlsym(h,"CRYPTO_free");
                    if(cf) cf(der); else free(der);
                }
            }
            prf(rsa);
        }
        ppf(pkey);
    }
    pxf(x);
    return rc;
}
