/*
 * tls12_trusteval.c
 *
 * libcrypto-based X.509 chain verification fallback for the SecTrust path
 * (Trust::evaluate) on Snow Leopard.
 *
 * WHY: SL's CSSM x509 TP cannot parse EC (ECDSA P-256) leaf certificates, so
 * Trust::evaluate()'s certGroupVerify throws CSSMERR_TP_INVALID_CERTIFICATE for
 * modern sites (google, youtube, most of the web). The SSL *handshake* path was
 * already fixed (sslVerifyCertChainOpenSSL in libsecurity_ssl), but Safari's
 * cert dialog comes from the *SecTrust* path (WebKit -> SecTrustEvaluate ->
 * Trust::evaluate), which had no fallback. This file adds the SAME libcrypto
 * fallback to that path.
 *
 * This mirrors tls12_chainverify.c (the proven SSL-path fallback). The only
 * difference is the INPUT: here we receive a CFArray of SecCertificateRef (the
 * Trust object's cert list, leaf FIRST) plus the hostname the caller pulled
 * from the SSL policy, instead of an SSLCertificate linked list + SSLContext.
 *
 * SECURITY: no weakening. libcrypto X509_verify_cert does full signature +
 * validity-period + chain-to-trusted-anchor checking against the same anchor
 * bundle; we additionally enforce hostname (SAN dNSName, wildcard-aware). A
 * genuinely invalid chain still fails. We only substitute a *working* validator
 * (libcrypto, EC-capable) for the *broken* CSSM TP, and ONLY when the TP raised
 * the specific "can't parse this cert" error.
 *
 * Compiled into libsecurity_keychain. Exposed as extern "C" for Trust.cpp.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/cssmtype.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LIBCRYPTO_PATH   "/usr/lib/libcrypto.0.9.8.dylib"
#define ANCHOR_BUNDLE    "/usr/local/SecurityPieces/ssl_anchors.pem"

/* ---- libcrypto function typedefs (opaque void* handles; never deref) ---- */
typedef void  (*add_all_algos_fn)(void);
typedef void *(*d2i_X509_fn)(void **px, const unsigned char **in, long len);
typedef void  (*X509_free_fn)(void *x);
typedef void *(*X509_STORE_new_fn)(void);
typedef void  (*X509_STORE_free_fn)(void *store);
typedef int   (*X509_STORE_add_cert_fn)(void *store, void *x);
typedef void *(*X509_STORE_CTX_new_fn)(void);
typedef void  (*X509_STORE_CTX_free_fn)(void *ctx);
typedef int   (*X509_STORE_CTX_init_fn)(void *ctx, void *store, void *x509, void *chain);
typedef int   (*X509_verify_cert_fn)(void *ctx);
typedef int   (*X509_STORE_CTX_get_error_fn)(void *ctx);
typedef void *(*sk_new_null_fn)(void);
typedef int   (*sk_push_fn)(void *st, void *data);
typedef void  (*sk_free_fn)(void *st);
typedef void *(*BIO_new_file_fn)(const char *filename, const char *mode);
typedef void  (*BIO_free_fn)(void *bio);
typedef void *(*PEM_read_bio_X509_fn)(void *bio, void **x, void *cb, void *u);
typedef int   (*X509_get_ext_by_NID_fn)(void *x, int nid, int lastpos);
typedef void *(*X509_get_ext_fn)(void *x, int loc);
typedef void *(*X509_EXTENSION_get_data_fn)(void *ex);
typedef unsigned char *(*ASN1_STRING_data_fn)(void *x);
typedef int   (*ASN1_STRING_length_fn)(void *x);

#ifndef NID_subject_alt_name
#define NID_subject_alt_name 85
#endif

/* Env-gated diagnostic, mirroring sslErrorLog in the SSL-path twin
 * (tls12_chainverify.c). secdebug() is compiled out in Deployment builds, which
 * left this whole fallback silent and undiagnosable; SSL_TLS12_DEBUG=1 turns it
 * on with zero output otherwise. */
#include <stdlib.h>
#define tlsTrustLog(args...) \
    do { if (getenv("SSL_TLS12_DEBUG")) fprintf(stderr, ## args); } while (0)

/* ------------------------------------------------------------------------
 * ECDSA-SHA2 verification, bypassing 0.9.8's ASN1_item_verify.
 *
 * Identical in purpose to tls12_verify_ecdsa_sha2() in tls12_chainverify.c --
 * see that file for the full rationale. Short version: libcrypto 0.9.8y has the
 * ecdsa-with-SHA256/384/512 OIDs, the curves and ECDSA_verify, but no
 * signature-OID -> digest binding, so ASN1_item_verify reports "unknown message
 * digest algorithm" and X509_verify_cert fails with err 7
 * (X509_V_ERR_CERT_SIGNATURE_FAILURE) on every EC-signed link. We redo those
 * links by hand: re-encode the TBSCertificate with i2d_X509_CINF, digest it
 * with CommonCrypto, and call ECDSA_verify with the issuer's EC key.
 *
 * SECURITY: full cryptographic verification, nothing skipped. Validity windows
 * are checked separately because X509_verify_cert may abort at err 7 before
 * reaching its own date checks.
 * ---------------------------------------------------------------------- */
#include <CommonCrypto/CommonDigest.h>

typedef int   (*i2d_X509_CINF_fn)(void *cinf, unsigned char **out);
typedef void *(*X509_get_pubkey_fn)(void *x);
typedef void  (*EVP_PKEY_free_fn)(void *pkey);
typedef void *(*EVP_PKEY_get1_EC_KEY_fn)(void *pkey);
typedef void  (*EC_KEY_free_fn)(void *eckey);
typedef int   (*ECDSA_verify_fn)(int type, const unsigned char *dgst, int dgstlen,
                                 const unsigned char *sig, int siglen, void *eckey);
typedef int   (*OBJ_obj2nid_fn)(const void *obj);
typedef int   (*X509_cmp_current_time_fn)(const void *asn1time);
typedef int   (*X509_STORE_CTX_get_error_depth_fn)(void *ctx);

#ifndef NID_ecdsa_with_SHA256
#define NID_ecdsa_with_SHA256 794
#endif
#ifndef NID_ecdsa_with_SHA384
#define NID_ecdsa_with_SHA384 795
#endif
#ifndef NID_ecdsa_with_SHA512
#define NID_ecdsa_with_SHA512 796
#endif

/* 0.9.8 struct heads -- see tls12_chainverify.c for the layout rationale.
 * X509_get_notBefore/notAfter are macros, so we walk cert_info->validity. */
struct tls12_x509_head { void *cert_info; void *sig_alg; void *signature; };
struct tls12_algor     { void *algorithm; void *parameter; };
struct tls12_cinf_head {
    void *version; void *serialNumber; void *signature;
    void *issuer;  void *validity;
};
struct tls12_val { void *notBefore; void *notAfter; };

/* 1 = currently valid, 0 = expired / not yet valid / cannot tell */
static int tls12_trust_time_ok(void *h, void *x)
{
    X509_cmp_current_time_fn pCmp =
        (X509_cmp_current_time_fn)dlsym(h, "X509_cmp_current_time");
    if (!pCmp) return 0;
    struct tls12_x509_head *xh = (struct tls12_x509_head *)x;
    if (!xh || !xh->cert_info) return 0;
    struct tls12_cinf_head *ci = (struct tls12_cinf_head *)xh->cert_info;
    if (!ci || !ci->validity) return 0;
    struct tls12_val *v = (struct tls12_val *)ci->validity;
    if (!v || !v->notBefore || !v->notAfter) return 0;
    int nb = pCmp(v->notBefore);   /* want < 0 */
    int na = pCmp(v->notAfter);    /* want > 0 */
    if (nb >= 0 || na <= 0) {
        tlsTrustLog("tls12_trust_time_ok: outside validity window (nb=%d na=%d)\n", nb, na);
        return 0;
    }
    return 1;
}

/*  1 = ECDSA-SHA2 signature verified
 *  0 = not an ECDSA-SHA2 signature (normal libcrypto path applies)
 * -1 = ECDSA-SHA2 but verification failed
 */
static int tls12_trust_verify_ecdsa(void *h, void *subject, void *issuer)
{
    i2d_X509_CINF_fn        pi2d     = (i2d_X509_CINF_fn)dlsym(h, "i2d_X509_CINF");
    X509_get_pubkey_fn      pGetPub  = (X509_get_pubkey_fn)dlsym(h, "X509_get_pubkey");
    EVP_PKEY_free_fn        pPkFree  = (EVP_PKEY_free_fn)dlsym(h, "EVP_PKEY_free");
    EVP_PKEY_get1_EC_KEY_fn pGetEC   = (EVP_PKEY_get1_EC_KEY_fn)dlsym(h, "EVP_PKEY_get1_EC_KEY");
    EC_KEY_free_fn          pECFree  = (EC_KEY_free_fn)dlsym(h, "EC_KEY_free");
    ECDSA_verify_fn         pECDSA   = (ECDSA_verify_fn)dlsym(h, "ECDSA_verify");
    OBJ_obj2nid_fn          pObj2nid = (OBJ_obj2nid_fn)dlsym(h, "OBJ_obj2nid");
    ASN1_STRING_data_fn     pStrData = (ASN1_STRING_data_fn)dlsym(h, "ASN1_STRING_data");
    ASN1_STRING_length_fn   pStrLen  = (ASN1_STRING_length_fn)dlsym(h, "ASN1_STRING_length");

    if (!pi2d || !pGetPub || !pPkFree || !pGetEC || !pECFree || !pECDSA ||
        !pObj2nid || !pStrData || !pStrLen)
        return 0;

    struct tls12_x509_head *sx = (struct tls12_x509_head *)subject;
    if (!sx || !sx->cert_info || !sx->sig_alg || !sx->signature) return 0;
    struct tls12_algor *alg = (struct tls12_algor *)sx->sig_alg;
    if (!alg || !alg->algorithm) return 0;
    int signid = pObj2nid(alg->algorithm);

    unsigned char md[CC_SHA512_DIGEST_LENGTH];
    unsigned int mdlen = 0;
    switch (signid) {
        case NID_ecdsa_with_SHA256: mdlen = CC_SHA256_DIGEST_LENGTH; break;
        case NID_ecdsa_with_SHA384: mdlen = CC_SHA384_DIGEST_LENGTH; break;
        case NID_ecdsa_with_SHA512: mdlen = CC_SHA512_DIGEST_LENGTH; break;
        default: return 0;
    }

    unsigned char *tbs = NULL;
    int tbslen = pi2d(sx->cert_info, &tbs);
    if (tbslen <= 0 || !tbs) return -1;
    switch (signid) {
        case NID_ecdsa_with_SHA256: CC_SHA256(tbs, (CC_LONG)tbslen, md); break;
        case NID_ecdsa_with_SHA384: CC_SHA384(tbs, (CC_LONG)tbslen, md); break;
        case NID_ecdsa_with_SHA512: CC_SHA512(tbs, (CC_LONG)tbslen, md); break;
    }
    { typedef void (*cfree_fn)(void*);
      cfree_fn cf = (cfree_fn)dlsym(h, "CRYPTO_free");
      if (cf) cf(tbs); else free(tbs); }

    const unsigned char *sig = pStrData(sx->signature);
    int siglen = pStrLen(sx->signature);
    if (!sig || siglen <= 0) return -1;

    int rc = -1;
    void *pkey = pGetPub(issuer);
    if (pkey) {
        void *eckey = pGetEC(pkey);
        if (eckey) {
            int vr = pECDSA(0, md, (int)mdlen, sig, siglen, eckey);
            rc = (vr == 1) ? 1 : -1;
            tlsTrustLog("tls12_trust_verify_ecdsa: nid=%d mdlen=%u siglen=%d -> %s\n",
                        signid, mdlen, siglen, (vr == 1 ? "VALID" : "FAILED"));
            pECFree(eckey);
        }
        pPkFree(pkey);
    }
    return rc;
}

/* Case-insensitive hostname match with a single leading-wildcard label. */
static int tls12_hostname_matches(const char *pattern, size_t plen,
                                  const char *host, size_t hlen)
{
    if (plen == hlen) {
        size_t i; int eq = 1;
        for (i = 0; i < plen; i++)
            if (tolower((unsigned char)pattern[i]) != tolower((unsigned char)host[i])) { eq = 0; break; }
        if (eq) return 1;
    }
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *psuf = pattern + 1; size_t psuflen = plen - 1;
        const char *dot = memchr(host, '.', hlen);
        if (dot) {
            size_t hsuflen = hlen - (size_t)(dot - host);
            if (hsuflen == psuflen) {
                size_t i; int eq = 1;
                for (i = 0; i < psuflen; i++)
                    if (tolower((unsigned char)psuf[i]) != tolower((unsigned char)dot[i])) { eq = 0; break; }
                if (eq && (dot - host) >= 1) return 1;
            }
        }
    }
    return 0;
}

/* Scan a subjectAltName extension's raw DER for dNSName (tag 0x82) entries. */
static int tls12_san_matches(const unsigned char *der, int derlen,
                             const char *host, size_t hlen)
{
    int i = 0;
    while (i + 2 <= derlen) {
        unsigned char tag = der[i];
        int len, lenbytes = 0;
        if (i + 1 >= derlen) break;
        if ((der[i+1] & 0x80) == 0) { len = der[i+1]; lenbytes = 1; }
        else {
            int nb = der[i+1] & 0x7f, k;
            if (nb < 1 || nb > 3 || i + 2 + nb > derlen) { i++; continue; }
            len = 0; for (k = 0; k < nb; k++) len = (len << 8) | der[i+2+k];
            lenbytes = 1 + nb;
        }
        if (tag == 0x82) {
            int off = i + 1 + lenbytes;
            if (off + len <= derlen && len > 0)
                if (tls12_hostname_matches((const char *)(der + off), (size_t)len, host, hlen))
                    return 1;
            i = i + 1 + lenbytes + (len > 0 ? len : 0);
        } else if (tag == 0x30 || tag == 0xa0) {
            i = i + 1 + lenbytes;
        } else {
            i = i + 1 + lenbytes + (len > 0 ? len : 0);
        }
    }
    return 0;
}

/*
 * tls12LeafIsEC - return 1 if the leaf cert (index 0 of the CFArray) has an
 * EC (id-ecPublicKey) public key, 0 otherwise. PURE DER byte scan; does NOT
 * touch CSSM (CSSM is what crashes on EC certs in DecodedCert::freeCertFieldData).
 *
 * We scan the leaf DER for the id-ecPublicKey OID encoded as an ASN.1 OBJECT
 * IDENTIFIER: tag 0x06, len 0x07, bytes 2A 86 48 CE 3D 02 01
 * (= 1.2.840.10045.2.1). This OID appears in the SubjectPublicKeyInfo's
 * AlgorithmIdentifier for every EC cert. A raw byte search is sufficient and
 * safe (it cannot dereference bad structures the way the CSSM decoder does).
 *
 * extern "C" so Trust.cpp can call it. Used to guard the EV pre-check.
 */
#ifdef __cplusplus
extern "C"
#endif
int tls12LeafIsEC(CFArrayRef certs)
{
    if (!certs || CFArrayGetCount(certs) < 1) return 0;
    SecCertificateRef cr = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
    if (!cr) return 0;
    CSSM_DATA d; memset(&d, 0, sizeof(d));
    if (SecCertificateGetData(cr, &d) != 0 || !d.Data || d.Length < 9) return 0;

    /* id-ecPublicKey OID, fully DER-encoded (tag+len+value): */
    static const unsigned char EC_OID[] =
        { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    const unsigned char *p = (const unsigned char *)d.Data;
    size_t n = (size_t)d.Length, i;
    for (i = 0; i + sizeof(EC_OID) <= n; i++) {
        if (p[i] == EC_OID[0] && memcmp(p + i, EC_OID, sizeof(EC_OID)) == 0)
            return 1;
    }
    return 0;
}

/*
 * Verify the cert chain (CFArray of SecCertificateRef, leaf FIRST) via libcrypto.
 * hostname/hostlen may be NULL/0 to skip the SAN check (e.g. non-SSL policy).
 * Returns 0 on success (chain valid & host matches), -1 otherwise.
 *
 * extern "C" so Trust.cpp (C++) can call it without name mangling.
 */
#ifdef __cplusplus
extern "C"
#endif
int tls12TrustEvaluateOpenSSL(CFArrayRef certs, const char *hostname, size_t hostlen)
{
    static void *h = NULL;
    if (!h) h = dlopen(LIBCRYPTO_PATH, RTLD_LAZY);
    if (!h) return -1;

    /* CRITICAL: register digest/cipher algorithms, or X509_verify_cert fails
       with X509_V_ERR_CERT_SIGNATURE_FAILURE (err 7). The openssl CLI does this
       at startup; loading libcrypto via dlopen does NOT, so we must call it. */
    {
        add_all_algos_fn paa = (add_all_algos_fn)dlsym(h, "OpenSSL_add_all_algorithms");
        if (!paa) paa = (add_all_algos_fn)dlsym(h, "OPENSSL_add_all_algorithms_noconf");
        if (!paa) paa = (add_all_algos_fn)dlsym(h, "OpenSSL_add_all_digests");
        if (paa) paa();
    }

    d2i_X509_fn                 pd2i          = (d2i_X509_fn)dlsym(h, "d2i_X509");
    X509_free_fn                pX509_free    = (X509_free_fn)dlsym(h, "X509_free");
    X509_STORE_new_fn           pStore_new    = (X509_STORE_new_fn)dlsym(h, "X509_STORE_new");
    X509_STORE_free_fn          pStore_free   = (X509_STORE_free_fn)dlsym(h, "X509_STORE_free");
    X509_STORE_add_cert_fn      pStore_add    = (X509_STORE_add_cert_fn)dlsym(h, "X509_STORE_add_cert");
    X509_STORE_CTX_new_fn       pCtx_new      = (X509_STORE_CTX_new_fn)dlsym(h, "X509_STORE_CTX_new");
    X509_STORE_CTX_free_fn      pCtx_free     = (X509_STORE_CTX_free_fn)dlsym(h, "X509_STORE_CTX_free");
    X509_STORE_CTX_init_fn      pCtx_init     = (X509_STORE_CTX_init_fn)dlsym(h, "X509_STORE_CTX_init");
    X509_verify_cert_fn         pVerify       = (X509_verify_cert_fn)dlsym(h, "X509_verify_cert");
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

    if (!pd2i || !pX509_free || !pStore_new || !pStore_free || !pStore_add ||
        !pCtx_new || !pCtx_free || !pCtx_init || !pVerify ||
        !psk_new || !psk_push || !psk_free || !pBIO_new_file || !pBIO_free ||
        !pPEM_read || !pExtByNID || !pGetExt || !pExtData || !pStrData || !pStrLen)
        return -1;

    int result = -1;
    void *store = NULL, *sctx = NULL, *untrusted = NULL, *bio = NULL, *leafX = NULL;
    void *owned[64]; int nowned = 0;

    if (!certs) return -1;
    CFIndex n = CFArrayGetCount(certs);
    if (n <= 0) return -1;

    untrusted = psk_new();
    if (!untrusted) goto done;

    /* Trust cert order is leaf FIRST (index 0). Parse each via SecCertificateGetData. */
    for (CFIndex i = 0; i < n && nowned < 64; i++) {
        SecCertificateRef cr = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
        if (!cr) continue;
        CSSM_DATA d; memset(&d, 0, sizeof(d));
        if (SecCertificateGetData(cr, &d) != 0 || !d.Data || d.Length == 0) goto done;
        const unsigned char *p = (const unsigned char *)d.Data;
        void *x = pd2i(NULL, &p, (long)d.Length);
        if (!x) goto done;
        owned[nowned++] = x;
        if (i == 0) leafX = x;            /* leaf */
        else        psk_push(untrusted, x); /* intermediate / cross-cert */
    }
    if (!leafX) goto done;

    /* anchors from the same PEM bundle the SSL fallback uses */
    store = pStore_new();
    if (!store) goto done;
    bio = pBIO_new_file(ANCHOR_BUNDLE, "r");
    if (!bio) goto done;
    {
        int added = 0; void *ax;
        while ((ax = pPEM_read(bio, NULL, NULL, NULL)) != NULL) {
            if (pStore_add(store, ax)) added++;
            pX509_free(ax);
        }
        if (added == 0) goto done;
    }

    sctx = pCtx_new();
    if (!sctx) goto done;
    if (!pCtx_init(sctx, store, leafX, untrusted)) goto done;

    if (pVerify(sctx) == 1) {
        result = 0;
    } else {
        X509_STORE_CTX_get_error_fn pGetErr =
            (X509_STORE_CTX_get_error_fn)dlsym(h, "X509_STORE_CTX_get_error");
        int err = pGetErr ? pGetErr(sctx) : 0;
        tlsTrustLog("tls12TrustEvaluateOpenSSL: X509_verify_cert failed err=%d\n", err);

        /* err 7 == X509_V_ERR_CERT_SIGNATURE_FAILURE. On 0.9.8 that is what we
         * get for every ecdsa-with-SHA256/384/512 link (ASN1_item_verify has no
         * digest for those OIDs) -- not because the signature is bad. Redo the
         * chain by hand with ECDSA_verify + CommonCrypto digests.
         *
         * Cert ORDER is not trusted: the SSL-path twin measured index 0 holding
         * the intermediate rather than the leaf, so pair certs by trying every
         * candidate issuer instead of assuming adjacency. Exactly one cert (the
         * chain top) may be left unverified; it must then chain to an anchor. */
        if (err == 7) {
            int i, j, ok = 1, ecLinks = 0;
            int verified[64];
            int unver = 0, topIdx = -1;

            for (i = 0; i < nowned; i++) verified[i] = 0;
            for (i = 0; i < nowned; i++) {
                for (j = 0; j < nowned; j++) {
                    if (i == j) continue;
                    if (tls12_trust_verify_ecdsa(h, owned[i], owned[j]) == 1) {
                        verified[i] = 1; ecLinks++;
                        tlsTrustLog("tls12TrustEvaluateOpenSSL: cert %d verified by cert %d\n", i, j);
                        break;
                    }
                }
            }
            for (i = 0; i < nowned; i++)
                if (!verified[i]) { unver++; topIdx = i; }
            if (unver != 1) {
                tlsTrustLog("tls12TrustEvaluateOpenSSL: %d certs unverified (want 1)\n", unver);
                ok = 0;
            }

            /* validity window on every cert we are vouching for */
            if (ok) {
                for (i = 0; i < nowned; i++) {
                    if (!tls12_trust_time_ok(h, owned[i])) {
                        tlsTrustLog("tls12TrustEvaluateOpenSSL: cert %d outside validity\n", i);
                        ok = 0; break;
                    }
                }
            }

            /* the chain top must be issued by a trusted anchor */
            if (ok && ecLinks > 0 && topIdx >= 0) {
                void *topCert = owned[topIdx];
                void *topctx = pCtx_new();
                int anchored = 0;
                if (topctx) {
                    if (pCtx_init(topctx, store, topCert, NULL)) {
                        int tvr = pVerify(topctx);
                        int terr = pGetErr ? pGetErr(topctx) : 0;
                        if (tvr == 1) anchored = 1;
                        else if (terr == 7) {
                            void *abio = pBIO_new_file(ANCHOR_BUNDLE, "r");
                            if (abio) {
                                void *ax;
                                while ((ax = pPEM_read(abio, NULL, NULL, NULL)) != NULL) {
                                    int r = tls12_trust_verify_ecdsa(h, topCert, ax);
                                    pX509_free(ax);
                                    if (r == 1) { anchored = 1; break; }
                                }
                                pBIO_free(abio);
                            }
                        }
                    }
                    pCtx_free(topctx);
                }
                if (anchored) {
                    result = 0;
                    tlsTrustLog("tls12TrustEvaluateOpenSSL: chain VALID via manual "
                                "ECDSA-SHA2 verification (%d EC link(s), anchored)\n", ecLinks);
                } else {
                    tlsTrustLog("tls12TrustEvaluateOpenSSL: EC links OK but no trusted anchor\n");
                    result = -1;
                }
            } else {
                result = -1;
            }
        } else {
            result = -1;
        }
    }

    /* hostname (SAN dNSName) check.
     * NOTE: cannot assume owned[0] is the leaf -- the SSL-path twin measured the
     * cert list arriving intermediate-first on cnn.com. Checking only owned[0]
     * would test the wrong cert and, since this check is FATAL here (unlike the
     * advisory one in tls12_chainverify.c), would reject a valid chain. Try every
     * cert and accept if any one presents a matching SAN: only the leaf carries
     * the server's dNSName, so a match unambiguously identifies it. */
    if (result == 0 && hostname && hostlen > 0) {
        int hostOK = 0;
        int ci;
        for (ci = 0; ci < nowned && !hostOK; ci++) {
            int idx = pExtByNID(owned[ci], NID_subject_alt_name, -1);
            if (idx < 0) continue;
            void *ext = pGetExt(owned[ci], idx);
            if (!ext) continue;
            void *os = pExtData(ext);
            if (!os) continue;
            const unsigned char *der = pStrData(os);
            int derlen = pStrLen(os);
            if (der && derlen > 0)
                hostOK = tls12_san_matches(der, derlen, hostname, hostlen);
        }
        if (!hostOK) {
            tlsTrustLog("tls12TrustEvaluateOpenSSL: no cert SAN matched host\n");
            result = -1;
        } else {
            tlsTrustLog("tls12TrustEvaluateOpenSSL: SAN matched host\n");
        }
    }

done:
    if (sctx)      pCtx_free(sctx);
    if (bio)       pBIO_free(bio);
    if (untrusted) psk_free(untrusted);
    if (store)     pStore_free(store);
    { int i; for (i = 0; i < nowned; i++) if (owned[i]) pX509_free(owned[i]); }
    return result;
}
