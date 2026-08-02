#!/bin/bash
# patch-ssl-rsa-pubkey.sh
# ---------------------------------------------------------------------------
# Fix: on i386, CSSM_CL_CertGetKeyInfo fails to extract the RSA public key from
# modern certs (returns -9808), so ECDHE_RSA (apple/itunes) handshakes fail at
# ServerKeyExchange signature verification (peerPubKey is never set up).
#
# The project already rebuilds a usable PKCS1 peerPubKey from modulus+exponent
# bits via sslGetPubKeyFromBits (sslCert.c ~line 240), but ONLY when the CSSM
# extraction succeeded (keyErr==noErr). This fix: when keyErr != noErr, extract
# modulus+exponent from the cert DER via libcrypto (tls12ExtractRSAPubKey), and
# if successful, set keyErr=noErr so the existing rebuild path runs.
#
# Two edits:
#   1. Add tls12ExtractRSAPubKey() to tls12_chainverify.c (libcrypto RSA extract).
#   2. In sslCert.c, after the ECDHE_ECDSA workaround, add an ECDHE_RSA/RSA
#      libcrypto-recovery path that populates modulus/exponent for the existing
#      sslGetPubKeyFromBits rebuild.
#
# Run from the repository root with VM set (VM="$(pwd)"), or let it self-locate.
# ---------------------------------------------------------------------------
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
SSL="$VM/libsecurity_ssl-55002/lib"
CV="$SSL/tls12_chainverify.c"
CERT="$SSL/sslCert.c"

for f in "$CV" "$CERT"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
  [ -f "$f.rsaorig" ] || cp "$f" "$f.rsaorig"
done

# ---- EDIT 1: add tls12ExtractRSAPubKey to tls12_chainverify.c ----
if grep -q "tls12ExtractRSAPubKey" "$CV"; then
  echo "tls12_chainverify.c already has RSA extractor, skipping edit 1"
else
python - "$CV" << 'PYEOF'
# -*- coding: utf-8 -*-
import sys
p=sys.argv[1]; s=open(p).read()
# append the RSA extractor at end of file. Uses libcrypto dlsym like the rest.
addon = r'''

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
'''
s = s + addon
open(p,"w").write(s)
print("EDIT 1: tls12ExtractRSAPubKey appended to tls12_chainverify.c")
PYEOF
fi

# ---- EDIT 2: wire it into sslCert.c ----
if grep -q "tls12ExtractRSAPubKey" "$CERT"; then
  echo "sslCert.c already wired, skipping edit 2"
else
python - "$CERT" << 'PYEOF'
# -*- coding: utf-8 -*-
import sys, re
p=sys.argv[1]; s=open(p).read()
# Find the ECDHE_ECDSA workaround block by its distinctive content, tolerant of
# whitespace. Anchor: the line with 'keyExchangeMethod == SSL_ECDHE_ECDSA' and
# the following '} ' close. We insert our recovery block right after that close.
m = re.search(r'keyExchangeMethod == SSL_ECDHE_ECDSA\)\s*\{\s*\n[ \t]*keyErr = noErr;\s*\n[ \t]*\}', s)
if not m:
    print("FATAL: could not locate ECDHE_ECDSA workaround block (regex)"); sys.exit(2)
insert_at = m.end()
recovery = '''

	/* TLS12 i386 RSA fix: on i386, CSSM_CL_CertGetKeyInfo also fails to extract
	 * the RSA public key from modern certs (apple/itunes, ECDHE_RSA/RSA). When
	 * that happens, extract modulus+exponent from the leaf DER via libcrypto and
	 * build a usable PKCS1 peerPubKey via sslGetPubKeyFromBits, so the SKE
	 * signature verification works. Set keyErr=noErr on success. */
	if (keyErr != noErr && ctx->selectedCipherSpec != NULL &&
	    (ctx->selectedCipherSpec->keyExchangeMethod == SSL_ECDHE_RSA ||
	     ctx->selectedCipherSpec->keyExchangeMethod == SSL_RSA ||
	     ctx->selectedCipherSpec->keyExchangeMethod == SSL_RSA_EXPORT)) {
		extern int tls12ExtractRSAPubKey(const unsigned char *derCert, long derLen,
			unsigned char **modOut, unsigned int *modLen,
			unsigned char **expOut, unsigned int *expLen);
		unsigned char *mb = NULL, *eb = NULL; unsigned int ml = 0, el = 0;
		if (tls12ExtractRSAPubKey(a_cert->derCert.data, (long)a_cert->derCert.length,
		                          &mb, &ml, &eb, &el) == 0 && mb && eb) {
			SSLBuffer modBuf, expBuf;
			modBuf.data = mb; modBuf.length = ml;
			expBuf.data = eb; expBuf.length = el;
			CSSM_KEY_PTR rsaKey = NULL; CSSM_CSP_HANDLE rsaCsp = 0;
			if (sslGetPubKeyFromBits(ctx, &modBuf, &expBuf, &rsaKey, &rsaCsp) == noErr
			    && rsaKey != NULL) {
				rsaKey->KeyHeader.KeyUsage |= CSSM_KEYUSE_VERIFY | CSSM_KEYUSE_ENCRYPT;
				if (ctx->peerPubKey != NULL)
					sslFreeKey(ctx->peerPubKeyCsp, &ctx->peerPubKey, NULL);
				ctx->peerPubKey    = rsaKey;
				ctx->peerPubKeyCsp = rsaCsp;
				keyErr = noErr;
				sslErrorLog("TLS12: recovered RSA peerPubKey via libcrypto (i386 CSSM fail)\\n");
			}
			free(mb); free(eb);
		}
	}'''
s = s[:insert_at] + recovery + s[insert_at:]
open(p,"w").write(s)
print("EDIT 2: RSA recovery wired into sslCert.c (regex anchor)")
PYEOF
fi

echo ""
echo "=== verify ==="
echo "extractor in chainverify: $(grep -c 'int tls12ExtractRSAPubKey' "$CV")"
echo "recovery in sslCert:      $(grep -c 'recovered RSA peerPubKey via libcrypto' "$CERT")"
echo ""
echo "Next: rebuild ssl (appleCdsa.o + tls12_chainverify.o + sslCert.o), relink, test."
