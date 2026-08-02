/*
 * sslGcmAes.h — libcrypto-0.9.8 AES backend for the GCM AEAD core.
 *
 * Bridges sslGcm.c's generic forward-AES callback to Snow Leopard's
 * /usr/lib/libcrypto.0.9.8.dylib (AES_set_encrypt_key + AES_encrypt),
 * resolved via dlsym — the same approach the ECDH/RSA fallbacks use.
 */
#ifndef _SSL_GCM_AES_H_
#define _SSL_GCM_AES_H_

#include "sslGcm.h"   /* pulls in <stdint.h>; defines SslGcmBlockFn */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque AES-GCM key context. Holds the libcrypto AES_KEY schedule plus the
 * 4-byte fixed (implicit) IV that prefixes every per-record nonce.
 *
 * AES_KEY in OpenSSL 0.9.8 is { unsigned int rd_key[4*(AES_MAXNR+1)]; int rounds; }
 * = 60 uint32 + 1 int = 244 bytes. We over-allocate to 256 for safety; the
 * exact internal layout is opaque to us (libcrypto fills and reads it).
 */
#define SSL_GCM_AESKEY_BYTES 256

typedef struct {
    unsigned char aesKey[SSL_GCM_AESKEY_BYTES]; /* opaque libcrypto AES_KEY */
    unsigned char fixedIV[4];                   /* implicit nonce prefix     */
    int           valid;                        /* 1 once initialized        */
} SslGcmCtx;

/*
 * Initialize a GCM context.
 *   key      : raw AES key (16 bytes for AES-128, 32 for AES-256)
 *   keyBits  : 128 or 256
 *   fixedIV  : 4-byte implicit IV from the TLS key block
 * Returns 0 on success, non-zero if libcrypto/symbols unavailable or key bad.
 */
int sslGcmInit(SslGcmCtx *ctx, const uint8_t *key, int keyBits, const uint8_t *fixedIV);

/*
 * Seal one record.
 *   explicitNonce : 8-byte per-record nonce (sent on the wire). The full
 *                   12-byte GCM IV is fixedIV(4) || explicitNonce(8).
 *   aad/aadLen    : additional authenticated data (seq||type||ver||len)
 *   pt/ptLen      : plaintext
 *   ct  (out)     : ciphertext (ptLen bytes; may alias pt)
 *   tag (out)     : 16-byte tag
 * Returns 0 on success.
 */
int sslGcmEncrypt(const SslGcmCtx *ctx,
                  const uint8_t *explicitNonce,
                  const uint8_t *aad, size_t aadLen,
                  const uint8_t *pt,  size_t ptLen,
                  uint8_t *ct, uint8_t *tag);

/*
 * Open one record. Returns 0 if tag valid (pt filled), non-zero otherwise.
 */
int sslGcmDecrypt(const SslGcmCtx *ctx,
                  const uint8_t *explicitNonce,
                  const uint8_t *aad, size_t aadLen,
                  const uint8_t *ct,  size_t ctLen,
                  const uint8_t *tag,
                  uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* _SSL_GCM_AES_H_ */
