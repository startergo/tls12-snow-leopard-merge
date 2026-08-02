/*
 * sslGcm.h — AES-GCM AEAD for TLS 1.2 backport (Snow Leopard).
 * See sslGcm.c for design notes. Implements NIST SP 800-38D on top of a
 * generic forward-AES block callback.
 *
 * Uses explicit <stdint.h> fixed-width types (uint8_t/uint32_t/uint64_t)
 * rather than the project's lowercase uint8/uint32/uint64 typedefs, so this
 * module compiles identically in the standalone unit-test harness and in the
 * in-tree dylib build without depending on the CDSA/CoreServices include
 * chain. These types are available on 10.6.
 */
#ifndef _SSL_GCM_H_
#define _SSL_GCM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward AES block-encrypt callback.
 *   in     : 16-byte input block
 *   out    : 16-byte output block (may NOT alias in)
 *   key    : opaque expanded-key pointer (e.g. libcrypto AES_KEY*)
 */
typedef void (*SslGcmBlockFn)(const uint8_t *in, uint8_t *out, const void *key);

/*
 * AES-GCM authenticated encryption.
 *   iv12 : 12-byte nonce. tag : 16-byte output. ct may alias pt.
 */
void sslGcmSeal(SslGcmBlockFn block, const void *blockKey,
                const uint8_t *iv12,
                const uint8_t *aad, size_t aadLen,
                const uint8_t *pt,  size_t ptLen,
                uint8_t *ct, uint8_t *tag);

/*
 * AES-GCM authenticated decryption. Returns 0 if tag valid, -1 otherwise.
 * On -1 the plaintext MUST be discarded. pt may alias ct.
 */
int sslGcmOpen(SslGcmBlockFn block, const void *blockKey,
               const uint8_t *iv12,
               const uint8_t *aad, size_t aadLen,
               const uint8_t *ct,  size_t ctLen,
               const uint8_t *tag,
               uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* _SSL_GCM_H_ */
