/*
 * sslGcmCipher.h — TLS 1.2 AES-GCM cipher-spec callouts (Snow Leopard backport).
 *
 * Provides the SSLSymmetricCipher `initialize`/`finish` callouts and the
 * SSLCipherAES_128_GCM / _256_GCM spec objects used by the AEAD cipher suites.
 *
 * GCM does NOT use the symmetric encrypt/decrypt callout shape (those take a
 * single SSLBuffer and produce ciphertext of identical length with a separate
 * HMAC). Instead the AEAD record path in tls12Callouts.c detects the GCM
 * sentinel mode and calls sslGcmEncrypt/sslGcmDecrypt directly. The encrypt /
 * decrypt function pointers in the GCM specs are therefore set to AEAD stubs
 * that must never be reached on the normal path; they return errSSLInternal
 * if they ever are (defensive).
 *
 * NOTE on includes: this header intentionally does NOT include sslContext.h /
 * cryptType.h. Those two have a circular include relationship that only
 * resolves correctly when sslContext.h is the FIRST of the pair to be entered
 * (it defines struct CipherContext, then includes cryptType.h). Pulling
 * cryptType.h in first from here breaks that ordering. Any .c that uses this
 * header must include "sslContext.h" and "cryptType.h" themselves first (as
 * all the sibling cipher modules already do). We only forward-declare the one
 * struct tag needed for the extern declarations below.
 */
#ifndef _SSL_GCM_CIPHER_H_
#define _SSL_GCM_CIPHER_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sentinel value placed in SSLSymmetricCipher.encrMode to mark an AEAD/GCM
 * cipher. The record layer tests this to choose the AEAD path. Chosen to be
 * distinct from any real CSSM_ENCRYPT_MODE value used by the CBC/stream
 * ciphers in this build (CSSM_ALGMODE_CBC_IV8, CSSM_ALGMODE_NONE, etc.).
 * CSSM_ALGMODE_GCM is not defined in the 10.6 SDK, so we define our own.
 */
#define SSL_CSSM_ALGMODE_GCM   0xACED0001

/*
 * Returns true if a symmetric cipher spec is an AEAD/GCM cipher. Only expanded
 * in .c files that already have the full SSLSymmetricCipher definition.
 */
#define SSL_CIPHER_IS_GCM(symCipher)  \
    ((symCipher) != NULL && (symCipher)->encrMode == SSL_CSSM_ALGMODE_GCM)

/*
 * The two GCM cipher specs (AES-128-GCM, AES-256-GCM).
 * SSLSymmetricCipher is a typedef from cryptType.h, which the including .c
 * must have pulled in first (see the include note above).
 */
extern const SSLSymmetricCipher SSLCipherAES_128_GCM;
extern const SSLSymmetricCipher SSLCipherAES_256_GCM;

#ifdef __cplusplus
}
#endif

#endif /* _SSL_GCM_CIPHER_H_ */
