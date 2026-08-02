/*
 * sslGcmAes.c — libcrypto-0.9.8 AES backend for the GCM AEAD core.
 *
 * Snow Leopard's /usr/lib/libcrypto.0.9.8.dylib exports the raw AES block
 * primitives AES_set_encrypt_key + AES_encrypt (confirmed via nm -gU). GCM
 * needs only the FORWARD cipher, so these two symbols are sufficient for both
 * sealing and opening. We resolve them once via dlsym (same pattern as the
 * ECDHE/RSA fallbacks in sslKeyExchange.c) and feed AES_encrypt to the
 * generic GCM core in sslGcm.c.
 */

#include "sslGcmAes.h"

#include <string.h>
#include <dlfcn.h>
#include <stdio.h>

#ifdef GCM_STANDALONE_TEST
  /* standalone self-test build: no project logging available */
  #define sslErrorLog(...) fprintf(stderr, __VA_ARGS__)
#else
  #include "sslDebug.h"
#endif

/* ---- libcrypto symbol resolution (lazy, one-time) ---- */

/* int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key); */
typedef int  (*AES_set_encrypt_key_fn)(const unsigned char *userKey, int bits, void *key);
/* void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key); */
typedef void (*AES_encrypt_fn)(const unsigned char *in, unsigned char *out, const void *key);

static AES_set_encrypt_key_fn p_AES_set_encrypt_key = NULL;
static AES_encrypt_fn         p_AES_encrypt         = NULL;
static int                    g_resolved            = 0;  /* 0=untried,1=ok,-1=failed */

static int resolveAesSyms(void) {
    if (g_resolved != 0) {
        return (g_resolved == 1) ? 0 : -1;
    }
    void *h = dlopen("/usr/lib/libcrypto.0.9.8.dylib", RTLD_LAZY);
    if (!h) {
        h = dlopen("libcrypto.dylib", RTLD_LAZY);
    }
    if (!h) {
        sslErrorLog("sslGcmAes: cannot dlopen libcrypto\n");
        g_resolved = -1;
        return -1;
    }
    p_AES_set_encrypt_key = (AES_set_encrypt_key_fn)dlsym(h, "AES_set_encrypt_key");
    p_AES_encrypt         = (AES_encrypt_fn)dlsym(h, "AES_encrypt");
    if (!p_AES_set_encrypt_key || !p_AES_encrypt) {
        sslErrorLog("sslGcmAes: missing AES symbols in libcrypto\n");
        g_resolved = -1;
        return -1;
    }
    g_resolved = 1;
    return 0;
}

/* Forward-AES adapter matching SslGcmBlockFn: key points at the AES_KEY blob. */
static void aesBlock(const uint8_t *in, uint8_t *out, const void *key) {
    p_AES_encrypt((const unsigned char *)in, (unsigned char *)out, key);
}

int sslGcmInit(SslGcmCtx *ctx, const uint8_t *key, int keyBits, const uint8_t *fixedIV) {
    if (ctx == NULL || key == NULL || fixedIV == NULL) {
        return -1;
    }
    if (keyBits != 128 && keyBits != 256) {
        sslErrorLog("sslGcmInit: unsupported keyBits %d\n", keyBits);
        return -1;
    }
    if (resolveAesSyms() != 0) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    /* Build the AES encryption key schedule in our opaque blob. Returns 0 on
     * success in OpenSSL (negative on bad bits/null). */
    if (p_AES_set_encrypt_key((const unsigned char *)key, keyBits, ctx->aesKey) != 0) {
        sslErrorLog("sslGcmInit: AES_set_encrypt_key failed\n");
        return -1;
    }
    memcpy(ctx->fixedIV, fixedIV, 4);
    ctx->valid = 1;
    return 0;
}

/* Build the 12-byte GCM nonce: fixedIV(4) || explicitNonce(8). */
static void buildNonce(const SslGcmCtx *ctx, const uint8_t *explicitNonce, uint8_t *iv12) {
    memcpy(iv12,     ctx->fixedIV,    4);
    memcpy(iv12 + 4, explicitNonce,   8);
}

int sslGcmEncrypt(const SslGcmCtx *ctx,
                  const uint8_t *explicitNonce,
                  const uint8_t *aad, size_t aadLen,
                  const uint8_t *pt,  size_t ptLen,
                  uint8_t *ct, uint8_t *tag) {
    uint8_t iv12[12];
    if (ctx == NULL || !ctx->valid) {
        return -1;
    }
    buildNonce(ctx, explicitNonce, iv12);
    sslGcmSeal(aesBlock, ctx->aesKey, iv12, aad, aadLen, pt, ptLen, ct, tag);
    return 0;
}

int sslGcmDecrypt(const SslGcmCtx *ctx,
                  const uint8_t *explicitNonce,
                  const uint8_t *aad, size_t aadLen,
                  const uint8_t *ct,  size_t ctLen,
                  const uint8_t *tag,
                  uint8_t *pt) {
    uint8_t iv12[12];
    if (ctx == NULL || !ctx->valid) {
        return -1;
    }
    buildNonce(ctx, explicitNonce, iv12);
    return sslGcmOpen(aesBlock, ctx->aesKey, iv12, aad, aadLen, ct, ctLen, tag, pt);
}
