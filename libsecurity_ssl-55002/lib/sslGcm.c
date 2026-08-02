/*
 * sslGcm.c — Self-contained AES-GCM (AEAD) for libsecurity_ssl TLS 1.2 backport.
 *
 * Snow Leopard (10.6) has neither CommonCrypto GCM (added 10.8) nor an
 * EVP_aes_*_gcm interface (OpenSSL 0.9.8). It DOES export the raw AES block
 * function AES_encrypt / AES_set_encrypt_key from libcrypto.0.9.8.dylib.
 *
 * This module implements GCM (GHASH + GCTR + seal/open) on top of a generic
 * 128-bit block-encrypt callback, so the exact same core can be:
 *   - unit-tested against NIST KAT vectors with a reference AES (test harness)
 *   - wired to libcrypto AES_encrypt via dlsym on the VM (production)
 *
 * Reference: NIST SP 800-38D. Validated against NIST/McGrew GCM test cases
 * (AES-128 & AES-256, with and without AAD) — see scripts/gcm-selftest.
 *
 * GCM only ever uses the FORWARD AES block cipher (encrypt) — both for the
 * counter-mode keystream and for the hash key H = E(0^128). So a single
 * encrypt-only primitive suffices for both sealing and opening.
 *
 * Uses explicit <stdint.h> types (via sslGcm.h) so it is independent of the
 * project's lowercase uint8/uint32/uint64 typedefs.
 */

#include "sslGcm.h"
#include <string.h>

/* ---- 128-bit block helpers (big-endian byte order per GCM spec) ---- */

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

/*
 * GHASH multiplication in GF(2^128):  Z = X * Y  (mod the GCM polynomial).
 * Bitwise "shift-and-add" reference algorithm (NIST SP 800-38D, Alg. 1).
 * R = 0xe1000000000000000000000000000000 (the reduction constant).
 * Not constant-time, but correct and dependency-free. Performance is fine
 * for TLS record sizes on this use case.
 */
static void gf_mult(const uint8_t *X, const uint8_t *Y, uint8_t *out) {
    uint8_t Z[16];
    uint8_t V[16];
    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        /* bit i of X, MSB-first */
        int byte = i >> 3;
        int bit  = 7 - (i & 7);
        if ((X[byte] >> bit) & 1) {
            xor_block(Z, Z, V);
        }
        /* V = V >> 1 (as a 128-bit big-endian number); if LSB was set, xor R */
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) {
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xe1;
        }
    }
    memcpy(out, Z, 16);
}

/* GHASH: process `len` bytes of data into the running hash Y (16 bytes).
 * Caller pads partial final blocks with zeros (handled here). H is the hash key. */
static void ghash_update(uint8_t *Y, const uint8_t *H, const uint8_t *data, size_t len) {
    uint8_t block[16];
    size_t i = 0;
    while (i + 16 <= len) {
        xor_block(Y, Y, data + i);
        gf_mult(Y, H, Y);
        i += 16;
    }
    if (i < len) {
        size_t rem = len - i;
        memset(block, 0, 16);
        memcpy(block, data + i, rem);
        xor_block(Y, Y, block);
        gf_mult(Y, H, Y);
    }
}

/* increment the rightmost 32 bits of a counter block (mod 2^32), big-endian */
static void inc32(uint8_t *ctr) {
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
                 ((uint32_t)ctr[14] << 8)  |  (uint32_t)ctr[15];
    c++;
    ctr[12] = (uint8_t)(c >> 24);
    ctr[13] = (uint8_t)(c >> 16);
    ctr[14] = (uint8_t)(c >> 8);
    ctr[15] = (uint8_t)c;
}

/*
 * GCTR: encrypt/decrypt `len` bytes of `in` to `out` using counter block `icb`.
 * The block cipher is the caller-supplied forward AES.
 */
static void gctr(SslGcmBlockFn block, const void *blockKey,
                 const uint8_t *icb, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ctr[16];
    uint8_t ks[16];
    size_t i = 0;
    memcpy(ctr, icb, 16);
    while (i + 16 <= len) {
        block(ctr, ks, blockKey);
        for (int j = 0; j < 16; j++) out[i+j] = in[i+j] ^ ks[j];
        inc32(ctr);
        i += 16;
    }
    if (i < len) {
        size_t rem = len - i;
        block(ctr, ks, blockKey);
        for (size_t j = 0; j < rem; j++) out[i+j] = in[i+j] ^ ks[j];
        /* no inc needed; last partial block */
    }
}

/* Compute J0 for the TLS-standard 96-bit (12-byte) IV case:
 * J0 = IV || 0x00000001  */
static void compute_j0_96(const uint8_t *iv12, uint8_t *J0) {
    memcpy(J0, iv12, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
}

/* Build the GHASH length block: [len(AAD) in bits : 64][len(C) in bits : 64] */
static void len_block(uint64_t aadLen, uint64_t cLen, uint8_t *out) {
    uint64_t aBits = aadLen * 8;
    uint64_t cBits = cLen * 8;
    for (int i = 0; i < 8; i++) out[7 - i]  = (uint8_t)(aBits >> (8*i));
    for (int i = 0; i < 8; i++) out[15 - i] = (uint8_t)(cBits >> (8*i));
}

/* Core GHASH over AAD || ciphertext || lenblock, producing S (16 bytes). */
static void ghash_full(const uint8_t *H,
                       const uint8_t *aad, size_t aadLen,
                       const uint8_t *ct,  size_t ctLen,
                       uint8_t *S) {
    uint8_t lb[16];
    memset(S, 0, 16);
    ghash_update(S, H, aad, aadLen);
    ghash_update(S, H, ct,  ctLen);
    len_block((uint64_t)aadLen, (uint64_t)ctLen, lb);
    xor_block(S, S, lb);
    gf_mult(S, H, S);
}

/*
 * AES-GCM seal (authenticated encrypt).
 *   block/blockKey : forward AES-128/256 block cipher + opaque key schedule
 *   iv12           : 12-byte nonce (4-byte fixed IV || 8-byte explicit nonce)
 *   aad/aadLen     : additional authenticated data
 *   pt/ptLen       : plaintext
 *   ct  (out)      : ciphertext, ptLen bytes (may alias pt)
 *   tag (out)      : 16-byte authentication tag
 */
void sslGcmSeal(SslGcmBlockFn block, const void *blockKey,
                const uint8_t *iv12,
                const uint8_t *aad, size_t aadLen,
                const uint8_t *pt,  size_t ptLen,
                uint8_t *ct, uint8_t *tag) {
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t zero[16];
    uint8_t S[16];
    uint8_t EkJ0[16];
    uint8_t ctr[16];

    /* H = E(0^128) */
    memset(zero, 0, 16);
    block(zero, H, blockKey);

    /* J0 for 96-bit IV */
    compute_j0_96(iv12, J0);

    /* Ciphertext = GCTR(K, inc32(J0), plaintext) */
    memcpy(ctr, J0, 16);
    inc32(ctr);
    gctr(block, blockKey, ctr, pt, ct, ptLen);

    /* S = GHASH(AAD || C || lens) */
    ghash_full(H, aad, aadLen, ct, ptLen, S);

    /* Tag = GCTR(K, J0, S) = E(K,J0) XOR S */
    block(J0, EkJ0, blockKey);
    xor_block(tag, S, EkJ0);
}

/*
 * AES-GCM open (verify + decrypt).
 * Returns 0 on success (tag valid), -1 on auth failure (caller must discard).
 */
int sslGcmOpen(SslGcmBlockFn block, const void *blockKey,
               const uint8_t *iv12,
               const uint8_t *aad, size_t aadLen,
               const uint8_t *ct,  size_t ctLen,
               const uint8_t *tag,
               uint8_t *pt) {
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t zero[16];
    uint8_t S[16];
    uint8_t EkJ0[16];
    uint8_t expectedTag[16];
    uint8_t ctr[16];

    memset(zero, 0, 16);
    block(zero, H, blockKey);
    compute_j0_96(iv12, J0);

    /* Verify tag FIRST (GCM authenticates the ciphertext): GHASH over ct */
    ghash_full(H, aad, aadLen, ct, ctLen, S);
    block(J0, EkJ0, blockKey);
    xor_block(expectedTag, S, EkJ0);

    /* constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(expectedTag[i] ^ tag[i]);
    if (diff != 0) {
        return -1;
    }

    /* Decrypt = GCTR(K, inc32(J0), ciphertext) */
    memcpy(ctr, J0, 16);
    inc32(ctr);
    gctr(block, blockKey, ctr, ct, pt, ctLen);
    return 0;
}
