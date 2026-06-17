# TLS 1.2 Snow Leopard Merge — Project Status

**Last updated:** Phase 1 build clean  
**Dylib:** `build/libssl-patched/libsecurity_ssl.dylib` (x86_64, MH_DYLIB)

---

## Phase 1 — COMPLETE ✅

All source changes compiled and linked clean. 38 objects, 0 errors.

### Callout symbols confirmed present:
```
_Ssl3Callouts   (existing)
_Tls1Callouts   (existing)
_Tls12Callouts  (NEW — tls12Callouts.c)
```

### Changes applied (all groups):

| Group | File(s) | Change | Status |
|-------|---------|--------|--------|
| A1 | `sslPriv.h` | `TLS_Version_1_1 = 0x0302`, `TLS_Version_1_2 = 0x0303` added to enum | ✅ |
| A2 | `SecureTransportPriv.h` | `kTLSProtocol11 = (SSLProtocol)7`, `kTLSProtocol12 = (SSLProtocol)8` #defines; `SSLSetProtocolVersionMax/Min` declarations | ✅ |
| B1 | `sslContext.h` | `versionTls11Enable`, `versionTls12Enable`, `maxProtocolVersion`, `sha256State` appended to SSLContext struct | ✅ |
| B2 | `sslContext.c` | `DEFAULT_TLS11/12_ENABLE = true`; init in `SSLNewContext`; `CloseHash(SHA256)` in `SSLDisposeContext` | ✅ |
| C1 | `sslContext.c` | `convertProtToExtern()` extended with 1.1/1.2 | ✅ |
| C2 | `sslContext.c` | `SSLSetProtocolVersionEnabled()` extended | ✅ |
| C3 | `sslContext.c` | `SSLGetProtocolVersionEnabled()` extended | ✅ |
| C4 | `sslContext.c` | `SSLSetProtocolVersion()` / `SSLGetProtocolVersion()` extended; `SSLSetProtocolVersionMax/Min` / `SSLGetProtocolVersionMax/Min` bodies added | ✅ |
| D1 | `sslUtils.c` | `sslGetMaxProtVersion()` checks 1.2 then 1.1 first | ✅ |
| D2 | `sslUtils.c` | `sslVerifyProtVersion()` TLS 1.1/1.2 downgrade ladder | ✅ |
| D3 | `sslHandshakeHello.c` | Both `SSLProcessServerHello` and `SSLProcessClientHello` callout switches extended with 1.1→Tls1Callouts, 1.2→Tls12Callouts | ✅ |
| D-F4 | `sslHandshake.c` | `== TLS_Version_1_0` → `>= TLS_Version_1_0` in no-cert branch | ✅ |
| E5 | `sslHandshakeHello.c` | `SSLInitMessageHashes()` — `CloseHash` + `ReadyHash` for SHA-256 | ✅ |
| E5 | `sslHandshake.c` | 3 update sites (incoming, outgoing, SSL2 ClientHello) — SHA-256 added unconditionally | ✅ |
| F1 | `tls_hmac.h` | `HA_SHA256` added to `HMAC_Algs` enum | ✅ |
| F2 | `tls_hmac.h` | `TLS_HMAC_MAX_SIZE` bumped 20→32 | ✅ |
| F3 | `tls_hmac.c` | `HA_SHA256` case in `HMAC_Alloc` | ✅ |
| F4 | `tls_hmac.c` | `TlsHmacSHA256` const instance | ✅ |
| F5 | `tls_hmac.h` | `extern const HMACReference TlsHmacSHA256` | ✅ |
| F6 | `tls_hmac.c` | `HashHmacSHA256` pairing instance | ✅ |
| F6 | `cryptType.h` | `extern const HashHmacReference HashHmacSHA256` | ✅ |
| F-dep | `sslDigests.h` | `SSL_SHA256_DIGEST_LEN=32`, `SSL_MAX_DIGEST_LEN` 20→32, `extern SSLHashSHA256` | ✅ |
| F-dep | `sslDigests.c` | 5 SHA-256 statics + `SSLHashSHA256` table entry | ✅ |
| H1 | `sslHandshakeFinish.c` | `SSLEncodeFinishedMessage` switch: TLS 1.1/1.2 → finishedSize=12 | ✅ |
| H2 | `sslHandshakeFinish.c` | `SSLProcessFinished` switch: same | ✅ |
| H3 | `sslHandshakeFinish.c` | `SSLEncodeServerHelloDone` assert widened to `>= SSL_Version_3_0` | ✅ |
| tls_ssl.h | `tls_ssl.h` | `extern const SslTlsCallouts Tls12Callouts` | ✅ |
| E | `docs/tls12Callouts.c` | Full TLS 1.2 dispatch table: SHA-256 PRF, explicit-IV decrypt, version-correct MAC, SHA-256 Finished/CertVfy | ✅ |

---

## Phase 1 — Known limitations (Phase 2 work)

- **Explicit IV (write side)**: `ssl3WriteRecord` (shared) does NOT prepend the explicit IV for TLS 1.1/1.2 CBC records. The encrypt path needs a TLS 1.2 write record function that prepends `blockSize` bytes of random IV before the plaintext. This is required for interop with compliant servers.

- **CipherSpecs**: No TLS 1.2-specific cipher suites added to `cipherSpecs.c` yet (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA256`). The patched dylib negotiates TLS 1.2 using only the existing TLS 1.0 suites (SHA-1 HMAC), which many modern servers no longer accept.

- **CertificateVerify**: `tls12ComputeCertVfyMac` returns a raw SHA-256 transcript digest. The full TLS 1.2 `CertificateVerify` structure adds a `SignatureAndHashAlgorithm` prefix that `sslCert.c`'s callers don't yet construct. Client cert auth with TLS 1.2 is disabled until Phase 2.

- **AEAD (GCM)**: `TLS_RSA_WITH_AES_128_GCM_SHA256` and similar suites require a new encrypt/decrypt path; not attempted in Phase 1.

---

## Next step: VM smoke test

```bash
# Deploy and test:
bash scripts/deploy-to-vm.sh

# Or test only (if dylib already deployed):
bash scripts/deploy-to-vm.sh --test-only

# Restore original:
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    sl@slqemu.local \
    'sudo cp /tmp/libsecurity_ssl.dylib.orig \
     /System/Library/Frameworks/Security.framework/Versions/A/Libraries/libsecurity_ssl.dylib'
```

Expected results:
- `tls12.badssl.com` → HTTP 200 ✅ (TLS 1.2 negotiated)
- `tls10.badssl.com` → HTTP 200 ✅ (TLS 1.0 regression-free)
- `howsmyssl.com/a/check` → `"tls_version":"TLS 1.2"` ✅

---

## Phase 2 — TODO

1. **Explicit-IV write path** — `tls12WriteRecord()` prepends random IV for CBC suites
2. **SHA-256 cipher suites** — add `TLS_RSA_WITH_AES_128_CBC_SHA256` to `cipherSpecs.c`
3. **CertificateVerify rework** — version-aware `SignatureAndHashAlgorithm` prefix in `sslCert.c`
4. **Session cache** — ensure resumed sessions store/restore `negProtocolVersion` correctly for TLS 1.2
5. **AEAD groundwork** — evaluate feasibility of GCM on 10.6 CommonCrypto (CC_GCM available in 10.8+; may need software fallback)
