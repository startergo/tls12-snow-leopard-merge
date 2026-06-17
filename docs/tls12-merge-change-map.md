# TLS 1.2 Merge — Annotated Change-Map for `libsecurity_ssl-55002`
## Source-merging TLS 1.2 into Apple's open-source Snow Leopard Security framework

**Compiled:** June 2026
**Source base:** `libsecurity_ssl-55002` (standalone), read verbatim from a local copy of the Apple open-source tree.
**Self-contained:** this document stands alone. Everything needed to understand and execute the merge — the goal, the base versions, the architecture, the constraints, and every code change — is contained below. No other document is required.

---

## §0. BACKGROUND & CONTEXT (read first)

### 0.1 What this is and why it exists
The goal is **system-wide TLS 1.2 on Mac OS X 10.6 (Snow Leopard), x86_64 (Intel)** — for shipping in a custom Snow Leopard distribution, and to support a modern-ish WebKit/Safari and other networked apps on 10.6. (Snow Leopard is Intel-only; 10.5 Leopard was the last PowerPC-capable release. Everything here targets the 10.6 x86_64 framework — the base version below was binary-confirmed on a live 10.6.8 x86_64 system.) Apple's stock Snow Leopard `Secure Transport` (the system TLS implementation, inside the `Security` framework) tops out at **TLS 1.0** — its public API doesn't even have constants for later versions. This worksheet is the complete, line-level plan to add TLS 1.1 and TLS 1.2 to the **stock Apple open-source sources** for 10.6, by source-merge (re-implementing against the 10.6 layout), not binary patching.

### 0.2 Why a source merge (the precedent and the blocker)
A TLS-1.2-capable `Security.framework` was previously produced for **Mac OS X 10.5 (Leopard)** as part of the Leopard WebKit effort. That prebuilt Leopard framework is **NOT usable on Snow Leopard**: the TLS-1.2 changes have to be merged into the Snow Leopard version of the framework's sources, because the Leopard build is not binary-compatible with Snow Leopard. A built framework loading on a given CPU arch is not the same as OS compatibility — the Leopard build links against 10.5's `securityd`/CDSA/keychain ABI and internal structures, which differ on 10.6. So the only correct path is to take the *nature* of the Leopard TLS-1.2 changes and re-merge them into the **10.6** sources. That is what this worksheet specifies.

### 0.3 The exact base versions (pinned, binary-confirmed)
The Snow Leopard `Security` constellation was resolved to these Apple open-source tags. They are internally consistent (one release manifest) and the primary one is confirmed against the actual installed framework:

| Component | Tag | Role |
|---|---|---|
| **`Security`** (umbrella) | **`Security-55002`** | Contains `libsecurity_ssl` + all `libsecurity_*` sub-projects as subdirectories. **The merge base.** |
| **`CommonCrypto`** | **`CommonCrypto-36064`** | `CCDigest`/`CCHmac`/`CCCrypt` — supplies SHA-256 + AES primitives the TLS 1.2 PRF/MAC need. |
| **`CF`** (CoreFoundation) | **`CF-550.43`** | The CoreFoundation `Security-55002` links against. |

**Binary confirmation of the base:** on a live 10.6.8 x86_64 system, `otool -L /System/Library/Frameworks/Security.framework/Security` reports umbrella `current version 55002.0.0` — matching the source tag `Security-55002` exactly. So the source tag and the shipped binary version are the same number; there is no version-reconciliation gap. `sw_vers` on that system = 10.6.8.

**Guardrails — versions NOT to use (each would silently mislead a diff):**
- **`Security-55179.13` = OS X 10.8.5** (the "goto fail" train). A Mountain Lion tag — never use for a 10.6 merge.
- **`aosm/Security` `master` = 2014-era Lion+ refactor** (copyright 2014, `#include <tls_handshake.h>`, *external* coreTLS engine). Wrong architecture entirely — never diff against it.
- **`libsecurity_ssl-40581` = 10.6.0 GM**, superseded by `55002` on 10.6.8.
- **`corecrypto` does not exist before 10.8.** On Snow Leopard, crypto = `CommonCrypto-36064` + `libsecurity_apple_csp`. The SL merge therefore has *fewer* dependencies than a modern Security build (no corecrypto to satisfy) — favorable.

> The standalone `libsecurity_ssl` project (`libsecurity_ssl-55002`) is also published on its own, so the TLS sub-project can be analyzed/cloned in isolation without the whole umbrella. All "Stock (confirmed)" code blocks in this worksheet were read verbatim from that standalone `libsecurity_ssl-55002/lib/` tree.

### 0.4 The architecture, in one sentence
Snow Leopard's `Secure Transport` uses the **inline / monolithic coreTLS layout**: all protocol logic lives inside `libsecurity_ssl` (no external `tls_handshake.h` engine — that is the later Lion+ design). It dispatches all protocol-version-specific crypto through a **10-function callout table**, the C struct `SslTlsCallouts` (declared in `tls_ssl.h`), of which there are currently exactly two instances: `Ssl3Callouts` (SSL 3.0) and `Tls1Callouts` (TLS 1.0). **TLS 1.2 is added as a third instance, `Tls12Callouts`, plus a widening of the protocol-version enums and the negotiation logic.** This is confirmed by the symbols present in the Leopard framework binary — `_Tls12Callouts`, `_tls12ComputeFinishedMac`, `_tls12ComputeCertVfyMac`, `_SSLSetProtocolVersionMax/Min`, `_SSLCipherAES_*_GCM` — which are exactly the members/entry points this design produces. The architecture *anticipates* adding a protocol version cleanly; the merge follows the grain of the existing code.

### 0.5 The "10 callouts" contract (`SslTlsCallouts`, from `tls_ssl.h`)
Each protocol version provides one instance of this table. The 10 function-pointer members, in order, are: `decryptRecord`, `writeRecord`, `initMac`, `freeMac`, `computeMac`, `generateKeyMaterial`, `generateExportKeyAndIv`, `generateMasterSecret`, `computeFinishedMac`, `computeCertVfyMac`. The negotiated table is selected into `ctx->sslTslCalls` once the version is known, and the rest of the handshake calls through it. TLS 1.2's table reuses several TLS 1.0 members (the record layer is unchanged) and replaces the PRF/MAC/digest members — see Change Group E.

### 0.6 The central risk: don't break the system keychain
The Leopard effort reportedly had to be "sneaked in only where needed" because a full-umbrella rebuild broke the system keychain — the rebuilt `libsecurity_keychain`/CDSA no longer matched the running `securityd` ABI. **This decides the distribution model:**
- If the patch is **confined to `libsecurity_ssl`** (and draws crypto only from stock `CommonCrypto`), the keychain/CDSA/`securityd` ABI is untouched → a **system-default** install (replace the system `Security` framework) is plausible.
- If the patch perturbs shared CDSA/keychain structs → **sneak/relink-only** (patch just the apps that need it: Safari/Mail/WebKit), as the Leopard effort had to.

**A core finding of this worksheet is that the entire TLS 1.2 merge stays inside `libsecurity_ssl` + stock `CommonCrypto-36064` calls.** Every struct change is an append to an *internal* (opaque to clients) context struct; no `libsecurity_keychain`, CDSA, or `securityd` source is touched, and no new crypto primitive is needed beyond what stock CommonCrypto already exports. This is the concrete evidence that the **system-default model is viable** for the distribution — the favorable outcome. (Post-build verification step is in Critical Engineering Note 1.)

### 0.7 Sub-project merge stances (what to touch, what to leave stock)
All `libsecurity_*` are subdirectories inside `Security-55002` (versioned together by that one tag). Stances:
- **`libsecurity_ssl` — PRIMARY TARGET.** ~95%+ of the merge. Every change in this worksheet except the optional cipher-table work lives here.
- **`libsecurity_keychain`, `libsecurity_cdsa_*`, `libsecurity_asn1`, `libsecurity_apple_x509_tp` — keep stock.** The keychain-break risk lives in the keychain/CDSA ABI; do not rebuild-with-changes.
- **`libsecurity_apple_csp` — keep stock.** Secondary target *only if* the SL CSP lacked a needed primitive — but it does not: SHA-256 HMAC and SHA-256 digest both come from stock CommonCrypto at the `libsecurity_ssl` layer (the Leopard binary's self-contained `_SSLCipherAES_*_GCM` symbols indicate GCM too was carried at the ssl layer, keeping the CSP stock). Favorable.
- **`securityd` / `libsecurityd` / `libsecurity_codesigning` — DO NOT TOUCH.** ABI mismatch here is the keychain-break mechanism; modifying code-signing risks the system rejecting its own components.

### 0.8 Reference: Leopard patches located
The Leopard *patched* `libsecurity_ssl` sources are available at:
`~/tls12-snow-leopard-merge/patches/Patches_Security-55002_4/libsecurity_ssl.diff` (603 KB).

Comparison with this worksheet reveals:
- ✅ Architecture match: callout-table approach confirmed, version enums confirmed, Finished message sizes confirmed.
- ⚠️ **One design divergence (intentional):** Leopard reuses `Tls1Callouts` for TLS 1.2 (with runtime `sslVersionIsLikeTls12()` introspection), rather than creating a new `Tls12Callouts` table. **This Snow Leopard merge uses a new table (§0.4) — cleaner, explicit dispatch, chosen intentionally.**
- ✅ All logic blocks (PRF, MAC, digest, signature algorithms) match this worksheet's predictions.

### 0.9 Phasing (set by what each goal actually exercises)
- **Phase 1 — working TLS 1.2 for SERVER authentication** (a client verifying a website: the browser / Snow Leopard x86_64 distribution goal). Change Groups **A–F + H**, plus the explicit-IV record change. Does **not** require client-certificate auth. This delivers a working TLS 1.2 client handshake against real-world servers.
- **Phase 2 — client-certificate auth under 1.2** (Group **I**) **+ SHA-256/GCM cipher suites** (Group **G**). Separable; the dominant server-auth handshake never invokes Group I, and existing AES-CBC-SHA suites are enough to negotiate 1.2 without Group G.

### 0.10 Division of labor (desk work vs. build/test)
The source analysis, version-pinning, change-mapping, and draft-porting (this document and the drafted new file) are complete as desk work. What remains requires the Snow Leopard x86_64 build toolchain and the 10.6 test VM, which only the human operator has: (1) compile stock first to surface any "unreleased code" gaps, (2) compile the patched `libsecurity_ssl`, (3) test keychain + TLS 1.2 together → decide system-default vs. sneak. A draft of the one wholly-new file (`tls12Callouts.c`) is in `docs/tls12Callouts.c` in this project (uncompiled — first compile against the 10.6 toolchain will iterate symbol/field details).

### 0.11 How to read the change groups
Each group names the **file**, shows the **Stock (confirmed)** code verbatim, then the **Change**. "✅ FULLY MAPPED" = every site read verbatim from stock source. "🟡" = fully analyzed but deliberately deferred to Phase 2. A per-group **Mapping status** table and a **File-by-file summary** appear after the groups. Line numbers, where given, are approximate (offsets shift as edits land). Internal cross-references use the group/finding IDs (e.g. "D-FINDING-4", "E5") defined herein.

---

## CHANGE GROUP A — Protocol version enums (the "API doesn't know later versions" core)

### A1. Internal wire-value enum — `sslPriv.h`
**Stock (confirmed):**
```c
typedef enum {
    SSL_Version_Undetermined = 0,
    SSL_Version_2_0 = 0x0002,
    SSL_Version_3_0 = 0x0300,
    TLS_Version_1_0 = 0x0301        /* TLS 1.0 == SSL 3.1 */
} SSLProtocolVersion;
```
**Change:** add two members with the real over-the-wire values.
```c
    TLS_Version_1_0 = 0x0301,
    TLS_Version_1_1 = 0x0302,       /* ADD */
    TLS_Version_1_2 = 0x0303        /* ADD */
```
*This is the single most foundational change — every version comparison downstream keys off these.*

### A2. Public API enum — `SecureTransport.h`
**Stock (confirmed):** `SSLProtocol` enum ends at `kTLSProtocol1`, `kTLSProtocol1Only`, `kSSLProtocolAll`.
**Change:** add public constants so apps can request the new versions.
```c
    kTLSProtocol1,
    kTLSProtocol1Only,
    kTLSProtocol11,      /* ADD — TLS 1.1 */
    kTLSProtocol12,      /* ADD — TLS 1.2 */
    kSSLProtocolAll
```
**Plus** declare the modern setter/getter pair the Leopard binary exports:
```c
OSStatus SSLSetProtocolVersionMax(SSLContextRef ctx, SSLProtocol maxVersion);   /* ADD */
OSStatus SSLSetProtocolVersionMin(SSLContextRef ctx, SSLProtocol minVersion);   /* ADD */
OSStatus SSLGetProtocolVersionMax(SSLContextRef ctx, SSLProtocol *maxVersion);  /* ADD */
OSStatus SSLGetProtocolVersionMin(SSLContextRef ctx, SSLProtocol *minVersion);  /* ADD */
```
*Caveat: keep `kSSLProtocolAll` last (its "highest" sentinel role).*

---

## CHANGE GROUP B — SSLContext struct + version-enable plumbing

### B1. Context struct — `sslContext.h`
**Stock (confirmed):**
```c
Boolean             versionTls1Enable;
```
**Change:** append new fields at END of struct.
```c
Boolean             versionTls1Enable;
Boolean             versionTls11Enable;   /* ADD */
Boolean             versionTls12Enable;   /* ADD */
SSLProtocolVersion  maxProtocolVersion;   /* ADD — for SSLSetProtocolVersionMax */
SSLBuffer           sha256State;          /* ADD — running SHA-256 of handshake msgs (E5) */
```
> **ABI WARNING:** `SSLContext` is internal (clients hold opaque `SSLContextRef`). Adding fields at the END keeps existing offsets stable — this is the mechanism that keeps the keychain ABI untouched. Do not reorder existing fields.

### B2. Defaults — `sslContext.c`, `SSLNewContext()` + dispose cleanup
**Stock (confirmed):**
```c
ctx->versionTls1Enable = DEFAULT_TLS1_ENABLE;
```
**Change:**
```c
#define DEFAULT_TLS11_ENABLE  true   /* ADD */
#define DEFAULT_TLS12_ENABLE  true   /* ADD */
...
ctx->versionTls11Enable = DEFAULT_TLS11_ENABLE;   /* ADD */
ctx->versionTls12Enable = DEFAULT_TLS12_ENABLE;   /* ADD */
ctx->maxProtocolVersion = TLS_Version_1_2;        /* ADD */
```
`SSLDisposeContext` must also `SSLFreeBuffer(&ctx->sha256State, ctx)` — mirror the existing `shaState`/`md5State` cleanup.

---

## CHANGE GROUP C — Version conversion + enable/disable switches (`sslContext.c`)

### C1. `convertProtToExtern()` (~line 820)
**Stock (confirmed):**
```c
case TLS_Version_1_0:  return kTLSProtocol1;
default:               return kSSLProtocolUnknown;
```
**Change:**
```c
case TLS_Version_1_0:  return kTLSProtocol1;
case TLS_Version_1_1:  return kTLSProtocol11;   /* ADD */
case TLS_Version_1_2:  return kTLSProtocol12;   /* ADD */
```

### C2. `SSLSetProtocolVersionEnabled()` switch
Add `kTLSProtocol11 → versionTls11Enable`, `kTLSProtocol12 → versionTls12Enable`; extend `kSSLProtocolAll` to set all five flags.

### C3. `SSLGetProtocolVersionEnabled()` switch
Mirror C2 — add getters for the two new flags.

### C4. `SSLSetProtocolVersion()` (deprecated mapper) + `SSLGetProtocolVersion()`
Add `kTLSProtocol11/kTLSProtocol12` cases. `kTLSProtocol12` enables ssl3+tls1+tls11+tls12. New setter/getter bodies for `SSLSetProtocolVersionMax/Min` / `SSLGetProtocolVersionMax/Min` (straightforward enum-to-field mapping).

---

## CHANGE GROUP D — Version negotiation logic — ✅ FULLY MAPPED

`sslHandshakeHello.c`, `sslUtils.c`, `sslHandshake.c` all read verbatim.

### D1. `sslGetMaxProtVersion()` — max-version selection (`sslUtils.c`)
**Stock (confirmed):**
```c
if(ctx->versionTls1Enable)      *version = TLS_Version_1_0;
else if(ctx->versionSsl3Enable) *version = SSL_Version_3_0;
```
**Change — prepend higher versions:**
```c
if(ctx->versionTls12Enable)      *version = TLS_Version_1_2;   /* ADD */
else if(ctx->versionTls11Enable) *version = TLS_Version_1_1;   /* ADD */
else if(ctx->versionTls1Enable)  *version = TLS_Version_1_0;
else if(ctx->versionSsl3Enable)  *version = SSL_Version_3_0;
else if(ctx->versionSsl2Enable)  *version = SSL_Version_2_0;
else                             ortn = paramErr;
```

### D2-accept. `sslVerifyProtVersion()` — peer-version acceptance (`sslUtils.c`)
**Stock pattern (confirmed — the TLS 1.0 case):**
```c
case TLS_Version_1_0:
    if(ctx->versionTls1Enable)                    *negVersion = TLS_Version_1_0;
    else if(ctx->protocolSide == SSL_ClientSide)  ortn = errSSLNegotiation;
    else if(ctx->versionSsl3Enable)               *negVersion = SSL_Version_3_0;
    ...
```
**Change — add two new cases following the identical downgrade-ladder pattern:**
```c
case TLS_Version_1_1:
    if(ctx->versionTls11Enable)                   *negVersion = TLS_Version_1_1;
    else if(ctx->protocolSide == SSL_ClientSide)  ortn = errSSLNegotiation;
    else if(ctx->versionTls1Enable)               *negVersion = TLS_Version_1_0;
    else if(ctx->versionSsl3Enable)               *negVersion = SSL_Version_3_0;
    else if(ctx->versionSsl2Enable)               *negVersion = SSL_Version_2_0;
    else                                          ortn = errSSLNegotiation;
    break;
case TLS_Version_1_2:
    if(ctx->versionTls12Enable)                   *negVersion = TLS_Version_1_2;
    else if(ctx->protocolSide == SSL_ClientSide)  ortn = errSSLNegotiation;
    else if(ctx->versionTls11Enable)              *negVersion = TLS_Version_1_1;
    else if(ctx->versionTls1Enable)               *negVersion = TLS_Version_1_0;
    else if(ctx->versionSsl3Enable)               *negVersion = SSL_Version_3_0;
    else if(ctx->versionSsl2Enable)               *negVersion = SSL_Version_2_0;
    else                                          ortn = errSSLNegotiation;
    break;
```

### D3. Callout-table selection — `SSLProcessServerHello` + `SSLProcessClientHello` (`sslHandshakeHello.c`)
**Stock (confirmed, identical switch in BOTH functions):**
```c
switch(negVersion) {
    case SSL_Version_3_0:  ctx->sslTslCalls = &Ssl3Callouts; break;
    case TLS_Version_1_0:  ctx->sslTslCalls = &Tls1Callouts; break;
    default:               return errSSLNegotiation;
}
```
**Change (apply to BOTH):**
```c
    case TLS_Version_1_1:  ctx->sslTslCalls = &Tls1Callouts;  break;  /* ADD — 1.1 reuses 1.0 callouts */
    case TLS_Version_1_2:  ctx->sslTslCalls = &Tls12Callouts; break;  /* ADD — the new table */
```

### D-FINDING-1. Extension gate already forward-compatible
`if((clientHello->protocolVersion >= TLS_Version_1_0) && ...)` — SNI/elliptic-curve extensions auto-activate for 1.1/1.2 with NO change.

### D-FINDING-2. `SSLInitMessageHashes` — E5 init site (`sslHandshakeHello.c`, VERBATIM)
**Stock (confirmed):**
```c
CloseHash(&SSLHashSHA1, &ctx->shaState, ctx);
CloseHash(&SSLHashMD5,  &ctx->md5State, ctx);
ReadyHash(&SSLHashSHA1, &ctx->shaState, ctx);
ReadyHash(&SSLHashMD5,  &ctx->md5State, ctx);
```
**Change — add 2 lines:**
```c
CloseHash(&SSLHashSHA256, &ctx->sha256State, ctx);   /* ADD */
ReadyHash(&SSLHashSHA256, &ctx->sha256State, ctx);   /* ADD */
```

### D-FINDING-4. ⚠️ Exact-equality version test — REAL BUG (`sslHandshake.c`, VERBATIM)
**Stock (confirmed, `SSLAdvanceHandshake` no-cert path):**
```c
if(ctx->negProtocolVersion == TLS_Version_1_0) {
    /* TLS: send empty cert msg */
```
**Problem:** exact `==` test — fails for 1.1/1.2; code falls into SSL3 "no cert" alert branch.
**Change:**
```c
if(ctx->negProtocolVersion >= TLS_Version_1_0) {   /* >= so 1.1/1.2 also send empty cert msg */
```

### D-FINDING-5. Sweep: grep for `== TLS_Version_1_0`
Before building, audit every exact-equality hit. Known bugs: D-FINDING-4, Group H switches, Group I-FINDING asserts.

### E5-confirmed. Handshake digest UPDATE sites — `sslHandshake.c` (VERBATIM) — 3 sites, 1 line each
**Stock pattern at each site (2 lines):**
```c
if ((err = SSLHashSHA1.update(&ctx->shaState, &<buf>)) != 0 ||
    (err = SSLHashMD5.update(&ctx->md5State, &<buf>)) != 0)
```
**Change — add one line at each of the 3 sites:**
```c
    (err = SSLHashSHA256.update(&ctx->sha256State, &<buf>)) != 0 ||   /* ADD */
```
> **Run unconditionally** — SHA-256 must accumulate from the first handshake message (including ClientHello sent before version negotiation completes).

---

## CHANGE GROUP E — The TLS 1.2 crypto callouts (NEW FILE: `tls12Callouts.c`)

**A draft is in `docs/tls12Callouts.c` (uncompiled).** The third `SslTlsCallouts` instance.

### E1. New PRF — `tls12_PRF()`
TLS 1.2 PRF = single `P_SHA256(secret, label + seed)`. Simpler than TLS 1.0 (no secret split, no MD5⊕SHA1 XOR). The new file carries its own `tls12PHash` (self-contained; `tlsPHash` in `tls1Callouts.c` is `static`).

> **Dependency:** needs `TlsHmacSHA256` (Group F) and `TLS_HMAC_MAX_SIZE ≥ 32` (F2).

### E2. `tls12ComputeFinishedMac`
`verify_data = PRF(master_secret, finished_label, SHA256(handshake_messages))`. Clones `ctx->sha256State`; ignores the legacy `shaMsgState`/`md5MsgState` params (keeps the fixed 10-member callout signature). Declare digest buffer as `digest[CC_SHA256_DIGEST_LENGTH]` (32).

### E3. `tls12ComputeCertVfyMac`
Returns 32-byte SHA-256 handshake-hash (clones `ctx->sha256State`). Correct primitive; Group I wires it for client-cert CertificateVerify in Phase 2.

### E4. `tls12ComputeMac`
Record MAC — same HMAC construction as TLS 1.0 but uses `ctx->negProtocolVersion` for the MAC header version bytes (instead of TLS 1.0's hardcoded `0x0301`).

### E5. Running SHA-256 — ✅ FULLY MAPPED
Declare (B1) → free in dispose (B2) → init 2 lines (D-FINDING-2) → feed 3 sites/1 line each (E5-confirmed, unconditional) → consume in E2/E3.

### E6. The dispatch table
```c
const SslTlsCallouts Tls12Callouts = {
    tls1DecryptRecord,         /* reuse — record decrypt identical (but see Note 3: explicit IV) */
    ssl3WriteRecord,           /* reuse */
    tls1InitMac,               /* reuse */
    tls1FreeMac,               /* reuse */
    tls12ComputeMac,           /* NEW — version-parameterized MAC header (E4) */
    tls12GenerateKeyMaterial,  /* NEW — uses tls12_PRF */
    tls12GenerateExportKeyAndIv, /* NEW — uses tls12_PRF (near-dead: 1.2 forbids export) */
    tls12GenerateMasterSecret, /* NEW — uses tls12_PRF */
    tls12ComputeFinishedMac,   /* NEW */
    tls12ComputeCertVfyMac     /* NEW — primitive only (Group I for full client-cert) */
};
```

---

## CHANGE GROUP F — HMAC-SHA256 (`tls_hmac.c/.h`) — ✅ FULLY MAPPED

Both files read verbatim. ~6 mechanical edits, zero new crypto. CommonCrypto is already the backend.

### F1. Algorithm enum — `tls_hmac.h`
```c
HA_MD5,
HA_SHA256,   /* ADD */
```

### F2. ⚠️ `TLS_HMAC_MAX_SIZE` bump — MOST DANGEROUS SINGLE EDIT
**Stock:** `#define TLS_HMAC_MAX_SIZE 20` (SHA-1 size)
**Change:** `#define TLS_HMAC_MAX_SIZE 32` (SHA-256 size)
> **Silent stack overflow if missed.** `tlsPHash` / `tls12PHash` declare `aSubI[TLS_HMAC_MAX_SIZE]` on the stack. SHA-256 writes 32 bytes; leaving the guard at 20 corrupts memory on every TLS 1.2 PRF call.

### F3. `HMAC_Alloc` switch — `tls_hmac.c`
```c
case HA_SHA256:
    ccAlg = kCCHmacAlgSHA256;
    hmacCtx->macSize = CC_SHA256_DIGEST_LENGTH;   /* 32 */
    break;
```

### F4. `TlsHmacSHA256` instance
```c
const HMACReference TlsHmacSHA256 = {
    32, HA_SHA256,
    HMAC_Alloc, HMAC_Free, HMAC_Init, HMAC_Update, HMAC_Final, HMAC_Hmac
};
```

### F5. Extern declaration — `tls_hmac.h`
```c
extern const HMACReference TlsHmacSHA256;
```

### F6. `HashHmacSHA256` pairing — `tls_hmac.c` + `cryptType.h`
```c
/* tls_hmac.c: */
const HashHmacReference HashHmacSHA256 = { &SSLHashSHA256, &TlsHmacSHA256 };
/* cryptType.h: */
extern const HashHmacReference HashHmacSHA256;
```

---

### F-DEPENDENCY — SHA-256 digest (`sslDigests.c/.h`) — FULLY MAPPED

Clone the SHA-1 block (`SHA1`→`SHA256`). 5 new statics using `CC_SHA256_Init/Update/Final` / `CC_SHA256_CTX` / `CC_SHA256_DIGEST_LENGTH`. One table entry:
```c
const HashReference SSLHashSHA256 = {
    sizeof(CC_SHA256_CTX),
    CC_SHA256_DIGEST_LENGTH,   /* 32 */
    0,                         /* macPadSize — set 0 for HMAC-only SHA256 */
    HashSHA256Init, HashSHA256Update, HashSHA256Final, HashSHA256Close, HashSHA256Clone
};
```
Extern in `sslDigests.h`: `extern const HashReference SSLHashSHA256;`

---

## CHANGE GROUP G — Cipher suites (`cipherSpecs.c`) — 🟡 PHASE 2-3

Phase 1 can negotiate TLS 1.2 using existing AES-CBC-SHA suites (version + PRF + Finished is enough). SHA-256 CBC and AES-GCM suites are Phase 2–3. *(SL `cipherSpecs.c` not yet read verbatim; read before doing Group G.)*

---

## CHANGE GROUP H — Finished-message size switches (`sslHandshakeFinish.c`) — ✅ MAPPED, PHASE 1 REQUIRED

`sslHandshakeFinish.c` read verbatim. Current code `assert(0)` on unknown versions — TLS 1.2 traps here before `tls12ComputeFinishedMac` ever runs.

### H1. `SSLEncodeFinishedMessage` switch
**Stock (confirmed):**
```c
case TLS_Version_1_0:  finishedSize = 12; break;
default:               assert(0); return errSSLInternal;
```
**Change:**
```c
case TLS_Version_1_1:  finished->protocolVersion = TLS_Version_1_1; finishedSize = 12; break;  /* ADD */
case TLS_Version_1_2:  finished->protocolVersion = TLS_Version_1_2; finishedSize = 12; break;  /* ADD */
```

### H2. `SSLProcessFinished` switch — same pattern, both must be updated.

### H3. `SSLEncodeServerHelloDone` assert
```c
/* Stock: asserts == SSL_Version_3_0 || == TLS_Version_1_0 */
/* Change: admit 1.1/1.2 */
assert(ctx->negProtocolVersion >= SSL_Version_3_0);
```

> **Note:** H1/H2 are the callout *callers*. They pass legacy SHA1/MD5 clones to `computeFinishedMac`, which `tls12ComputeFinishedMac` ignores (it clones `ctx->sha256State` itself). No change to the clone calls — only the size/version switches above.

---

## CHANGE GROUP I — CertificateVerify (`sslCert.c`) — 🟡 PHASE 2

`sslCert.c` read verbatim. Exercised only when a server requests a client cert AND the client has one — never on the server-auth handshake (the Phase 1 goal). Defer. For Phase 1, guard: decline client cert when `negProtocolVersion >= TLS_Version_1_2`.

### I1. Hash buffer sizing
```c
size_t vfyHashLen = (ctx->negProtocolVersion >= TLS_Version_1_2)
    ? CC_SHA256_DIGEST_LENGTH : (SSL_MD5_DIGEST_LEN + SSL_SHA1_DIGEST_LEN);
hashDataBuf.length = vfyHashLen;
```

### I2. On-wire SignatureAndHashAlgorithm prefix
TLS 1.2 CertificateVerify (RFC 5246 §7.4.8) prepends a 2-byte `{hash, signature}` identifier. New wire-format encode + parse work.

### I3. Version-aware sign-length / data selection
Under TLS 1.2, both RSA and ECDSA sign the single 32-byte SHA-256 digest.

### I4. ECDSA verify bypass rework
Stock code bypasses callout for ECDSA, hardcodes SHA-1. Under 1.2 ECDSA must use SHA-256 through `tls12ComputeCertVfyMac`.

### I-FINDING. Four version asserts in `sslCert.c`
All assert `== SSL_Version_3_0 || == TLS_Version_1_0` — widen to `>= TLS_Version_1_0`.

---

## File-by-file change summary

| File | Changes | Phase | Effort |
|---|---|---|---|
| `sslPriv.h` | A1 — 2 enum values | 1 | trivial |
| `SecureTransport.h` | A2 — 2 enum values + 4 func decls | 1 | trivial |
| `sslContext.h` | B1 — 3 struct fields + sha256State (append at END) | 1 | small, ABI-sensitive |
| `sslContext.c` | B2, C1–C4 + 4 new setter/getter bodies + dispose cleanup | 1 | **moderate** |
| `sslUtils.c` | D1, D2-accept, D-FINDING-3 | 1 | small |
| `sslHandshakeHello.c` | D3 (2 copies), D-FINDING-2 (2 lines) | 1 | small |
| `sslHandshake.c` | E5 update (3 sites), D-FINDING-4 fix | 1 | small |
| `sslHandshakeFinish.c` | H1/H2 switches (2), H3 assert | 1 | small |
| `tls12Callouts.c` | E1–E6 — NEW FILE (draft in docs/) | 1 | **high** |
| `tls_hmac.c/.h` | F1–F6 (6 edits, no new crypto) | 1 | small |
| `sslDigests.c/.h` | F-DEP — SSLHashSHA256 (5 statics + 1 entry) | 1 | small |
| record layer | explicit-IV for 1.1/1.2 CBC (Note 3) | 1 | moderate |
| `sslCert.c` | I1–I4 + I-FINDING asserts | 2 | moderate-high |
| `cipherSpecs.c` | G — new suites | 2–3 | low→high |
| `libsecurity_ssl.xcodeproj` | add `tls12Callouts.c` to build | 1 | trivial |

---

## Critical engineering notes

1. **ABI confinement = keychain safety.** Every struct change appends to the internal `SSLContext`. Nothing in Groups A–I touches `libsecurity_keychain`, CDSA, or `securityd`. Post-build verify: `nm` the rebuilt dylib and confirm no CDSA symbols moved.

2. **TLS 1.1 is nearly free.** TLS 1.1 uses the same PRF and Finished MAC as TLS 1.0; D3 routes 1.1 → `Tls1Callouts`. Only the explicit-IV record change (Note 3) separates 1.0 from 1.1.

3. **Explicit-IV record change (1.1+).** TLS 1.1+ prepend an explicit random IV to each CBC record. `tls1DecryptRecord` currently assumes implicit IV. For 1.1/1.2 CBC suites the record layer must skip the explicit IV on decrypt and prepend it on encrypt.

4. **Validation is all-or-nothing.** Build E5 + `tls12_PRF` + `tls12ComputeFinishedMac` + Group H together as one unit — the Finished check is binary pass/fail, so partial landings will all fail the same way.

5. **Sweep exact-equality version tests (D-FINDING-5).** `grep -rn 'TLS_Version_1_0' lib/` before building. Any bare `==` needs widening. Confirmed bug-class hits: D-FINDING-4, Group H switches, Group I-FINDING asserts.

6. **Phase 1 vs Phase 2.** Groups A–F + H delivers working TLS 1.2 client handshake against real servers. Group I and G are Phase 2 and never block server-auth. If Phase-1 build must coexist with servers that request client certs, use the Group I guard (decline client cert under 1.2).

7. **Build sequence.** Compile stock `libsecurity_ssl-55002` first on the Snow Leopard x86_64 toolchain to surface any "unreleased code" gaps before patching confuses the picture.

---

## Mapping status

| Group | Status |
|---|---|
| A (enums) | ✅ fully mapped |
| B (struct/defaults) | ✅ fully mapped |
| C (conversion switches) | ✅ fully mapped |
| D (negotiation) | ✅ fully mapped — incl. D-FINDING-4 bug fix |
| E (tls12Callouts.c) | ✅ spec'd + DRAFTED (uncompiled) |
| F (HMAC-SHA256) | ✅ fully mapped |
| F-dep (digest-SHA256) | ✅ fully mapped |
| G (cipher suites) | 🟡 Phase 2-3 |
| H (Finished-size) | ✅ fully mapped — Phase 1 REQUIRED |
| I (CertVerify) | 🟡 Phase 2 |

*Phase-1 plumbing (Groups A–F, H + E5 + F-dep) is verbatim-mapped and `tls12Callouts.c` is drafted. Remaining Phase-1 work: (1) compile/iterate `tls12Callouts.c`; (2) explicit-IV record change; (3) D-FINDING-5 equality sweep. Phase-2: Group I + Group G.*

---

## Glossary

- **`SslTlsCallouts`** — 10-function dispatch table; one instance per protocol version. TLS 1.2 adds the third: `Tls12Callouts`.
- **PRF** — TLS pseudorandom function. TLS 1.0/1.1: MD5⊕SHA1. TLS 1.2: single SHA-256 P_hash.
- **Finished `verify_data`** — 12-byte handshake-integrity check = PRF(master_secret, finished_label, SHA256(transcript)).
- **CertificateVerify** — client proves cert possession. TLS 1.2 reworks wire format. (Group I)
- **CBC explicit IV** — TLS 1.1+ prepends per-record IV; TLS 1.0 uses implicit chained IV. (Note 3)
- **CommonCrypto** — Apple's crypto library (`CCHmac`, `CC_SHA256_*`); supplies every primitive this merge needs.
- **system-default vs. sneak/relink** — replace system `Security.framework` (viable iff keychain ABI untouched) vs. patch only linked apps.

---

## §X. WORKING-BASELINE FIXES (post-bringup — record-layer correctness)

This section documents two bugs found during live bring-up that, once fixed,
produced the first **end-to-end working TLS 1.2 session in both `ssltest` and
Safari/CFNetwork** on the 10.6.8 x86_64 VM. Both are subtle and easy to
reintroduce; do not revert either without re-reading this section.

**Verification of the working baseline (all observed on the live VM):**
- `ssltest` against `tls12.badssl.com` → `Negotiated protocol: TLS 1.2`,
  cipher `0xC027`, and a real `HTTP/1.1 ...` response line (server app-data
  decrypted and MAC-verified).
- `ssltest` against `howsmyssl.com` → TLS 1.2, cipher `0xC013` (ECDHE-RSA),
  real `HTTP/1.0 301` response.
- Safari loaded `tls12.badssl.com` and `howsmyssl.com` pages (HTML rendered).
- `howsmyssl` page confirmed the wire-level ECDHE curve list
  (secp256r1/384r1/521r1) arriving intact.

### X-FIX-1 — `sslChangeCipher.c`: `readCipher.ready` MUST stay 0 after server CCS

**File:** `lib/sslChangeCipher.c`, function `SSLProcessChangeCipherSpec`.

**Symptom (when broken):** heap double-free / `"incorrect checksum for freed
object"` abort, crashing in `SSLServiceWriteQueue + 110` ← `SSLHandshakeProceed`
← `SSLHandshake`, on **every** TLS 1.2 connection (cert-request sites and
plain sites alike), reproducible on Safari startup. NOT related to client-cert
handling (that was a long red herring).

**Root cause:** an experimental edit had changed the post-server-CCS line to
`ctx->readCipher.ready = 1`. `SSLHandshake`'s loop condition is
`while (ctx->readCipher.ready == 0 || ctx->writeCipher.ready == 0)`. Setting
`readCipher.ready = 1` here (before the server's **Finished** is processed)
makes the loop exit prematurely; the still-unread encrypted Finished and the
partially-serviced write queue are then re-entered by CFNetwork in an
inconsistent state, double-freeing a `WaitingRecord`.

**Fix (stock value — DO NOT CHANGE):**
```c
    ctx->readCipher = ctx->readPending;
    ctx->readCipher.ready = 0;      /* Can't send data until Finished is sent */
    SSLChangeHdskState(ctx, SSL_HdskStateFinished);
```
`readCipher.ready` is correctly raised to 1 later, at the right time, by the
`SSL_HdskFinished` case in `SSLAdvanceHandshake` (after the server Finished is
verified). The `=1` hack also produced a *false* "SUCCESS" in ssltest — it
never actually verified the server Finished, so no server record was ever
decrypted. Reverting to `0` is what exposed X-FIX-2.

### X-FIX-2 — `tls12Callouts.c`: record-MAC pointer must be relative to `content.data`

**File:** `docs/tls12Callouts.c` (compiled into the patched build), function
`tls12DecryptRecord`.

**Symptom (when broken):** `SSLHandshake failed: -9846 (errSSLBadRecordMac)`
on the server's first encrypted record (its Finished), with the protocol
already negotiated as TLS 1.2. Every encrypted CBC record fails MAC.

**Root cause:** explicit-IV CBC record layout is
`[ IV(blockSize) | content | MAC(digestSize) | pad | padlen ]`. The code
advanced `content.data += blockSize` (to skip the explicit IV) but then passed
the MAC pointer as `payload->data + content.length`, which lands `blockSize`
bytes too low — inside the ciphertext — because it ignored the IV shift that
was applied to `content.data`. MAC compare therefore never matched.

**Fix (pass the MAC pointer relative to the IV-shifted content):**
```c
    /* MAC immediately follows the content. content.data already includes
     * the explicit-IV shift, so the MAC pointer must be relative to
     * content.data, NOT payload->data. */
    if ((err = SSLVerifyMac(type, &content,
             content.data + content.length, ctx)) != 0) { ... }
```
This is self-consistent with the write side: `tls12WriteRecord` places the MAC
immediately after the plaintext (after the IV), and `tls12ComputeMac` includes
the content length in the MAC header on both encrypt and verify.

### X-NOTE — known remaining gap (not a regression): SNI + sig-algs on the CFNetwork path

`howsmyssl` (loaded through Safari/CFNetwork) reported **"Version: TLS 1.0"** and
**"didn't send any signature algorithms"** for that particular connection,
even though `ssltest` negotiates 1.2 against the same host. Two linked issues,
both on the CFNetwork path (NOT the SSL record layer, which is proven correct):
1. The `signature_algorithms` extension added in `SSLEncodeClientHello` is
   present on the ssltest path but appears absent on the CFNetwork path → some
   gate (e.g. `ecdsaEnable` / `versionTls12Enable` evaluated before the
   version-force) is suppressing it, likely causing the server to downgrade to
   1.0.
2. No SNI (`server_name`) extension is sent, so multi-cert hosts (e.g. badssl)
   return their fallback cert.
These are the next items to chase; they do not affect the correctness of the
TLS 1.2 record/handshake crypto established above. Do NOT "fix" them by
reverting X-FIX-1 or X-FIX-2.
