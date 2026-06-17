# TLS 1.2 — macOS 10.6 Snow Leopard Security.framework

**Status:** Design phase complete → Ready for implementation

## What This Is

Source-level merge of TLS 1.2 (and 1.1) into Apple's `libsecurity_ssl-55002`
for macOS 10.6.8 Snow Leopard (x86_64 Intel). Stock Snow Leopard tops out
at TLS 1.0. This project adds the version negotiation, callout table, PRF,
and MAC changes needed for TLS 1.2.

**Approach:** source merge against stock `Security-55002`, not a binary patch.  
**Design:** new `Tls12Callouts` callout table (clean separation, not Leopard's
function-level introspection).  
**Safety:** all changes isolated to `libsecurity_ssl`; zero CDSA/keychain ABI
impact → system-default install is viable.

## Quick Start

```bash
# 1. Download sources, patches, and 10.6 SDK (~500 MB total)
bash scripts/setup.sh

# 2. Read the spec
open docs/tls12-merge-change-map.md

# 3. Compile baseline (stock, to confirm build env works)
bash scripts/build-libsecurity-ssl.sh

# 4. Apply Groups A–H from the spec, then:
bash scripts/build-libsecurity-ssl.sh --patched
```

## Directory Layout

```
tls12-snow-leopard-merge/
├── scripts/
│   ├── setup.sh                   ← download + extract everything
│   └── build-libsecurity-ssl.sh   ← compile stock or patched
│
├── docs/                          ← analysis & spec (see below)
│
├── downloads/                     ← archives (populated by setup.sh)
│   ├── Patches_Security-55002_4.tar.bz2
│   ├── Security.framework.tar.bz2
│   └── MacOSX10.6.sdk.tar.xz
│
├── sources/                       ← extracted (populated by setup.sh)
│   ├── libsecurity_ssl-55002/     ← THE SOURCE TO PATCH
│   └── Security.framework/        ← Leopard reference binary
│
├── patches/                       ← extracted (populated by setup.sh)
│   └── Patches_Security-55002_4/
│       └── libsecurity_ssl.diff   ← Leopard's TLS 1.2 patch (603 KB reference)
│
├── sdk/                           ← extracted (populated by setup.sh)
│   └── MacOSX10.6.sdk/
│
└── build/                         ← compiled output
    ├── libssl-stock/              ← baseline build
    └── libssl-patched/            ← TLS 1.2 build
```

## Key Documents in `docs/`

| File | Purpose |
|------|---------|
| `tls12-merge-change-map.md` | **Master spec** — every code change, Groups A–I |
| `tls12Callouts.c` | Draft implementation of new callout functions |
| `snowleopard-security-version-manifest.md` | Version pinning (Security-55002, etc.) |
| `leopard-patch-validation-and-divergences.md` | Analysis of Leopard's patch vs our design |
| `DECISION-tls12-callouts-new-table-approach.md` | Why new table, not Leopard's introspection |
| `PROJECT-STATUS-TLS12-MERGE.md` | Current status & confidence levels |

## Implementation Overview

**Phase 1 (target):** TLS 1.2 for server-authenticated connections (browser use case)

| Group | Files | What |
|-------|-------|------|
| A | `sslPriv.h`, `SecureTransport.h` | Version enums (`TLS_Version_1_1/1_2`, `kTLSProtocol11/12`) |
| B | `sslContext.h`, `sslContext.c` | Append `sha256State` + version fields to `SSLContext` |
| C | `sslContext.c` | Enum conversion & `SSLSetProtocolVersionMax/Min` bodies |
| D | `sslHandshake.c`, `sslHandshakeHello.c` | Negotiation ladder + callout dispatch |
| E | `tls12Callouts.c` *(new file)* | `Tls12Callouts` table + PRF/MAC/Finished functions |
| F | `tls_hmac.c/.h`, `sslDigests.c` | HMAC-SHA256 + `SSLHashSHA256` digest |
| H | `sslHandshakeFinish.c` | `finishedSize = 12` for TLS 1.1 and 1.2 |

**Phase 2 (deferred):**

| Group | Files | What |
|-------|-------|------|
| G | `cipherSpecs.c` | SHA-256 CBC and GCM cipher suite entries |
| I | `sslCert.c` | Client-cert `CertificateVerify` for TLS 1.2 |

## Validated Against Leopard

The Leopard patches (`patches/Patches_Security-55002_4/libsecurity_ssl.diff`)
confirm:
- ✅ Version enums `0x0302`/`0x0303` correct
- ✅ `finishedSize = 12` for both 1.1 and 1.2
- ✅ All SHA-256/GCM cipher suites present
- ✅ `callout->computeFinishedMac` dispatch architecture confirmed
- ⚠️ Leopard **reused** `Tls1Callouts` (fall-through) — we use a **new table** (cleaner)

## Build Requirements

- macOS host with Xcode command-line tools (clang)
- 10.6 SDK provided in `sdk/` (downloaded by `setup.sh`)
- Deployment target `x86_64 10.6`

## Testing

After patched build:
```bash
# 1. CDSA safety (must return nothing)
nm build/libssl-patched/libsecurity_ssl.dylib | grep -iE "cdsa|securityd"

# 2. Confirm TLS 1.2 symbols present
nm build/libssl-patched/libsecurity_ssl.dylib | grep Tls12

# 3. Deploy to Snow Leopard VM and test
curl --tlsv1.2 https://howsmyssl.com/a/check
```
