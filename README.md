# TLS 1.2 — macOS 10.6 Snow Leopard Security.framework

**Status:** ✅ Working end-to-end — TLS 1.2 verified in both `ssltest` and Safari on a live 10.6.8 x86_64 VM.

## What This Is

A source-level merge of TLS 1.2 (and 1.1) into Apple's `libsecurity_ssl-55002`
for macOS 10.6.8 Snow Leopard (x86_64 Intel). Stock Snow Leopard tops out at
TLS 1.0. This project adds the version negotiation, callout table, PRF, MAC,
and explicit-IV record-layer changes needed for TLS 1.2.

**Approach:** source merge against stock `Security-55002`, not a binary patch.
**Design:** a new `Tls12Callouts` callout table (clean separation, rather than
Leopard's function-level introspection).
**Safety:** changes are isolated to `libsecurity_ssl`; no CDSA/keychain ABI
impact, so a system-default install is viable.

## Current Status

Both RSA and ECDHE TLS 1.2 handshakes complete and exchange encrypted
application data. Verified on the live Snow Leopard VM:

- `ssltest` → `tls12.badssl.com`: TLS 1.2, cipher `0xC027`
  (ECDHE-RSA-AES128-SHA256), real HTTP response.
- `ssltest` → `howsmyssl.com`: TLS 1.2, cipher `0xC013`
  (ECDHE-RSA-AES128-SHA), real HTTP response.
- Safari renders `tls12.badssl.com` and `howsmyssl.com` pages over the
  patched stack (via `DYLD_INSERT_LIBRARIES` + an in-process function patcher).

Working cipher suites: `0xC013`, `0xC027`, `0x003C`/`0x003D`.

**Known open items (not blocking the baseline):**
- On the Safari/CFNetwork path, the `signature_algorithms` extension is not
  reaching the wire, which can cause a downgrade to TLS 1.0 on some hosts.
- No SNI (`server_name`) extension is sent yet, so multi-cert hosts may return
  a fallback certificate.
- AES-GCM suites (`0xC02B`/`0xC02C`) are deferred (no GCM in SL's
  OpenSSL 0.9.8 / CommonCrypto).

See `docs/tls12-merge-change-map.md` (section X) for the two record-layer
fixes that produced the first working session, and for the full change map.

## Quick Start

```bash
# 1. Download sources, patches, and the 10.6 SDK (~500 MB total)
bash scripts/setup.sh

# 2. Wire up include-path symlinks
bash scripts/post-setup.sh

# 3. Compile the baseline (stock, to confirm the build env works)
bash scripts/build-libsecurity-ssl.sh

# 4. Compile the TLS 1.2 build
bash scripts/build-libsecurity-ssl.sh --patched
```

### Local configuration

Scripts that talk to the test VM read a git-ignored `config.sh`. Create it
from the template before running deploy/test scripts:

```bash
cp config.sh.example config.sh
$EDITOR config.sh      # set VM_SUDO_PASS, VM_HOST, VM_HOST_CLEAN
```

`config.sh` is git-ignored and never committed.

## Directory Layout

```
tls12-snow-leopard-merge/
├── scripts/                       ← build, deploy, diagnostic, and patch scripts
│   ├── setup.sh                   ← download + extract everything
│   ├── post-setup.sh              ← wire include-path symlinks
│   └── build-libsecurity-ssl.sh   ← compile stock or --patched
│
├── docs/                          ← analysis & spec
│   ├── tls12-merge-change-map.md  ← master spec + section X (working-baseline fixes)
│   ├── tls12Callouts.c            ← the new TLS 1.2 callout implementation (compiled in)
│   └── PROJECT-STATUS-TLS12-MERGE.md
│
├── sources/
│   └── libsecurity_ssl-55002/     ← THE MERGE TARGET (hand-edited; committed)
│
├── config.sh.example              ← template for local VM config (config.sh is git-ignored)
│
├── downloads/  sdk/  patches/     ← populated by setup.sh (git-ignored, regenerable)
└── build/                         ← compiled output (git-ignored)
```

`downloads/`, `sdk/`, `patches/`, `build/`, and the pristine extracted Apple
trees under `sources/` are all regenerable via `setup.sh` and are git-ignored.
Only the hand-edited `sources/libsecurity_ssl-55002/`, the new
`docs/tls12Callouts.c`, the scripts, and the docs are committed.

## Architecture

Snow Leopard's Secure Transport dispatches all protocol-version-specific crypto
through a 10-function callout table (`SslTlsCallouts`). Stock ships two
instances: `Ssl3Callouts` and `Tls1Callouts`. This merge adds a third,
`Tls12Callouts`, plus the version-enum, negotiation, and record-layer changes.

**Phase 1 (done):** TLS 1.2 for server-authenticated connections — version
enums, `SSLContext` fields, negotiation ladder, callout dispatch, the new
`tls12Callouts.c` (PRF / MAC / key derivation / Finished), HMAC-SHA256 +
`SSLHashSHA256`, finished-size switches, and the explicit-IV CBC record layer.

**Phase 2 (partial / deferred):** SHA-256 CBC + AES-GCM cipher-suite table
entries, client-cert `CertificateVerify` for TLS 1.2, SNI and wire-level
`signature_algorithms` on the CFNetwork path.

## Build Requirements

- macOS host with Xcode command-line tools (clang)
- 10.6 SDK in `sdk/` (downloaded by `setup.sh`)
- Deployment target `x86_64`, `-mmacosx-version-min=10.6`

## Testing

After a patched build:

```bash
# CDSA/keychain ABI safety (must return nothing)
nm build/libssl-patched/libsecurity_ssl.dylib | grep -iE "cdsa|securityd"

# Confirm TLS 1.2 symbols are present
nm build/libssl-patched/libsecurity_ssl.dylib | grep Tls12

# Deploy + smoke-test on the Snow Leopard VM
bash scripts/deploy-to-vm.sh
```

## Branches

- `main` — default branch (release/integration target).
- `develop` — active development; work lands here first, then is promoted to
  `main` via pull request.
