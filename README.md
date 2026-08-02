# TLS 1.2 for Mac OS X 10.6.8 (Snow Leopard) — Security.framework rebuild

A source-level backport that brings **system-wide TLS 1.2** (with AES-GCM and
modern EC certificate handling) to Snow Leopard 10.6.8 by rebuilding Apple's
`Security.framework` and its `securityd` daemon from open-source components — no
per-application dylib injection, no `DYLD_INSERT_LIBRARIES`.

The stock 10.6.8 `Security.framework` tops out at TLS 1.0 and cannot validate
many current certificate chains. This project rebuilds the framework from the
Apple `mac-os-x-1068` component sources, patches TLS 1.2 + AES-GCM into
`libsecurity_ssl`, and installs a matched framework + daemon pair so that every
consumer on the system — Safari/WebKit, `curl`, and anything else linking
`Security.framework` — negotiates TLS 1.2.

## Status

This build produces a `Security.framework` + `securityd` pair **end-to-end from a
fresh clone** of the committed sources. A from-scratch run on a wiped 10.6.8
machine produces:

- `Security.fat.new` — the rebuilt framework (x86_64 + i386)
- `dst-securityd-fat/securityd` — the matched daemon (x86_64 + i386)

with all 26 framework component archives resolving on both architectures.

The build is reproducible in the sense that matters: it completes from a clean
clone of the committed sources, with no hand-staged state, and produces a working
2-slice (x86_64 + i386) framework and a matched daemon. The exact binary hash
depends on the toolchain and build host, so it may not be byte-identical across
machines. Inspect the result with:

```sh
lipo -info Security.fat.new
shasum Security.fat.new
```

The 32-bit and 64-bit slices are built here; the `ppc7400` slice is grafted from
the stock system framework with `lipo` at install time, producing the 3-slice
binary 10.6.8 expects (see [BUILDING.md](BUILDING.md)).

Tested toolchain: **Xcode 4.1** with the **10.6 SDK** and **`llvm-gcc-4.2`** on
Mac OS X 10.6.8. (Xcode 4.2 may also work, per xcodereleases.com; 4.1 is what
this has been built with.)

## Quick start

On a prepared 10.6.8 build host (prerequisites in [BUILDING.md](BUILDING.md)),
from the repository root, run bootstrap once and then the full build. `VM` is the
checkout root the scripts resolve their inputs against; it defaults to the
script's own directory, so setting it is optional when you run from the
repository root. It is shown explicitly here for clarity:

```sh
VM="$(pwd)" STAGE=bootstrap bash build-consistent-framework.sh
VM="$(pwd)" STAGE=all ARCHES='x86_64 i386' bash build-consistent-framework.sh
```

This produces `Security.fat.new` and `dst-securityd-fat/securityd`. To install
the matched pair, rebuild the dyld shared cache, and reboot:

```sh
bash install-consistent-and-reboot.sh
```

After reboot, unlocking the keychain returns 0 and an HTTPS fetch returns 200:

```sh
security unlock-keychain -p <pw> ~/Library/Keychains/login.keychain
curl -sS -o /dev/null -w '%{http_code}\n' https://www.google.com
```

## What's in this repository

```
build-consistent-framework.sh     Driver: bootstrap → build 26 components → daemon
link-fat-framework.sh             Links the per-arch Security monoliths
apply-*.sh, *-ssl-*.sh, patch-*   Build helpers (patches, generator determinism,
                                  legacy HMAC, SSL add-ons)
install-consistent-and-reboot.sh  Installs the matched pair, grafts ppc, reboots

libsecurity_*-<ver>/              The 26 pinned framework component sources
securityd-40600/                  The securityd daemon source
libsecurityd-37613/               MIG client/server + securityd_client headers
SecurityTokend-55000/             Token daemon interface
libsecurity_agent-55000/          SecurityAgent client (daemon link chain)
libsecurity_cryptkit-55002/       Vendored legacy-HMAC crypto (keychain unlock)
Security-55002/                   Umbrella: Security.order + export lists
Security-55471/                   Donor tree (provenance only — see note below)

vendor/                           ANTLR runtime + trust anchors (ssl_anchors.pem)
patches/                          Source patches applied during the build
stubs/                            Headers absent from the 10.6 SDK (asn1 SPI,
                                  NSS/NSPR, fsctl, audit_session, …)
extra-headers/, priv-headers/     Additional staged headers
src/                              TLS 1.2 / AES-GCM implementation added to ssl
sl-compat-prefix.h                Compat prefix force-included into every compile
ssltest.c, ssltest_multi.c        TLS test programs (link -framework Security)
```

> **Provenance pin set:** the exact upstream commit each vendored tree above
> was taken from is recorded in
> [`apple-security-mac-os-x-1068`](https://github.com/startergo/apple-security-mac-os-x-1068)
> — a parallel repository of 30 git submodules (29 pinned to `aosm/*` + 1 to
> `startergo/libsecurity_checkpw` for the reconstructed 55471). Reference
> artifact for audit and future OS backports; not consumed by this build.

### Trust anchors

The root certificates the rebuilt trust path validates against ship in-tree at
`vendor/anchors/ssl_anchors.pem` (219 roots) and are staged automatically during
`STAGE=bootstrap`. No separate root-import step is required; validation of
current certificate chains works out of the box.

### Component versions

The build uses the Apple **`mac-os-x-1068`** (10.6.8) component set with three
deliberate exceptions, in two distinct shapes:

- **Private-header exceptions (`apple_csp`, `checkpw`)**: the 1068 tag needs a
  private header that's not in the 10.6 SDK or in the component's own tree, but
  IS available in a companion Apple open-source repo. The non-1068 version is
  kept for what lives on it (not because the 1068 tag is impossible to build):
  `apple_csp-55003` hosts the SL backport + legacy-HMAC; `checkpw-55471` is
  Apple's PAM rewrite. See VERSION-DISCOVERY.md for the full rationale.
- **Patch-carrying exception (`ssl`)**: the 1068 tag builds clean; `ssl-55002`
  is kept because it carries this project's TLS 1.2 + AES-GCM patches.

| component   | version | why not the 1068 tag |
|-------------|---------|----------------------|
| `ssl`       | 55002   | patch-carrying: hosts TLS 1.2 + AES-GCM patches (1068 tag 40581 builds clean) |
| `apple_csp` | 55003   | hosts SL backport + legacy-HMAC; 1068 tag 36859's private CommonCrypto headers are available in `aosm/CommonCrypto@mac-os-x-1068` but not in the 10.6 SDK |
| `checkpw`   | 55471   | Apple's PAM rewrite; 1068 tag 36064's `<DirectoryServiceMIG.h>` can be mig-generated from `aosm/DirectoryService@mac-os-x-1068` but PAM is cleaner. Identical exports |

Every other component is on its `1068` tag. The full pinned map is in
`build-consistent-framework.sh` (`comp_ver`).

> **Note on `Security-55471/`.** This umbrella tree is kept for provenance only.
> The build does not read it: everything needed from it was extracted into
> standalone trees (`libsecurity_checkpw-55471`, `libsecurity_cryptkit-55002`)
> or dereferenced into `stubs/` (the asn1 SPI / NSS / NSPR headers). It is
> retained so the origin of those extracted files is auditable.

## Scope and limitations

- **Target:** Mac OS X 10.6.8 only. The backport patches the native 10.6 CSSM /
  SecureTransport and depends on the stock `libcrypto.0.9.8` being present.
- **Known open issue:** TLS 1.2 session resumption fails intermittently under
  concurrent load. Full handshakes are unaffected.
- This is a research/preservation project for a long-obsolete OS. It replaces a
  core system framework; read [BUILDING.md](BUILDING.md), keep the printed
  recovery commands, and do not run it on a machine you cannot restore.

## License

The Apple `libsecurity_*`, `securityd`, and `Security` sources are under the
Apple Public Source License (see `APPLE_LICENSE` in each component tree). Vendored
third-party code (ANTLR runtime) retains its own license. Patches and build
scripts in this repository are provided as-is.
