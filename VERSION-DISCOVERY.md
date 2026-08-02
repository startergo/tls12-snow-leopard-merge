# Component version discovery and rationale

This document records why the build pins the component versions it does. Snow
Leopard's `Security.framework` is assembled from ~30 Apple open-source component
trees, and the correct version of each is not obvious: Apple's release tags span
several OS versions, some components need a version other than the plain 10.6.8
tag, and a few tags reference private headers Apple never published. The analysis
below is the "why these versions" reference for anyone building from or auditing
this repository.

## The version regime

The `mac-os-x-1068` tags in Apple's open-source repositories define the actual
Snow Leopard 10.6.8 component set. The build pins every component to its
`mac-os-x-1068` tag **with exactly three documented exceptions** (see below). The
authoritative pin map is the `comp_ver` function in
`build-consistent-framework.sh`; this document explains the reasoning behind it.

A key early finding: `securityd` uses a **separate version series** from the
`libsecurity_*` components — 40xxx for 10.6, 55xxx for 10.7 (Lion).
`securityd-40600` is the real 10.6.8 daemon; `securityd-55009` is Lion. An
earlier iteration of this project used the Lion daemon (55009) plus a
post-10.6.8 `libsecurity_utilities` (55017), which introduced problems that do
not exist in the correct 10.6.8 versions. That discovery drove the migration to
the version-consistent `1068` set, which is what the build now uses.

## What using the wrong versions cost (historical)

The Lion `securityd` (55009) and post-10.6.8 `utilities` (55017) caused several
problems that turned out to be self-inflicted — artifacts of the wrong version,
not real bugs:

1. **audit.set() EPERM / SecurityAgent session-join failures.** 55009 authhost
   does `audit.get(); audit.set()` (Lion audit-session model). The native 40600
   authhost does not call `audit.set()` at all — it uses the bootstrap model
   (`StBootstrap bootSaver(session().bootstrapPort()); fork();`). And
   `utilities-55010` has no `AuditInfo::set()` method at all. So the ccaudit
   `set()` no-op EPERM fix was patching a method that only exists in the
   wrong-version 55017.

2. **SecurityAgent "Error 1002 creating CGSWindow" (no keychain-unlock dialog).**
   55009 lacks the `StBootstrap bootSaver(session().bootstrapPort())` that native
   40600 has, so SecurityAgent forks into securityd's system bootstrap (no
   WindowServer) instead of the user's session. The native 40600 + 55010 do this
   correctly.

3. **getSessionInfo MIG "restoration".** Effort was spent un-skipping
   `getSessionInfo` in `ucsp.defs` because 55009 (Lion) changed it. 40600 has
   `ucsp_server_getSessionInfo` natively — the backport was compensating for the
   wrong daemon.

4. **AuditToken API mismatch** building 40600 against 55017: 40600 wants
   `AuditToken::auditSession()`; 55017 renamed it to `sessionId()`.
   `utilities-55010` has both, so 40600 builds against 55010 cleanly.

5. **CFClass divergence.** 55017's `cfclass.h` has extra static methods
   (`refCountForType`, `cleanupObject`) that 55010 lacks — confirming 55017 is a
   later branch, not 10.6.8.

The migration to the consistent `1068` set (utilities → 55010, securityd →
40600, cdsa_utilities → 36658) resolved these, and the backport hacks that only
existed for the wrong versions were dropped.

## AS-BUILT: the pinned version map

The `comp_ver` map is a **`mac-os-x-1068` manifest with three documented
exceptions**, with two distinct shapes:

**Private-header exception (`apple_csp`, `checkpw`).** The plain 1068 tag for
these components `#include`s a private header that is not shipped in the 10.6
SDK and is not co-located in the component's own source tree. The header may
exist in a companion Apple open-source tree (`apple_csp`'s CommonCrypto
headers — `cast.h`, `aesopt.h`, `opensslDES.h` — are present at the 1068 tag
of `aosm/CommonCrypto` under `Source/CommonCrypto/`; `checkpw`'s
`<DirectoryServiceMIG.h>` exists nowhere public and cannot be mig-generated
from anything in the project), but is absent from the SDK and from the
component tree itself. For each, a different version — a Snow Leopard
backport or an adjacent release — was used that compiles against public APIs
instead, with **identical exports and an unchanged linked ABI**.
`apple_csp-55003` hosts the SL-backport adaptation onto the public
CommonCryptor/CommonDigest API and the legacy-HMAC keychain-unlock
vendoring. `checkpw-55471` is Apple's PAM rewrite (the 36064 tag is genuinely
unbuildable from public sources).

**Patch-carrying exception (`ssl`).** The plain 1068 tag (40581) builds
clean; `ssl-55002` is kept because it carries the TLS 1.2 + AES-GCM patches
that are the point of the project, on top of the SL base. This is a
deliberate divergence to host this project's TLS work, not a header issue.

    apple_csp   55003   1068 tag 36859 #includes private CommonCrypto headers
                        (cast.h, aesopt.h, opensslDES.h) that are absent from the
                        10.6 SDK and from the apple_csp tree itself — obtainable
                        only by separately fetching the CommonCrypto sources
                        (github aosm/CommonCrypto at the 1068 tag). 55003 is the
                        Snow Leopard backport onto the public CommonCryptor/
                        CommonDigest API, and hosts the legacy-HMAC keychain-unlock
                        vendoring.
    ssl         55002   1068 tag is 40581. 55002 carries the TLS 1.2 + AES-GCM
                        patches (the point of the project) on top of the SL base.
    checkpw     55471   1068 tag 36064 #includes a private <DirectoryServiceMIG.h>
                        (kDSStdMachPortName) that exists nowhere on the system and
                        cannot be mig-generated. 55471 uses PAM, with identical
                        exports (_checkpw, _checkpw_internal).

The three exceptions were confirmed against Apple's actual `mac-os-x-1068` tags
(`git tag --points-at mac-os-x-1068` in the `Security-55002-full` tree): apple_csp
36859, ssl 40581, checkpw 36064 — none of which the build uses, for the reasons
above. Every other component below matches its authoritative 1068 tag exactly.

Every other component is on its `mac-os-x-1068` tag:

    utilities       55010     apple_x509_tp   55006     cssm            40418
    cdsa_utilities  36658     cdsa_client     36213     cdsa_plugin     36327
    cdsa_utils      36064     asn1            36064     authorization   36329
    apple_cspdl     36064     apple_file_dl   36064     apple_x509_cl   36064
    cms             36064     manifest        36064     mds             36495
    filedb          36725     ocspd           55004     pkcs12          40627
    sd_cspdl        35752     smime           36873     codesigning     55005
    keychain        55017

`keychain-55017` is the correct 1068 tag (verified). There is no 55xxx-vs-1068
cross-regime split in the framework build: the whole component set is on the 1068
tags apart from the three exceptions above.

### Authoritative 1068 tags (reference)

The correct `mac-os-x-1068` tag for every component, read directly from Apple's
`Security-55002-full` tree (`git tag --points-at mac-os-x-1068` per component).
The build uses these exactly, except the three exceptions noted above
(apple_csp, ssl, checkpw), where the authoritative 1068 tag is shown in
parentheses and is deliberately not used:

    apple_csp        (36859 → build uses 55003)   apple_cspdl     36064
    apple_file_dl    36064                          apple_x509_cl   36064
    apple_x509_tp    55006                          asn1            36064
    authorization    36329                          cdsa_client     36213
    cdsa_plugin      36327                          cdsa_utilities  36658
    cdsa_utils       36064                          checkpw   (36064 → uses 55471)
    cms              36064                          codesigning     55005
    cssm             40418                          filedb          36725
    keychain         55017                          manifest        36064
    mds              36495                          ocspd           55004
    pkcs12           40627                          sd_cspdl        35752
    smime            36873                          ssl       (40581 → uses 55002)
    utilities        55010                          libsecurityd    37613
    securityd        40600                          Security        55002

## Version-locked trees NOT pinned by comp_ver

Four additional source trees are version-locked build inputs but are resolved
outside the `comp_ver` map, so a reader auditing only `comp_ver` would miss them:

- **`securityd-40600`** — the daemon source itself. Pinned by env var
  (`SECURITYD_DIR="${SECURITYD_DIR:-securityd-40600}"` in
  `build-consistent-framework.sh`), not by `comp_ver`. The native 10.6.8 daemon;
  NOT the Lion-era 55009 that earlier iterations of this project used.
- **`libsecurityd-37613`** — MIG client/server + `securityd_client` /
  `securityd_server` framework sources. Pinned by env var
  (`LIBSECURITYD_DIR="${LIBSECURITYD_DIR:-libsecurityd-37613}"`). This is the
  tree that produces the `securityd_client` archive linked into
  `Security.framework` (see `link-fat-framework.sh` COMPONENTS) — the 26th
  framework component archive — so it is a genuine framework-link-chain input,
  not just a daemon-side input.
- **`libsecurity_agent-55000`** — builds the `security_agent_client` framework
  the daemon links. Resolved by glob (`$VM/libsecurity_agent-*/*.xcodeproj`) in
  the i386 build block, not by `comp_ver`. Daemon-side input.
- **`SecurityTokend-55000`** — builds the `security_tokend_client` framework
  the daemon links. Resolved by glob (`$VM/SecurityTokend-*/*.xcodeproj`) in
  the i386 build block, not by `comp_ver`. Daemon-side input.

So the build consumes **29** version-locked source trees: the **25** in
`comp_ver` (the 24 in `COMPS` plus `ssl`, which `comp_ver` resolves via its
own case statement), plus these 4. Of those 29:

- **26** are framework-link-chain inputs (the 25 `comp_ver` trees +
  `libsecurityd-37613`, which produces `securityd_client`). This is what
  README means by "26 framework component archives" — the 26 archives
  `link-fat-framework.sh` links into `Security.framework`.
- The remaining 3 (`securityd-40600`, `libsecurity_agent-55000`,
  `SecurityTokend-55000`) are daemon-side inputs consumed by the daemon link
  chain, not `Security.framework`.

## Provenance-only trees (shipped, not read by the build)

Two trees ship in the repository for provenance and auditability but are not read
by the build:

- **`Security-55471`** — the umbrella tree the standalone `checkpw-55471`,
  `cryptkit`, and asn1 SPI headers were extracted from. Everything the build
  needs from it was copied into standalone trees or into `stubs/`; the build does
  not read `Security-55471/` itself.
- **`libsecurity_cryptkit-55002`** — the origin of the legacy-HMAC pieces. The
  build actually compiles the HMAC source from `cryptkit-vendor/` (11 files:
  `HmacSha1Legacy`, `ckSHA1`, `falloc`, `ckconfig`); `libsecurity_cryptkit-55002/`
  is kept only to record where those vendored files came from.

## Version-independent fixes (not version artifacts)

These are real fixes in correctly-versioned components — keep them regardless of
version:

- **Legacy HMAC** (`apple_csp-55003` + vendored cryptkit): the keychain-unlock
  crypto fix.
- **generator.pl determinism** (`cdsa_plugin-36327`, `cssm-40418`): the vtable /
  `CSSMERR_DL_INVALID_DB_HANDLE` fix.
- **TLS 1.2** (`ssl-55002`): the purpose of the project.

## Status

The version migration described above is complete. The build uses the
version-consistent 1068 set (with the three exceptions), builds end-to-end from a
clean clone (26/26 component archives, both architectures), and the resulting
framework + daemon boot and function as the system framework (keychain unlock
succeeds, HTTPS negotiates TLS 1.2). The wrong-version backport hacks (ccaudit
`set()` no-op, the getSessionInfo MIG un-skip) were dropped as part of the
migration, since 40600 provides those natively.
