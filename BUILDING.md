# Building

This document covers building the framework and daemon from a clean checkout on
a Snow Leopard 10.6.8 host, installing the result, and verifying it. For what the
project is and what it produces, see [README.md](README.md).

## 1. Prerequisites

### Host

- **Mac OS X 10.6.8 (Snow Leopard).** A physical Mac or a QEMU guest. The build
  must run on 10.6.8 itself — it patches the native 10.6 CSSM / SecureTransport
  and links against the stock system libraries.
- **Xcode 4.1** with the **10.6 SDK** at `/Developer/SDKs/MacOSX10.6.sdk`.
  This is the tested version. Xcode 4.2 may also work (per xcodereleases.com) but
  has not been verified here; 3.2.x is not recommended.
- **`llvm-gcc-4.2`** at `/Developer/usr/bin/llvm-gcc-4.2` (and `/usr/bin/gcc`).
  This is the required compiler — **not** clang. `xcodebuild` and `lipo` (from the
  Xcode command-line tools) must be present.
- **Stock `/usr/lib/libcrypto.0.9.8.dylib`.** The EC/RSA verification fallback
  `dlsym`s from it. It ships with 10.6; do not remove or replace it.

Everything else the build needs (the ANTLR runtime, trust anchors, and all
headers absent from the 10.6 SDK) is vendored in the repository. There is no
network dependency and no MacPorts requirement.

### Disk / privileges

- ~2 GB free for the build tree and staged headers.
- `sudo` access. The install step rebuilds the dyld shared cache and reboots,
  and several build steps stage headers into `/usr/local/SecurityPieces`. The
  scripts run these through `sudo -S`. By default `sudo` will prompt
  interactively. To supply the password non-interactively (useful over SSH), set
  `VM_SUDO_PASS` — either in the environment (`VM_SUDO_PASS=yourpass bash
  build-consistent-framework.sh ...`) or, more conveniently, in a local
  `config.sh` at the repository root, which the scripts source automatically. Copy
  `config.sh.example` to `config.sh` and set `VM_SUDO_PASS` there. `config.sh` is
  git-ignored, so your password is never committed. If `VM_SUDO_PASS` is unset,
  the scripts fall back to an interactive `sudo` prompt.

## 2. Build

From the repository root. `VM` is the variable the scripts use for the checkout
root — the directory they resolve every source tree, helper script, and staged
header against. Each script defaults `VM` to its own directory
(`${VM:-$(cd "$(dirname "$0")" && pwd)}`), so setting it is optional when you run
from the repository root; the commands below set it explicitly for clarity and
so they work regardless of the working directory. If you keep a local
`config.sh` (see `config.sh.example`), it is sourced automatically from `$VM`.

Run bootstrap once per machine. It generates `/usr/local/SecurityPieces` (staged
headers, framework stubs, ANTLR runtime) from the pinned sources:

```sh
VM="$(pwd)" STAGE=bootstrap bash build-consistent-framework.sh
```

Then build all 26 framework components and the securityd daemon for both
architectures, and link the fat framework:

```sh
VM="$(pwd)" STAGE=all ARCHES='x86_64 i386' bash build-consistent-framework.sh
```

**`ARCHES='x86_64 i386'` is required, not optional.** The daemon links several
per-arch client frameworks (`security_agent_client`, `security_tokend_client`,
`securityd_server`, …) that are built and fat-staged only when both architectures
are in the build. An `x86_64`-only run will fail at the daemon link with
`ld: framework not found security_agent_client`.

A successful run ends with:

```
resolved 26/26 archives for x86_64
resolved 26/26 archives for i386
FAT daemon OK (gate passed): … x86_64 i386
fat framework: …/Security.fat.new  (x86_64 i386)
```

Outputs (each `lipo`-combined from its per-arch slices by the build):

- `Security.fat.new` — the rebuilt framework (2-slice: x86_64 + i386)
- `dst-securityd-fat/securityd` — the matched daemon (2-slice: x86_64 + i386)

Both are 2-slice at this point. The third (`ppc7400`) slice is added at install
time — see step 3 below.

### Why two stages

`STAGE=bootstrap` populates `/usr/local/SecurityPieces/` — the header + framework
tree every component compile points at — from the version-pinned sources, and
builds the vendored ANTLR runtime. It must run once before the first build.
`STAGE=all` compiles the components, builds the daemon, and links the monolith;
it reuses the bootstrapped `SecurityPieces`. Re-run `STAGE=bootstrap` only if you
change a pinned header source or wipe `SecurityPieces`.

## 3. Install

The framework and daemon are a **matched pair** — they share the CSSM handle ABI
and must be installed together. Installing one without the other yields
`CSSMERR_DL_INVALID_DB_HANDLE` on keychain unlock.

```sh
bash install-consistent-and-reboot.sh
```

Despite the name, the script does not reboot unconditionally: it installs, tests
the new framework in place, and prompts before rebooting (see step 5).

This script:

1. **Verifies** the framework and daemon carry the expected symbols.
2. **Backs up** the current stock framework and daemon on first run (only after
   confirming they are genuinely stock), so there is a recovery path.
3. **Grafts the `ppc7400` slice** from the stock framework with `lipo`,
   producing the 3-slice binary 10.6.8 expects. This is required — a 2-slice
   framework leaves PubSub, WebKit, and QuickTimeComponents unable to bind in the
   dyld shared cache. In effect it extracts the `ppc7400` slice from the saved
   stock framework, combines it with the freshly built x86_64 + i386 framework,
   and confirms the result is 3-slice:

   ```sh
   lipo "$STOCK_FRAMEWORK" -thin ppc7400 -output /tmp/Security.ppc
   lipo Security.fat.new /tmp/Security.ppc -create -output /tmp/Security.fat3
   lipo -info /tmp/Security.fat3
   ```

   The last command reports `x86_64 i386 ppc7400`. The install script runs this
   automatically from the stock backup it made on first run.
4. **Installs** the matched pair and **rebuilds the dyld shared cache**
   (`update_dyld_shared_cache -force`) — required, or the old framework loads
   from cache.
5. **Tests the new framework in place, before rebooting.** Because the cache was
   just rebuilt, the newly installed framework is already live for freshly
   launched processes, so the script exercises it immediately — a keychain unlock
   and an HTTPS fetch — and reports PASS/FAIL for each. It then **prompts** before
   rebooting (defaulting to no). If the tests fail, it prints a rollback that
   restores the stock framework and daemon **without** rebooting into the new one,
   so a bad build never has to be booted to be backed out.

To let the keychain test unlock non-interactively, set `TESTPW` before running:

```sh
TESTPW=<pw> bash install-consistent-and-reboot.sh
```

Over SSH, without a login session, the keychain-unlock test can report a false
negative even on a good install; if the HTTPS test passes and `system.log` is
clean, the install is fine. Reboot only when you are satisfied with the in-place
results.

The script prints a single-user-mode recovery command before it prompts. **Note
it down.** If a reboot ever hangs, boot to single-user mode (⌘-S) and run it to
restore the stock framework, daemon, and cache.

### Runtime requirement: trust anchors at a hardcoded path

The rebuilt framework's cert-chain verifier (`sslVerifyCertChainOpenSSL`) reads
trust roots from `/usr/local/SecurityPieces/ssl_anchors.pem` at that literal
hardcoded path. The path is baked into the framework binary; it cannot be
configured via environment variable or framework preferences.

`STAGE=bootstrap` stages the anchors (from `vendor/anchors/ssl_anchors.pem`,
219 roots) into `/usr/local/SecurityPieces/` as part of the build's normal
header-pieces staging. So on a build-then-install-same-machine flow — the
documented one — the anchors are already present when you run
`install-consistent-and-reboot.sh`, and cert validation works out of the box.

**The install script does NOT stage or verify the anchors.** It only installs
the framework + daemon binaries and rebuilds the dyld cache. The script does
include a preflight that *warns* (does not fail) if the anchors are missing.
So:

- On the build host: anchors are present from bootstrap; install works.
- On a different 10.6.8 machine that received only the binaries: anchors are
  absent, cert validation fails silently with `cannot open anchor bundle`,
  HTTPS fetches return errors, and the only signal is in `system.log`.

If you are copying just the binaries to another machine, also copy
`vendor/anchors/ssl_anchors.pem` to `/usr/local/SecurityPieces/ssl_anchors.pem`
on the target (creating `/usr/local/SecurityPieces/` if needed).

## 4. Verify

After reboot, reconnect and check. Unlocking the keychain should return 0, the
HTTPS fetch should return 200, and the desktop processes should be running:

```sh
security unlock-keychain -p <pw> ~/Library/Keychains/login.keychain
curl -sS -o /dev/null -w '%{http_code}\n' https://www.google.com
ps axww | grep -iE '[F]inder|[D]ock'
```

The system `openssl` (0.9.8) cannot itself speak TLS 1.2, so it does not test the
framework. To exercise the rebuilt TLS 1.2 path directly, build one of the
included test programs — they link `-framework Security`:

```sh
gcc -arch x86_64 -o /tmp/ssltest ssltest.c -framework Security -framework CoreFoundation
/tmp/ssltest www.google.com 443
```

`ssltest` takes a host and a port, with optional trailing arguments for a maximum
protocol version and `-v` for verbose output:

```sh
/tmp/ssltest www.google.com 443 -v
```

## 5. Troubleshooting

The build is designed to run from committed sources alone. If a from-scratch
build fails, these are the classes of problem seen during development and how to
read them:

- **`… : No such file or directory` for a header** (e.g. `keyTemplates.h`,
  `SecPkcs12.h`). A staged header or a pinned source tree is missing. Confirm the
  relevant `libsecurity_*` tree is present at the repository root and that
  `STAGE=bootstrap` was run after any source change. Header staging happens in
  bootstrap; `STAGE=all` reuses whatever bootstrap produced.

- **`… was not declared in this scope`** for a `Sec*` symbol. A private header is
  being shadowed. The full private headers are staged into
  `/usr/local/SecurityPieces/PrivateHeaders/`; thin stubs must not also be staged
  into `Headers/` for the same name.

- **`ld: framework not found security_agent_client`** (or `tokend_client`,
  `securityd_server`). You built `x86_64` only. Rebuild with
  `ARCHES='x86_64 i386'` — these frameworks are produced in the i386 build chain.

- **`resolved N/26 archives … ABORT`** where N < 26. A component did not produce
  its archive. The named components in the preceding `!! MISSING … archive`
  lines identify which; check that each has a source tree at the repository root
  and inspect its log under `cc-build/<component>-<arch>/build.log`.

- **`CSSMERR_DL_INVALID_DB_HANDLE` on keychain unlock after install.** The
  framework and daemon are not a matched pair, or the dyld cache was not rebuilt.
  Reinstall both from the same build with `install-consistent-and-reboot.sh`.

- **Keychain-unlock SIGSEGV / vtable crash.** The CSSM plugin `abstractsession`
  headers must be generated once and shared by every consumer. This is handled in
  `build-consistent-framework.sh`; if you modified the generator or the build
  order, ensure `cdsa_plugin` builds before `apple_cspdl` / `sd_cspdl`.

### 10.6-specific notes

- `mktemp` on 10.6 requires a template argument (`mktemp -t name`); bare `mktemp`
  fails. The scripts account for this.
- Some components require specific compiler behavior encoded in the scripts (e.g.
  the ANTLR runtime skips a Windows-only source file). These are handled; a
  vanilla `xcodebuild` invocation outside the scripts may not reproduce them.
