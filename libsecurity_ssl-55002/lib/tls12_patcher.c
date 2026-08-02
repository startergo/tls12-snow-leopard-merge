/*
 * tls12_patcher.c - Runtime in-process patcher for TLS 1.2 on Snow Leopard
 *
 * This file is compiled into our dylib. When loaded via LC_LOAD_WEAK_DYLIB
 * into an app (Safari, curl, etc.), the constructor runs AFTER Security.framework
 * is fully initialized. It then patches Security's SSL function bodies in-memory
 * to redirect to our TLS 1.2 implementations.
 *
 * No symbol conflicts: our SSL implementations are named tls12_SSLxxx (private),
 * and we only export _tls12_init (the constructor) with a unique name.
 */

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Our TLS 1.2 SSL implementations are defined in the other source files
 * (sslTransport.c, sslContext.c, etc.) but compiled with renamed symbols
 * to avoid conflicts. We reference them here by their internal names.
 *
 * Actually: since we compile the full SSL layer into this dylib, our
 * implementations ARE named SSLHandshake etc. but we prevent them from
 * being exported by using the exports list. The patching approach instead
 * will write trampolines in Security's memory pointing to our functions.
 *
 * We get our function addresses via dlsym on OURSELVES:
 */

/* Write a 14-byte absolute JMP trampoline at 'target' pointing to 'dest' */
static int
write_trampoline(void *target, void *dest)
{
    /* Make page writable */
    vm_address_t start = (vm_address_t)target & ~(vm_page_size - 1);
    vm_address_t end   = ((vm_address_t)target + 14 + vm_page_size - 1) & ~(vm_page_size - 1);
    vm_size_t    plen  = end - start;
    kern_return_t kr = vm_protect(mach_task_self(), start, plen,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        /* Try mprotect as fallback */
        if (mprotect((void*)start, plen,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            fprintf(stderr, "[tls12] vm_protect failed for %p: %d\n", target, kr);
            return -1;
        }
    }

    /* Write: FF 25 00 00 00 00 <8-byte-addr> */
    uint8_t *p = (uint8_t *)target;
    p[0] = 0xFF; p[1] = 0x25;
    p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
    uint64_t addr = (uint64_t)dest;
    memcpy(p + 6, &addr, 8);

    /* Restore protection */
    vm_protect(mach_task_self(), start, plen,
               FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    return 0;
}

/* SSL function list to patch in Security.framework */
    static const char *ssl_syms[] = {
    "_SSLHandshake",
    "_SSLRead",
    "_SSLWrite",
    "_SSLClose",
    "_SSLNewContext",
    "_SSLDisposeContext",
    "_SSLSetIOFuncs",
    "_SSLSetConnection",
    "_SSLGetConnection",
    "_SSLGetSessionState",
    "_SSLGetNegotiatedProtocolVersion",
    "_SSLGetNegotiatedCipher",
    "_SSLSetProtocolVersionEnabled",
    "_SSLGetProtocolVersionEnabled",
    "_SSLSetProtocolVersion",
    "_SSLGetProtocolVersion",
    "_SSLGetNumberEnabledCiphers",
    "_SSLGetEnabledCiphers",
    "_SSLSetEnabledCiphers",
    "_SSLGetBufferedReadSize",
    "_SSLSetEnableCertVerify",
    "_SSLGetEnableCertVerify",
    "_SSLSetAllowsExpiredCerts",
    "_SSLGetAllowsExpiredCerts",
    "_SSLSetAllowsExpiredRoots",
    "_SSLGetAllowsExpiredRoots",
    "_SSLSetAllowsAnyRoot",
    "_SSLGetAllowsAnyRoot",
    "_SSLSetPeerDomainName",
    "_SSLGetPeerDomainNameLength",
    "_SSLGetPeerDomainName",
    "_SSLCopyPeerCertificates",
    "_SSLGetPeerCertificates",
    "_SSLCopyPeerTrust",
    NULL
};

/* Trust function overrides: Security symbol → our internal implementation name */
static const struct { const char *sec_sym; const char *our_sym; } trust_syms[] = {
    /* DISABLED: real Security SecTrust* now works (roots present). Patching these
       stubbed SecTrustGetResult to return NULL cert chain -> broke Safari trust dialog
       ("data does not appear to be a valid certificate"). Leave real functions intact. */
    { NULL, NULL }
};

__attribute__((constructor))
static void tls12_init(void)
{
    /* Get handle to ourselves to find our implementations */
    void *self = dlopen("/usr/local/lib/libsecurity_ssl_tls12.dylib",
                        RTLD_NOLOAD | RTLD_LOCAL);
    if (!self) {
        /* Try RTLD_SELF equivalent */
        self = dlopen(NULL, RTLD_LOCAL);
    }
    if (!self) {
        fprintf(stderr, "[tls12] could not get self handle\n");
        return;
    }

    /* Get Security handle to find original function addresses */
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security",
                       RTLD_NOLOAD | RTLD_LOCAL);
    if (!sec) {
        fprintf(stderr, "[tls12] could not find Security\n");
        dlclose(self);
        return;
    }

    int patched = 0;
    int failed  = 0;

    for (int i = 0; ssl_syms[i] != NULL; i++) {
        /* Find our implementation (without leading _) */
        const char *sym = ssl_syms[i] + 1;  /* skip leading _ */

        void *our_impl = dlsym(self, sym);
        if (!our_impl) {
            /* Try RTLD_DEFAULT in case we're the same image */
            our_impl = dlsym(RTLD_DEFAULT, sym);
        }

        /* Find Security's current implementation */
        void *sec_impl = dlsym(sec, sym);

        if (!sec_impl) {
            /* Symbol not found in Security, skip */
            continue;
        }

        if (!our_impl || our_impl == sec_impl) {
            /* No distinct implementation to patch, skip */
            continue;
        }

        /* Patch Security's function to jump to ours */
        if (write_trampoline(sec_impl, our_impl) == 0) {
            patched++;
        } else {
            fprintf(stderr, "[tls12] failed to patch %s\n", sym);
            failed++;
        }
    }

    fprintf(stderr, "[tls12] patched %d SSL functions (%d failed)\n",
            patched, failed);

    /* Patch trust evaluation functions using explicit name mapping */
    for (int i = 0; trust_syms[i].sec_sym != NULL; i++) {
        void *our_impl = dlsym(self, trust_syms[i].our_sym);
        void *sec_impl = dlsym(sec, trust_syms[i].sec_sym);
        if (!our_impl || !sec_impl) {
            fprintf(stderr, "[tls12] trust: missing %s (our=%p sec=%p)\n",
                trust_syms[i].sec_sym, our_impl, sec_impl);
            continue;
        }
        if (write_trampoline(sec_impl, our_impl) == 0) {
            fprintf(stderr, "[tls12] patched %s\n", trust_syms[i].sec_sym);
        } else {
            fprintf(stderr, "[tls12] failed to patch %s\n", trust_syms[i].sec_sym);
        }
    }

    dlclose(sec);
    dlclose(self);
}
