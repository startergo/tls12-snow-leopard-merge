/*
 * tls12_interpose.c — dyld __DATA,__interpose section
 *
 * DYLD_INSERT_LIBRARIES + __interpose works WITHOUT DYLD_FORCE_FLAT_NAMESPACE.
 * dyld processes this section at bind time and redirects calls to the original
 * symbols to our replacement functions — even for two-level namespace binaries
 * that link directly against Security.framework.
 *
 * Pattern: { &our_replacement, &original_in_loaded_image }
 *
 * We prefix our implementations with tls12__ to avoid name collision with
 * the Security.framework symbols we're replacing.
 */

#include <SecureTransport.h>
#include <Security/SecureTransport.h>

/* Our renamed implementations — defined as wrappers that call the real
 * functions in this dylib (which have the patched TLS 1.2 code).
 * We use the _tls12 prefix to distinguish from Security's versions. */

/* These are the actual implementations from sslTransport.c / sslContext.c
 * compiled into this dylib. We re-export them under tls12__ names. */
extern OSStatus SSLHandshake(SSLContextRef ctx);
extern OSStatus SSLRead(SSLContextRef ctx, void *data, size_t dataLength, size_t *processed);
extern OSStatus SSLWrite(SSLContextRef ctx, const void *data, size_t dataLength, size_t *bytesWritten);
extern OSStatus SSLClose(SSLContextRef ctx);
extern OSStatus SSLNewContext(Boolean isServer, SSLContextRef *contextPtr);
extern OSStatus SSLDisposeContext(SSLContextRef ctx);

/* Wrapper functions with unique names for the interpose table */
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLHandshake(SSLContextRef ctx) { return SSLHandshake(ctx); }
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLRead(SSLContextRef ctx, void *d, size_t l, size_t *p) { return SSLRead(ctx,d,l,p); }
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLWrite(SSLContextRef ctx, const void *d, size_t l, size_t *p) { return SSLWrite(ctx,d,l,p); }
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLClose(SSLContextRef ctx) { return SSLClose(ctx); }
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLNewContext(Boolean s, SSLContextRef *p) { return SSLNewContext(s,p); }
__attribute__((visibility("hidden")))
static OSStatus tls12_SSLDisposeContext(SSLContextRef ctx) { return SSLDisposeContext(ctx); }

typedef struct { const void *replacement; const void *original; } interpose_t;

__attribute__((used))
static const interpose_t interpose_table[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void*)tls12_SSLHandshake,    (const void*)SSLHandshake },
    { (const void*)tls12_SSLRead,         (const void*)SSLRead },
    { (const void*)tls12_SSLWrite,        (const void*)SSLWrite },
    { (const void*)tls12_SSLClose,        (const void*)SSLClose },
    { (const void*)tls12_SSLNewContext,   (const void*)SSLNewContext },
    { (const void*)tls12_SSLDisposeContext,(const void*)SSLDisposeContext },
};
