/*
 * stubs/ModuleAttacher_stub.c
 *
 * Stub implementation of ModuleAttacher for our cross-compile build.
 * The real ModuleAttacher.c calls private CSSM plugin-attachment APIs
 * not available in the cross-compile environment.
 *
 * attachToModules() is called from attachToAll() in appleCdsa.c, which
 * is called from SSLNewContext(). On Snow Leopard the system Security
 * framework handles CDSA module management at runtime; our rebuilt
 * libsecurity_ssl.dylib will be loaded into a process that already has
 * the Security framework attached, so returning an error here causes
 * SSLNewContext() to fail gracefully rather than crash.
 *
 * When the patched dylib is installed on Snow Leopard and loaded inside
 * the real Security.framework umbrella, the real ModuleAttacher object
 * from the umbrella's link will be used instead of this stub.
 */

#include <Security/cssm.h>
#include "sslContext.h"

/* Declared in ModuleAttacher.h */
CSSM_RETURN attachToModules(
    CSSM_CSP_HANDLE *cspHand,
    CSSM_CL_HANDLE  *clHand,
    CSSM_TP_HANDLE  *tpHand)
{
    /*
     * Return an error so attachToAll() → errSSLModuleAttach.
     * When running inside the real Security umbrella this stub is
     * not linked; the umbrella provides the real implementation.
     */
    return CSSMERR_CSSM_FUNCTION_NOT_IMPLEMENTED;
}
