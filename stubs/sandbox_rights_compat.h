/*
 * sandbox_rights_compat.h  --  Snow Leopard (10.6.8) compatibility shim
 *
 * securityd-55009's AuthorizationEngine.cpp uses SANDBOX_FILTER_RIGHT_NAME,
 * a sandbox_filter_type enum value Apple added in 10.7. The 10.6.8 <sandbox.h>
 * enum stops at SANDBOX_FILTER_LOCAL_NAME (3).
 *
 * Usage in securityd:
 *     sandbox_check(pid, "authorization-right-obtain",
 *                   SANDBOX_FILTER_RIGHT_NAME, rightName)
 * This is a DEFENSE-IN-DEPTH check: it denies a right if the calling process is
 * sandboxed against obtaining it. On 10.6.8 the sandbox operation
 * "authorization-right-obtain" does not exist in any profile, so sandbox_check
 * returns 0 (== not denied) regardless. Defining the constant as
 * SANDBOX_FILTER_NONE (0) makes the call a well-formed global check of a
 * nonexistent operation, which 10.6.8's sandbox_check answers with 0 (allowed) --
 * the correct, safe fallback for a system without per-right sandbox filtering.
 * (This affects ONLY the auxiliary sandbox gate, never the username/auth flow.)
 *
 * This header is force-included via the prefix header so it applies everywhere
 * SANDBOX_FILTER_RIGHT_NAME is referenced, after <sandbox.h> is included.
 */
#ifndef _SANDBOX_RIGHTS_COMPAT_SHIM
#define _SANDBOX_RIGHTS_COMPAT_SHIM

#include <sandbox.h>

#ifndef SANDBOX_FILTER_RIGHT_NAME
#define SANDBOX_FILTER_RIGHT_NAME SANDBOX_FILTER_NONE
#endif

#endif /* _SANDBOX_RIGHTS_COMPAT_SHIM */
