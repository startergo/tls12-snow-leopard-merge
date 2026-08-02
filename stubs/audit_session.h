/*
 * audit_session.h  --  Snow Leopard (10.6.8) compatibility shim
 *
 * securityd-55009 #includes <bsm/audit_session.h>, which Apple introduced in
 * 10.7. The 10.6.8 SDK ships the rest of the bsm suite (audit.h, libbsm.h, ...)
 * but NOT this header. However, the underlying functionality DOES exist in the
 * 10.6.8 runtime: nm on /usr/lib/libSystem.B.dylib shows _audit_session_self and
 * _audit_session_join are exported (T). So this is a header-only gap; declaring
 * the prototypes + flag constants lets securityd-55009 compile and link against
 * the functions the running system already provides.
 *
 * Values for the AU_SESSION_FLAG_* constants and the auditinfo_addr_t-based
 * session model match Apple's 10.7 <bsm/audit_session.h> (the next train), which
 * is ABI-compatible with the 10.6.8 kernel audit session implementation.
 */
#ifndef _BSM_AUDIT_SESSION_H_COMPAT_SHIM
#define _BSM_AUDIT_SESSION_H_COMPAT_SHIM

#include <bsm/audit.h>          /* au_asid_t, auditinfo_addr_t, AU_IPv4, etc. */
#include <mach/port.h>          /* mach_port_name_t */
#include <sys/types.h>

__BEGIN_DECLS

/*
 * Session attribute flags carried in auditinfo_addr_t.ai_flags.
 * (Apple 10.7 bsm/audit_session.h values.)
 */
#ifndef AU_SESSION_FLAG_IS_INITIAL
#define AU_SESSION_FLAG_IS_INITIAL          0x0001  /* initial session */
#endif
#ifndef AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS
#define AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS  0x0010  /* has graphic access (WindowServer) */
#endif
#ifndef AU_SESSION_FLAG_HAS_TTY
#define AU_SESSION_FLAG_HAS_TTY             0x0020  /* has a TTY */
#endif
#ifndef AU_SESSION_FLAG_IS_REMOTE
#define AU_SESSION_FLAG_IS_REMOTE           0x1000  /* remote session */
#endif
#ifndef AU_SESSION_FLAG_HAS_CONSOLE_ACCESS
#define AU_SESSION_FLAG_HAS_CONSOLE_ACCESS  0x2000  /* console access */
#endif
#ifndef AU_SESSION_FLAG_HAS_AUTHENTICATED
#define AU_SESSION_FLAG_HAS_AUTHENTICATED   0x4000  /* a user has authenticated in this session */
#endif

/*
 * Special session id values.
 */
#ifndef AU_SESSION_ANY
#define AU_SESSION_ANY      ((au_asid_t)-1)
#endif

/*
 * Audit session lifecycle event codes (Apple 10.7 bsm/audit_session.h values).
 * securityd server.cpp compares the self-notify event against AUE_SESSION_CLOSE
 * to tear down a Session. These are the standard BSM AUE_SESSION_* event ids.
 */
#ifndef AUE_SESSION_START
#define AUE_SESSION_START   32800
#endif
#ifndef AUE_SESSION_UPDATE
#define AUE_SESSION_UPDATE  32801
#endif
#ifndef AUE_SESSION_END
#define AUE_SESSION_END     32802
#endif
#ifndef AUE_SESSION_CLOSE
#define AUE_SESSION_CLOSE   32803
#endif

/*
 * Session API (implemented in libSystem on 10.6.8; headers added in 10.7).
 *   audit_session_self  -> mach send right to the current audit session
 *   audit_session_join  -> join the audit session named by a port
 *   audit_session_port  -> obtain a port naming a session by asid
 */
extern mach_port_name_t audit_session_self(void);
extern au_asid_t        audit_session_join(mach_port_name_t port);
extern int              audit_session_port(au_asid_t asid, mach_port_name_t *port);

__END_DECLS

#endif /* _BSM_AUDIT_SESSION_H_COMPAT_SHIM */
