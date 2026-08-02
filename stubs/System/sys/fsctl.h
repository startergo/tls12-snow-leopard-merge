/*
 * System/sys/fsctl.h  --  Snow Leopard (10.6.8) compatibility shim (self-contained)
 *
 * securityd-55009 #includes <System/sys/fsctl.h> and uses ffsctl() with the
 * FSCTL_SYNC_* constants + FSCTL_SYNC_VOLUME command (all added in 10.7). On
 * 10.6.8 there is NO <sys/fsctl.h> at all (it was split out in 10.7), so this
 * shim must be self-contained -- it cannot #include <sys/fsctl.h>. ffsctl IS
 * exported by libSystem on 10.6.8 (verified via nm: _ffsctl present), so this is
 * a header-only gap: declare the prototype + constants directly.
 *
 * Values match Apple's 10.7 <sys/fsctl.h>. FSCTL_SYNC_VOLUME is an _IOW command
 * built with the standard ioctl encoding macros from <sys/ioccom.h>.
 */
#ifndef _SYSTEM_SYS_FSCTL_H_COMPAT_SHIM
#define _SYSTEM_SYS_FSCTL_H_COMPAT_SHIM

#include <sys/cdefs.h>
#include <sys/ioccom.h>     /* _IOW and friends (present on 10.6) */
#include <stdint.h>

/*
 * fs sync fsctl: the FSCTL_SYNC_VOLUME command and its flag bits (10.7 values).
 */
#ifndef FSCTL_SYNC_VOLUME
#define FSCTL_SYNC_VOLUME      _IOW('A', 19, uint32_t)
#endif
#ifndef FSCTL_SYNC_WAIT
#define FSCTL_SYNC_WAIT        0x00000001   /* wait for completion */
#endif
#ifndef FSCTL_SYNC_FULLSYNC
#define FSCTL_SYNC_FULLSYNC    0x00000002   /* fullsync (barrier) */
#endif

__BEGIN_DECLS
/*
 * ffsctl: fsctl on an open fd. Exported by libSystem on 10.6.8 but not declared
 * in any 10.6 header. Prototype matches Apple's 10.7 <sys/fsctl.h>.
 */
#ifndef _FFSCTL_DECLARED_SHIM
#define _FFSCTL_DECLARED_SHIM
extern int ffsctl(int fd, unsigned long request, void *data, unsigned int options);
#endif
__END_DECLS

#endif /* _SYSTEM_SYS_FSCTL_H_COMPAT_SHIM */
