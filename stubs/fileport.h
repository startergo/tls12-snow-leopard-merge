/*
 * fileport.h  --  Snow Leopard (10.6.8) compatibility shim
 *
 * securityd-55009 #includes <System/sys/fileport.h>, introduced in 10.7. The
 * 10.6.8 SDK lacks the header, but the functions exist in the runtime:
 * nm /usr/lib/libSystem.B.dylib shows _fileport_makeport and _fileport_makefd
 * are exported (T). Header-only gap; declaring the prototypes lets securityd
 * compile and link against what the system already provides.
 *
 * A fileport is a mach port that wraps a file descriptor so it can be passed
 * across a mach IPC boundary (securityd uses it to hand the userPrefs fd to
 * SecurityAgent). Signatures match Apple's 10.7 <sys/fileport.h>.
 */
#ifndef _SYS_FILEPORT_H_COMPAT_SHIM
#define _SYS_FILEPORT_H_COMPAT_SHIM

#include <mach/port.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

typedef mach_port_t fileport_t;

#define FILEPORT_NULL ((fileport_t)0)

/*
 * fileport_makeport: create a fileport naming the given fd.
 * fileport_makefd:   recover a new fd from a received fileport.
 * Both are exported by libSystem on 10.6.8.
 */
extern int fileport_makeport(int fd, fileport_t *port);
extern int fileport_makefd(fileport_t port);

__END_DECLS

#endif /* _SYS_FILEPORT_H_COMPAT_SHIM */
