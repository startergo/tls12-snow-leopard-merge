/*
 * stubs/security_utilities/debugging.h
 *
 * Stub for libsecurity_utilities/debugging.h — provides the secdebug() macro
 * that sslDebug.h references unconditionally.
 *
 * The real implementation logs via DTrace/syslog. For our standalone
 * cross-compile build we discard all debug output. This is correct for a
 * deployment (NDEBUG) build; sslDebug.h already gates all call sites on
 * NDEBUG so none of them generate any code.
 */
#ifndef _SECURITY_UTILITIES_DEBUGGING_H_
#define _SECURITY_UTILITIES_DEBUGGING_H_

#define secdebug(scope, format, ...)    do {} while (0)

#endif
