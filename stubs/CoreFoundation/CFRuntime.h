/*
 * CFRuntime.h — SL-BACKPORT shim for the 10.6 SDK.
 *
 * <CoreFoundation/CFRuntime.h> is a PRIVATE CoreFoundation header: the CF
 * runtime-class registration API (how a C++/C type becomes a first-class CF
 * object). It is NOT shipped in the public 10.6 SDK's CoreFoundation.framework
 * Headers, but the SYMBOLS it declares ARE present in the 10.6 CoreFoundation
 * dylib (verified with nm) — every CFTypeRef on 10.6 is created through exactly
 * this machinery, so it is fully present at runtime.
 *
 * libsecurity_utilities' seccfobject.h / cfclass.h (and the CMSDecoder/CMSEncoder
 * in libsecurity_cms) include this header to derive Sec* objects from the CF
 * runtime. They use a small, STABLE slice of the API: CFRuntimeBase,
 * CFRuntimeClass, _kCFRuntimeNotATypeID, _CFRuntimeCreateInstance,
 * _CFRuntimeRegisterClass, _CFRuntimeSetInstanceTypeID, _CFRuntimeInitStaticInstance.
 *
 * The declarations below are the canonical CF-550-era (10.6) contents of this
 * header — the exact struct layouts and prototypes the 10.6 CoreFoundation
 * implements. Staging this header lets the dependent subprojects compile and
 * link against the existing 10.6 CF dylib. This is the §2.10-class fix for a
 * PRIVATE-but-present API: provide the missing header for symbols that DO exist
 * in the OS (contrast with CommonCryptorSPI, whose symbols are absent).
 *
 * Source of truth: Apple CF-550.x CFRuntime.h (10.6). Kept minimal-but-complete
 * for what the Security subprojects reference.
 */

#if !defined(__COREFOUNDATION_CFRUNTIME__)
#define __COREFOUNDATION_CFRUNTIME__ 1

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFDictionary.h>

CF_EXTERN_C_BEGIN

/* All CF "instances" start with this structure.  Never refer to
 * these fields directly -- they are for CF's use and may be added
 * to or removed or change format without warning.  Binary
 * compatibility for uses of this structure is not guaranteed from
 * release to release.
 */
typedef struct __CFRuntimeBase {
    uintptr_t _cfisa;
    uint8_t _cfinfo[4];
#if __LP64__
    uint32_t _rc;
#endif
} CFRuntimeBase;

#if __LP64__
#define INIT_CFRUNTIME_BASE(...) {0, {0, 0, 0, 0}, 0}
#else
#define INIT_CFRUNTIME_BASE(...) {0, {0, 0, 0, 0}}
#endif

#define _kCFRuntimeNotATypeID (0UL)
#define _kCFRuntimeScannedObject (1UL << 0)
#define _kCFRuntimeResourcefulObject (1UL << 2)
#define _kCFRuntimeCustomRefCount (1UL << 3)

typedef struct __CFRuntimeClass {
    CFIndex version;
    const char *className;
    void (*init)(CFTypeRef cf);
    CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf);
#if MAC_OS_X_VERSION_10_2 <= MAC_OS_X_VERSION_MAX_ALLOWED
    void (*finalize)(CFTypeRef cf);
#else
    void (*dealloc)(CFTypeRef cf);
#endif
    Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2);
    CFHashCode (*hash)(CFTypeRef cf);
    CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions);
    CFStringRef (*copyDebugDesc)(CFTypeRef cf);

#define CF_RECLAIM_AVAILABLE 1
    void (*reclaim)(CFTypeRef cf);

#define CF_REFCOUNT_AVAILABLE 1
    uint32_t (*refcount)(intptr_t op, CFTypeRef cf);
} CFRuntimeClass;

#define RADAR_5115468_FIXED 1

/* Registns a new class with the CF runtime.  Pass in a
 * pointer to a CFRuntimeClass structure.  The pointer is
 * remembered by the CF runtime -- the structure is NOT copied.
 */
CF_EXPORT CFTypeID _CFRuntimeRegisterClass(const CFRuntimeClass * const cls);

CF_EXPORT const CFRuntimeClass * _CFRuntimeGetClassWithTypeID(CFTypeID typeID);

CF_EXPORT void _CFRuntimeUnregisterClassWithTypeID(CFTypeID typeID);

/* Creates a new CF instance of the class specified by the
 * given CFTypeID, using the given allocator, and returns it.
 */
CF_EXPORT CFTypeRef _CFRuntimeCreateInstance(CFAllocatorRef allocator, CFTypeID typeID, CFIndex extraBytes, unsigned char *category);

CF_EXPORT void _CFRuntimeSetInstanceTypeID(CFTypeRef cf, CFTypeID typeID);

CF_EXPORT void _CFRuntimeInitStaticInstance(void *memory, CFTypeID typeID);
#define CF_HAS_INIT_STATIC_INSTANCE 1

CF_EXTERN_C_END

#endif /* ! __COREFOUNDATION_CFRUNTIME__ */
