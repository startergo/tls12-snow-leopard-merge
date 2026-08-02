/*
 * membershipPriv.h  --  Snow Leopard (10.6.8) compatibility shim
 *
 * securityd-55009's AuthorizationRule.cpp does:
 *     extern "C" { #include <membershipPriv.h> }
 * and uses mbr_group_name_to_uuid / mbr_uid_to_uuid / mbr_check_membership.
 * The 10.6.8 SDK ships <membership.h> but NOT the private <membershipPriv.h>.
 * The mbr_* functions are exported by libSystem on 10.6.8 (verified via nm:
 * _mbr_group_name_to_uuid, _mbr_uid_to_uuid, _mbr_check_membership present).
 * Header-only gap; declare the prototypes. Signatures match Apple's
 * membershipPriv.h. <membership.h> already provides uuid_t etc.
 */
#ifndef _MEMBERSHIPPRIV_H_COMPAT_SHIM
#define _MEMBERSHIPPRIV_H_COMPAT_SHIM

#include <membership.h>
#include <uuid/uuid.h>
#include <sys/types.h>

__BEGIN_DECLS

/* name/id -> uuid translation (private SPI, in libSystem on 10.6.8) */
extern int mbr_group_name_to_uuid(const char *name, uuid_t uu);
extern int mbr_user_name_to_uuid(const char *name, uuid_t uu);

__END_DECLS

#endif /* _MEMBERSHIPPRIV_H_COMPAT_SHIM */
