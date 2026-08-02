/*
 * Copyright (c) 2005-2010 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

//
// Fast hasing support
//
#include "hashing.h"
#include "unix++.h"


namespace Security {


//
// Basic DynamicHash infrastructure
//
DynamicHash::~DynamicHash()
{
	// virtual
}


//
// CommonCrypto-based DynamicHash instances
//
// SL-BACKPORT: CCHashInstance is built on the CCDigest* SPI (CommonDigestSPI.h),
// which is 10.7+ only and absent from the 10.6 SDK. The class declaration in
// hashing.h is gated on SL_HAVE_CC_DIGEST_SPI (OFF for 10.6); this definition
// must be gated identically or it references the missing SPI. No code in the
// Security-55002 subprojects we build uses CCHashInstance.
#if SL_HAVE_CC_DIGEST_SPI
CCHashInstance::CCHashInstance(CCDigestAlg alg)
{
	if (!(mDigest = CCDigestCreate(alg)))
		UnixError::throwMe(ENOMEM);
}
#endif // SL_HAVE_CC_DIGEST_SPI


}	// Security
