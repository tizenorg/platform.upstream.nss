/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _HASH_H_
#define _HASH_H_

#include "seccomon.h"
#include "hasht.h"
#include "secoidt.h"

SEC_BEGIN_PROTOS

/*
** Generic hash api.  
*/

extern unsigned int  HASH_ResultLen(HASH_HashType type);

__attribute__ ((visibility ("default"))) extern unsigned int  HASH_ResultLenContext(HASHContext *context);

__attribute__ ((visibility ("default"))) extern unsigned int  HASH_ResultLenByOidTag(SECOidTag hashOid);

__attribute__ ((visibility ("default"))) extern SECStatus     HASH_HashBuf(HASH_HashType type,
				 unsigned char *dest,
				 const unsigned char *src,
				 PRUint32 src_len);

__attribute__ ((visibility ("default"))) extern HASHContext * HASH_Create(HASH_HashType type);

__attribute__ ((visibility ("default"))) extern HASHContext * HASH_Clone(HASHContext *context);

__attribute__ ((visibility ("default"))) extern void          HASH_Destroy(HASHContext *context);

__attribute__ ((visibility ("default"))) extern void          HASH_Begin(HASHContext *context);

__attribute__ ((visibility ("default"))) extern void          HASH_Update(HASHContext *context,
				const unsigned char *src,
				unsigned int len);

__attribute__ ((visibility ("default"))) extern void          HASH_End(HASHContext *context,
			     unsigned char *result,
			     unsigned int *result_len,
			     unsigned int max_result_len);
			     
__attribute__ ((visibility ("default"))) extern HASH_HashType HASH_GetType(HASHContext *context);

__attribute__ ((visibility ("default"))) extern const SECHashObject * HASH_GetHashObject(HASH_HashType type);

__attribute__ ((visibility ("default"))) extern const SECHashObject * HASH_GetHashObjectByOidTag(SECOidTag hashOid);

__attribute__ ((visibility ("default"))) extern HASH_HashType HASH_GetHashTypeByOidTag(SECOidTag hashOid);
__attribute__ ((visibility ("default"))) extern SECOidTag HASH_GetHashOidTagByHMACOidTag(SECOidTag hmacOid);
__attribute__ ((visibility ("default"))) extern SECOidTag HASH_GetHMACOidTagByHashOidTag(SECOidTag hashOid);

SEC_END_PROTOS

#endif /* _HASH_H_ */
