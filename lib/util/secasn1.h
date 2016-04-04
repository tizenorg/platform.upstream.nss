/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * Support for encoding/decoding of ASN.1 using BER/DER (Basic/Distinguished
 * Encoding Rules).  The routines are found in and used extensively by the
 * security library, but exported for other use.
 */

#ifndef _SECASN1_H_
#define _SECASN1_H_

#include "utilrename.h"
#include "plarena.h"

#include "seccomon.h"
#include "secasn1t.h"


/************************************************************************/
SEC_BEGIN_PROTOS

/*
 * XXX These function prototypes need full, explanatory comments.
 */

/*
** Decoding.
*/

__attribute__ ((visibility ("default"))) extern SEC_ASN1DecoderContext *SEC_ASN1DecoderStart(PLArenaPool *pool,
						    void *dest,
						    const SEC_ASN1Template *t);

/* XXX char or unsigned char? */
__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1DecoderUpdate(SEC_ASN1DecoderContext *cx,
				       const char *buf,
				       unsigned long len);

__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1DecoderFinish(SEC_ASN1DecoderContext *cx);

/* Higher level code detected an error, abort the rest of the processing */
__attribute__ ((visibility ("default"))) extern void SEC_ASN1DecoderAbort(SEC_ASN1DecoderContext *cx, int error);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1DecoderSetFilterProc(SEC_ASN1DecoderContext *cx,
					 SEC_ASN1WriteProc fn,
					 void *arg, PRBool no_store);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1DecoderClearFilterProc(SEC_ASN1DecoderContext *cx);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1DecoderSetNotifyProc(SEC_ASN1DecoderContext *cx,
					 SEC_ASN1NotifyProc fn,
					 void *arg);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1DecoderClearNotifyProc(SEC_ASN1DecoderContext *cx);

__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1Decode(PLArenaPool *pool, void *dest,
				const SEC_ASN1Template *t,
				const char *buf, long len);

/* Both classic ASN.1 and QuickDER have a feature that removes leading zeroes
   out of SEC_ASN1_INTEGER if the caller sets siUnsignedInteger in the type
   field of the target SECItem prior to calling the decoder. Otherwise, the
   type field is ignored and untouched. For SECItem that are dynamically
   allocated (from POINTER, SET OF, SEQUENCE OF) the decoder sets the type
   field to siBuffer. */

__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1DecodeItem(PLArenaPool *pool, void *dest,
				    const SEC_ASN1Template *t,
				    const SECItem *src);

__attribute__ ((visibility ("default"))) extern SECStatus SEC_QuickDERDecodeItem(PLArenaPool* arena, void* dest,
                     const SEC_ASN1Template* templateEntry,
                     const SECItem* src);

/*
** Encoding.
*/

__attribute__ ((visibility ("default"))) extern SEC_ASN1EncoderContext *SEC_ASN1EncoderStart(const void *src,
						    const SEC_ASN1Template *t,
						    SEC_ASN1WriteProc fn,
						    void *output_arg);

/* XXX char or unsigned char? */
__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1EncoderUpdate(SEC_ASN1EncoderContext *cx,
				       const char *buf,
				       unsigned long len);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderFinish(SEC_ASN1EncoderContext *cx);

/* Higher level code detected an error, abort the rest of the processing */
__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderAbort(SEC_ASN1EncoderContext *cx, int error);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderSetNotifyProc(SEC_ASN1EncoderContext *cx,
					 SEC_ASN1NotifyProc fn,
					 void *arg);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderClearNotifyProc(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderSetStreaming(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderClearStreaming(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void sec_ASN1EncoderSetDER(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void sec_ASN1EncoderClearDER(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderSetTakeFromBuf(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern void SEC_ASN1EncoderClearTakeFromBuf(SEC_ASN1EncoderContext *cx);

__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1Encode(const void *src, const SEC_ASN1Template *t,
				SEC_ASN1WriteProc output_proc,
				void *output_arg);

/*
 * If both pool and dest are NULL, the caller should free the returned SECItem
 * with a SECITEM_FreeItem(..., PR_TRUE) call.  If pool is NULL but dest is
 * not NULL, the caller should free the data buffer pointed to by dest with a
 * SECITEM_FreeItem(dest, PR_FALSE) or PORT_Free(dest->data) call.
 */
__attribute__ ((visibility ("default"))) extern SECItem * SEC_ASN1EncodeItem(PLArenaPool *pool, SECItem *dest,
				    const void *src, const SEC_ASN1Template *t);

__attribute__ ((visibility ("default"))) extern SECItem * SEC_ASN1EncodeInteger(PLArenaPool *pool,
				       SECItem *dest, long value);

__attribute__ ((visibility ("default"))) extern SECItem * SEC_ASN1EncodeUnsignedInteger(PLArenaPool *pool,
					       SECItem *dest,
					       unsigned long value);

__attribute__ ((visibility ("default"))) extern SECStatus SEC_ASN1DecodeInteger(SECItem *src,
				       unsigned long *value);

/*
** Utilities.
*/

/*
 * We have a length that needs to be encoded; how many bytes will the
 * encoding take?
 */
__attribute__ ((visibility ("default"))) extern int SEC_ASN1LengthLength (unsigned long len);

/* encode the length and return the number of bytes we encoded. Buffer
 * must be pre allocated  */
__attribute__ ((visibility ("default"))) extern int SEC_ASN1EncodeLength(unsigned char *buf,int value);

/*
 * Find the appropriate subtemplate for the given template.
 * This may involve calling a "chooser" function, or it may just
 * be right there.  In either case, it is expected to *have* a
 * subtemplate; this is asserted in debug builds (in non-debug
 * builds, NULL will be returned).
 *
 * "thing" is a pointer to the structure being encoded/decoded
 * "encoding", when true, means that we are in the process of encoding
 *	(as opposed to in the process of decoding)
 */
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template *
SEC_ASN1GetSubtemplate (const SEC_ASN1Template *inTemplate, void *thing,
			PRBool encoding);

/* whether the template is for a primitive type or a choice of
 * primitive types
 */
__attribute__ ((visibility ("default"))) extern PRBool SEC_ASN1IsTemplateSimple(const SEC_ASN1Template *theTemplate);

/************************************************************************/

/*
 * Generic Templates
 * One for each of the simple types, plus a special one for ANY, plus:
 *	- a pointer to each one of those
 *	- a set of each one of those
 *	- a sequence of each one of those
 *
 * Note that these are alphabetical (case insensitive); please add new
 * ones in the appropriate place.
 */

__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_AnyTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_BitStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_BMPStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_BooleanTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_EnumeratedTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_GeneralizedTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_IA5StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_IntegerTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_NullTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_ObjectIDTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_OctetStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PrintableStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_T61StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_UniversalStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_UTCTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_UTF8StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_VisibleStringTemplate[];

__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToAnyTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToBitStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToBMPStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToBooleanTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToEnumeratedTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToGeneralizedTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToIA5StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToIntegerTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToNullTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToObjectIDTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToOctetStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToPrintableStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToT61StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToUniversalStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToUTCTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToUTF8StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_PointerToVisibleStringTemplate[];

__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfAnyTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfBitStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfBMPStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfBooleanTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfEnumeratedTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfGeneralizedTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfIA5StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfIntegerTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfNullTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfObjectIDTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfOctetStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfPrintableStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfT61StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfUniversalStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfUTCTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfUTF8StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SequenceOfVisibleStringTemplate[];

__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfAnyTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfBitStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfBMPStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfBooleanTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfEnumeratedTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfGeneralizedTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfIA5StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfIntegerTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfNullTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfObjectIDTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfOctetStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfPrintableStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfT61StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfUniversalStringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfUTCTimeTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfUTF8StringTemplate[];
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SetOfVisibleStringTemplate[];

/*
 * Template for skipping a subitem; this only makes sense when decoding.
 */
__attribute__ ((visibility ("default"))) extern const SEC_ASN1Template SEC_SkipTemplate[];

/* These functions simply return the address of the above-declared templates.
** This is necessary for Windows DLLs.  Sigh.
*/
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_AnyTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_BMPStringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_BooleanTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_BitStringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_GeneralizedTimeTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_IA5StringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_IntegerTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_NullTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_ObjectIDTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_OctetStringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_UTCTimeTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_UTF8StringTemplate)

__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_PointerToAnyTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_PointerToOctetStringTemplate)

__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_SetOfAnyTemplate)

__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_EnumeratedTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_PointerToEnumeratedTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_SequenceOfAnyTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_SequenceOfObjectIDTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_SkipTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_UniversalStringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_PrintableStringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_T61StringTemplate)
__attribute__ ((visibility ("default"))) SEC_ASN1_CHOOSER_DECLARE(SEC_PointerToGeneralizedTimeTemplate)
SEC_END_PROTOS
#endif /* _SECASN1_H_ */
