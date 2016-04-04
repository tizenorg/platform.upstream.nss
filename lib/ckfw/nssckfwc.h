/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NSSCKFWC_H
#define NSSCKFWC_H

/*
 * nssckfwc.h
 *
 * This file prototypes all of the NSS Cryptoki Framework "wrapper" 
 * which implement the PKCS#11 API.  Technically, these are public
 * routines (with capital "NSS" prefixes), since they are called
 * from (generated) code within a Module using the Framework.
 * However, they should not be called except from those generated
 * calls.  Hence, the prototypes have been split out into this file.
 */

#ifndef NSSCKT_H
#include "nssckt.h"
#endif /* NSSCKT_H */

#ifndef NSSCKFWT_H
#include "nssckfwt.h"
#endif /* NSSCKFWT_H */

#ifndef NSSCKMDT_H
#include "nssckmdt.h"
#endif /* NSSCKMDT_H */

/*
 * NSSCKFWC_Initialize
 * NSSCKFWC_Finalize
 * NSSCKFWC_GetInfo
 * -- NSSCKFWC_GetFunctionList -- see the API insert file
 * NSSCKFWC_GetSlotList
 * NSSCKFWC_GetSlotInfo
 * NSSCKFWC_GetTokenInfo
 * NSSCKFWC_WaitForSlotEvent
 * NSSCKFWC_GetMechanismList
 * NSSCKFWC_GetMechanismInfo
 * NSSCKFWC_InitToken
 * NSSCKFWC_InitPIN
 * NSSCKFWC_SetPIN
 * NSSCKFWC_OpenSession
 * NSSCKFWC_CloseSession
 * NSSCKFWC_CloseAllSessions
 * NSSCKFWC_GetSessionInfo
 * NSSCKFWC_GetOperationState
 * NSSCKFWC_SetOperationState
 * NSSCKFWC_Login
 * NSSCKFWC_Logout
 * NSSCKFWC_CreateObject
 * NSSCKFWC_CopyObject
 * NSSCKFWC_DestroyObject
 * NSSCKFWC_GetObjectSize
 * NSSCKFWC_GetAttributeValue
 * NSSCKFWC_SetAttributeValue
 * NSSCKFWC_FindObjectsInit
 * NSSCKFWC_FindObjects
 * NSSCKFWC_FindObjectsFinal
 * NSSCKFWC_EncryptInit
 * NSSCKFWC_Encrypt
 * NSSCKFWC_EncryptUpdate
 * NSSCKFWC_EncryptFinal
 * NSSCKFWC_DecryptInit
 * NSSCKFWC_Decrypt
 * NSSCKFWC_DecryptUpdate
 * NSSCKFWC_DecryptFinal
 * NSSCKFWC_DigestInit
 * NSSCKFWC_Digest
 * NSSCKFWC_DigestUpdate
 * NSSCKFWC_DigestKey
 * NSSCKFWC_DigestFinal
 * NSSCKFWC_SignInit
 * NSSCKFWC_Sign
 * NSSCKFWC_SignUpdate
 * NSSCKFWC_SignFinal
 * NSSCKFWC_SignRecoverInit
 * NSSCKFWC_SignRecover
 * NSSCKFWC_VerifyInit
 * NSSCKFWC_Verify
 * NSSCKFWC_VerifyUpdate
 * NSSCKFWC_VerifyFinal
 * NSSCKFWC_VerifyRecoverInit
 * NSSCKFWC_VerifyRecover
 * NSSCKFWC_DigestEncryptUpdate
 * NSSCKFWC_DecryptDigestUpdate
 * NSSCKFWC_SignEncryptUpdate
 * NSSCKFWC_DecryptVerifyUpdate
 * NSSCKFWC_GenerateKey
 * NSSCKFWC_GenerateKeyPair
 * NSSCKFWC_WrapKey
 * NSSCKFWC_UnwrapKey
 * NSSCKFWC_DeriveKey
 * NSSCKFWC_SeedRandom
 * NSSCKFWC_GenerateRandom
 * NSSCKFWC_GetFunctionStatus
 * NSSCKFWC_CancelFunction
 */

/*
 * NSSCKFWC_Initialize
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Initialize
(
  NSSCKFWInstance **pFwInstance,
  NSSCKMDInstance *mdInstance,
  CK_VOID_PTR pInitArgs
);

/*
 * NSSCKFWC_Finalize
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Finalize
(
  NSSCKFWInstance **pFwInstance
);

/*
 * NSSCKFWC_GetInfo
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetInfo
(
  NSSCKFWInstance *fwInstance,
  CK_INFO_PTR pInfo
);
  
/*
 * C_GetFunctionList is implemented entirely in the Module's file which
 * includes the Framework API insert file.  It requires no "actual"
 * NSSCKFW routine.
 */

/*
 * NSSCKFWC_GetSlotList
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetSlotList
(
  NSSCKFWInstance *fwInstance,
  CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount
);
 
/*
 * NSSCKFWC_GetSlotInfo
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetSlotInfo
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
);

/*
 * NSSCKFWC_GetTokenInfo
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetTokenInfo
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
);

/*
 * NSSCKFWC_WaitForSlotEvent
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_WaitForSlotEvent
(
  NSSCKFWInstance *fwInstance,
  CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pReserved
);

/*
 * NSSCKFWC_GetMechanismList
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetMechanismList
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
);

/*
 * NSSCKFWC_GetMechanismInfo
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetMechanismInfo
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo
);

/*
 * NSSCKFWC_InitToken
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_InitToken
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_CHAR_PTR pLabel
);

/*
 * NSSCKFWC_InitPIN
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_InitPIN
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen
);

/*
 * NSSCKFWC_SetPIN
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SetPIN
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
);

/*
 * NSSCKFWC_OpenSession
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_OpenSession
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID,
  CK_FLAGS flags,
  CK_VOID_PTR pApplication,
  CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession
);

/*
 * NSSCKFWC_CloseSession
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_CloseSession
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession
);

/*
 * NSSCKFWC_CloseAllSessions
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_CloseAllSessions
(
  NSSCKFWInstance *fwInstance,
  CK_SLOT_ID slotID
);

/*
 * NSSCKFWC_GetSessionInfo
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetSessionInfo
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
);

/*
 * NSSCKFWC_GetOperationState
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetOperationState
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG_PTR pulOperationStateLen
);

/*
 * NSSCKFWC_SetOperationState
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SetOperationState
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
);

/*
 * NSSCKFWC_Login
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Login
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen
);

/*
 * NSSCKFWC_Logout
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Logout
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession
);

/*
 * NSSCKFWC_CreateObject
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_CreateObject
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
);

/*
 * NSSCKFWC_CopyObject
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_CopyObject
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
);

/*
 * NSSCKFWC_DestroyObject
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DestroyObject
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
);

/*
 * NSSCKFWC_GetObjectSize
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetObjectSize
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize
);

/*
 * NSSCKFWC_GetAttributeValue
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetAttributeValue
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);
  
/*
 * NSSCKFWC_SetAttributeValue
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SetAttributeValue
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);

/*
 * NSSCKFWC_FindObjectsInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_FindObjectsInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);

/*
 * NSSCKFWC_FindObjects
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_FindObjects
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG ulMaxObjectCount,
  CK_ULONG_PTR pulObjectCount
);

/*
 * NSSCKFWC_FindObjectsFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_FindObjectsFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession
);

/*
 * NSSCKFWC_EncryptInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_EncryptInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_Encrypt
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Encrypt
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
);

/*
 * NSSCKFWC_EncryptUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_EncryptUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);

/*
 * NSSCKFWC_EncryptFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_EncryptFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
);

/*
 * NSSCKFWC_DecryptInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DecryptInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_Decrypt
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Decrypt
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);

/*
 * NSSCKFWC_DecryptUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DecryptUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);

/*
 * NSSCKFWC_DecryptFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DecryptFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
);

/*
 * NSSCKFWC_DigestInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DigestInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
);

/*
 * NSSCKFWC_Digest
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Digest
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);

/*
 * NSSCKFWC_DigestUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DigestUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen
);

/*
 * NSSCKFWC_DigestKey
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DigestKey
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_DigestFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DigestFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);

/*
 * NSSCKFWC_SignInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_Sign
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Sign
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);

/*
 * NSSCKFWC_SignUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);

/*
 * NSSCKFWC_SignFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);

/*
 * NSSCKFWC_SignRecoverInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignRecoverInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_SignRecover
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignRecover
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);

/*
 * NSSCKFWC_VerifyInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_VerifyInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_Verify
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_Verify
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);

/*
 * NSSCKFWC_VerifyUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_VerifyUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);

/*
 * NSSCKFWC_VerifyFinal
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_VerifyFinal
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);

/*
 * NSSCKFWC_VerifyRecoverInit
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_VerifyRecoverInit
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);

/*
 * NSSCKFWC_VerifyRecover
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_VerifyRecover
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);

/*
 * NSSCKFWC_DigestEncryptUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DigestEncryptUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);

/*
 * NSSCKFWC_DecryptDigestUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DecryptDigestUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);

/*
 * NSSCKFWC_SignEncryptUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SignEncryptUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);

/*
 * NSSCKFWC_DecryptVerifyUpdate
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DecryptVerifyUpdate
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);

/*
 * NSSCKFWC_GenerateKey
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GenerateKey
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phKey
);

/*
 * NSSCKFWC_GenerateKeyPair
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GenerateKeyPair
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
  CK_ULONG ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
  CK_ULONG ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey
);

/*
 * NSSCKFWC_WrapKey
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_WrapKey
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG_PTR pulWrappedKeyLen
);

/*
 * NSSCKFWC_UnwrapKey
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_UnwrapKey
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);

/*
 * NSSCKFWC_DeriveKey
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_DeriveKey
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);

/*
 * NSSCKFWC_SeedRandom
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_SeedRandom
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen
);

/*
 * NSSCKFWC_GenerateRandom
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GenerateRandom
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pRandomData,
  CK_ULONG ulRandomLen
);

/*
 * NSSCKFWC_GetFunctionStatus
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_GetFunctionStatus
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession
);

/*
 * NSSCKFWC_CancelFunction
 *
 */
__attribute__ ((visibility ("default"))) NSS_EXTERN CK_RV
NSSCKFWC_CancelFunction
(
  NSSCKFWInstance *fwInstance,
  CK_SESSION_HANDLE hSession
);

#endif /* NSSCKFWC_H */
