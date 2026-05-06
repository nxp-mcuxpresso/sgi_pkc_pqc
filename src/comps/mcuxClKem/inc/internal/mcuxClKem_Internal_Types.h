/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2026 NXP                                                 */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClKem_Internal_Types.h
 *  @brief Internal type definitions for the mcuxClKem component */

#ifndef MCUXCLKEM_INTERNAL_TYPES_H_
#define MCUXCLKEM_INTERNAL_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClKem_Types.h>
#include <mcuxClBuffer.h>
#include <mcuxClSession.h>
#include <mcuxClKey_Types.h>
#include <mcuxCsslFlowProtection.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Mode/Skeleton function types
 */

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKem_encapsulateFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) (*mcuxClKem_encapsulateFunc_t) (
mcuxClSession_Handle_t session,
mcuxClKey_Handle_t key,
mcuxClKem_Mode_t mode,
mcuxClKey_Handle_t sharedKey,
mcuxCl_Buffer_t pOut,
uint32_t *const pOutSize
));

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKem_decapsulateFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) (*mcuxClKem_decapsulateFunc_t) (
mcuxClSession_Handle_t session,
mcuxClKey_Handle_t key,
mcuxClKem_Mode_t mode,
mcuxCl_InputBuffer_t pIn,
uint32_t inSize,
mcuxClKey_Handle_t sharedKey
));


/**
 * @brief Kem mode/algorithm descriptor structure
 *
 * This structure captures all the information that the Kem interfaces need
 * to know about a particular Kem mode/algorithm.
 */
struct mcuxClKem_ModeDescriptor
{
  mcuxClKem_encapsulateFunc_t encapsulateFct;
  mcuxClKem_decapsulateFunc_t decapsulateFct;
  uint32_t protection_token_encapsulate;
  uint32_t protection_token_decapsulate;
  const void * pAlgorithmDescriptor;
};


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEM_INTERNAL_TYPES_H_ */
