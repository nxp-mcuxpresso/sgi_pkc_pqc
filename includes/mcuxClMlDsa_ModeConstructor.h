/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 *
 * @file mcuxClMlDsa_ModeConstructor.h
 * @brief Mode constructors of the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_ModeConstructor mcuxClMlDsa_ModeConstructor
 * @brief Mode constructors possibly used by the ML-DSA operations.
 * @ingroup mcuxClMlDsa
 * @{
 */

#ifndef MCUXCLMLDSA_MODECONSTRUCTOR_H_
#define MCUXCLMLDSA_MODECONSTRUCTOR_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxCsslFlowProtection.h>

#include <mcuxClSignature_Types.h>

#include <mcuxClBuffer.h>
#include <mcuxClHash_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMlDsa_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief ML-DSA signature protocol descriptor structure
 *
 * This structure captures all the information that the signature interface needs
 * to know about ML-DSA specific operations.
 */
struct mcuxClMlDsa_Signature_ProtocolDescriptor;
typedef struct mcuxClMlDsa_Signature_ProtocolDescriptor mcuxClMlDsa_SignatureProtocolDescriptor_t;

/**
 * @brief Mode constructor for ML-DSA signature generation and verification
 *
 * @param[out]      pSignatureMode        Pointer to a mode descriptor that will be updated by this function.
 * @param[in,out]   pProtocolDescriptor   Pointer to an ML-DSA protocol descriptor that will be updated by this function.
 * @param[in]       options               Struct type used to indicate the ML-DSA mode (44, 65, 87), the API mode (PURE and PRE-HASH) and whether internal or external API is expected.
 * @param[in]       pPreHashAlgo          If PRE-HASH is used, the algorithm that is used to pre-hash the message; otherwise NULL.
 *                                        Note that this is a void pointer: it will either accept mcuxClHash_Algo_t or mcuxClXof_Algo_t.
 * @param[in]       ctx                   User provided context string; otherwise NULL.
 * @param[in]       ctxLength             Length of the user provided context string; otherwise 0U.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_SignatureModeConstructor)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_SignatureModeConstructor(
  mcuxClSignature_ModeDescriptor_t *pSignatureMode,
  mcuxClMlDsa_SignatureProtocolDescriptor_t *pProtocolDescriptor,
  mcuxClMlDsa_Options_t options,
  const void* const pPreHashAlgo,
  mcuxCl_InputBuffer_t ctx,
  uint8_t ctxLength
);


/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_MODECONSTRUCTOR_H_ */
