/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

/**
 *
 * @file mcuxClMlDsa_Internal_ExternalApi.h
 * @brief Functions used for the external API of @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_EXTERNALAPI_H_
#define MCUXCLMLDSA_INTERNAL_EXTERNALAPI_H_

#include <stdint.h>
#include <mcuxClBuffer.h>
#include <mcuxClMlDsa_ModeConstructor.h>
#include <mcuxClSession.h>
#include <mcuxClXof.h>

#include <internal/mcuxClMlDsa_Internal_Types.h>

/**
 * @brief Processing the external API of ML-DSA
 *
 * This function makes sure that the external API is performed (pure and pre-hash mode)
 *
 * @param[in]       session                               Handle for the current CL session
 * @param[in,out]   pShakeContextMu                       XOF context in which data is absorbed
 * @param[in]       pMessage                              Message to be absorbed
 * @param[in]       messageLen                            Length of pMessage
 * @param[in]       mode                                  ML-DSA mode
 * @param[in]       pMlDsa_SignatureProtocolDescriptor    Protocol descriptor containing e.g. the API mode and context
 * @param[in]       pPreHashBuf                           Buffer memory in which the pre-hash operation will happen
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_ProcessExternalData)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_ProcessExternalData(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContextMu,
  const mcuxCl_InputBuffer_t pMessage,
  const uint32_t messageLen,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor,
  uint8_t* const pPreHashBuf);


#endif /* MCUXCLMLDSA_INTERNAL_EXTERNALAPI_H_ */
