/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file mcuxClMlDsa_Internal_Functions.h
 * @brief Internal function definitions of the crypto library ML-DSA component
 *
 * @defgroup mcuxClMlDsa_Internal_Functions mcuxClMlDsa_Internal_Functions
 * @ingroup mcuxClMlDsa
 * @brief Internal function definitions of the @ref mcuxClMlDsa component.
 * @{
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_FUNCTIONS_H_
#define MCUXCLMLDSA_INTERNAL_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClSignature.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @defgroup mcuxClMlDsa_Internal_Functions mcuxClMlDsa_Internal_Functions
 * @brief Interfaces to perform @ref mcuxClMlDsa operations.
 * @ingroup mcuxClMlDsa
 */

/**
 * @brief ML-DSA keypair function
 *
 * This function generates a ML-DSA keypair.
 *
 * @param[in]       session       Handle for the current CL session
 * @param[in]       generation    Variable to handover the ML-DSA mode
 * @param[out]      privKey       Key handle for the private key (word-aligned)
 * @param[out]      pubKey        Key handle for the public key (word-aligned)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Keypair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Keypair(
  mcuxClSession_Handle_t session,
  mcuxClKey_Generation_t generation,
  mcuxClKey_Handle_t privKey,
  mcuxClKey_Handle_t pubKey
  );

/**
 * @brief ML-DSA sign function
 *
 * This function generates a ML-DSA signature.
 *
 * @param[in]       session         Handle for the current CL session
 * @param[in]       keyDesc         Handle for the private key (word-aligned)
 * @param[in]       signMode        Variable to handover the ML-DSA mode
 * @param[in]       pMessage        Message buffer for which the signature will be calculated
 * @param[in]       messageLen      Length of the message buffer
 * @param[out]      pSignature      Buffer for the signature output
 * @param[out]      pSignatureLen   pSignatureLen Will be set to the number of bytes of data that have been written to the pSignature buffer
 *
 * @return Returns an explicit status code on failure
 *
 * @retval MCUXCLSIGNATURE_STATUS_OK                    Signature generation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Sign, mcuxClSignature_SignFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Sign(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t keyDesc,
  mcuxClSignature_Mode_t signMode,
  mcuxCl_InputBuffer_t pMessage,
  uint32_t messageLen,
  mcuxCl_Buffer_t pSignature,
  uint32_t * const pSignatureLen
);

/**
 * @brief ML-DSA verify function
 *
 * This function verifies a ML-DSA signature.
 *
 * @param[in]       session           Handle for the current CL session
 * @param[in]       keyDesc           Handle to the bit packed public key to verify the signature (word-aligned)
 * @param[in]       signMode          Variable to handover the ML-DSA mode
 * @param[in]       pMessageOrDigest  Input buffer for which the signature will be verfied
 * @param[in]       messageLen        Length of the message Buffer
 * @param[in]       pSignature        Buffer for the input signature
 * @param[in]       signatureLen      Length of the input signature
 *
 * @return Returns an explicit status code on failure
 *
 * @retval MCUXCLSIGNATURE_STATUS_OK                    Signature validated
 * @retval MCUXCLSIGNATURE_STATUS_NOT_OK                Invalid signature
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Verify, mcuxClSignature_VerifyFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify(
  mcuxClSession_Handle_t           session,
  mcuxClKey_Handle_t               keyDesc,
  mcuxClSignature_Mode_t           signMode,
  mcuxCl_InputBuffer_t             pMessageOrDigest,
  uint32_t                        messageLen,
  mcuxCl_InputBuffer_t             pSignature,
  uint32_t                        signatureLen
  );
/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_INTERNAL_FUNCTIONS_H_ */
