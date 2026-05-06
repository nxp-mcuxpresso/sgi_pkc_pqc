/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Indcpa.h
 * @brief: Interface for IND-CPA secure calls of the crypto library ML-KEM component
 *
 */

#ifndef MCUXCLMLKEM_INDCPA_H_
#define MCUXCLMLKEM_INDCPA_H_

#include <mcuxClBuffer.h>
#include <mcuxClHash_Types.h>
#include <mcuxClMlKem.h>
#include <mcuxClXof_Types.h>
#include <mcuxClMemory_Types.h>

#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClMlKem_Poly.h>

/**
 * @brief  mcuxClMlKem_Indcpa_Generate_Keys
 *
 * This function generates public and private key for the CPA-secure
 *               public-key encryption scheme underlying ML-KEM
 *
 * @param[in]       session         Handle for the current CL session
 * @param[out]      pk              Key handle to output public key
 * @param[out]      sk              Key handle to output private key
 * @param[in]       d               Seed out of which private and public seed are expanded
 * @param[in]       pParams         Pointer to the ML-KEM parameter structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK        Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Indcpa_Generate_Keys)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Indcpa_Generate_Keys(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pk,
  mcuxClKey_Handle_t sk,
  const uint8_t d[MCUXCLMLKEM_SYMBYTES],
  mcuxClMlKem_Params_t pParams
);

/**
 * @brief  mcuxClMlKem_Encrypt
 *
 * This function implements the encryption function of the CPA-secure public-key encryption scheme underlying ML-KEM
 *
 * @param[in]       session                   Handle for the current CL session
 * @param[in,out]   ct                        Pointer to output ciphertext (of length MCUXCLMLKEM_INDCPA_BYTES bytes)
 * @param[in]       m                         Pointer to input message (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       pk                        Pointer to input public key (of length MCUXCLMLKEM_INDCPA_PUBLICKEYBYTES)
 * @param[in]       coins                     Pointer to input random coins used as seed (of length MCUXCLMLKEM_SYMBYTES) to deterministically generate all randomness
 * @param[in]       opFn                      Function pointer to either compare or write generated ciphertext to reference ciphertext
 * @param[in]       pParams                   ML-KEM parameter set structure
 * @param[in,out]   rc                        Pointer to comparison value
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK        Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encrypt(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t ct,
  const uint8_t *m,
  const uint8_t *pk,
  const uint8_t coins[MCUXCLMLKEM_SYMBYTES],
  mcuxClMlKem_Poly_Compress_Op_t opFn,
  uint32_t protectionToken_opFn,
  mcuxClMlKem_Params_t pParams,
  mcuxClMemory_Status_t *rc);

/**
 * @brief  mcuxClMlKem_Decrypt
 *
 * This function implements the decryption function of the CPA-secure public-key encryption scheme underlying ML-KEM.
 *
 * @param[in]       session         Handle for the current CL session
 * @param[out]      m               Pointer to output decrypted message (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       c               Pointer to input ciphertext (of length MCUXCLMLKEM_INDCPA_BYTES bytes)
 * @param[in]       sk              Pointer to input secret key (of length MCUXCLMLKEM_INDCPA_SECRETKEYBYTES)
 * @param[in]       pParams         ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK        Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Decrypt(
  mcuxClSession_Handle_t session,
  uint8_t *const m,
  mcuxCl_InputBuffer_t c,
  const uint8_t *sk,
  mcuxClMlKem_Params_t pParams);


#endif   /* MCUXCLMLKEM_INDCPA_H_ */
