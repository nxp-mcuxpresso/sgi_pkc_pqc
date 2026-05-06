/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Internal_Functions.h
 * @brief: Internal function definitions of the crypto library ML-KEM component
 *
 */

#ifndef MCUXCLMLKEM_INTERNAL_FUNCTIONS_H_
#define MCUXCLMLKEM_INTERNAL_FUNCTIONS_H_

#include <mcuxClKey.h>
#include <mcuxClMlKem_Types.h>
#include <mcuxClSession_Types.h>

#include <mcuxClKem_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Public function definitions */
/**
 * @brief Internal derandomized keygen function, with regards to d and z.
 *
 * @param[in]    session        Session handle.
 * @param[in]    mode           Key generation mode.
 * @param[out]   privateKey     Private key key handle.
 * @param[out]   publicKey      Public key key handle
 * @param[in]    d              Random seed d.
 * @param[in]    z              Randomness used for decapsulation failures.
 *
 * @return returns a status code
 * @retval #MCUXCLKEY_STATUS_OK                 Kem operation successful
 * @retval MCUXCLxxx_STATUS_xxx                 The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_KeyGen_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_KeyGen_Internal(mcuxClSession_Handle_t session,
                                                            mcuxClKey_Generation_t mode,
                                                            mcuxClKey_Handle_t privateKey,
                                                            mcuxClKey_Handle_t publicKey,
                                                            const uint8_t d[MCUXCLMLKEM_SYMBYTES],
                                                            uint8_t z[MCUXCLMLKEM_SYMBYTES]);
/**
 * @brief ML-KEM key generation function
 *
 * This function generates a public and a private key for ML-KEM
 *
 * @param[in]       session       Handle for the current CL session
 * @param[in]       mode          Variable to handover the ML-KEM mode
 * @param[out]      privateKey    Pointer to the output private key handle
 * @param[out]      publicKey     Pointer to the output public key handle
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_KeyGen, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_KeyGen(
  mcuxClSession_Handle_t session,
  mcuxClKey_Generation_t mode,
  mcuxClKey_Handle_t     privateKey,
  mcuxClKey_Handle_t     publicKey);

/**
 * @brief Internal derandomized encapsulation function, with regards to m.
 *
 * @param[in]    session        Session handle.
 * @param[in]    pPublicKey     Pointer to the loaded public key
 * @param[in]    pParams        Pointer to parameter structure
 * @param[in]    m              Random message m.
 * @param[out]   sharedKey      Shared secret key handle.
 * @param[out]   pOut           Pointer to ciphertext.
 * @param[out]   pOutSize       Pointer to output size, to be set by this function.
 *
 * @return returns a mcuxClKem_Status_t status code
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Encaps_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encaps_Internal(mcuxClSession_Handle_t session,
                                                                         const uint8_t* pPublicKey,
                                                                         mcuxClMlKem_Params_t pParams,
                                                                         const uint8_t m[MCUXCLMLKEM_SYMBYTES],
                                                                         mcuxClKey_Handle_t sharedKey,
                                                                         mcuxCl_Buffer_t pOut,
                                                                         uint32_t *const pOutSize);
/**
 * @brief ML-KEM encapsulation function
 *
 * This function generates a shared secret and an associated ciphertext
 * using a public key.
 *
 * @param[in]       session      Handle for the current CL session
 * @param[in]       key          Pointer to the the public key handle
 * @param[in]       mode         Variable to handover the ML-KEM mode
 * @param[out]      sharedKey    Pointer to output the shared secret
 * @param[out]      pOut         Pointer to output the ciphertext
 * @param[out]      pOutSize     Length of the ciphertext
 *
 * @return returns a mcuxClKem_Status_t status code
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Encaps, mcuxClKem_encapsulateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encaps(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t     key,
  mcuxClKem_Mode_t       mode,
  mcuxClKey_Handle_t     sharedKey,
  mcuxCl_Buffer_t        pOut,
  uint32_t *const       pOutSize);

/**
 * @brief ML-KEM decapsulation function
 *
 * This function generates a shared secret from a ciphertext using
 * a public/private key pair.
 *
 * @param[in]       session             Handle for the current CL session
 * @param[in]       key                 Pointer to the private key handle
 *                                      with a linked public key
 * @param[in]       mode                Variable to handover the ML-KEM mode
 * @param[in]       pIn                 Pointer to the input ciphertext buffer
 * @param[in]       inSize              Length of the input ciphertext
 * @param[out]      sharedKey           Pointer to output the shared secret
 *
 * @return returns a mcuxClKem_Status_t status code
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Decaps, mcuxClKem_decapsulateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Decaps(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t     key,
  mcuxClKem_Mode_t       mode,
  mcuxCl_InputBuffer_t   pIn,
  uint32_t              inSize,
  mcuxClKey_Handle_t     sharedKey);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_INTERNAL_FUNCTIONS_H_ */
