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

#ifndef MCUX_CL_KEM_FUNCTIONS_H_
#define MCUX_CL_KEM_FUNCTIONS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClBuffer.h>

#include <mcuxClSession_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClKem_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup mcuxClKem_Functions mcuxClKem_Functions
 * \brief Interfaces to perform Kem operations.
 * \ingroup mcuxClKem
 * @{
 */

MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \brief Encapsulation function
 * \api
 *
 * This function performs an key encapsulation operation. The algorithm
 * to be used will be determined based on the mode that is provided.
 *
 * For example, to perform an ML-KEM Encapsulation operation, the following needs to be provided::
 *  - ML-KEM public key
 *  - ML-KEM mode
 *  - sharedKey data buffer
 *  - pOut buffer of correct size
 *
 * \param      session    Handle for the current CL session.
 * \param      key        Key to be used to encapsulate the \p sharedKey.
 * \param      mode       Kem mode that should be used during the encapsulation operation.
 * \param[out] sharedKey  Key to populate with the generated shared key.
 * \param[out] pOut       Output buffer for the ciphertext.
 * \param[out] pOutSize   Will be incremented by the number of bytes of ciphertext.
 *                        that have been written to the \p pOut buffer.
 * \return status
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKem_encapsulate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClKem_encapsulate(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKem_Mode_t mode,
  mcuxClKey_Handle_t sharedKey,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutSize
);

/**
 * \brief Decapsulate function
 * \api
 *
 * This function performs a key decapsulation operation. The algorithm to
 * be used will be determined based on the mode that is provided.
 *
 * For example, to perform an ML-KEM Decapsulation operation, the following needs to be provided:
 *  - ML-KEM key pair (private/public)
 *  - ML-KEM mode
 *  - ciphertext generated in Encapsulate operation
 *  - sharedKey data buffer
 *
 * \param      session    Handle for the current CL session.
 * \param      key        Key to be used to decrypt the data.
 * \param      mode       Kem mode that should be used during the decryption operation.
 * \param[in]  pIn        Input buffer that contains the ciphertext.
 * \param[in]  inSize     Number of bytes in the \p pIn buffer.
 * \param[out] sharedKey  Key to populate with the generated shared key.
 * \return status
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKem_decapsulate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClKem_decapsulate(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKem_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxClKey_Handle_t sharedKey
);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUX_CL_KEM_FUNCTIONS_H_ */
