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
 * @file:  mcuxClMlKem_Utils.h
 * @brief: Utility wrapper functions for SHA3/SHAKE of the crypto library ML-KEM component
 */

#ifndef MCUXCLMLKEM_UTILS_H_
#define MCUXCLMLKEM_UTILS_H_

#include <mcuxClMlKem.h>
#include <internal/mcuxClMlKem_Internal.h>


#include <mcuxClSession_Types.h>
#include <mcuxClBuffer.h>
#include <mcuxClXof_Types.h>

/**
 * @brief mcuxClMlKem_PRF
 *
 * This function generates outlen output bytes from (key || nonce) using Shake256
 *
 * @param[in]       session             Handle for the current CL session
 * @param[out]      out                 Pointer to output (of length 32 bytes)
 * @param[in]       outlen              Number of output bytes
 * @param[in]       key                 pointer to key (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       nonce               nonce
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK      Kem operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_PRF)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)mcuxClMlKem_PRF(mcuxClSession_Handle_t session,
                                                                    uint8_t * const out,
                                                                    uint16_t outlen,
                                                                    const uint8_t key[32],
                                                                    uint8_t nonce);

/**
 * @brief mcuxClMlKem_PRF
 *
 * This function initializes the state and absorbs seed || x || y using Shake128
 *
 * @param[in]       session             Handle for the current CL session
 * @param[in]       pContext            Pointer to context
 * @param[in]       seed                Pointer to seed (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       x                   Matrix index
 * @param[in]       y                   Matrix index
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK      Kem operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Stream128_Absorb)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Stream128_Absorb(
                                                      mcuxClSession_Handle_t session,
                                                      mcuxClXof_Context_t pContext,
                                                      const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                      uint8_t x,
                                                      uint8_t y);

/**
 * @brief mcuxClMlKem_Stream128_Squeeze
 *
 * This function generates nblocks output blocks of nblocks*{168,64} bytes using Shake128
 *
 * @param[in]       session             Handle for the current CL session
 * @param[in]       pContext            Pointer to context
 * @param[out]      out                 Pointer to output (of length nblocks*168)
 * @param[in]       nblocks             Number of output blocks
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK      Kem operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Stream128_Squeeze)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Stream128_Squeeze(
                                                                mcuxClSession_Handle_t session,
                                                                mcuxClXof_Context_t pContext,
                                                                uint8_t *const out,
                                                                uint16_t noOfBytes);

/**
 * @brief cmov
 *
 * This function copy len bytes from x to r if b is 1 don't modify x if b is 0. Requires b to be in {0,1};
 *     assumes two's complement representation of negative integers. Runs in constant time.
 *
 * @param[out]      r            Pointer to output byte array
 * @param[in]       x            Pointer to input byte array
 * @param[in]       len          Amount of bytes to be copied
 * @param[in]       b            Condition bit; has to be in {0,1}
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Cmov)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Cmov(uint8_t * const r, const uint8_t * const x, uint32_t len, uint8_t b);

#endif /* MCUXCLMLKEM_UTILS_H_ */
