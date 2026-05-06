/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Internal_Params.h
 * @brief Parameter-related functions and macros for @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_PARAMS_H_
#define MCUXCLMLDSA_INTERNAL_PARAMS_H_

#include <internal/mcuxClMlDsa_Internal_Types.h>

/**
* @brief ML-DSA get parameter set, given the mode
*
* Retrieves all the (mode-specific) parameters for ML-DSA.
*
* @param[in]       session         Session handle
* @param[in]       mode            ML-DSA parameter set (44, 65, 87)
* @param[out]      ppParams        Pointer getting updated to point to the right parameter set
*
* @return void
*/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Get_Params)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Get_Params(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_Params_t** ppParams);

#endif /* MCUXCLMLDSA_INTERNAL_PARAMS_H_ */
