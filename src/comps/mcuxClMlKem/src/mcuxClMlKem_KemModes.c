/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024, 2026 NXP                                            */
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
 * @file:   mcuxClMlKem_KemModes.c
 * @brief:  Modes for the KEM
 *
 */

#include <mcuxClMlKem.h>
#include <mcuxClKem_Types.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClKem_Internal_Types.h>

const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem512 =
{
  .encapsulateFct = mcuxClMlKem_Encaps,
  .decapsulateFct = mcuxClMlKem_Decaps,
  .protection_token_encapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encaps),
  .protection_token_decapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decaps),
  .pAlgorithmDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem512
};

const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem768 =
{
  .encapsulateFct = mcuxClMlKem_Encaps,
  .decapsulateFct = mcuxClMlKem_Decaps,
  .protection_token_encapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encaps),
  .protection_token_decapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decaps),
  .pAlgorithmDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem768
};

const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem1024 =
{
  .encapsulateFct = mcuxClMlKem_Encaps,
  .decapsulateFct = mcuxClMlKem_Decaps,
  .protection_token_encapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encaps),
  .protection_token_decapsulate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decaps),
  .pAlgorithmDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem1024
};

