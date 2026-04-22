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
 * @file:   mcuxClMlKem_KeyGenerationModes.c
 * @brief:  Modes for the key generation
 *
 */
#include <mcuxCsslAnalysis.h>

#include <mcuxClKey_Constants.h>
#include <mcuxClMlKem.h>

#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMlKem_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem512 =
{
  .pKeyGenFct = (mcuxClKey_KeyGenFct_t)&mcuxClMlKem_KeyGen,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlKem_KeyGen,
  .pProtocolDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem512
};

const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem768 =
{
  .pKeyGenFct = (mcuxClKey_KeyGenFct_t)&mcuxClMlKem_KeyGen,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlKem_KeyGen,
  .pProtocolDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem768
};

const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem1024 =
{
  .pKeyGenFct = (mcuxClKey_KeyGenFct_t)&mcuxClMlKem_KeyGen,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlKem_KeyGen,
  .pProtocolDescriptor = (const void *) &mcuxClMlKem_ParamsDescriptor_MlKem1024
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
