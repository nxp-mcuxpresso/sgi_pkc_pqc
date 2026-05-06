/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_KeyGenerationModes.c
 * @brief Implementation of @ref mcuxClMlDsa related key generation mode descriptors.
 *
 */

#include <mcuxClMlDsa_Types.h>
#include <mcuxClKey_Types.h>

#include <internal/mcuxClMlDsa_Internal_Constants.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>
#include <internal/mcuxClMlDsa_Internal_Functions.h>
#include <internal/mcuxClKey_Types_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

static const mcuxClMlDsa_Mode_t mcuxClMlDsa_ModeDescriptor_MlDsa44 = MCUXCLMLDSA_MODE_44;
const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa44 =
{
  .pKeyGenFct = mcuxClMlDsa_Keypair,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_Keypair,
  .pProtocolDescriptor = (const void *)&mcuxClMlDsa_ModeDescriptor_MlDsa44
};

static const mcuxClMlDsa_Mode_t mcuxClMlDsa_ModeDescriptor_MlDsa65 = MCUXCLMLDSA_MODE_65;
const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa65 =
{
  .pKeyGenFct = mcuxClMlDsa_Keypair,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_Keypair,
  .pProtocolDescriptor = (const void *)&mcuxClMlDsa_ModeDescriptor_MlDsa65
};

static const mcuxClMlDsa_Mode_t mcuxClMlDsa_ModeDescriptor_MlDsa87 = MCUXCLMLDSA_MODE_87;
const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa87 =
{
  .pKeyGenFct = mcuxClMlDsa_Keypair,
  .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_Keypair,
  .pProtocolDescriptor = (const void *)&mcuxClMlDsa_ModeDescriptor_MlDsa87
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
