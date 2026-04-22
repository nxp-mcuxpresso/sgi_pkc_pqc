/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Params.c
 * @brief Defining the parameter sets used in @ref mcuxClMlDsa.
 *
 */

#include <mcuxClMlDsa.h>

#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <mcuxCsslDataIntegrity.h>

/**
 * Parameters and sizes for ML-DSA modes 44, 65, 87
 */
static const mcuxClMlDsa_Params_t mcuxClMlDsa_Params[3U] = {
  {
    .gamma1                 = MCUXCLMLDSA_MLDSA44_GAMMA1,
    .gamma2                 = MCUXCLMLDSA_MLDSA44_GAMMA2,
    .signature_bytes        = MCUXCLMLDSA_MLDSA44_SIG_LEN,

    .mode                   = MCUXCLMLDSA_MODE_44,

    .cTildeSize             = MCUXCLMLDSA_MLDSA44_CTILDE_SIZE,
    .trSize                 = MCUXCLMLDSA_TRBYTES,

    .publickey_bytes        = MCUXCLMLDSA_MLDSA44_PK_LEN,
    .secretkey_bytes        = MCUXCLMLDSA_MLDSA44_SK_LEN,
    .polyz_packedbytes      = MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES,
    .polyw1_packedbytes     = MCUXCLMLDSA_MLDSA44_POLYW1_PACKEDBYTES,
    .polyeta_packedbytes    = MCUXCLMLDSA_MLDSA44_POLYETA_PACKEDBYTES,
    .max_attempts           = MCUXCLMLDSA_MLDSA44_MAX_ATTEMPTS,

    .k                      = MCUXCLMLDSA_MLDSA44_K,
    .l                      = MCUXCLMLDSA_MLDSA44_L,
    .eta                    = MCUXCLMLDSA_MLDSA44_ETA,
    .beta                   = MCUXCLMLDSA_MLDSA44_BETA,
    .tau                    = MCUXCLMLDSA_MLDSA44_TAU,
    .omega                  = MCUXCLMLDSA_MLDSA44_OMEGA,
    .polyvech_packedbytes   = MCUXCLMLDSA_MLDSA44_POLYVECH_PACKEDBYTES,

    .crc                    = MCUXCLMLDSA_MODE44_PARAMS_CRC,
  },
  {
    .gamma1                 = MCUXCLMLDSA_MLDSA65_GAMMA1,
    .gamma2                 = MCUXCLMLDSA_MLDSA65_GAMMA2,
    .signature_bytes        = MCUXCLMLDSA_MLDSA65_SIG_LEN,

    .mode                   = MCUXCLMLDSA_MODE_65,

    .cTildeSize             = MCUXCLMLDSA_MLDSA65_CTILDE_SIZE,
    .trSize                 = MCUXCLMLDSA_TRBYTES,

    .publickey_bytes        = MCUXCLMLDSA_MLDSA65_PK_LEN,
    .secretkey_bytes        = MCUXCLMLDSA_MLDSA65_SK_LEN,
    .polyz_packedbytes      = MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES,
    .polyw1_packedbytes     = MCUXCLMLDSA_MLDSA65_POLYW1_PACKEDBYTES,
    .polyeta_packedbytes    = MCUXCLMLDSA_MLDSA65_POLYETA_PACKEDBYTES,
    .max_attempts           = MCUXCLMLDSA_MLDSA65_MAX_ATTEMPTS,

    .k                      = MCUXCLMLDSA_MLDSA65_K,
    .l                      = MCUXCLMLDSA_MLDSA65_L,
    .eta                    = MCUXCLMLDSA_MLDSA65_ETA,
    .beta                   = MCUXCLMLDSA_MLDSA65_BETA,
    .tau                    = MCUXCLMLDSA_MLDSA65_TAU,
    .omega                  = MCUXCLMLDSA_MLDSA65_OMEGA,
    .polyvech_packedbytes   = MCUXCLMLDSA_MLDSA65_POLYVECH_PACKEDBYTES,

    .crc                    = MCUXCLMLDSA_MODE65_PARAMS_CRC,
  },
  {
    .gamma1                 = MCUXCLMLDSA_MLDSA87_GAMMA1,
    .gamma2                 = MCUXCLMLDSA_MLDSA87_GAMMA2,
    .signature_bytes        = MCUXCLMLDSA_MLDSA87_SIG_LEN,

    .mode                   = MCUXCLMLDSA_MODE_87,

    .cTildeSize             = MCUXCLMLDSA_MLDSA87_CTILDE_SIZE,
    .trSize                 = MCUXCLMLDSA_TRBYTES,

    .publickey_bytes        = MCUXCLMLDSA_MLDSA87_PK_LEN,
    .secretkey_bytes        = MCUXCLMLDSA_MLDSA87_SK_LEN,
    .polyz_packedbytes      = MCUXCLMLDSA_MLDSA87_POLYZ_PACKEDBYTES,
    .polyw1_packedbytes     = MCUXCLMLDSA_MLDSA87_POLYW1_PACKEDBYTES,
    .polyeta_packedbytes    = MCUXCLMLDSA_MLDSA87_POLYETA_PACKEDBYTES,
    .max_attempts           = MCUXCLMLDSA_MLDSA87_MAX_ATTEMPTS,

    .k                      = MCUXCLMLDSA_MLDSA87_K,
    .l                      = MCUXCLMLDSA_MLDSA87_L,
    .eta                    = MCUXCLMLDSA_MLDSA87_ETA,
    .beta                   = MCUXCLMLDSA_MLDSA87_BETA,
    .tau                    = MCUXCLMLDSA_MLDSA87_TAU,
    .omega                  = MCUXCLMLDSA_MLDSA87_OMEGA,
    .polyvech_packedbytes   = MCUXCLMLDSA_MLDSA87_POLYVECH_PACKEDBYTES,

    .crc                    = MCUXCLMLDSA_MODE87_PARAMS_CRC,
  },
};

/**
 * Name:        mcuxClMlDsa_Get_Params
 *
 * Description: Returns parameters for a given mode
 *
 * Arguments:   - session: session handle
 *              - mode: ML-DSA security level
 *              - ppParams: Pointer to pointer to ML-DSA params
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Get_Params)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Get_Params(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_Params_t** ppParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Get_Params);
  if(MCUXCLMLDSA_MODE_44 == mode)
  {
    *ppParams = &mcuxClMlDsa_Params[0U];
  }
  else if(MCUXCLMLDSA_MODE_65 == mode)
  {
    *ppParams = &mcuxClMlDsa_Params[1U];
  }
  else if(MCUXCLMLDSA_MODE_87 == mode)
  {
    *ppParams = &mcuxClMlDsa_Params[2U];
  }
  else
  {
    MCUXCLSESSION_ERROR(session, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Get_Params);
}
