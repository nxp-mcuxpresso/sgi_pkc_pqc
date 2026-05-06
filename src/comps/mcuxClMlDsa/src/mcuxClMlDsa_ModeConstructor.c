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
 * @file  mcuxClMlDsa_ModeConstructor.c
 * @brief mcuxClMlDsa: implementation of ML-DSA mode constructors for the signature component
 *
 */

#include <mcuxClHashModes.h>
#include <mcuxClMlDsa.h>
#include <mcuxClMlDsa_ModeConstructor.h>
#include <mcuxClSignature.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClMlDsa_Internal_Functions.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>
#include <internal/mcuxClSignature_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/*************************************************
 * Name:        mcuxClMlDsa_CheckPreHashAlgorithm
 *
 * Description: Subroutine of the processing of setting up the mode constuctor.
 *              This function checks whether a valid pre-hash algorithm is provided.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_CheckPreHashAlgorithm)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_CheckPreHashAlgorithm(
  const void* const pPreHashAlgo)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_CheckPreHashAlgorithm);

  if(
    (mcuxClHash_Algorithm_Sha224 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
    (mcuxClHash_Algorithm_Sha256 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
    (mcuxClHash_Algorithm_Sha384 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
    (mcuxClHash_Algorithm_Sha512 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
#if defined(MCUXCL_FEATURE_HASH_LTC_SHA3_224) || defined(MCUXCL_FEATURE_HASH_C_SHA3)
    (mcuxClHash_Algorithm_Sha3_224 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
#endif /* defined(MCUXCL_FEATURE_HASH_LTC_SHA3_224) || defined(MCUXCL_FEATURE_HASH_C_SHA3) */
#if defined(MCUXCL_FEATURE_HASH_LTC_SHA3_256) || defined(MCUXCL_FEATURE_HASH_C_SHA3)
    (mcuxClHash_Algorithm_Sha3_256 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
#endif /* defined(MCUXCL_FEATURE_HASH_LTC_SHA3_256) || defined(MCUXCL_FEATURE_HASH_C_SHA3) */
#if defined(MCUXCL_FEATURE_HASH_LTC_SHA3_384) || defined(MCUXCL_FEATURE_HASH_C_SHA3)
    (mcuxClHash_Algorithm_Sha3_384 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
#endif /* defined(MCUXCL_FEATURE_HASH_LTC_SHA3_384) || defined(MCUXCL_FEATURE_HASH_C_SHA3) */
#if defined(MCUXCL_FEATURE_HASH_LTC_SHA3_512) || defined(MCUXCL_FEATURE_HASH_C_SHA3)
    (mcuxClHash_Algorithm_Sha3_512 != (mcuxClHash_Algo_t)pPreHashAlgo) &&
#endif /* defined(MCUXCL_FEATURE_HASH_LTC_SHA3_512) || defined(MCUXCL_FEATURE_HASH_C_SHA3) */
    (mcuxClXof_Algorithm_Shake_128 != (mcuxClXof_Algo_t)pPreHashAlgo) &&
    (mcuxClXof_Algorithm_Shake_256 != (mcuxClXof_Algo_t)pPreHashAlgo))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_CheckPreHashAlgorithm, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_CheckPreHashAlgorithm, MCUXCLSIGNATURE_STATUS_OK);
}

/*************************************************
 * Name:        mcuxClMlDsa_SignatureModeConstructor
 *
 * Description: This function does the set-up of the mode constuctor.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_SignatureModeConstructor)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_SignatureModeConstructor(
  mcuxClSignature_ModeDescriptor_t *pSignatureMode,
  mcuxClMlDsa_SignatureProtocolDescriptor_t *pProtocolDescriptor,
  mcuxClMlDsa_Options_t options,
  const void* const pPreHashAlgo,
  mcuxCl_InputBuffer_t ctx,
  uint8_t ctxLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_SignatureModeConstructor);

  /* Check that if no context is given, the length of the context is set to 0 */
  if((NULL == ctx) && (0U < ctxLength))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_SignatureModeConstructor, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  /* Check that a valid ML-DSA mode is provided: 44, 65 or 87 */
  if((MCUXCLMLDSA_MODE_44 != (options & MCUXCLMLDSA_SELECT_MODE)) && (MCUXCLMLDSA_MODE_65 != (options & MCUXCLMLDSA_SELECT_MODE)) && (MCUXCLMLDSA_MODE_87 != (options & MCUXCLMLDSA_SELECT_MODE)))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_SignatureModeConstructor, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  /* Check that a valid API mode is provided: pure or pre-hash */
  if((MCUXCLMLDSA_MODE_PURE != (options & MCUXCLMLDSA_SELECT_APIMODE)) && (MCUXCLMLDSA_MODE_PREHASH != (options & MCUXCLMLDSA_SELECT_APIMODE)))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_SignatureModeConstructor, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  /* Check that a valid pre-hash function is provided */
  if((MCUXCLMLDSA_MODE_PREHASH == (options & MCUXCLMLDSA_SELECT_APIMODE)))
  {
    MCUX_CSSL_FP_FUNCTION_CALL(retPreHash, mcuxClMlDsa_CheckPreHashAlgorithm(pPreHashAlgo));

    if(MCUXCLSIGNATURE_STATUS_OK != retPreHash)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_SignatureModeConstructor, retPreHash,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_CheckPreHashAlgorithm)
      );
    }
  }

  /* If valid parameters are provided: fill signature protocol parameters for ML-DSA */
  pProtocolDescriptor->mode = options;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the protocol parameters.")
  pProtocolDescriptor->pPreHashAlgo = (mcuxClHash_AlgorithmDescriptor_t *)pPreHashAlgo;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  pProtocolDescriptor->ctx = ctx;
  pProtocolDescriptor->ctxLength = ctxLength;

  /* Fill signature mode parameters for ML-DSA */
  pSignatureMode->pSignFct = mcuxClMlDsa_Sign;
  pSignatureMode->protection_token_sign = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign),
  pSignatureMode->pVerifyFct = mcuxClMlDsa_Verify,
  pSignatureMode->protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify),
  pSignatureMode->pProtocolDescriptor = pProtocolDescriptor;

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_SignatureModeConstructor, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_PREHASH == (options & MCUXCLMLDSA_SELECT_APIMODE),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_CheckPreHashAlgorithm)
    )
  );
}

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
