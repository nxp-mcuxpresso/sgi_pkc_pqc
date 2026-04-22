/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file mcuxClMlDsa_ExternalApi.c
 * @brief Implementation of functions related to the external API of @ref mcuxClMlDsa.
 *
 */

#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClMlDsa_Types.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClXof_Internal.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>
#include <internal/mcuxClMlDsa_Internal_Constants.h>
#include <internal/mcuxClMlDsa_Internal_ExternalApi.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

/**
 * @brief
 * Select the algorithm OID belonging to the pre-hash function.
 * Process this OID in the XOF context.
 *
 * @param[in]   session           Current session
 * @param[in]   pShakeContextMu   XOF context in which the OID is absorbed
 * @param[in]   pPreHashAlgo      Pre-hash algorithm used in external API
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_ProcessOidAlg)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_ProcessOidAlg(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContextMu,
  const void* const pPreHashAlgo)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_ProcessOidAlg);

  /* Create the correct OID algorithm */
  const uint8_t* oidAlgorithm = NULL;

  if((mcuxClXof_Algorithm_Shake_128 == (mcuxClXof_Algo_t)pPreHashAlgo) ||
     (mcuxClXof_Algorithm_Shake_256 == (mcuxClXof_Algo_t)pPreHashAlgo))
  {
    oidAlgorithm = &((mcuxClHash_Algo_t)((mcuxClXof_Algo_t)pPreHashAlgo)->algoDetails)->pOid[4u];
  }
  else
  {
    oidAlgorithm = &((mcuxClHash_Algo_t)pPreHashAlgo)->pOid[4u];
  }

  /* Process the OID algorithm */
  MCUXCLBUFFER_INIT_RO(oidAlgBuf, NULL, oidAlgorithm, 11U);
  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, oidAlgBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, 11U);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pShakeContextMu,
                                                           oidAlgBuf,
                                                           11U));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_ProcessOidAlg, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));
}

/*************************************************
 * Name:        mcuxClMlDsa_PreHash
 *
 * Description: Subroutine of the processing of the external API
 *              to do the pre-hashing (if the mode pre-hash is used).
 **************************************************/
/**
 * @brief
 * Subroutine of computing M' if the pre-hash mode is used.
 * This function computes OID || PH_M according to NIST FIPS 204.
 *
 * @param[in]   session           Current session
 * @param[in]   pShakeContextMu   XOF context in which M' is absorbed
 * @param[in]   pMessage          Input message M
 * @param[in]   messageLen        Length of message M
 * @param[in]   pPreHashAlgo      Pre-hash algorithm used in external API
 * @param[out]  pPreHashBuf       Temporary buffer for the pre-hashed message PH_M
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_PreHash)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_PreHash(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContextMu,
  const mcuxCl_InputBuffer_t pMessage,
  const uint32_t messageLen,
  const void* const pPreHashAlgo,
  uint8_t* const pPreHashBuf)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_PreHash);

  /* Process the OID */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_ProcessOidAlg));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_ProcessOidAlg(session,
                                                          pShakeContextMu,
                                                          pPreHashAlgo));

  /* Pre-hash the message */
  uint32_t preHashSize;
  if(mcuxClXof_Algorithm_Shake_128 == (mcuxClXof_Algo_t)pPreHashAlgo)
  {
    preHashSize = 32U;
    MCUXCLBUFFER_INIT(hashBuf, session, pPreHashBuf, preHashSize); // PH_M <- SHAKE128(M, 256)

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute_internal));

    /* Balance DI for mcuxClXof_compute_internal() */
    MCUX_CSSL_DI_RECORD(xofComputeParams, pMessage);
    MCUX_CSSL_DI_RECORD(xofComputeParams, messageLen);
    MCUX_CSSL_DI_RECORD(xofComputeParams, hashBuf);
    MCUX_CSSL_DI_RECORD(xofComputeParams, 32U);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_compute_internal(session,
                                                             (mcuxClXof_Algo_t)pPreHashAlgo,
                                                             pMessage,
                                                             messageLen,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                             NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                             0U,
                                                             hashBuf,
                                                             32U));
  }
  else if(mcuxClXof_Algorithm_Shake_256 == (mcuxClXof_Algo_t)pPreHashAlgo)
  {
    preHashSize = 64U;
    MCUXCLBUFFER_INIT(hashBuf, session, pPreHashBuf, preHashSize); // PH_M <- SHAKE256(M, 512)

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute_internal));

    /* Balance DI for mcuxClXof_compute_internal() */
    MCUX_CSSL_DI_RECORD(xofComputeParams, pMessage);
    MCUX_CSSL_DI_RECORD(xofComputeParams, messageLen);
    MCUX_CSSL_DI_RECORD(xofComputeParams, hashBuf);
    MCUX_CSSL_DI_RECORD(xofComputeParams, 64U);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_compute_internal(session,
                                                             (mcuxClXof_Algo_t)pPreHashAlgo,
                                                             pMessage,
                                                             messageLen,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                             NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                             0U,
                                                             hashBuf,
                                                             64U));
  }
  else
  {
    uint32_t outSize = 0U;
    preHashSize = (uint32_t)(((mcuxClHash_Algo_t)pPreHashAlgo)->hashSize);
    MCUXCLBUFFER_INIT(hashBuf, session, pPreHashBuf, preHashSize);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute_internal));

    /* Balance DI for mcuxClHash_compute_internal() */
    MCUX_CSSL_DI_RECORD(hashComputeParams, pMessage);
    MCUX_CSSL_DI_RECORD(hashComputeParams, messageLen);
    MCUX_CSSL_DI_RECORD(hashComputeParams, hashBuf);
    MCUX_CSSL_DI_RECORD(hashComputeParams, &outSize);
    MCUX_CSSL_FP_FUNCTION_CALL(retHashCompute, mcuxClHash_compute_internal(session,
                                                                         (mcuxClHash_Algo_t)pPreHashAlgo,
                                                                         pMessage,
                                                                         messageLen,
                                                                         hashBuf,
                                                                         &outSize));
    if(MCUXCLHASH_STATUS_OK != retHashCompute)
    {
      MCUXCLSESSION_ERROR(session, retHashCompute);
    }
  }

  /* Absorb the pre-hashed message into the SHAKE context */
  MCUXCLBUFFER_INIT(preHashBuf, session, pPreHashBuf, preHashSize);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, preHashBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, preHashSize);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pShakeContextMu,
                                                           preHashBuf,
                                                           preHashSize));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_PreHash);
}

/**
 * @brief
 * Subroutine for ML-DSA sign and verify to process the external context and message.
 * Computing M' according to NIST FIPS 204.
 *
 * @param[in]   session                             Current session
 * @param[in]   pShakeContextMu                     XOF context in which M' is absorbed
 * @param[in]   pMessage                            Input message M
 * @param[in]   messageLen                          Length of message M
 * @param[in]   mode                                ML-DSA mode
 * @param[in]   pMlDsa_SignatureProtocolDescriptor  Signature protocol descriptor containing the context, context length and pre-hash algorithm
 * @param[out]  pPreHashBuf                         Temporary buffer for the pre-hashed message PH_M
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_ProcessExternalData)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_ProcessExternalData(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContextMu,
  const mcuxCl_InputBuffer_t pMessage,
  const uint32_t messageLen,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor,
  uint8_t* const pPreHashBuf)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_ProcessExternalData);

  /* Unpack the signature protocol descriptor */
  const void* const pPreHashAlgo = (const void*)pMlDsa_SignatureProtocolDescriptor->pPreHashAlgo;
  mcuxCl_InputBuffer_t pCtx = pMlDsa_SignatureProtocolDescriptor->ctx;
  const uint8_t ctxLength = pMlDsa_SignatureProtocolDescriptor->ctxLength;

  /* Create the padding: API mode (pure or pre-hash) + context length */
  const uint8_t pPadding[2U] = {(uint8_t)((mode & MCUXCLMLDSA_SELECT_APIMODE_CTX) >> MCUXCLMLDSA_POS_APIMODE), ctxLength};
  MCUXCLBUFFER_INIT_RO(paddingBuf, NULL, pPadding, 2U);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  /* Process the padding */
  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, paddingBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, 2U);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pShakeContextMu,
                                                           paddingBuf,
                                                           2U));

  /* Process the context */
  if(pCtx != NULL)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

    /* Balance DI for mcuxClXof_process_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, pCtx);
    MCUX_CSSL_DI_RECORD(xofProcessParams, ctxLength);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                             pShakeContextMu,
                                                             pCtx,
                                                             ctxLength));
  }

  /* If pre-hash mode is used: process the OID and prehash the message/digest */
  if(MCUXCLMLDSA_MODE_PREHASH == (mode & MCUXCLMLDSA_SELECT_APIMODE))
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_PreHash));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_PreHash(session,
                                                      pShakeContextMu,
                                                      pMessage,
                                                      messageLen,
                                                      pPreHashAlgo,
                                                      pPreHashBuf));
  }
  /* If pure mode is used: process the message/digest */
  else
  {
    /* Absorb the message into the shake context */
    /* Balance DI for mcuxClXof_process_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, pMessage);
    MCUX_CSSL_DI_RECORD(xofProcessParams, messageLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                             pShakeContextMu,
                                                             pMessage,
                                                             messageLen));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_ProcessExternalData);
}
