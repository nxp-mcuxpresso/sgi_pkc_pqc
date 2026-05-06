/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Sign.c
 * @brief Implementation of signature generation for @ref mcuxClMlDsa.
 *
 */

#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>

#include <mcuxClBuffer.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClKey_Functions.h>
#include <mcuxClMlDsa.h>
#include <mcuxClSession.h>
#include <mcuxClSignature.h>
#include <mcuxClToolchain.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClHashModes_Internal_Algorithms.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClPrng_Internal_Functions.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClXofModes_Internal_Memory.h>

/**
 * @brief The function computes mu = Shake256(tr, msg) and generates rhoprime.
 *
 * @param[in,out]     session                 The current session
 * @param[in,out]     pShakeContextMu         The Shake-256 context to compute mu
 * @param[out]        rho                     rho
 * @param[out]        tr                      tr
 * @param[out]        key                     key
 * @param[in]         pSecretKey              The secret key
 * @param[in]         pMessage                The message which shall be signed
 * @param[in]         messageLen              The length of the message
 * @param[out]        mu                      mu
 * @param[out]        rhoprime                rhoprime
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_Prepare)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Sign_Prepare(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContextMu,
  uint8_t* const rho,
  uint8_t* const tr,
  uint8_t* const key,
  const uint8_t* const pSecretKey,
  mcuxCl_InputBuffer_t const pMessage,
  const uint32_t messageLen,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor,
  uint8_t* const pPreHashBuf,
  uint8_t* const mu,
  uint8_t* const rhoprime,
  uint8_t* const pRng
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_Prepare);

  MCUXCLBUFFER_INIT_RO(trBuf, NULL, tr, MCUXCLMLDSA_TRBYTES);
  MCUXCLBUFFER_INIT(muBuf, NULL, mu, MCUXCLMLDSA_CRHBYTES);
  MCUXCLBUFFER_INIT(rhoprimeBuf, NULL, rhoprime, MCUXCLMLDSA_CRHBYTES);

  /* Partially unpack secret key (remainder done on the fly) */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_SK_Unpack(rho, tr, key, pSecretKey));

  /* Init RhoPrime with low entropy before filling with high quality randomness */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(rhoprime, MCUXCLMLDSA_CRHBYTES));

  /* Compute mu = Shake256(tr, msg) */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session, pShakeContextMu, mcuxClXof_Algorithm_Shake_256, NULL, 0U));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, trBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_TRBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, pShakeContextMu, trBuf, MCUXCLMLDSA_TRBYTES));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_ProcessExternalData(session,
                                                                pShakeContextMu,
                                                                pMessage,
                                                                messageLen,
                                                                mode,
                                                                pMlDsa_SignatureProtocolDescriptor,
                                                                pPreHashBuf));

  /* Balance DI for mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, muBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session, pShakeContextMu, muBuf, MCUXCLMLDSA_CRHBYTES));

  /* Compute rhoprime = Shake256(key || rng || mu) */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session, pShakeContextMu, mcuxClXof_Algorithm_Shake_256, NULL, 0U));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  MCUXCLBUFFER_INIT_RO(keyBuf, NULL, key, MCUXCLMLDSA_SEEDBYTES);
  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, keyBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_SEEDBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, pShakeContextMu, keyBuf, MCUXCLMLDSA_SEEDBYTES));

  MCUXCLBUFFER_INIT_RO(rngBuf, NULL, pRng, MCUXCLMLDSA_RNGBYTES);
  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, rngBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_RNGBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, pShakeContextMu, rngBuf, MCUXCLMLDSA_RNGBYTES));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, muBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, pShakeContextMu, muBuf, MCUXCLMLDSA_CRHBYTES));

  /* Balance DI for mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, rhoprimeBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session, pShakeContextMu, rhoprimeBuf, MCUXCLMLDSA_CRHBYTES));

  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_SK_Unpack),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_ProcessExternalData),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Sign_Prepare);
}

/**
 * @brief The function computes the hints for w1 and writes the signature in case it is not rejected.
 *
 * @param[in]         session        Session handle
 * @param[out]        hintBuf        Hint buffer in output signature
 * @param[in]         pHints         Workarea for hints
 * @param[in]         pParams        The ML-DSA parameters
 * @param[in]         pSecretKey     The secret key for signing
 * @param[in,out]     w0             The first CPU workarea
 * @param[in,out]     w1             The second CPU workarea
 * @param[in]         c_packed       The packed polynomial c
 * @param[in]         wPackedP       Packed polynomial w
 * @param[out]        pAbortFlag     Indicates an abort in the main loop for rejection sampling
 *
 * @return returns an explicit status code on failure
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_ComputeHintsForW1)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Sign_ComputeHintsForW1(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t hintBuf,
  uint8_t* const pHints,
  const mcuxClMlDsa_Params_t* const pParams,
  const uint8_t* const pSecretKey,
  mcuxClMlDsa_Poly_t* const w0,
  mcuxClMlDsa_Poly_t* const w1,
  uint8_t* const c_packed,
  uint8_t* const wPackedP,
  bool* pAbortFlag)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_ComputeHintsForW1);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->k, MCUXCLMLDSA_MLDSA44_K, MCUXCLMLDSA_MLDSA87_K, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->gamma2, MCUXCLMLDSA_MLDSA44_GAMMA2, MCUXCLMLDSA_MLDSA87_GAMMA2, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->l, 0u, MCUXCLMLDSA_MLDSA87_L, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyz_packedbytes, 0u, MCUXCLMLDSA_MLDSA87_POLYZ_PACKEDBYTES, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyeta_packedbytes, 0u, MCUXCLMLDSA_MLDSA65_POLYETA_PACKEDBYTES, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);

  mcuxClMlDsa_Poly_t* const t0 = w0;
  mcuxClMlDsa_Poly_t* const h = w1;
  mcuxClMlDsa_Poly_t* const cp = w1;
  *pAbortFlag = false;

  /* Clear h via mcuxClMemory API, and balance calls with appropriate DI_RECORD macros */
  MCUX_CSSL_DI_RECORD(memClearHDst, pHints);
  MCUX_CSSL_DI_RECORD(memClearHLen, (uint32_t)pParams->omega + (uint32_t)pParams->k);
  MCUXCLMEMORY_CLEAR_INT(pHints, (uint32_t)pParams->omega + (uint32_t)pParams->k);

  /* Check that function calls match up to this point (also cover later INVALID_PARAMS exit) */
  MCUX_CSSL_FP_EXPECT(MCUXCLMEMORY_CLEAR_INT_FP_EXPECT);

  uint16_t k = 0u; /* For encoding h */
  uint16_t n = 0u; /* Reset #1's in h */
  for(uint16_t i = 0u; i < pParams->k; ++i)
  {
    /* Unpack t0 from the secret key and transform */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_T0_Unpack(t0,
                                                                pSecretKey + 2U * MCUXCLMLDSA_SEEDBYTES
                                                                  + MCUXCLMLDSA_TRBYTES
                                                                  + pParams->l * pParams->polyeta_packedbytes
                                                                  + pParams->k * pParams->polyeta_packedbytes
                                                                  + i * MCUXCLMLDSA_POLYT0_PACKEDBYTES));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(t0));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_C_Unpack(cp, c_packed, pParams));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(cp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery(h, t0, cp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(h));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(h));
    MCUX_CSSL_DI_RECORD(polyCheckNormPtr, h);
    MCUX_CSSL_DI_RECORD(polyCheckNormBound, (int32_t)pParams->gamma2);
    MCUX_CSSL_FP_FUNCTION_CALL(checkNormRet, mcuxClMlDsa_Poly_CheckNorm(session, h, (int32_t)pParams->gamma2));
    MCUX_CSSL_FP_EXPECT(
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_T0_Unpack),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_C_Unpack),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointwiseMontgomery),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm));

    if(MCUXCLSIGNATURE_STATUS_OK != checkNormRet)
    {
      *pAbortFlag = true;
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign_ComputeHintsForW1, checkNormRet);
    }

    /* Recover the packed w0 */
    MCUXCLBUFFER_INIT_RO(zBuf, NULL, wPackedP + i * pParams->polyz_packedbytes + i * pParams->polyw1_packedbytes, pParams->polyz_packedbytes);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack(session, w0, zBuf, pParams));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Add(w0, w0, h));

    /* Recover the packed w1 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W1_Unpack(session,
                                                                w1,
                                                                wPackedP + i * pParams->polyz_packedbytes
                                                                  + i * pParams->polyw1_packedbytes
                                                                  + pParams->polyz_packedbytes,
                                                                pParams));

    MCUX_CSSL_FP_EXPECT(
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Add),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W1_Unpack));

    /* Encode h and write the signature */
    for(uint16_t j = 0u; j < MCUXCLMLDSA_N; ++j)
    {
      MCUX_CSSL_FP_FUNCTION_CALL(uint8_t, temp, mcuxClMlDsa_Poly_MakeHint(w0->coefficients[j], w1->coefficients[j], pParams));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_MakeHint));

      /* The variable n is less than or equal UINT8_MAX before the addition, otherwise n would be greater
         than pParams->omega (of type uint8_t), which leads to an early exit */
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(n, 0u, (uint8_t)UINT8_MAX, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
      n += temp;
      if(temp != 0u)
      {
        if(n > pParams->omega) /* Reject h */
        {
          *pAbortFlag = true;
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign_ComputeHintsForW1, MCUXCLSIGNATURE_STATUS_NOT_OK);
        }

        /* If the number of 1's already exceeded omega then we would have had an early exit already */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(k, 0u, pParams->omega, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
        pHints[k++] = (uint8_t)j;
      }
    }

    pHints[(uint16_t)pParams->omega + i] = (uint8_t)(k & 0xFFu);
  }

  /* Write hint to the signature */
  MCUX_CSSL_DI_RECORD(bufferWriteParams, hintBuf);
  MCUX_CSSL_DI_RECORD(bufferWriteParams, pHints);
  MCUX_CSSL_DI_RECORD(bufferWriteParams, (uint32_t)pParams->omega + (uint32_t)pParams->k);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(hintBuf, 0U, pHints, (uint32_t)pParams->omega + (uint32_t)pParams->k));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign_ComputeHintsForW1, MCUXCLSIGNATURE_STATUS_OK);
}

/**
 * @brief The function checks that subtracting cs2 does not change high bits of w and low bits
 *        do not reveal secret information.
 *
 * @param[in]         session                             Session handle
 * @param[in]         pParams                             The ML-DSA parameters
 * @param[in]         pSecretKey                          The secret key for signing
 * @param[in,out]     w0                                  The first CPU workarea
 * @param[in,out]     w1                                  The second CPU workarea
 * @param[in]         c_packed                            The packed polynomial c
 * @param[in,out]     wPackedP                            Pointer to packed w
 * @param[out]        pAbortFlag                          Indicates an abort in the main loop for rejection sampling
 *
 * @return returns an explicit status code on failure
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_CheckCS2)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Sign_CheckCS2(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  const uint8_t* const pSecretKey,
  mcuxClMlDsa_Poly_t* const w0,
  mcuxClMlDsa_Poly_t* const w1,
  uint8_t* const c_packed,
  uint8_t* const wPackedP,
  bool* pAbortFlag
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_CheckCS2);

  mcuxClMlDsa_Poly_t* const s2 = w0;
  mcuxClMlDsa_Poly_t* const h = w1;
  mcuxClMlDsa_Poly_t* const cp = w1;
  *pAbortFlag = false;

  for(uint16_t i = 0u; i < pParams->k; ++i)
  {
    /* Unpack s2 from sk and transform */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Eta_Unpack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Eta_Unpack(session,
                                                                 s2,
                                                                 pSecretKey + 2U * MCUXCLMLDSA_SEEDBYTES
                                                                     + MCUXCLMLDSA_TRBYTES + i * pParams->polyeta_packedbytes
                                                                     + pParams->l * pParams->polyeta_packedbytes,
                                                                 pParams));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(s2));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_C_Unpack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_C_Unpack(cp, c_packed, pParams));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(cp));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointwiseMontgomery));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery(h, s2, cp));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(h));

    /* Recover packed w0 */
    MCUXCLBUFFER_INIT_RO(zBuf, NULL, wPackedP + i * pParams->polyz_packedbytes + i * pParams->polyw1_packedbytes, pParams->polyz_packedbytes);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack(session, w0, zBuf, pParams));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Sub));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Sub(w0, w0, h));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(w0));

    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pParams->gamma2, MCUXCLMLDSA_MLDSA44_GAMMA2, MCUXCLMLDSA_MLDSA65_GAMMA2)
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pParams->beta, MCUXCLMLDSA_MLDSA44_BETA, MCUXCLMLDSA_MLDSA65_BETA)

    MCUX_CSSL_DI_RECORD(polyCheckNormPtr, w0);
    MCUX_CSSL_DI_RECORD(polyCheckNormBound, (int32_t)pParams->gamma2 - (int32_t)pParams->beta);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm));
    MCUX_CSSL_FP_FUNCTION_CALL(chkNormRes, mcuxClMlDsa_Poly_CheckNorm(session, w0, (int32_t)pParams->gamma2 - (int32_t)pParams->beta));

    if(MCUXCLSIGNATURE_STATUS_OK != chkNormRes)
    {
      *pAbortFlag = true;
      break;
    }

    /* Pack w0 again for later reuse */
    MCUXCLBUFFER_INIT_RW(wPackedBuf, NULL, wPackedP + i * pParams->polyz_packedbytes + i * pParams->polyw1_packedbytes, pParams->polyz_packedbytes);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Pack(session, wPackedBuf, w0, pParams));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Sign_CheckCS2);
}

/**
 * @brief The function computes the polynomial z, and rejects
 * (setting \p pAbortFlag to true) if it reveals the secret.
 *
 * @param[out]        zBuf            The buffer to z in the signature
 * @param[in]         pParams         The ML-DSA parameters
 * @param[in]         pSecretKey      The secret key for signing
 * @param[in,out]     w0              The first CPU workarea
 * @param[in,out]     w1              The second CPU workarea
 * @param[in]         c_packed        The packed polynomial c
 * @param[in]         pRhoPrime       Buffer to the seed for y generation
 * @param[in]         nonce           Nonce for y generation
 * @param[out]        pHashOutBuf256  Buffer to store output of SHAKE256
 * @param[in,out]     session         Session handle
 * @param[in,out]     pShakeContext   Context to be used for SHAKE256
 * @param[out]        pAbortFlag      Indicates an abort in the main loop for rejection sampling
 *
 * @return returns an explicit status code on failure
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_ComputeZ)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Sign_ComputeZ(
  mcuxCl_Buffer_t zBuf,
  const mcuxClMlDsa_Params_t *const pParams,
  const uint8_t* const pSecretKey,
  mcuxClMlDsa_Poly_t* const w0,
  mcuxClMlDsa_Poly_t* const w1,
  uint8_t* const c_packed,
  uint8_t* const pRhoPrime,
  uint16_t nonce,
  uint8_t* pHashOutBuf256,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pShakeContext,
  bool* pAbortFlag
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_ComputeZ);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pParams->l, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L)
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(nonce, 0u, MCUXCLMLDSA_MLDSA65_MAX_ATTEMPTS)

  mcuxClMlDsa_Poly_t* const z = w0;
  mcuxClMlDsa_Poly_t* const s1 = w0;
  mcuxClMlDsa_Poly_t* const y = w1;
  mcuxClMlDsa_Poly_t* const cp = w1;
  *pAbortFlag = false;

  for(uint16_t i = 0u; i < pParams->l; ++i)
  {
    /* Unpack s1 from secret key and transform */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Eta_Unpack(session,
                                                                 s1,
                                                                 pSecretKey + 2U * MCUXCLMLDSA_SEEDBYTES
                                                                     + MCUXCLMLDSA_TRBYTES + i * pParams->polyeta_packedbytes,
                                                                 pParams));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(s1));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_C_Unpack(cp, c_packed, pParams));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(cp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery(z, s1, cp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(z));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UniformGamma1(y,
                                                                 pRhoPrime,
                                                                 (uint16_t)((uint16_t)pParams->l * nonce) + i,
                                                                 pHashOutBuf256,
                                                                 pParams,
                                                                 session,
                                                                 pShakeContext));

    MCUX_CSSL_FP_EXPECT(
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Eta_Unpack),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_C_Unpack),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointwiseMontgomery),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UniformGamma1));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Add(z, z, y));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(z));

    MCUX_CSSL_DI_RECORD(polyCheckNormPtr, z);
    MCUX_CSSL_DI_RECORD(polyCheckNormBound, (int32_t)pParams->gamma1 - (int32_t)pParams->beta);
    MCUX_CSSL_FP_FUNCTION_CALL(chkNormRes, mcuxClMlDsa_Poly_CheckNorm(session, z, (int32_t)pParams->gamma1 - (int32_t)pParams->beta));

    MCUX_CSSL_FP_EXPECT(
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Add),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm));

    if(MCUXCLSIGNATURE_STATUS_OK != chkNormRes)
    {
      *pAbortFlag = true;
      break;
    }

    /* Write the signature */
    MCUXCLBUFFER_DERIVE_RW(ziBuf, zBuf, i*pParams->polyz_packedbytes);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Pack(session, ziBuf, z, pParams));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Pack));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Sign_ComputeZ);
}

/**
 * @brief Computes and packed w by unpacking/accumulating/packing intermediate values.
 *        A is generated column-wise for this operation.
 *
 * @param[out]    wPackedP          Pointer to packed w
 * @param[in]     pParams           Pointer to the ML-DSA parameters structure
 * @param[out]    y                 Workarea poynomial that holds y
 * @param[out]    w                 Workarea polynomial to compute w in
 * @param[in]     rho               Public seed
 * @param[in]     rhoprime          Private seed
 * @param[in]     nonce             Current nonce in this iteration of the signing loop
 * @param[out]    pHashOutBuf128    Output buffer to generate A using SHAKE128
 * @param[out]    pHashOutBuf256    Output buffer to generate y using SHAKE256
 * @param[in]     session           Session handle
 * @param[out]    shakeContext      Shake context
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_ComputeWPacked)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Sign_ComputeWPacked(
  uint8_t* const wPackedP,
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxClMlDsa_Poly_t* const y,
  mcuxClMlDsa_Poly_t* const w,
  uint8_t* const rho,
  uint8_t* const rhoprime,
  uint16_t nonce,
  uint8_t* pHashOutBuf128,
  uint8_t* pHashOutBuf256,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t shakeContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_ComputeWPacked);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pParams->l, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L)
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(nonce, 0u, MCUXCLMLDSA_MLDSA65_MAX_ATTEMPTS)

  uint16_t i;
  uint16_t j;

  /* Initialize wPacked as zero */
  const uint32_t wPackedSize = (uint32_t)pParams->k * MCUXCLMLDSA_POLY_W_SIZE;
  MCUX_CSSL_DI_RECORD(memClearW1Dst, wPackedP);
  MCUX_CSSL_DI_RECORD(memClearW1Len, wPackedSize);
  MCUX_CSSL_FP_EXPECT(MCUXCLMEMORY_CLEAR_INT_FP_EXPECT);
  MCUXCLMEMORY_CLEAR_INT(wPackedP, wPackedSize);

  for(j = 0u; j < pParams->l; ++j)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UniformGamma1));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UniformGamma1(y,
                                                                 rhoprime,
                                                                 (uint16_t)((uint16_t)pParams->l * nonce) + j,
                                                                 pHashOutBuf256,
                                                                 pParams,
                                                                 session,
                                                                 shakeContext));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(y));

    for(i = 0u; i < pParams->k; ++i)
    {
      /* Load intermediate value of w packed in memory */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W_Unpack));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W_Unpack(w, wPackedP + i * MCUXCLMLDSA_POLY_W_SIZE));
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(i, MCUXCLMLDSA_MLDSA44_K, MCUXCLMLDSA_MLDSA87_K)
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(j, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L)
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate(w,
                                                                              y,
                                                                              rho,
                                                                              (uint16_t)(i << 8u) + j,
                                                                              pHashOutBuf128,
                                                                              session,
                                                                              shakeContext));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(w));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Caddq));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Caddq(w));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W_Pack));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W_Pack(wPackedP + i * MCUXCLMLDSA_POLY_W_SIZE, w));
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Sign_ComputeWPacked);
}



/**
 * @brief Computes ~c = H(mu | w1) from w and writes into the signature.
 * Uses w0 and w1 as working area and stores w0 and w1 in packed from in wPacked.
 *
 * @param[in]    session          Session handle
 * @param[out]   pSignature       Buffer to the signature to write ~c to
 * @param[in]    wPackedP         Packed version of w
 * @param[in]    pParams          Pointer to ML-DSA paramemeters structure
 * @param[out]   w0               Workarea polynomial to hold the lower-order bits of w, w0
 * @param[out]   w1               Workarea polynomial to hold w and later the higher-order bits of w, w1
 * @param[in]    mu               Pointer to mu = H(tr || M)
 * @param[out]   shakeContextMu   Shake256 context to compute H(mu | w1)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_ComputeTildeC)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Sign_ComputeTildeC(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t pSignature,
  uint8_t* const wPackedP,
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxClMlDsa_Poly_t* const w0,
  mcuxClMlDsa_Poly_t* const w1,
  const uint8_t* const mu,
  mcuxClXof_Context_t shakeContextMu)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_ComputeTildeC);
  uint16_t i;

  /* Compute H(mu || w1)*/
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session, shakeContextMu, mcuxClXof_Algorithm_Shake_256, NULL, 0u));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  MCUXCLBUFFER_INIT_RO(muBuf, NULL, mu, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, muBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, shakeContextMu, muBuf, MCUXCLMLDSA_CRHBYTES));

  /* Hash decomposed w1 into hash context */
  for(i = 0u; i < pParams->k; ++i)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W_Unpack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W_Unpack(w1, wPackedP + i * MCUXCLMLDSA_POLY_W_SIZE));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(w1));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(w1));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Caddq));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Caddq(w1));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Decompose));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Decompose(session, w1, w0, w1, pParams));

    /* Store w0 and w1 in packed form for later reuse */
    MCUXCLBUFFER_INIT_RW(wPackedBuf, NULL, wPackedP + i * pParams->polyz_packedbytes + i * pParams->polyw1_packedbytes, pParams->polyz_packedbytes);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Pack(session, wPackedBuf, w0, pParams));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W1_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W1_Pack(session,
                                                              wPackedP + i * pParams->polyz_packedbytes
                                                                 + i * pParams->polyw1_packedbytes
                                                                 + pParams->polyz_packedbytes,
                                                              w1,
                                                              pParams));

    /* Absorb into challenge state */
    MCUXCLBUFFER_INIT_RO(wBuf,
                        NULL,
                        wPackedP + i * pParams->polyz_packedbytes + i * pParams->polyw1_packedbytes
                          + pParams->polyz_packedbytes,
                        pParams->polyw1_packedbytes);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

    /* Balance DI for mcuxClXof_process_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, wBuf);
    MCUX_CSSL_DI_RECORD(xofProcessParams, pParams->polyw1_packedbytes);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session, shakeContextMu, wBuf, pParams->polyw1_packedbytes));
  }

  /* Finalize the challenge ~c */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));

    /* Balance DI for mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, pSignature);
  MCUX_CSSL_DI_RECORD(xofProcessParams, pParams->cTildeSize);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session, shakeContextMu, pSignature, (uint32_t)pParams->cTildeSize));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Sign_ComputeTildeC);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign_Derandomized)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Sign_Derandomized(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t keyDesc,
  mcuxClSignature_Mode_t signMode,
  mcuxCl_InputBuffer_t pMessage,
  uint32_t messageLen,
  mcuxCl_Buffer_t pSignature,
  uint32_t *const pSignatureLen,
  uint8_t *const pRng)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign_Derandomized);

  /******************************************************************/
  /* Step 1: Setup environment                                      */
  /******************************************************************/

  /* Unpack the protocol descriptor. This descriptor contains the ML-DSA mode, the pre-hash algorithm, the context and the context length */
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor = (const mcuxClMlDsa_SignatureProtocolDescriptor_t *)(signMode->pProtocolDescriptor);
  const mcuxClMlDsa_Mode_t mode = pMlDsa_SignatureProtocolDescriptor->mode;

  /* Fetch the parameters, given the security level */
  const mcuxClMlDsa_Params_t *pParams = NULL;
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Get_Params(session, (mode & MCUXCLMLDSA_SELECT_MODE), &pParams));

  uint8_t *pKeyDest = NULL;
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(keyDesc));
  MCUXCLKEY_LOAD_FP(session, keyDesc, &pKeyDest, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);

  const uint8_t* const sk = (const uint8_t*)pKeyDest;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, shakeContext, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL)));
  mcuxClXof_Context_t shakeContextMu = (mcuxClXof_Context_t) shakeContext;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  /* Use one memory location for both hash output buffers */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pXofOutBuf, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_SIGN_XOF_OUT_BUFFER_SIZE)));
  uint8_t* const pHashOutBuf128 = pXofOutBuf;
  uint8_t* const pHashOutBuf256 = pXofOutBuf;
  uint8_t* const pPreHashBuf = pXofOutBuf;
  /* |pHints| =  omega + k bytes, depending on mode, reuse xof outbuf */
  uint8_t* const pHints = pXofOutBuf;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory")
  /* |w0| = 1024 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, w0, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  /* |w1| = 1024 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, w1, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  mcuxClMlDsa_Poly_t* const y = w0;
  mcuxClMlDsa_Poly_t* const cp = w1;

  /* |wPackedP| = MLDSA_K*(POLYZ_PACKEDBYTES + POLYW1_PACKEDBYTES) */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->k, MCUXCLMLDSA_MLDSA44_K, MCUXCLMLDSA_MLDSA87_K, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyz_packedbytes, MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES, MCUXCLMLDSA_MLDSA87_POLYZ_PACKEDBYTES, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyw1_packedbytes, MCUXCLMLDSA_MLDSA87_POLYW1_PACKEDBYTES, MCUXCLMLDSA_MLDSA44_POLYW1_PACKEDBYTES, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS)
  const uint32_t polyWPackedPSize = (uint32_t) pParams->k * (uint32_t) pParams->polyz_packedbytes + (uint32_t) pParams->k * (uint32_t) pParams->polyw1_packedbytes;
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, wPackedP, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(polyWPackedPSize)));

  /* allocate space for rho, tr, key, mu and rhoprime */
  const uint32_t seedBufSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_TRBYTES + 2U * MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, seedBuf, mcuxClSession_allocateWords_cpuWa(session, seedBufSizeInWords));

  /* create some pointers into the seedbuf */
  uint8_t* const rho = seedBuf;
  uint8_t* const tr = rho + MCUXCLMLDSA_SEEDBYTES;
  uint8_t* const key = tr + MCUXCLMLDSA_TRBYTES;
  uint8_t* const mu = key + MCUXCLMLDSA_SEEDBYTES;
  uint8_t* const rhoprime = mu + MCUXCLMLDSA_CRHBYTES;

  /* |c_packed| = MCUXCLMLDSA_C_PACKED_BYTES bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, c_packed, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_C_PACKED_BYTES)));

  /******************************************************************/
  /* Step 2: Prepare parameters                                     */
  /******************************************************************/

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The shakeContextMu pointer is of the right type");
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_Prepare));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Sign_Prepare(session,
                                                         shakeContextMu,
                                                         rho,
                                                         tr,
                                                         key,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("MCUXCLKEY_LOAD_FP was called, which means the pointer is updated to not be NULL.")
                                                         sk,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
                                                         pMessage,
                                                         messageLen,
                                                         mode,
                                                         pMlDsa_SignatureProtocolDescriptor,
                                                         pPreHashBuf,
                                                         mu,
                                                         rhoprime,
                                                         pRng));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /******************************************************************/
  /* Step 3: Main loop for the rejection sampling                   */
  /******************************************************************/
  for(uint16_t nonce = 0U; nonce < pParams->max_attempts; nonce++)
  {
    bool abort_flag = false;

    /******************************************************************/
    /* Step 3a: Fully compute w (w0,w1) in packed format              */
    /******************************************************************/
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The y pointer is of the right type (mcuxClMlDsa_Poly_t* const)")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_ComputeWPacked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Sign_ComputeWPacked(wPackedP,
                                                                  pParams,
                                                                  y,
                                                                  w1,
                                                                  rho,
                                                                  rhoprime,
                                                                  nonce,
                                                                  pHashOutBuf128,
                                                                  pHashOutBuf256,
                                                                  session,
                                                                  shakeContextMu));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

    /******************************************************************/
    /* Step 3b: Compute c'                                            */
    /******************************************************************/
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_ComputeTildeC));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Sign_ComputeTildeC(session,
                                                                 pSignature,
                                                                 wPackedP,
                                                                 pParams,
                                                                 w0,
                                                                 w1,
                                                                 mu,
                                                                 shakeContextMu));

    /* compute c from ~c*/
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The cp pointer is of the right type (mcuxClMlDsa_Poly_t * const)")
    MCUXCLBUFFER_DERIVE_RO(cTildeBuf, pSignature, 0U);

    /* Balance DI for mcuxClMlDsa_Poly_Challenge */
    MCUX_CSSL_DI_RECORD(polyChallengeC, (uintptr_t)cp);
    MCUX_CSSL_DI_RECORD(polyChallengeSeed, (uintptr_t)cTildeBuf);
    MCUX_CSSL_DI_RECORD(polyChallengeParams, (uintptr_t)pParams);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Challenge));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Challenge(session,
                                                             shakeContextMu,
                                                             cp,
                                                             cTildeBuf,
                                                             pHashOutBuf256,
                                                             pParams,
                                                             MCUXCLMLDSA_CHALLENGE_POSITIVE));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

    /* Pack c for later re-use */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_C_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_C_Pack(c_packed, cp, pParams));

    /******************************************************************/
    /* Step 3c: Compute z and reject if it reveals the secret         */
    /******************************************************************/

    MCUXCLBUFFER_DERIVE_RW(zBuf, pSignature, (uint32_t)pParams->cTildeSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_ComputeZ));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Sign_ComputeZ(zBuf,
                                                            pParams,
                                                            sk,
                                                            w0,
                                                            w1,
                                                            c_packed,
                                                            rhoprime,
                                                            nonce,
                                                            pHashOutBuf256,
                                                            session,
                                                            shakeContextMu,
                                                            &abort_flag));
    if(abort_flag)
    {
      continue;
    }

    /******************************************************************/
    /* Step 3d: Computes r0 = LowBits(w - cs2, 2 * gamma) and checks  */
    /*         the bound on r0, aborts if check fails                 */
    /******************************************************************/

    /* Computes r0 = LowBits(w - cs2, 2 * gamma) and checks the bound on r0, aborts if check fails */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_CheckCS2));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Sign_CheckCS2(session, pParams, sk, w0, w1, c_packed, wPackedP, &abort_flag));

    if(abort_flag)
    {
      continue;
    }

    /******************************************************************/
    /* Step 3e: Compute hint vector and write the signature in case   */
    /*          it is not rejected                                    */
    /******************************************************************/

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_OF_COMPOSITE_EXPRESSION("the result of uint16_t multi by uint8_t should be extended to 32-bit. ")
    uint32_t zSize = (uint32_t) pParams->l * (uint32_t) pParams->polyz_packedbytes;
    MCUXCLBUFFER_DERIVE_RW(hintBuf, pSignature, (uint32_t) pParams->cTildeSize + zSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_OF_COMPOSITE_EXPRESSION()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_ComputeHintsForW1));
    MCUX_CSSL_FP_FUNCTION_CALL(computeHintsForW1Res, mcuxClMlDsa_Sign_ComputeHintsForW1(session,
                                                                                      hintBuf,
                                                                                      pHints,
                                                                                      pParams,
                                                                                      sk,
                                                                                      w0,
                                                                                      w1,
                                                                                      c_packed,
                                                                                      wPackedP,
                                                                                      &abort_flag));
    if(abort_flag)
    {
      continue;
    }
    if(MCUXCLSIGNATURE_STATUS_OK != computeHintsForW1Res)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign_Derandomized, computeHintsForW1Res);
    }

    *(pSignatureLen) = pParams->signature_bytes;

    mcuxClSession_freeWords_cpuWa(
      session,
      MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_C_PACKED_BYTES)                 /* |c_packed| */
        + seedBufSizeInWords                                                    /* |seedBuf| */
        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(polyWPackedPSize)                      /* |wPackedP| */
        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)                  /* |w1| */
        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)                  /* |w0| */
        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_SIGN_XOF_OUT_BUFFER_SIZE)   /* |pXofOutBuf| */
        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL)); /* |shakeContext| */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign_Derandomized, MCUXCLSIGNATURE_STATUS_OK);
  }

  /* The probability of an abort is approximately:
      1 - exp[ −256 * beta * (l / gamma_1 + k / gamma_2) ].
    This probability is lowest for ML-DSA3, where it is approximately
    equal to 0.804.  The probability of 406 or more subsequent aborts is
    less than 2^(-128). If this happens, something is *clearly* wrong.
  */
  *(pSignatureLen) = 0u;

  MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Sign, mcuxClSignature_SignFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Sign(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t keyDesc,
  mcuxClSignature_Mode_t signMode,
  mcuxCl_InputBuffer_t pMessage,
  uint32_t messageLen,
  mcuxCl_Buffer_t pSignature,
  uint32_t *const pSignatureLen)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Sign);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, rng, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_RNGBYTES)));

  MCUXCLBUFFER_INIT(rngBuf, NULL, rng, MCUXCLMLDSA_RNGBYTES);
  MCUX_CSSL_DI_RECORD(rngParams, session);
  MCUX_CSSL_DI_RECORD(rngParams, rngBuf);
  MCUX_CSSL_DI_RECORD(rngParams, MCUXCLMLDSA_RNGBYTES);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(session, rngBuf, MCUXCLMLDSA_RNGBYTES, NULL));

  /* Call derandomized sign internal */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Sign_Derandomized));
  MCUX_CSSL_FP_FUNCTION_CALL(sign_derandomized_ret, mcuxClMlDsa_Sign_Derandomized(session,
                                                                                keyDesc,
                                                                                signMode,
                                                                                pMessage,
                                                                                messageLen,
                                                                                pSignature,
                                                                                pSignatureLen,
                                                                                rng));

  mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_RNGBYTES));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Sign, sign_derandomized_ret);
}
