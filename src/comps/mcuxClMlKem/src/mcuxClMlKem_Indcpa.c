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
 * @file:   mcuxClMlKem_Indcpa.c
 * @brief:  Functions for the IND-CPA secure calls
 *
 */

#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>

#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClMlKem.h>
#include <mcuxClKem.h>
#include <mcuxClRandom.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>

#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMlKem_Indcpa.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClMlKem_Poly.h>
#include <internal/mcuxClMlKem_Utils.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClPrng_Internal_Functions.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClXof_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Indcpa_Generate_Keys)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Indcpa_Generate_Keys(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pk,
  mcuxClKey_Handle_t sk,
  const uint8_t d[MCUXCLMLKEM_SYMBYTES],
  mcuxClMlKem_Params_t pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Indcpa_Generate_Keys);

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClXof_ContextDescriptor_t *, pContext, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()

  /* |buf| = 2*MCUXCLMLKEM_SYMBYTES = 64 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, buf, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)));
  /* |csk| = 96*MLKEM_K
   *       = 192 bytes when MLKEM_K=2
   *       = 288 bytes when MLKEM_K=3
   *       = 384 bytes when MLKEM_K=4 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, csk, mcuxClSession_allocateWords_cpuWa(session, (96u * (uint32_t)pParams->k) / sizeof(uint32_t)));
  uint8_t *publicseed = buf;
  uint8_t *noiseseed = buf + MCUXCLMLKEM_SYMBYTES;
  uint8_t nonce = 0;

  /* |skpv| = MLKEM_N * 2 = 512 bytes */
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, skpv, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
   /* |pkpv| = MLKEM_N * 2 = 512 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, pkpv, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()
  mcuxClMlKem_Poly_t *e = skpv;


  MCUXCLBUFFER_INIT(seedBuf, session, buf, 2U * MCUXCLMLKEM_SYMBYTES);

  /* Init seed and (rho, sigma) = G(d) with low entropy randomness */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(buf, 2U * MCUXCLMLKEM_SYMBYTES));

  /* Copy d into buf and append k as domain separation */
  MCUX_CSSL_DI_RECORD(copyDParams, buf);
  MCUX_CSSL_DI_RECORD(copyDParams, d);
  MCUX_CSSL_DI_RECORD(copyDParams, MCUXCLMLKEM_SYMBYTES);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(buf, d, MCUXCLMLKEM_SYMBYTES));
  buf[MCUXCLMLKEM_SYMBYTES] = pParams->k;

  /* Generate rho and sigma by applying G to the concatenated input of d and k. */
  uint32_t outSize = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL(ret_hash, mcuxClHash_compute(session, mcuxClHash_Algorithm_Sha3_512, seedBuf, MCUXCLMLKEM_SYMBYTES + 1U, seedBuf, &outSize));
  if(MCUXCLHASH_STATUS_OK != ret_hash)
  {
    MCUXCLSESSION_ERROR(session, ret_hash);
  }

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  /* Expand secret key polynomials s from sigma, and store for re-use in compressed form in csk */
  for(uint32_t i = 0u; i < (uint32_t) pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Get_Noise_Eta1, mcuxClMlKem_Poly_Get_Noise_Eta1(session, skpv, noiseseed, nonce++, pParams));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Get_Noise_Eta1)
    {
      MCUXCLSESSION_ERROR(session, ret_Get_Noise_Eta1);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Compress_Eta1(csk + 96u * i, skpv));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Get_Noise_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Eta1)
      );
  }

  /* Row-wise matrix-vector multiplication */
  MCUX_CSSL_FP_LOOP_DECL(loop_2);
  for(uint32_t i = 0u; i < (uint32_t) pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(skpv, csk + 96u * 0u));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(skpv));
    /* Process first element of row i */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Mul_Streamed_Matrix, mcuxClMlKem_Poly_Mul_Streamed_Matrix(session, pContext, pkpv, skpv, publicseed, (uint8_t)i, 0u, 0u));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Mul_Streamed_Matrix)
    {
      MCUXCLSESSION_ERROR(session, ret_Mul_Streamed_Matrix);
    }

    MCUX_CSSL_FP_LOOP_DECL(loop_3);
    /* Process remaining elements of row i */
    for(uint32_t j = 1u; j < (uint32_t) pParams->k; j++)
    {
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(skpv, csk + 96u * j));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(skpv));
      MCUX_CSSL_FP_FUNCTION_CALL(ret_Mul_Streamed_Matrix2, mcuxClMlKem_Poly_Mul_Streamed_Matrix(session, pContext, skpv, skpv, publicseed, (uint8_t)i, (uint8_t)j, 0u));
      if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Mul_Streamed_Matrix2)
      {
        MCUXCLSESSION_ERROR(session, ret_Mul_Streamed_Matrix2);
      }

      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(pkpv, pkpv, skpv));

      MCUX_CSSL_FP_LOOP_ITERATION(loop_3,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Matrix),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add)
          );
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(pkpv));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_To_Mont(pkpv));

    MCUX_CSSL_FP_FUNCTION_CALL(ret_Get_Noise_Eta1, mcuxClMlKem_Poly_Get_Noise_Eta1(session, e, noiseseed, nonce++, pParams));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Get_Noise_Eta1)
    {
      MCUXCLSESSION_ERROR(session, ret_Get_Noise_Eta1);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(e));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(pkpv, pkpv, e));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(pkpv));

    /* re-use skpv to temporarily store t, before writing to the public key */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_To_Bytes((uint8_t *)skpv, pkpv));

    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pk));
    MCUXCLKEY_STORE_FP(
      session,
      pk,
      (uint8_t *)skpv,
      MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLKEM_PK_T |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(i * MCUXCLMLKEM_POLYBYTES / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLKEM_POLYBYTES / sizeof(uint32_t))
    );

    MCUX_CSSL_FP_LOOP_ITERATION(loop_2,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Matrix),
      MCUX_CSSL_FP_LOOP_ITERATIONS(loop_3, (uint32_t)pParams->k - 1U),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_To_Mont),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Get_Noise_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_To_Bytes)
      );
  }

  MCUX_CSSL_FP_LOOP_DECL(loop_4);
  for(uint32_t i = 0u; i < (uint32_t) pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(skpv, csk + 96u * i));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(skpv));

    /* re-use pkpv to temporarily store s, before writing to the public key */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_To_Bytes((uint8_t *)pkpv, skpv));
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sk));
    MCUXCLKEY_STORE_FP(
      session,
      sk,
      (uint8_t *)pkpv,
      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_MLKEM_SK_S |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(i * MCUXCLMLKEM_POLYBYTES / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLKEM_POLYBYTES / sizeof(uint32_t))
    );

    MCUX_CSSL_FP_LOOP_ITERATION(loop_4,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_To_Bytes)
      );
  }

  /* Store rho in pk = t || rho */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pk));
  MCUXCLKEY_STORE_FP(
    session,
    pk,
    publicseed,
    MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL| MCUXCLKEY_ENCODING_SPEC_MLKEM_PK_RHO
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(pParams->polyvecbytes / sizeof(uint32_t))
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t)));


  mcuxClSession_freeWords_cpuWa(session, (MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS
                                         + (2u * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)) /* buf */
                                         + ((96u * (uint32_t)pParams->k) / sizeof(uint32_t)) /* csk */
                                         + ((2u * MCUXCLMLKEM_N) / sizeof(uint32_t)) /* pkpv */
                                         + (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)); /* skpv */

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Indcpa_Generate_Keys, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, pParams->k),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, pParams->k),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_4, pParams->k)
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encrypt(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t ct, /* will only be written to when mcuxClMlKem_Poly_Compress_Write is passed as opFn */
  const uint8_t *m,
  const uint8_t *pk,
  const uint8_t coins[MCUXCLMLKEM_SYMBYTES],
  mcuxClMlKem_Poly_Compress_Op_t opFn,
  uint32_t protectionToken_opFn,
  mcuxClMlKem_Params_t pParams,
  mcuxClMemory_Status_t *rc)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Encrypt);

  uint8_t i;
  uint8_t j;
  uint8_t nonce = 0u;

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClXof_ContextDescriptor_t *, pContext, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, seed, mcuxClSession_allocateWords_cpuWa(session, MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t)));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, csk, mcuxClSession_allocateWords_cpuWa(session, (96u * (uint32_t)pParams->k) / sizeof(uint32_t)));

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, bp, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, sp, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()

  mcuxClMlKem_Poly_t *ep = sp;
  mcuxClMlKem_Poly_t *epp = sp;
  mcuxClMlKem_Poly_t *k = sp;
  mcuxClMlKem_Poly_t *v = bp;

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(i = 0; i < MCUXCLMLKEM_SYMBYTES; i++)
  {
    seed[i] = pk[i+pParams->polyvecbytes];
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  /* Generate secret polynomial and compress for later use */
  MCUX_CSSL_FP_LOOP_DECL(loop_2);
  for(i = 0; i < pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Get_Noise_Eta1, mcuxClMlKem_Poly_Get_Noise_Eta1(session, sp, coins, nonce++, pParams));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Get_Noise_Eta1)
    {
      MCUXCLSESSION_ERROR(session, ret_Get_Noise_Eta1);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Compress_Eta1(csk + 96u * i, sp));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_2,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Get_Noise_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Eta1)
      );
  }

  /* Matrix vector multiplication and noise addition (u = A^T * r + e1) */
  MCUX_CSSL_FP_LOOP_DECL(loop_3);
  for(i = 0; i < pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(sp, csk + 96u * 0u));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(sp));

    MCUX_CSSL_FP_FUNCTION_CALL(ret_Mul_Streamed_Matrix1, mcuxClMlKem_Poly_Mul_Streamed_Matrix(session, pContext, bp, sp, seed, i, 0u, 1u));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Mul_Streamed_Matrix1)
    {
      MCUXCLSESSION_ERROR(session, ret_Mul_Streamed_Matrix1);
    }

    MCUX_CSSL_FP_LOOP_DECL(loop_4);
    for(j = 1; j < pParams->k; j++)
    {
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(sp, csk + 96u * j));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(sp));

      MCUX_CSSL_FP_FUNCTION_CALL(ret_Mul_Streamed_Matrix2, mcuxClMlKem_Poly_Mul_Streamed_Matrix(session, pContext, sp, sp, seed, i, j, 1u));
      if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Mul_Streamed_Matrix2)
      {
        MCUXCLSESSION_ERROR(session, ret_Mul_Streamed_Matrix2);
      }

      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(bp, bp, sp));

      MCUX_CSSL_FP_LOOP_ITERATION(loop_4,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Matrix),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add)
        );

    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_InvNTT_To_Mont(bp));

    /* Add noise */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Get_Noise_Eta2, mcuxClMlKem_Poly_Get_Noise_Eta2(session, ep, coins, nonce++));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Get_Noise_Eta2)
    {
      MCUXCLSESSION_ERROR(session, ret_Poly_Get_Noise_Eta2);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(bp, bp, ep));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(bp));

    /* write or compare to ciphertext, use sp as workarea */
    MCUX_CSSL_FP_FUNCTION_CALL(retOp,
                              opFn(session,
                                   pParams,
                                   bp,
                                   ct,
                                   mcuxClMlKem_Poly_Compress_Gen,
                                   pParams->polycompressedbytes_gen,
                                   (uint8_t *)sp,
                                   rc));
    if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != retOp)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encrypt, retOp);
    }
    /* Update ciphertext to point to next u (or v, if last) poly */
    MCUXCLBUFFER_UPDATE(ct, pParams->polycompressedbytes_gen);

    MCUX_CSSL_FP_LOOP_ITERATION(loop_3,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Matrix),
      MCUX_CSSL_FP_LOOP_ITERATIONS(loop_4, (uint32_t)pParams->k - 1U),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_InvNTT_To_Mont),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Get_Noise_Eta2),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce),
      protectionToken_opFn,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Gen)
      );
  }

  /* Now we will compute the shared secret in v (t * r^t + e2) */

  /* Inner product */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(sp, csk + 96u * 0u));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(sp));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Mul_Streamed_Skpk(v, sp, pk, 0u));

  MCUX_CSSL_FP_LOOP_DECL(loop_5);
  for(i = 1; i < pParams->k; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Decompress_Eta1(sp, csk + 96u * i));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(sp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Mul_Streamed_Skpk(sp, sp, pk, i));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(v, v, sp));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_5,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Skpk),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add)
      );
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_InvNTT_To_Mont(v));

  /* v = t * r^t */

  /* Add noise vector e2 */
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Get_Noise_Eta2, mcuxClMlKem_Poly_Get_Noise_Eta2(session, epp, coins, nonce));
  if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Get_Noise_Eta2)
  {
    MCUXCLSESSION_ERROR(session, ret_Poly_Get_Noise_Eta2);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(v, v, epp));
   /* v = t * r^t + e2 */

  /* encrypt the message by adding it to the shared secret */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_From_Msg(k, m));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(v, v, k));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(v));
   /* v = t * r^t + e2 + Decompress_q(Decode(m), 1)*/

  /* write or compare to ciphertext */
  MCUX_CSSL_FP_FUNCTION_CALL(retOp,
                            opFn(session,
                                 pParams,
                                 v,
                                 ct,
                                 mcuxClMlKem_Poly_Compress,
                                 pParams->polycompressedbytes,
                                 (uint8_t *)sp,
                                 rc));
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != retOp)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encrypt, retOp);
  }

  mcuxClSession_freeWords_cpuWa(session, (MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS
                                        + (MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t))
                                        + (((96u * (uint32_t)pParams->k) / sizeof(uint32_t)))
                                        + ((2u * MCUXCLMLKEM_N) / sizeof(uint32_t))
                                        + ((2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encrypt, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_SYMBYTES),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, pParams->k),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_3, pParams->k),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Eta1),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Skpk),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_5, (uint32_t)pParams->k - 1U),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_InvNTT_To_Mont),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Get_Noise_Eta2),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_From_Msg),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce),
    protectionToken_opFn,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)
mcuxClMlKem_Decrypt(mcuxClSession_Handle_t session,
                   uint8_t *const m,
                   mcuxCl_InputBuffer_t c,
                   const uint8_t *sk,
                   mcuxClMlKem_Params_t pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Decrypt);

  /* |bp| = 2*MLKEM_N = 512 bytes */
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, bp, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
  /* |mp| = 2*MLKEM_N = 512 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlKem_Poly_t*, mp, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_N) / sizeof(uint32_t)));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()
  mcuxClMlKem_Poly_t *v = bp; /* Reuse memory allocated to bp  */

  MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Decompress_Gen1, mcuxClMlKem_Poly_Decompress_Gen(session, bp, c, pParams));
  if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Decompress_Gen1)
  {
    MCUXCLSESSION_ERROR(session, ret_Poly_Decompress_Gen1);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(bp));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Mul_Streamed_Skpk(mp, bp, sk, 0u));

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 1u; i < (uint32_t)pParams->k; i++)
  {
    MCUXCLBUFFER_DERIVE_RO(cBuf, c, i*pParams->polycompressedbytes_gen);
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Decompress_Gen, mcuxClMlKem_Poly_Decompress_Gen(session, bp, cBuf, pParams));
    if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Decompress_Gen)
    {
    MCUXCLSESSION_ERROR(session, ret_Poly_Decompress_Gen);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_NTT(bp));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Mul_Streamed_Skpk(bp, bp, sk, (uint16_t)i));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Add(mp, mp, bp));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Gen),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Skpk),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Add)
    );
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_InvNTT_To_Mont(mp));

  MCUXCLBUFFER_DERIVE_RO(vBuf, c, pParams->polyveccompressedbytes);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Decompress_Gen2, mcuxClMlKem_Poly_Decompress(session, v, vBuf, pParams));
  if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Decompress_Gen2)
  {
    MCUXCLSESSION_ERROR(session, ret_Poly_Decompress_Gen2);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Sub(mp, v, mp));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(mp));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_To_Msg(m, mp));

  /*free bp and mp*/
  mcuxClSession_freeWords_cpuWa(session, (4u * MCUXCLMLKEM_N) / sizeof(uint32_t));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decrypt, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress_Gen),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_NTT),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Mul_Streamed_Skpk),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, (uint32_t)pParams->k - 1U),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_InvNTT_To_Mont),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Decompress),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Sub),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_To_Msg));
}
