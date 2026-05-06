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
 * @file mcuxClMlDsa_KeyGen.c
 * @brief Implementation of key generation for @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClMlDsa.h>
#include <mcuxClRandom.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxClSession.h>
#include <mcuxClSignature.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClKey_Functions.h>
#include <mcuxClToolchain.h>

#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClPrng_Internal_Functions.h>
#include <internal/mcuxClXofModes_Internal_Memory.h>

/**
 * @brief ML-DSA keypair core function, inlined into the main keypair function
 *
 * This function performs short vector sampling and matrix-vector multiplication for ML-DSA keypair generation.
 *
 * @param[in]       session       Handle for the current CL session
 * @param[in]       pParams       Pointer to parameters and sizes for ML-DSA mode
 * @param[in,out]   sk            Handle for the private key
 * @param[in,out]   pk            Handle for the public key
 * @param[in,out]   pS1           Pointer to memory for s1
 * @param[in,out]   pT1           Pointer to memory for t1
 * @param[in,out]   pRho          Pointer to public seed
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Keypair_Core)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Keypair_Core(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxClKey_Handle_t sk,
  mcuxClKey_Handle_t pk,
  mcuxClMlDsa_Poly_t* const pS1,
  mcuxClMlDsa_Poly_t* const pT1,
  uint8_t* const pRho,
  uint8_t* const pRhoPrime
)
{
  /* Initialize function */
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Keypair_Core);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pParams->l, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L)

  /***********************************
   * Allocate memory for Shake       *
  ************************************/

  /* allocate space for packed t0/t1 and xof context/output buffer */
  const uint32_t coreWaWords = MCUXCLCORE_MAX(
    MCUXCLCORE_MAX(MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLYT0_PACKEDBYTES),
                  MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLYT1_PACKEDBYTES)),
    MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL)
      + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_KEYGEN_XOF_OUT_BUFFER_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, coreWaWords));

  /* For new shake context (for both shake128 and shake256) */
  uint8_t* const pShakeContext8 = pWa;

  /* Use a single hash buffer in memory for both 128 and 256 bits */
  uint8_t* const pHashOutBuf = pWa + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL);
  uint8_t* const pHashOutBuf128 = pHashOutBuf;
  uint8_t* const pHashOutBuf256 = pHashOutBuf;

  /* Use workarea to hold packed t0/t1 before storing in public key */
  uint8_t* const pPackedT0 = pWa;
  uint8_t* const pPackedT1 = pWa;

  /* Allocate space for s1/s2 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPackedS1, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->l * (uint32_t)pParams->polyeta_packedbytes)));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPackedS2, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(pParams->polyeta_packedbytes)));

  /* Cast shake context pointer as Xof_Context_t */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("these contexts are 32-bit aligned because of mcuxClSession_allocateWords_cpuWa")
  mcuxClXof_Context_t pShakeContext = (mcuxClXof_Context_t) pShakeContext8;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /****************************************
   * Sample short vector s1               *
  *****************************************/

  /* Loop over all L entries */
  for (uint16_t i = 0U; i < pParams->l; ++i)
  {
    /* Sample polynomial and store in s1 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UniformEta));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UniformEta(pS1,
                                                              pRhoPrime,
                                                              i,
                                                              pHashOutBuf256,
                                                              pParams,
                                                              session,
                                                              MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("these contexts are 32-bit aligned because of mcuxClSession_allocateWords_cpuWa")
                                                              pShakeContext));
                                                              MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    /* Pack polynomial into memory */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Eta_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Eta_Pack(session,
                                                               pPackedS1 + i * pParams->polyeta_packedbytes,
                                                               pS1,
                                                               pParams));

    /* Write s1 to sk (chunked) */
    const uint32_t s1Off = 2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_TRBYTES + i * (uint32_t)pParams->polyeta_packedbytes;
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sk));
    MCUXCLKEY_STORE_FP(
      session,
      sk,
      pPackedS1 + i * pParams->polyeta_packedbytes,
      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_S1 |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(s1Off / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(pParams->polyeta_packedbytes / sizeof(uint32_t))
    );
  }

  /****************************************
   * Matrix-vector multiplication         *
  *****************************************/

  /* Loop over all K entries */
  for (uint16_t i = 0U; i < pParams->k; ++i)
  {
    /* Set pT1 to all-0 vector */
    MCUX_CSSL_DI_RECORD(memClearT1Dst, (uint8_t *)pT1->coefficients);
    MCUX_CSSL_DI_RECORD(memClearT1Len, MCUXCLMLDSA_POLY_SIZE);

    MCUX_CSSL_FP_EXPECT(MCUXCLMEMORY_CLEAR_INT_FP_EXPECT);
    MCUXCLMEMORY_CLEAR_INT((uint8_t *)pT1->coefficients, MCUXCLMLDSA_POLY_SIZE);

    /* Loop over all L entries */
    for (uint16_t j = 0U; j < pParams->l; ++j)
    {
      /* Unpack secret key element */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Eta_Unpack));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Eta_Unpack(session,
                                                                   pS1,
                                                                   pPackedS1 + j * pParams->polyeta_packedbytes,
                                                                   pParams));

      /* Move s1 into NTT domain */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(pS1));

      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(i, 0U, MCUXCLMLDSA_MLDSA87_K - 1U)
      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(j, 0U, MCUXCLMLDSA_MLDSA87_L - 1U)

      /* Expand matrix element on the fly during multiplication */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate(pT1,
                                                                              pS1,
                                                                              pRho,
                                                                              (i << 8U) + j,
                                                                              pHashOutBuf128,
                                                                              session,
                                                                              pShakeContext));
    }

    /* Center coefficients of t1 around 0 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(pT1));

    /* Perform inplace inverse NTT */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(pT1));

    /* Generate error vector s2 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UniformEta));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UniformEta(pS1,
                                                              pRhoPrime,
                                                              ((uint16_t)pParams->l) + i,
                                                              pHashOutBuf256,
                                                              pParams,
                                                              session,
                                                              pShakeContext));

    /* Add error vector to t1 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Add));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Add(pT1,
                                                       pT1,
                                                       pS1));

    /* Pack s2 into workarea */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Eta_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Eta_Pack(session, pPackedS2, pS1, pParams));

    const uint32_t s2Off = 2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_TRBYTES
                           + (uint32_t)pParams->l * (uint32_t)pParams->polyeta_packedbytes
                           + i * (uint32_t)pParams->polyeta_packedbytes;

    /* Write s2 to sk (chunked) */
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sk));
    MCUXCLKEY_STORE_FP(
      session,
      sk,
      pPackedS2,
      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_S2 |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(s2Off / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(pParams->polyeta_packedbytes / sizeof(uint32_t))
    );

    /* Extract t1 and write to public key */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Caddq));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Caddq(pT1));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Power2Round));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Power2Round(pT1, pS1, pT1));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_T0_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_T0_Pack(pPackedT0, pS1));

    /* Write packed t0 to secret key (chunked) */
    const uint32_t t0Off = 2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_TRBYTES
                           + (uint32_t)pParams->k * (uint32_t)pParams->polyeta_packedbytes
                           + (uint32_t)pParams->l * (uint32_t)pParams->polyeta_packedbytes
                           + i * MCUXCLMLDSA_POLYT0_PACKEDBYTES;
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sk));
    MCUXCLKEY_STORE_FP(
      session,
      sk,
      pPackedT0,
      MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_T0 |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(t0Off / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLDSA_POLYT0_PACKEDBYTES / sizeof(uint32_t))
    );

    /* Write packed t1 to pk (chunked) */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_T1_Pack));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_T1_Pack(pPackedT1, pT1));

    uint32_t t1Off = MCUXCLMLDSA_SEEDBYTES + (uint32_t)i * MCUXCLMLDSA_POLYT1_PACKEDBYTES;
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pk));
    MCUXCLKEY_STORE_FP(
      session,
      pk,
      pPackedT1,
      MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLDSA_PK_T |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(t1Off / sizeof(uint32_t)) |
        MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLDSA_POLYT1_PACKEDBYTES / sizeof(uint32_t))
    );
  }

  /* Free up the allocated memory */
  mcuxClSession_freeWords_cpuWa(session, coreWaWords);
  mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->l * (uint32_t)pParams->polyeta_packedbytes));
  mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->polyeta_packedbytes));

  /* Exit the function */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Keypair_Core);
}

/**
 * @brief ML-DSA derandomized keypair function
 *
 * This function performs short vector sampling and matrix-vector multiplication for ML-DSA keypair generation.
 *
 * @param[in]       session       Handle for the current CL session
 * @param[in]       generation    Parameters and sizes for ML-DSA mode
 * @param[in]       privKey       Handle for the private key data
 * @param[in]       pubKey        Handle for the public key data
 * @param[in]       pWa           Workarea that already contains the seed for keygen
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Keypair_Derandomized)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Keypair_Derandomized(
  mcuxClSession_Handle_t session,
  mcuxClKey_Generation_t generation,
  mcuxClKey_Handle_t privKey,
  mcuxClKey_Handle_t pubKey,
  uint8_t* pWa)
{
  /* Initialize keypair function */
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Keypair_Derandomized);

  /* Check key types on validity */
  if (((MCUXCLKEY_ALGO_ID_MLDSA) != mcuxClKey_getAlgorithm(privKey))
      || ((MCUXCLKEY_ALGO_ID_MLDSA) != mcuxClKey_getAlgorithm(pubKey)))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* Extract mode (2, 3, 5) from generation input variable */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST("Const must be discarded to initialize the mode.")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
  const mcuxClMlDsa_Mode_t mode = *((mcuxClMlDsa_Mode_t *)(generation->pProtocolDescriptor));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST()

  /* Obtain parameter set from mode */
  const mcuxClMlDsa_Params_t *pParams = NULL;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Get_Params(session, mode, &pParams));

  /* we still need to wrap this in a buffer to hash it into the secret key */
  uint8_t* const pPk = mcuxClKey_getKeyData(pubKey);

  /* Allocate memory for s1 and t1 */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The pointer is 32-bit aligned because of mcuxClSession_allocateWords_cpuWa")
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pS1, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pT1, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  /* Create convenient pointers to objects in memory */
  uint8_t* const pSeed = pWa;
  uint8_t* const pRho = pWa;                                                   /* |rho| = MCUXCLMLDSA_SEEDBYTES */
  uint8_t* const pRhoPrime = pWa + MCUXCLMLDSA_SEEDBYTES;                       /* |rhoprime| = MCUXCLMLDSA_CRHBYTES */
  uint8_t* const pK = pRhoPrime + MCUXCLMLDSA_CRHBYTES;                         /* |K| = MCUXCLMLDSA_SEEDBYTES */

  /* re-use key space for hash of public key */
  uint8_t* const pTr = pRhoPrime;                                              /* |pTr| = MCUXCLMLDSA_CRHBYTES */

  pSeed[MCUXCLMLDSA_SEEDBYTES] = pParams->k;
  pSeed[MCUXCLMLDSA_SEEDBYTES + 1U] = pParams->l;

  /* Hash the seedbuf in-place */
  MCUXCLBUFFER_INIT(seedBuf, NULL, pSeed, MCUXCLMLDSA_SEEDBYTES + 2U);

    /* Balance DI for mcuxClXof_compute_internal() */
  MCUX_CSSL_DI_RECORD(xofComputeParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, MCUXCLMLDSA_SEEDBYTES + 2U);
  MCUX_CSSL_DI_RECORD(xofComputeParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, 2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_compute_internal(session,
                                                           mcuxClXof_Algorithm_Shake_256,
                                                           seedBuf,
                                                           MCUXCLMLDSA_SEEDBYTES + 2U,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                           NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                        0U,
                                                      seedBuf,
                                                      2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_CRHBYTES));
  /* Call main Keypair_Core subroutine which takes care the polynomial arithmetic */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Keypair_Core(session,
                                                         pParams,
                                                         privKey,
                                                         pubKey,
                                                         MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The pointer is 32-bit aligned because of mcuxClSession_allocateWords_cpuWa")
                                                         pS1,
                                                         pT1,
                                                         MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
                                                         pRho,
                                                         pRhoPrime));

  /* Store Rho in Pk */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pubKey));
  MCUXCLKEY_STORE_FP(
    session,
    pubKey,
    pRho,
    MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLDSA_PK_RHO |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED | MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(0UL) |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE((uint32_t)MCUXCLMLDSA_SEEDBYTES / sizeof(uint32_t))
  );

  /* Store Rho in Sk */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privKey));
  MCUXCLKEY_STORE_FP(
    session,
    privKey,
    pRho,
    MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_RHO |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED | MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(0UL) |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLDSA_SEEDBYTES / sizeof(uint32_t))
  );

  /* Store K in Sk */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privKey));
  MCUXCLKEY_STORE_FP(
    session,
    privKey,
    pK,
    MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_K |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(MCUXCLMLDSA_SEEDBYTES / sizeof(uint32_t)) |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLDSA_SEEDBYTES / sizeof(uint32_t))
  );

  /* Compute Hash(pk) = CRH(rho || t1) and write secret key */
  MCUXCLBUFFER_INIT_RO(pkBuf, NULL, pPk, pParams->publickey_bytes);
  MCUXCLBUFFER_INIT(trBuf, NULL, pTr, MCUXCLMLDSA_TRBYTES);

  /* Balance DI for mcuxClXof_compute_internal() */
  MCUX_CSSL_DI_RECORD(xofComputeParams, pkBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, pParams->publickey_bytes);
  MCUX_CSSL_DI_RECORD(xofComputeParams, trBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, MCUXCLMLDSA_TRBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_compute_internal(session,
                                                           mcuxClXof_Algorithm_Shake_256,
                                                           pkBuf,
                                                           pParams->publickey_bytes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                           NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                           0U,
                                                           trBuf,
                                                           MCUXCLMLDSA_TRBYTES));

  /* Store tr = Hash(pk) in Sk */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privKey));
  MCUXCLKEY_STORE_FP(
    session,
    privKey,
    pTr,
    MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL | MCUXCLKEY_ENCODING_SPEC_MLDSA_SK_H_PK |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(2U * MCUXCLMLDSA_SEEDBYTES / sizeof(uint32_t)) |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLDSA_TRBYTES / sizeof(uint32_t))
  );

  /* Free up the allocated polynomials */
  mcuxClSession_freeWords_cpuWa(session,
                               MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)       /* pS1 */
                                 + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE));             /* pT1 */

  /* Link Keypair */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_linkKeyPair(session, privKey, pubKey));

  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Keypair_Derandomized,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Keypair_Core),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_linkKeyPair)
    );
}


/**
 * @brief ML-DSA keypair function
 *
 * This function performs short vector sampling and matrix-vector multiplication for ML-DSA keypair generation.
 *
 * @param[in]       session       Handle for the current CL session
 * @param[in]       generation    Parameters and sizes for ML-DSA mode
 * @param[in]       privKey       Handle for the private key data
 * @param[in]       pubKey        Handle for the public key data
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Keypair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Keypair(
  mcuxClSession_Handle_t session,
  mcuxClKey_Generation_t generation,
  mcuxClKey_Handle_t privKey,
  mcuxClKey_Handle_t pubKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Keypair);

  /* Allocate memory for zeta and rho, sigma, K */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_CRHBYTES)));

  /* Init seedbuf with low entropy before filling with high quality randomness as an FA countermeasure */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pWa, 2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_CRHBYTES));


  /* Init seedbuf with actual good randomness for the seed */
  MCUXCLBUFFER_INIT(seedBuf, NULL, pWa, MCUXCLMLDSA_SEEDBYTES);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, session);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, seedBuf);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, MCUXCLMLDSA_SEEDBYTES);

  /* Call internal generate function
    * Data Integrity: Expunge(pSession + pOut + outLength) */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(session, seedBuf, MCUXCLMLDSA_SEEDBYTES, NULL));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Keypair_Derandomized));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Keypair_Derandomized(session, generation, privKey, pubKey, pWa));

  /* Free up the allocated pWa */
  mcuxClSession_freeWords_cpuWa(session,
                               MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * MCUXCLMLDSA_SEEDBYTES
                                                              + MCUXCLMLDSA_CRHBYTES)); /* pWa */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Keypair);
}
