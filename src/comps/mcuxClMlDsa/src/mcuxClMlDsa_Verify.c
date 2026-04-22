/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file mcuxClMlDsa_Verify.c
 * @brief Implementation of signature verification for @ref mcuxClMlDsa.
 *
 */

#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>

#include <mcuxClBuffer.h>
#include <mcuxClCrc.h>
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
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClHashModes_Internal_Algorithms.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClMlDsa_Internal_Constants.h>
#include <internal/mcuxClPrng_Internal_Functions.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClXof_Internal.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>

#if !(defined(MCUXCL_FEATURE_PKC_RAM_8KB) || defined(MCUXCL_FEATURE_PKC_RAM_4KB))
#error "MCUXCL_FEATURE_MLDSA_USE_PKC_RAM requires either MCUXCL_FEATURE_PKC_RAM_8KB or MCUXCL_FEATURE_PKC_RAM_4KB"
#endif /* !(defined(MCUXCL_FEATURE_PKC_RAM_8KB) || defined(MCUXCL_FEATURE_PKC_RAM_4KB)) */
/*
 * PKC WA polynomial layout.
 * Polynomials z and -c * 2^d are in NTT form.
 *
 * mode     2       3       5
 * -----------------------------
 * p0      [      -c * 2^d     ]
 * p1      [        z0         ]
 * p2      [        z1         ]
 * p3      [        z2         ]
 * ---------PKC_RAM_4KB---------
 * p4      [        z3         ]
 * p5              [     z4    ]
 * p6      [    poly1   ][  z5 ]
 * p7      [    poly2   ][  z6 ]
 * --------PKC_RAM_8KB---------
 */
/* The macro MCUXCLMLDSA_PTR_Z is a helper to select the pointer to a polynomial of z.
 * idx: the index of the polynomial in z.
 * cpu: a pointer to a fallback workarea polynomial to unpack and NTT z in. */
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
/* Use PKC WA for polynomials z0-z6 */
#define MCUXCLMLDSA_PTR_Z(idx, cpu, pkc) (&(pkc)[(idx)])
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
/* Use PKC ram for polynomials z0-z2, fallback to CPU workarea for z3-z6 */
#define MCUXCLMLDSA_PTR_Z(idx, cpu, pkc) (((idx) > 2U) ? (cpu) : (&(pkc)[(idx)]))
#endif /* defined(MCUXCL_FEATURE_PKC_RAM_8KB) */

/*************************************************
 * Name:        mcuxClMlDsa_Verify_CheckInputs
 *
 * Description: Subroutine for ML-DSA verify
 *              to check inputs are proper and memory allocation succeeded.
 *
 * Data Integrity: Expunge(publicKeyLen + signatureLen + pParams)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_CheckInputs)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Verify_CheckInputs(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  const uint32_t publicKeyLen,
  const uint32_t signatureLen,
  mcuxClXof_Context_t pShakeContext,
  mcuxClXof_Context_t pShakeContextMu,
  const uint8_t* const pHashOutBuf,
  const mcuxClMlDsa_Poly_t* const pPoly1,
  const mcuxClMlDsa_Poly_t* const pPoly2
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_CheckInputs);

  /* Check that the signature length is consistent */
  if(signatureLen != pParams->signature_bytes)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  if(publicKeyLen != pParams->publickey_bytes)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
  }

  /* Exit function */
  MCUX_CSSL_DI_EXPUNGE(verifyCheckInputsPkLen, publicKeyLen);
  MCUX_CSSL_DI_EXPUNGE(verifyCheckInputsSLen, signatureLen);
  MCUX_CSSL_DI_EXPUNGE(verifyCheckInputsPParams, pParams);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Verify_CheckInputs);
}

/*************************************************
 * Name:        mcuxClMlDsa_Verify_ComputeMu
 *
 * Description: Subroutine for ML-DSA verify
 *              to compute mu.
 *
 * Data Integrity: Expunge(pMu + pMessage + messageLen + pPublicKey)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_ComputeMu)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Verify_ComputeMu(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxClXof_Context_t pShakeContextMu,
  const uint8_t* const pPublicKey,
  uint8_t* const pMu,
  mcuxCl_InputBuffer_t const pMessage,
  const uint32_t messageLen,
  const mcuxClMlDsa_Mode_t mode,
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor,
  uint8_t* const pPreHashBuf)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_ComputeMu);

  /* Hash the public key into tr */
  MCUXCLBUFFER_INIT_RO(pkBuf, NULL, pPublicKey, pParams->publickey_bytes);
  MCUXCLBUFFER_INIT(trBuf, NULL, pMu, MCUXCLMLDSA_TRBYTES);

  /* Balance DI for mcuxClXof_compute_internal() */
  MCUX_CSSL_DI_RECORD(xofComputeParams, pkBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, pParams->publickey_bytes);
  MCUX_CSSL_DI_RECORD(xofComputeParams, trBuf);
  MCUX_CSSL_DI_RECORD(xofComputeParams, MCUXCLMLDSA_TRBYTES);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_compute_internal(session,
                                                           mcuxClXof_Algorithm_Shake_256,
                                                           pkBuf,
                                                           pParams->publickey_bytes,
                                                           NULL,
                                                           0U,
                                                           trBuf,
                                                           MCUXCLMLDSA_TRBYTES));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  /* Initialize a new shake state to compute H(tr || m) */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pShakeContextMu,
                                                        mcuxClXof_Algorithm_Shake_256,
                                                        NULL,
                                                        0U));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, trBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_TRBYTES);

  /* Absorb tr into the shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pShakeContextMu,
                                                           trBuf,
                                                           MCUXCLMLDSA_TRBYTES));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_ProcessExternalData(session,
                                                                pShakeContextMu,
                                                                pMessage,
                                                                messageLen,
                                                                mode,
                                                                pMlDsa_SignatureProtocolDescriptor,
                                                                pPreHashBuf));

  /* Squeeze the shake context into the variable mu */
  MCUXCLBUFFER_INIT(muBuf, NULL, pMu, MCUXCLMLDSA_CRHBYTES);
  /* Balance DI for mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, muBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                            pShakeContextMu,
                                                            muBuf,
                                                            (uint32_t) MCUXCLMLDSA_CRHBYTES));

  MCUX_CSSL_DI_EXPUNGE(computeMuPMu, pMu);
  MCUX_CSSL_DI_EXPUNGE(computeMuPMessage, pMessage);
  MCUX_CSSL_DI_EXPUNGE(computeMuMessageLen, messageLen);
  MCUX_CSSL_DI_EXPUNGE(computeMuPPublicKey, pPublicKey);
  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Verify_ComputeMu,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute_internal), /* retXofCompute */
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal), /* retXofInit */
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal), /* retXofProcessMu */
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_ProcessExternalData), /* retProcessExternalData */
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal)); /* retXofGenerate */
}

/*************************************************
 * Name:        mcuxClMlDsa_Verify_PolynomialArithmetic
 *
 * Description: Subroutine for ML-DSA verify
 *              to compute A*z - 2^d * c * t1 from
 *              the public key and packed challenge.
 *
 * Data Integrity: Expunge(pMu + pCPacked + pPublicKey)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_PolynomialArithmetic)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify_PolynomialArithmetic(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxCl_InputBuffer_t zBuf,
  mcuxCl_InputBuffer_t hintBuf,
  mcuxClXof_Context_t pShakeContext,
  mcuxClXof_Context_t pShakeContextMu,
  const uint8_t* const pPublicKey,
  const uint8_t* const pMu,
  mcuxClMlDsa_Poly_t* pC, /* possibly an alias of poly2, see below */
  uint8_t* const pCPacked, /* possibly unused (if PKC WA is used) */
  mcuxClMlDsa_Poly_t* const poly1, /* used to hold variables (mu, t1, w1prime intermediates) */
  mcuxClMlDsa_Poly_t* const poly2, /* used for c, z and h (unless PKC WA is enabled) */
  mcuxClMlDsa_Poly_t* const pZPkc, /* only used when PKC WA is used */
  uint8_t* const pHashOutBuf128,
  uint8_t * const pHints
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_PolynomialArithmetic);

  /* Matrix-vector multiplication; compute A*z - 2^d * c * t1 and pack into state per row */
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for (uint16_t i = 0U; i < pParams->k; ++i)
  {
    /*********************************************************
     * Step 1: Compute -c into poly2
     ********************************************************/

    MCUX_CSSL_DI_RECORD(verifyPolyArithK, 1U);

    /* We already have pC pointing at NTT(-c * 2^d) in PKC WA */
    (void)pCPacked;

    /* Step 2: Unpack t1 in to poly */
    const uint8_t *pT1 = pPublicKey + MCUXCLMLDSA_SEEDBYTES + i * MCUXCLMLDSA_POLYT1_PACKEDBYTES;
    MCUX_CSSL_DI_RECORD(T1UnpackUnpacked, (uintptr_t)poly1);
    MCUX_CSSL_DI_RECORD(T1UnpackPacked, (uintptr_t)pT1);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_T1_Unpack(poly1, pT1));

    /* Apply NTT to t1 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(poly1));

    /* Step3: Multiply -c * 2^d and t1 in NTT domain */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery(poly1,
                                                                          poly1,
                                                                          pC));

    /* At this point, poly1 contains -2^d * c * t1 (in the Montgomery domain) */

    /* Step 3: Unpack and multiply with Az */

    /* For each of the remaining L coefficients of A*z, expand necessary part of A and update w1 accordingly */
    MCUX_CSSL_FP_LOOP_DECL(loop_2);
    for (uint16_t j = 0U; j < pParams->l; ++j)
    {
      MCUX_CSSL_DI_RECORD(verifyPolyArithL, 1U);

      /*  Three cases:
       *  1. When we have no PKC WA, we have to unpack and NTT _all_ of the polynomials in z,
       *  2. When we have 4 KiB PKC WA, z0, z1 and z2 are available, the rest we still need to unpack/NTT,
       *  3. When we have 8 KiB PKC WA, we already have all polynomials in z in NTT domain.
       */
#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
      if(j > 2U)
      {
#endif  /* MCUXCL_FEATURE_PKC_RAM_4KB */
        /* Unpack z[j] into z */
        MCUXCLBUFFER_DERIVE_RO(zjBuf, zBuf, j * pParams->polyz_packedbytes);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack(session, MCUXCLMLDSA_PTR_Z(j, poly2, pZPkc), zjBuf, pParams));

        /* Apply NTT to unpacked z[j] */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT((MCUXCLMLDSA_PTR_Z(j, poly2, pZPkc))));
#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
      }
#endif /* MCUXCL_FEATURE_PKC_RAM_4KB */
#else
      (void)zBuf;
#endif

      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(i, 0U, MCUXCLMLDSA_MLDSA87_K - 1U)
      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(j, 0U, MCUXCLMLDSA_MLDSA87_L - 1U)

      /* Compute A*z[j] */
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate(poly1,
                                                                              MCUXCLMLDSA_PTR_Z(j, poly2, pZPkc),
                                                                              pPublicKey,
                                                                              (i << 8U) + j,
                                                                              pHashOutBuf128,
                                                                              session,
                                                                              pShakeContext));


      MCUX_CSSL_FP_LOOP_ITERATION(loop_2,
#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
        MCUX_CSSL_FP_CONDITIONAL(j > 2U,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT)),
#else  /* defined(MCUXCL_FEATURE_MLDSA_USE_PKC_RAM) && defined(MCUXCL_FEATURE_PKC_RAM_4KB) */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
#endif /* defined(MCUXCL_FEATURE_MLDSA_USE_PKC_RAM) && defined(MCUXCL_FEATURE_PKC_RAM_4KB) */
#endif /* !defined(MCUXCL_FEATURE_MLDSA_USE_PKC_RAM) || (defined(MCUXCL_FEATURE_MLDSA_USE_PKC_RAM) && defined(MCUXCL_FEATURE_PKC_RAM_4KB)) */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate));
    }
    MCUX_CSSL_DI_EXPUNGE(verifyPolyArithL, pParams->l);

    /* At this point, poly1 contains A * z - 2^d * c * t1 (in the Montgomery domain) */

    /* Centralize all coefficients of w1 around 0 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Reduce(poly1));

    /* Exit NTT & Montgomery domains for w1 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTTToMont(poly1));

    /* Make all coefficients of w1 positive, so they are in the range [0, Q-1] */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Caddq(poly1));

    /* At this point, poly1 contains A * z - 2^d * c * t1 */

    /* Step 4: Use the hint to correct high bits of poly1 */

    /* record h unpack */
    MCUX_CSSL_DI_RECORD(packingHUnpackParams, (uintptr_t)pParams);
    MCUX_CSSL_DI_RECORD(packingHUnpackH, (uintptr_t)poly2);

    /* record use hint */
    MCUX_CSSL_DI_RECORD(polyUseHintB, (uintptr_t)poly1);
    MCUX_CSSL_DI_RECORD(polyUseHintA, (uintptr_t)poly1);
    MCUX_CSSL_DI_RECORD(polyUseHintH, (uintptr_t)poly2);
    MCUX_CSSL_DI_RECORD(polyUseHintpParams, (uintptr_t)pParams);

    /* Unpack hint-part of signature into variable h */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->l, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyz_packedbytes,
                                       MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES,
                                       MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES,
                                       MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)

    MCUX_CSSL_FP_FUNCTION_CALL(retPolyHUnpack, mcuxClMlDsa_Packing_H_Unpack(session, poly2, i, pHints, hintBuf, pParams));

    /* Check signature. If it is invalid, we need to fully balance DI before returning */
    if(MCUXCLSIGNATURE_STATUS_OK != retPolyHUnpack)
    {
      /* DI expunge internally recorded values */
      MCUX_CSSL_DI_EXPUNGE(verifyPolyArithK, (uint32_t)i + 1U);
      MCUX_CSSL_DI_EXPUNGE(computeMuPMu, pMu);
      MCUX_CSSL_DI_EXPUNGE(computeMuPMessage, pCPacked);
      MCUX_CSSL_DI_EXPUNGE(computeMuPPublicKey, pPublicKey);
      MCUX_CSSL_DI_EXPUNGE(polyUseHintB, (uintptr_t)poly1);
      MCUX_CSSL_DI_EXPUNGE(polyUseHintA, (uintptr_t)poly1);
      MCUX_CSSL_DI_EXPUNGE(polyUseHintH, (uintptr_t)poly2);
      MCUX_CSSL_DI_EXPUNGE(polyUseHintpParams, (uintptr_t)pParams);
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_PolynomialArithmetic,
        retPolyHUnpack,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_T1_Unpack),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointwiseMontgomery),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Caddq),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_H_Unpack),
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, i),
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, pParams->l));
    }

    /* Use the unpacked hint to correct the high bits of w1 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UseHint(session,
                                                           poly1,
                                                           poly1,
                                                           poly2,
                                                           pParams));

    /* Step 5: Pack and absorb W1' */

    /* Pack w1 into variable z for input into XOF */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_W1_Pack(session,
                                                              (uint8_t*) poly2,
                                                              poly1,
                                                              pParams));

    /* Absorb packed w1 into running state */
    MCUXCLBUFFER_INIT_RO(w1primeBuf, NULL, (uint8_t*)poly2, pParams->polyw1_packedbytes);
    /* Balance DI for mcuxClXof_process_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, w1primeBuf);
    MCUX_CSSL_DI_RECORD(xofProcessParams, pParams->polyw1_packedbytes);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                             pShakeContextMu,
                                                             w1primeBuf,
                                                             pParams->polyw1_packedbytes));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_T1_Unpack),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointwiseMontgomery),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTTToMont),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Caddq),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_H_Unpack), /* retPolyHUnpack */
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UseHint),     /* retPolyUseHint */
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_W1_Pack),  /* retPolyW1Pack */
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),   /* retXofProcessW1 */
      MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, pParams->l));
  }
  MCUX_CSSL_DI_EXPUNGE(verifyPolyArithK, pParams->k);

  MCUX_CSSL_DI_EXPUNGE(computeMuPMu, pMu);
  MCUX_CSSL_DI_EXPUNGE(computeMuPMessage, pCPacked);
  MCUX_CSSL_DI_EXPUNGE(computeMuPPublicKey, pPublicKey);
  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_PolynomialArithmetic, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, pParams->k));
}

/**
 * @brief Subroutine to check strong unforgeability of the signature.
 *
 * @param[in]    pParams      Pointer to the parameters
 * @param[in]    hintBuf      Hint buffer
 * @param[in]    pZero        Pointer to workarea to hold zero part of the hints
 *
 * @returns an explicit error code on failure.
 *
 * Data integrity: Expunge(pParams + pSignature)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_Strong_Unforgeability)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify_Strong_Unforgeability(
  const mcuxClMlDsa_Params_t* const pParams,
  mcuxCl_InputBuffer_t hintBuf,
  uint8_t* pZero)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_Strong_Unforgeability);
  const uint32_t hintSize = (uint32_t)pParams->omega + (uint32_t)pParams->k;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->l, MCUXCLMLDSA_MLDSA44_L, MCUXCLMLDSA_MLDSA87_L, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hintSize,
                                     MCUXCLMLDSA_MLDSA65_OMEGA + MCUXCLMLDSA_MLDSA65_K, // 61
                                     MCUXCLMLDSA_MLDSA44_OMEGA + MCUXCLMLDSA_MLDSA44_K, // 84
                                     MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->polyz_packedbytes,
                                     MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES,
                                     MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES,
                                     MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)

  /* Lookup where the zeros in the hints start */
  uint8_t zeroOff = 0U;
  MCUX_CSSL_DI_RECORD(readZeroOffParams, hintBuf);
  MCUX_CSSL_DI_RECORD(readZeroOffParams, hintSize - 1U);
  MCUX_CSSL_DI_RECORD(readZeroOffParams, &zeroOff);
  MCUX_CSSL_DI_RECORD(readZeroOffParams, 1U);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(hintBuf, hintSize - 1U, &zeroOff, 1U));

  const uint32_t zeroSize = (uint32_t)pParams->omega - (uint32_t)zeroOff;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(zeroSize, 0u, MCUXCLMLDSA_MLDSA44_OMEGA, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)

  MCUX_CSSL_DI_RECORD(readZerosParams, hintBuf);
  MCUX_CSSL_DI_RECORD(readZerosParams, zeroOff);
  MCUX_CSSL_DI_RECORD(readZerosParams, pZero);
  MCUX_CSSL_DI_RECORD(readZerosParams, zeroSize);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(hintBuf, zeroOff, pZero, zeroSize));

  uint32_t i;
  MCUX_CSSL_DI_RECORD(pZeroPtr, pZero);
  for(i = 0U; i < zeroSize; i++)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pZero);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER((uintptr_t)pZero, 0u, UINT32_MAX - zeroSize, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)
    MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
    if(0U != *pZero++)
    {
      /* normal status code, so balance */
      MCUX_CSSL_DI_EXPUNGE(pZeroPtr, pZero - i - 1U);
      MCUX_CSSL_DI_EXPUNGE(verifyStrongUnforgeabilityParams, pParams);
      MCUX_CSSL_DI_EXPUNGE(verifyStrongUnforgeabilityParams, hintBuf);
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_Strong_Unforgeability, MCUXCLSIGNATURE_STATUS_NOT_OK,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    }
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()
  }

  /* use DI to check that pZero progressed as expected */
  MCUX_CSSL_DI_EXPUNGE(pZeroPtr, pZero - zeroSize);
  MCUX_CSSL_DI_EXPUNGE(verifyStrongUnforgeabilityParams, pParams);
  MCUX_CSSL_DI_EXPUNGE(verifyStrongUnforgeabilityParams, hintBuf);
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_Strong_Unforgeability, MCUXCLSIGNATURE_STATUS_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}

/**
 * @brief Subroutine to unpack and check the z vector of the signature.
 * Conditionally, this function will store z in NTT form.
 *
 * @param[in]    session      Session handle
 * @param[out]   pPolyCpu     Pointer to cpu workarea to unpack z in
 * @param[out]   pPolyPkc     Pointer to pkc workarea to unpack z in
 * @param[in]    zBuf         Buffer to serialized z vector
 * @param[in]    pParams      Pointer to the parameters
 *
 * @returns an explicit error code on failure.
 *
 * Data integrity: Expunge(pPolyCpu + pPolyPkc + zBuf + pParams)
 * On normal ok:   Record(2U * pParams->l * MCUXCLSIGNATURE_STATUS_OK)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_Unpack_Check_Z)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify_Unpack_Check_Z(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t* pPolyCpu,
  mcuxClMlDsa_Poly_t* const pPolyPkc,
  mcuxCl_InputBuffer_t zBuf,
  const mcuxClMlDsa_Params_t* const pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_Unpack_Check_Z);

  /* Perform separate checks for each of the l entries of z */
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint16_t i = 0U; i < pParams->l; ++i)
  {
    /* Decide where to unpack to, depending on index and feature flags */
    mcuxClMlDsa_Poly_t* pZ = MCUXCLMLDSA_PTR_Z(i, pPolyCpu, pPolyPkc);

    /* Unpack z */
    MCUXCLBUFFER_DERIVE_RO(ziBuf, zBuf, i * pParams->polyz_packedbytes);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer z is of the right type (mcuxClMlDsa_Poly_t).")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack(session, pZ, ziBuf, pParams));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

    /* Perform norm check of unpacked z, twice */
    MCUX_CSSL_DI_RECORD(polyCheckNormPtr, 2U * (uintptr_t)pZ);
    MCUX_CSSL_DI_RECORD(polyCheckNormBound, 2 * ((int32_t)pParams->gamma1 - (int32_t)pParams->beta));

    MCUX_CSSL_FP_FUNCTION_CALL(retPolyChkNorm,
                              mcuxClMlDsa_Poly_CheckNorm(session, pZ, (int32_t)pParams->gamma1 - (int32_t)pParams->beta));
    MCUX_CSSL_DI_RECORD(verifyCheckNorm, retPolyChkNorm);

    MCUX_CSSL_FP_FUNCTION_CALL(retPolyChkNorm2,
                              mcuxClMlDsa_Poly_CheckNorm(session, pZ, (int32_t)pParams->gamma1 - (int32_t)pParams->beta));
    MCUX_CSSL_DI_RECORD(verifyCheckNorm, retPolyChkNorm2);

    if(retPolyChkNorm != retPolyChkNorm2)
    {
      MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }

    /* Check if z is indeed within the given norm bounds */
    if(MCUXCLSIGNATURE_STATUS_OK != retPolyChkNorm)
    {
      /* Since we are returning a normal mismatch status code here, we need to balance DI/FP */
      MCUX_CSSL_DI_EXPUNGE(verifyCheckNorm,
                            2U * (((uint32_t)i * MCUXCLSIGNATURE_STATUS_OK) + MCUXCLSIGNATURE_STATUS_NOT_OK));
      MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pPolyCpu);
      MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pPolyPkc);
      MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, zBuf);
      MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pParams);

      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_Unpack_Check_Z, retPolyChkNorm,
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack), /* retPolyZUnpack */
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm),   /* retPolyChkNorm */
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm),   /* retPolyChkNorm2 */
                                    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, i));
      }

#ifdef MCUXCL_FEATURE_PKC_RAM_4KB
    if(i <= 2U)
    {
#endif
      /* Store (parts of) z that are in PKC WA in NTT form */
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(pZ));
#ifdef MCUXCL_FEATURE_PKC_RAM_4KB
    }
#endif

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
#ifdef MCUXCL_FEATURE_PKC_RAM_4KB
      MCUX_CSSL_FP_CONDITIONAL((i <= 2U), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT)),
#else  /* MCUXCL_FEATURE_PKC_RAM_4KB */
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
#endif /* MCUXCL_FEATURE_PKC_RAM_4KB */
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_CheckNorm)
      );
  }

  MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pPolyCpu);
  MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pPolyPkc);
  MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, zBuf);
  MCUX_CSSL_DI_EXPUNGE(unpackCheckZParams, pParams);
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_Unpack_Check_Z, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, pParams->l));
}

/*************************************************
 * Name:        mcuxClMlDsa_Verify_CompareAndFree
 *
 * Description: Subroutine for ML-DSA verify
 *              to do the final comparison (twice) and
 *              free workareas.
 *
 * Data Integrity: Expunge(cTildeBuf + pParams->cTildeSize)
 *
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_CompareAndFree)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify_CompareAndFree(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Params_t* const pParams,
  uint8_t * const pC1,
  uint8_t * const pC2,
  mcuxClXof_Context_t pShakeContextMu,
  mcuxCl_InputBuffer_t cTildeBuf,
  uint32_t cpuWaWordsToFree,
  uint32_t pkcWaWordsToFree
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_CompareAndFree);

  /* Initialize c1/c2 buffer with pseudorandom bytes */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pC1, (uint32_t)pParams->cTildeSize));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pC2, (uint32_t)pParams->cTildeSize));

  /* Squeeze the shake context into c2 */
  MCUXCLBUFFER_INIT(C2Buf, NULL, pC2, (uint32_t)pParams->cTildeSize);

  /* Balance DI for mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, C2Buf);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                            pShakeContextMu,
                                                            C2Buf,
                                                            (uint32_t)pParams->cTildeSize));

  /* Export the CRC of the computed c tilde value in the session (if the fmcuxClSession_computeAndSetCrcForExternalVerificationsecurity option is enabled) */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSession_computeAndSetCrcForExternalVerification(session, pC2, (uint32_t)pParams->cTildeSize));

  /* Perform a memory comparison of c1 in original signature and recomputed c2 */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(cTildeBuf, 0U, pC1, (uint32_t)pParams->cTildeSize));
  mcuxClMemory_Status_t retMemoryCompare1 = MCUXCLMEMORY_STATUS_NOT_EQUAL;
  MCUXCLMEMORY_COMPARE_INT(retMemoryCompare1,pC1,
                                            pC2,
                                            (uint32_t)pParams->cTildeSize);
  MCUX_CSSL_DI_RECORD(memCompare1, (uint32_t)retMemoryCompare1);

  mcuxClSignature_Status_t status1 = MCUXCLSIGNATURE_STATUS_FAULT_ATTACK;
  if(MCUXCLMEMORY_STATUS_EQUAL == retMemoryCompare1)
  {
    status1 = MCUXCLSIGNATURE_STATUS_OK;
    MCUX_CSSL_DI_EXPUNGE(memCmpOkStatus1, MCUXCLMEMORY_STATUS_EQUAL);
  }
  else if(MCUXCLMEMORY_STATUS_NOT_EQUAL == retMemoryCompare1)
  {
    status1 = MCUXCLSIGNATURE_STATUS_NOT_OK;
    MCUX_CSSL_DI_EXPUNGE(memCmpNotEqStatus1, MCUXCLMEMORY_STATUS_NOT_EQUAL);
  }
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

/* We are done using polynomials, free all polynomials in PKC WA, if we have any */
  mcuxClSession_freeWords_pkcWa(session, pkcWaWordsToFree);

  /* Perform a second comparison in PKC if it is enabled and securityOptions are set */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClResource_request(session, MCUXCLRESOURCE_HWID_PKC, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE, NULL, 0U)
    );
    MCUXCLPKC_FP_INITIALIZE(session);

    /* Setup PKC workarea and PKC buffers for comparison. */
    const uint32_t wordNumPkcWa = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * (uint32_t)pParams->cTildeSize);
    MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(session, wordNumPkcWa));

    /* Initialize c1/c2 buffer in PKC with pseudorandom bytes */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pPkcWorkarea, 2U * (uint32_t)pParams->cTildeSize));

    /* Set PS1 MCLEN and LEN. */
    const uint32_t operandSize = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE((uint32_t)pParams->cTildeSize);
    MCUXCLPKC_PS1_SETLENGTH(operandSize, operandSize);

    /* Setup uptr table. */
    uint32_t pOperands32[(MCUXCLMLDSA_UPTRT_SIZE + 1U) / 2U];
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY("Create 16-bit UPTR table at CPU word (32-bit) aligned address.")
    uint16_t *pOperands = (uint16_t *)pOperands32;
    MCUXCLPKC_FP_GENERATEUPTRT(pOperands,
                              pPkcWorkarea,
                              (uint16_t) (operandSize & 0xffffU),
                              MCUXCLMLDSA_UPTRT_SIZE);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY()
    MCUXCLPKC_SETUPTRT(pOperands);

    /* Import c1 from original signature and c2 to PKC */
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(MCUXCLMLDSA_PKC_T0, pC1, (uint32_t)pParams->cTildeSize, operandSize);
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(MCUXCLMLDSA_PKC_T1, pC2, (uint32_t)pParams->cTildeSize, operandSize);

    /* Do a comparison of the original signature and c2 in PKC */
    MCUXCLPKC_FP_CALC_OP1_CMP(MCUXCLMLDSA_PKC_T0, MCUXCLMLDSA_PKC_T1);
    uint32_t zeroFlag_checkC2 = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_DI_RECORD(pkcCompare2, (uint32_t)zeroFlag_checkC2);

    mcuxClSignature_Status_t status2 = MCUXCLSIGNATURE_STATUS_FAULT_ATTACK;

    if(MCUXCLPKC_FLAG_ZERO == zeroFlag_checkC2)
    {
      status2 = MCUXCLSIGNATURE_STATUS_OK;
      volatile uint32_t zeroFlagDoubled = MCUXCLPKC_GETZERO();  /* use "volatile" to avoid optimization the following EXPUNGE */
      MCUX_CSSL_DI_EXPUNGE(pkcCompare2, zeroFlagDoubled);
    }
    else
    {
      status2 = MCUXCLSIGNATURE_STATUS_NOT_OK;
      volatile uint32_t zeroFlagDoubled = MCUXCLPKC_GETZERO();  /* use "volatile" to avoid optimization the following EXPUNGE */
      MCUX_CSSL_DI_EXPUNGE(pkcCompare2, zeroFlagDoubled);
    }

    if(status1 != status2)
    {
      MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }

    mcuxClSession_freeWords_pkcWa(session, wordNumPkcWa);
    MCUXCLPKC_FP_DEINITIALIZE_RELEASE(session);

  MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, cTildeBuf);
  MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, pParams->cTildeSize);

  /* Free the allocated memory before exiting */
  mcuxClSession_freeWords_cpuWa(session, cpuWaWordsToFree);

  /* Record status */
  MCUX_CSSL_DI_RECORD(verifyRetCode, status1);

  /* After final use of params, we check the CRC */
  MCUX_CSSL_FP_FUNCTION_CALL(crcParams, mcuxClCrc_computeCRC32(
    (const uint8_t *)pParams, sizeof(mcuxClMlDsa_Params_t) - sizeof(uint32_t)));

  if(pParams->crc != crcParams)
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify_CompareAndFree, status1,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_computeAndSetCrcForExternalVerification),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    MCUXCLMEMORY_COMPARE_INT_FP_EXPECT,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Initialize),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_GenerateUPTRT),
      MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,
      MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,
      MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
      MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeCRC32)
    );
}

/*************************************************
 * Name:        mcuxClMlDsa_Verify_HashMu
 *
 * Description: Subroutine for ML-DSA verify
 *              to initialize Shake and start hashing Mu
 *
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify_HashMu)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Verify_HashMu(
  mcuxClSession_Handle_t session,
  const uint8_t* const pMu,
  mcuxClXof_Context_t pShakeContextMu
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify_HashMu);

  MCUXCLBUFFER_INIT_RO(muBuf, NULL, pMu, MCUXCLMLDSA_CRHBYTES);

  /* Initialize running shake state to compute H(mu || w1') */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pShakeContextMu,
                                                        mcuxClXof_Algorithm_Shake_256,
                                                        NULL,
                                                        0U));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  /* Absorb mu into running shake state */
  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, muBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pShakeContextMu,
                                                           muBuf,
                                                           MCUXCLMLDSA_CRHBYTES));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Verify_HashMu,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));
}

/*************************************************
 * Name:        mcuxClMlDsa_Verify
 *
 * Description: Main ML-DSA verify routine.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Verify, mcuxClSignature_VerifyFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Verify(
  mcuxClSession_Handle_t           session,
  mcuxClKey_Handle_t               keyDesc,
  mcuxClSignature_Mode_t           signMode,
  mcuxCl_InputBuffer_t             pMessageOrDigest,
  uint32_t                        messageLen,
  mcuxCl_InputBuffer_t             pSignature,
  uint32_t                        signatureLen
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Verify);

  /******************************************************************/
  /* Step 1: Set up local structure and check input lengths         */
  /******************************************************************/

  /* Unpack the protocol descriptor. This descriptor contains the ML-DSA mode, the pre-hash algorithm, the context and the context length */
  const mcuxClMlDsa_SignatureProtocolDescriptor_t* pMlDsa_SignatureProtocolDescriptor = (const mcuxClMlDsa_SignatureProtocolDescriptor_t *)(signMode->pProtocolDescriptor);
  const mcuxClMlDsa_Mode_t mode = pMlDsa_SignatureProtocolDescriptor->mode;

  /* Extract public key data pointer from key handle */
  uint8_t *pKeyDest = NULL;
  MCUXCLKEY_LOAD_FP(session, keyDesc, &pKeyDest, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);

  const uint8_t* const pPublicKey = (const uint8_t*)pKeyDest;

  /* Fetch the parameters, given the security level */
  const mcuxClMlDsa_Params_t *pParams = NULL;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Get_Params(session, (mode & MCUXCLMLDSA_SELECT_MODE), &pParams));

  /* Initialize cTilde, z, h buffers based on cTildeSize */
  MCUXCLBUFFER_DERIVE_RO(cTildeBuf, pSignature, 0U);
  MCUXCLBUFFER_DERIVE_RO(zBuf, pSignature, (uint32_t)pParams->cTildeSize);
  MCUXCLBUFFER_DERIVE_RO(hBuf, zBuf, (uint32_t)pParams->l * pParams->polyz_packedbytes);

  MCUX_CSSL_DI_RECORD(cTildeBuf_Size_integrity, cTildeBuf);
  MCUX_CSSL_DI_RECORD(cTildeBuf_Size_integrity, pParams->cTildeSize);

  /* Record parameter for mcuxClXof_generate_internal in mcuxClMlDsa_Verify_CompareAndFree */
  MCUX_CSSL_DI_RECORD(xofProcessParams, pParams->cTildeSize);

  /* Record parameters for mcuxClBuffer_read in mcuxClMlDsa_Verify_CompareAndFree */
  MCUX_CSSL_DI_RECORD(readParams, cTildeBuf);
  MCUX_CSSL_DI_RECORD(readParams, pParams->cTildeSize);

  /* Calculate allocated words to free */
  uint32_t cpuWaWordsToFree = 0U;
  uint32_t pkcWaWordsToFree = 0U;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("All the following allocated pointers are 32-bit aligned because of mcuxClSession_allocateWords_cpuWa/pkcWa")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory")

  /* Shake context for generating entries of matrix A */
  MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pShakeContextBuff, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS));
  mcuxClXof_Context_t pShakeContext = (mcuxClXof_Context_t) pShakeContextBuff;
  cpuWaWordsToFree += MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS;

  /* Shake context for mu -- cannot reuse memory for pShakeContext as lifetimes overlap */
  MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pShakeContextMuBuff, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_SHAKE256_CONTEXT_SIZE_IN_WORDS));
  mcuxClXof_Context_t pShakeContextMu = (mcuxClXof_Context_t) pShakeContextMuBuff;
  cpuWaWordsToFree += MCUXCLXOF_SHAKE256_CONTEXT_SIZE_IN_WORDS;

  /* Initialize memory for hash out buffers */
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pHashOutBuf, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_SHAKE128_RATE)));
  cpuWaWordsToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_SHAKE128_RATE);

  /* Use same memory for both 128 bit and 256 bit hash buffers */
  uint8_t* const pHashOutBuf128 = pHashOutBuf;
  uint8_t* const pHashOutBuf256 = pHashOutBuf;
  uint8_t* const pPreHashBuf = pHashOutBuf;

  MCUX_CSSL_DI_RECORD(HashOutBuf, pHashOutBuf256);

  /* Allocate two working polynomials either in PKC or CPU wa (see table above) */
  mcuxClMlDsa_Poly_t* pPoly1;
  mcuxClMlDsa_Poly_t* pPoly2;

#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
  if(MCUXCLMLDSA_MODE_87 == (mode & MCUXCLMLDSA_SELECT_MODE))
  {
#endif
  /* Allocate memory for two workarea polynomials in CPU WA */
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pPoly12, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pPoly22, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  pPoly1 = pPoly12;
  pPoly2 = pPoly22;
  cpuWaWordsToFree += 2U * MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE);
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
  }
  else
  {
    /* Mode 44 and mode 65 can fit the two working polynomials in PKC WA */
    MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pPoly12, mcuxClSession_allocateWords_pkcWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
    MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pPoly22, mcuxClSession_allocateWords_pkcWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
    pkcWaWordsToFree += 2U * MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE);
    pPoly1 = pPoly12;
    pPoly2 = pPoly22;
  }
#endif

  /* Allocate z in PKC (see table above) */
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pZPkc, mcuxClSession_allocateWords_pkcWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->l * MCUXCLMLDSA_POLY_SIZE)));
  pkcWaWordsToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->l * MCUXCLMLDSA_POLY_SIZE);
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pZPkc, mcuxClSession_allocateWords_pkcWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(3U * MCUXCLMLDSA_POLY_SIZE)));
  pkcWaWordsToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(3U * MCUXCLMLDSA_POLY_SIZE);
#else
  mcuxClMlDsa_Poly_t * const pZPkc = pPoly2; /* unused */
#endif

  /* allocate space for c either in PKC wa or packed c in CPU WA */
  /* We store NTT(c) in PKC WA as well */
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMlDsa_Poly_t*, pC, mcuxClSession_allocateWords_pkcWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE)));
  pkcWaWordsToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_POLY_SIZE);
  /* (Parts of) vector NTT(z) will also be stored fully in PKC WA */

  /* In theory we don't need pCPacked in this case, but would add a lot of preprocessor guards to function arguments */
  uint8_t* const pCPacked = (uint8_t*)pC;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  /* Balance DI for mcuxClMlDsa_Poly_Challenge */
  MCUX_CSSL_DI_RECORD(polyChallengeC, (uintptr_t)pC);
  MCUX_CSSL_DI_RECORD(polyChallengeSeed, (uintptr_t)cTildeBuf);
  MCUX_CSSL_DI_RECORD(polyChallengeParams, (uintptr_t)pParams);

  /* Mu is absorbed before the lifetime of any other variables (mu, t1, w1) in poly1 */
  uint8_t* const pMu = (uint8_t *) pPoly1;

  /* Re-use pHashOutBuf to keep a copy of reference commitment hash */
  uint8_t* const pC1 = (uint8_t *) pHashOutBuf;
  uint8_t* const pC2 = (uint8_t *) pHashOutBuf + pParams->cTildeSize;

  /* |pHPacked| = omega + k bytes, depending on mode */
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pHPacked, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->omega + (uint32_t)pParams->k)));
  cpuWaWordsToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL((uint32_t)pParams->omega + (uint32_t)pParams->k);

  /* Record parameter for mcuxClBuffer_read in mcuxClMlDsa_Verify_CompareAndFree */
  MCUX_CSSL_DI_RECORD(readParams, (uintptr_t)pC1);

  /* Record values for mcuxClMemory_compare_int in mcuxClMlDsa_Verify_CompareAndFree (second compare may be done in PKC) */
  MCUX_CSSL_DI_RECORD(C1Pointer, (uintptr_t)pC1);
  MCUX_CSSL_DI_RECORD(C2Pointer, (uintptr_t)pC2);
  MCUX_CSSL_DI_RECORD(SeedBytesSize, (uint32_t)pParams->cTildeSize);

  /* Perform consistency check of inputs and if workarea was allocated */
  const uint32_t publicKeyLen = mcuxClKey_getKeyContainerSize(keyDesc);
  MCUX_CSSL_DI_RECORD(verifyCheckInputsPkLen, publicKeyLen);
  MCUX_CSSL_DI_RECORD(verifyCheckInputsSLen, signatureLen);
  MCUX_CSSL_DI_RECORD(verifyCheckInputsPParams, pParams);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Verify_CheckInputs(session,
                                                               pParams,
                                                               publicKeyLen,
                                                               signatureLen,
                                                               pShakeContext,
                                                               pShakeContextMu,
                                                               pHashOutBuf,
                                                               pPoly1,
                                                               pPoly2));

  /* Initialize hash output buffer with pseudorandom bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal((uint8_t*)pHashOutBuf, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_SHAKE128_RATE)));

  /******************************************************************/
  /* Step 2: Check infinity norm on z                               */
  /******************************************************************/

  MCUX_CSSL_DI_RECORD(unpackCheckZParams, pPoly2);
  MCUX_CSSL_DI_RECORD(unpackCheckZParams, pZPkc);
  MCUX_CSSL_DI_RECORD(unpackCheckZParams, zBuf);
  MCUX_CSSL_DI_RECORD(unpackCheckZParams, pParams);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pZPkc is cast to the right type (mcuxClMlDsa_Poly_t * const).")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("false positive: cannot be NULL pointer due to the call to MCUXCLSESSION_FAULT")
  MCUX_CSSL_FP_FUNCTION_CALL(retUnpackCheckZ, mcuxClMlDsa_Verify_Unpack_Check_Z(session, pPoly2, pZPkc, zBuf, pParams));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
  /* Check if z is indeed within the given norm bounds */
  if(MCUXCLSIGNATURE_STATUS_OK != retUnpackCheckZ)
  {
    /* Since we are returning a normal mismatch status code here, we need to balance */
    /* Undo balancing DI for mcuxClMlDsa_Poly_Challenge */
    MCUX_CSSL_DI_EXPUNGE(polyChallengeC, (uintptr_t)pC);
    MCUX_CSSL_DI_EXPUNGE(polyChallengeSeed, (uintptr_t)cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(polyChallengeParams, (uintptr_t)pParams);

    /* Undo balancing DI for mcuxClMlDsa_Verify_CompareAndFree */
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(C1Pointer, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(C2Pointer, (uintptr_t)pC2);
    MCUX_CSSL_DI_EXPUNGE(SeedBytesSize, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(xofProcessParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(readParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(HashOutBuf, pHashOutBuf256);

    MCUX_CSSL_DI_RECORD(verifyRetCode, retUnpackCheckZ);

    mcuxClSession_freeWords_cpuWa(session, cpuWaWordsToFree);
    mcuxClSession_freeWords_pkcWa(session, pkcWaWordsToFree);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify, retUnpackCheckZ,
        MCUXCLKEY_LOAD_FP_CALLED(keyDesc),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 == (mode & MCUXCLMLDSA_SELECT_MODE),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa)),
#else
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 != (mode & MCUXCLMLDSA_SELECT_MODE),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa)),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#endif
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_CheckInputs),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Unpack_Check_Z));
  }

  /* expunge the return codes for the bound check on z */
  MCUX_CSSL_DI_EXPUNGE(verifyCheckNorm, 2U * (uint32_t)pParams->l * MCUXCLSIGNATURE_STATUS_OK);

  /******************************************************************/
  /* Step 3: Compute mu = CRH(H(rho, t1), msg)                      */
  /******************************************************************/

  /* Perform ComputeMu subroutine */
  MCUX_CSSL_DI_RECORD(computeMuPMu, pMu);
  MCUX_CSSL_DI_RECORD(computeMuPMessage, (uintptr_t)pMessageOrDigest);
  MCUX_CSSL_DI_RECORD(computeMuMessageLen, messageLen);
  MCUX_CSSL_DI_RECORD(computeMuPPublicKey, pPublicKey);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST("Const must be discarded to pass pMessageOrDigest.")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pShakeContextMu is cast to the right type (mcuxClXof_Context_t).")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Verify_ComputeMu(session,
                                                             pParams,
                                                             pShakeContextMu,
                                                             pPublicKey,
                                                             pMu,
                                                             pMessageOrDigest,
                                                             messageLen,
                                                             mode,
                                                             pMlDsa_SignatureProtocolDescriptor,
                                                             pPreHashBuf));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST()

  /******************************************************************/
  /* Step 4: Compute the challenge c, negated                       */
  /******************************************************************/

  /* Perform challenge computation from signature */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pC is cast to the right type (mcuxClMlDsa_Poly_t * const). pShakeContextMu is cast to the right type (mcuxClXof_Context_t).")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Challenge(session,
                                                           pShakeContextMu,
                                                           pC,
                                                           cTildeBuf,
                                                           pHashOutBuf256,
                                                           pParams,
                                                           MCUXCLMLDSA_CHALLENGE_NEGATIVE));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /* Store challenge uncompressed in NTT form i.e. NTT(-c * 2^d) */
  MCUX_CSSL_DI_RECORD(polyShiftC, pC);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pC is cast to the right type (mcuxClMlDsa_Poly_t * const).")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Shiftl(pC));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /* Apply NTT to unpacked shifted challenge */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT(pC));

  /******************************************************************/
  /* Step 5: Polynomial arithmetic                                  */
  /******************************************************************/

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pShakeContextMu is cast to the right type (mcuxClXof_Context_t).")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Verify_HashMu(session, pMu, pShakeContextMu));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /* Perform polynomial arithmetic to compute A*z - 2^d * c * t1 */
  MCUX_CSSL_DI_RECORD(computeMuPMu, pMu);
  MCUX_CSSL_DI_RECORD(computeMuPMessage, pCPacked);
  MCUX_CSSL_DI_RECORD(computeMuPPublicKey, pPublicKey);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pShakeContext is cast to the right type (mcuxClXof_Context_t).")
  MCUX_CSSL_FP_FUNCTION_CALL(retVerifyPolynomialArithmetic,
                            mcuxClMlDsa_Verify_PolynomialArithmetic(session,
                                                                   pParams,
                                                                   zBuf,
                                                                   hBuf,
                                                                   pShakeContext,
                                                                   pShakeContextMu,
                                                                   pPublicKey,
                                                                   pMu,
                                                                   pC,
                                                                   pCPacked,
                                                                   pPoly1,
                                                                   pPoly2,
                                                                   pZPkc,
                                                                   pHashOutBuf128,
                                                                   pHPacked));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /* Check for errors */
  if(MCUXCLSIGNATURE_STATUS_OK != retVerifyPolynomialArithmetic)
  {
    /* Since we are returning a normal mismatch status code here, we need to balance */
    /* Undo balancing DI for mcuxClMlDsa_Verify_CompareAndFree */
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(C1Pointer, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(C2Pointer, (uintptr_t)pC2);
    MCUX_CSSL_DI_EXPUNGE(SeedBytesSize, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(xofProcessParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(readParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(HashOutBuf, pHashOutBuf256);

    MCUX_CSSL_DI_RECORD(verifyRetCode, retVerifyPolynomialArithmetic);

    mcuxClSession_freeWords_cpuWa(session, cpuWaWordsToFree);
    mcuxClSession_freeWords_pkcWa(session, pkcWaWordsToFree);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify, retVerifyPolynomialArithmetic,
        MCUXCLKEY_LOAD_FP_CALLED(keyDesc),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 == (mode & MCUXCLMLDSA_SELECT_MODE),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa)),
#else
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 != (mode & MCUXCLMLDSA_SELECT_MODE),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa)),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#endif
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_CheckInputs),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Unpack_Check_Z),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_ComputeMu),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Challenge),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Shiftl),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_HashMu),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_PolynomialArithmetic));
  }

  /******************************************************************/
  /* Step 6: Verify strong unforgeability                           */
  /******************************************************************/

  MCUX_CSSL_DI_RECORD(verifyStrongUnforgeabilityParams, pParams);
  MCUX_CSSL_DI_RECORD(verifyStrongUnforgeabilityParams, hBuf);
  MCUX_CSSL_FP_FUNCTION_CALL(verifyStatus, mcuxClMlDsa_Verify_Strong_Unforgeability(pParams, hBuf, (uint8_t*)pPoly1));
  if(MCUXCLSIGNATURE_STATUS_OK != verifyStatus)
  {
    /* Since we are returning a normal mismatch status code here, we need to balance */
    /* Undo balancing DI for mcuxClMlDsa_Verify_CompareAndFree */
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(cTildeBuf_Size_integrity, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(C1Pointer, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(C2Pointer, (uintptr_t)pC2);
    MCUX_CSSL_DI_EXPUNGE(SeedBytesSize, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(xofProcessParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, cTildeBuf);
    MCUX_CSSL_DI_EXPUNGE(readParams, pParams->cTildeSize);
    MCUX_CSSL_DI_EXPUNGE(readParams, (uintptr_t)pC1);
    MCUX_CSSL_DI_EXPUNGE(HashOutBuf, pHashOutBuf256);

    MCUX_CSSL_DI_RECORD(verifyRetCode, MCUXCLSIGNATURE_STATUS_NOT_OK);

    mcuxClSession_freeWords_cpuWa(session, cpuWaWordsToFree);
    mcuxClSession_freeWords_pkcWa(session, pkcWaWordsToFree);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify, MCUXCLSIGNATURE_STATUS_NOT_OK,
      MCUXCLKEY_LOAD_FP_CALLED(keyDesc),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
      MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 == (mode & MCUXCLMLDSA_SELECT_MODE),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa)),
#else
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
      MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 != (mode & MCUXCLMLDSA_SELECT_MODE),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa)),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#endif
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_CheckInputs),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Unpack_Check_Z),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_ComputeMu),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Challenge),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Shiftl),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_HashMu),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_PolynomialArithmetic),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Strong_Unforgeability));
  }

  /******************************************************************/
  /* Step 7: Final comparison                                       */
  /******************************************************************/

  /* Recalculate and compare the commitment hash. */
  MCUX_CSSL_FP_FUNCTION_CALL(retVerifyCompareAndFree,
                            mcuxClMlDsa_Verify_CompareAndFree(session,
                                                             pParams,
                                                             pC1,
                                                             pC2,
                                                             pShakeContextMu,
                                                             cTildeBuf,
                                                             cpuWaWordsToFree,
                                                             pkcWaWordsToFree));

  MCUX_CSSL_DI_EXPUNGE(HashOutBuf, pHashOutBuf256);

  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Verify, retVerifyCompareAndFree,
    MCUXCLKEY_LOAD_FP_CALLED(keyDesc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Get_Params),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 == (mode & MCUXCLMLDSA_SELECT_MODE),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa)),
#else
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLMLDSA_MODE_87 != (mode & MCUXCLMLDSA_SELECT_MODE),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa)),
#endif
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
#endif
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_CheckInputs),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Unpack_Check_Z),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_ComputeMu),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Challenge),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Shiftl),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_HashMu),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_PolynomialArithmetic),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_Strong_Unforgeability),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Verify_CompareAndFree));
}
