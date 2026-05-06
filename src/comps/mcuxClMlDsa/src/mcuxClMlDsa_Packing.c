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
 * @file mcuxClMlDsa_Packing.c
 * @brief Implementing packing/unpacking operations in @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClCore_Macros.h>
#include <mcuxClBuffer.h>
#include <mcuxClMlDsa.h>

#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>
#include <internal/mcuxClMemory_Set_Internal.h>
#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClSession_Internal.h>

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Eta_Pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - uint8_t *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Eta_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Pack(
  mcuxClSession_Handle_t session,
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Eta_Pack);
  uint16_t i;
  int8_t t[8];
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(params->eta, MCUXCLMLDSA_MLDSA44_ETA, MCUXCLMLDSA_MLDSA65_ETA)
  const int8_t ETA = (int8_t)params->eta;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pTs are 8 bit aligned")
  uint8_t* pT = (uint8_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(ETA == 2)
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 8u; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("2 - x for x in [-2, 2] is in [0, 4]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0u] = ETA - (int8_t)a->coefficients[8u * i + 0u];
      t[1u] = ETA - (int8_t)a->coefficients[8u * i + 1u];
      t[2u] = ETA - (int8_t)a->coefficients[8u * i + 2u];
      t[3u] = ETA - (int8_t)a->coefficients[8u * i + 3u];
      t[4u] = ETA - (int8_t)a->coefficients[8u * i + 4u];
      t[5u] = ETA - (int8_t)a->coefficients[8u * i + 5u];
      t[6u] = ETA - (int8_t)a->coefficients[8u * i + 6u];
      t[7u] = ETA - (int8_t)a->coefficients[8u * i + 7u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[3u * i + 0u] = (uint8_t)(pT[0] >> 0u) | (uint8_t)(pT[1] << 3u) | (uint8_t)(pT[2] << 6u);
      r[3u * i + 1u] = (uint8_t)(pT[2] >> 2u) | (uint8_t)(pT[3] << 1u) | (uint8_t)(pT[4] << 4u) | (uint8_t)(pT[5] << 7u);
      r[3u * i + 2u] = (uint8_t)(pT[5] >> 1u) | (uint8_t)(pT[6] << 2u) | (uint8_t)(pT[7] << 5u);
    }
  }
  else if(ETA == 4)
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("4 - x for x in [-4, 4] is in [0, 8]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
       MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0u] = ETA - (int8_t)a->coefficients[2u * i + 0u];
      t[1u] = ETA - (int8_t)a->coefficients[2u * i + 1u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      r[i] = (uint8_t)pT[0u] | (uint8_t)(pT[1u] << 4u);
    }
  }
  else
  {
    /* No other ETA allowed, fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Pack);
}


/*************************************************
 * Name:        mcuxClMlDsa_Packing_Eta_Unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - mcuxClMlDsa_Poly_t *r: pointer to output polynomial
 *              - const uint8_t *a: byte array with bit-packed polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Eta_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *r,
  const uint8_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Eta_Unpack);
  uint16_t i;
  int32_t ETA = (int32_t)params->eta;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* pCoeffs = (uint32_t*)r->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(ETA == 2)
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 8u; ++i)
    {
      pCoeffs[8u * i + 0u] = (((uint32_t)a[3u * i + 0u] >> 0u) & 7u);
      pCoeffs[8u * i + 1u] = (((uint32_t)a[3u * i + 0u] >> 3u) & 7u);
      pCoeffs[8u * i + 2u] = ((((uint32_t)a[3u * i + 0u] >> 6u) | ((uint32_t)a[3u * i + 1u] << 2u)) & 7u);
      pCoeffs[8u * i + 3u] = (((uint32_t)a[3u * i + 1u] >> 1u) & 7u);
      pCoeffs[8u * i + 4u] = (((uint32_t)a[3u * i + 1u] >> 4u) & 7u);
      pCoeffs[8u * i + 5u] = ((((uint32_t)a[3u * i + 1u] >> 7u) | ((uint32_t)a[3u * i + 2u] << 1u)) & 7u);
      pCoeffs[8u * i + 6u] = (((uint32_t)a[3u * i + 2u] >> 2u) & 7u);
      pCoeffs[8u * i + 7u] = (((uint32_t)a[3u * i + 2u] >> 5u) & 7u);

      r->coefficients[8u * i + 0u] = ETA - r->coefficients[8u * i + 0u];
      r->coefficients[8u * i + 1u] = ETA - r->coefficients[8u * i + 1u];
      r->coefficients[8u * i + 2u] = ETA - r->coefficients[8u * i + 2u];
      r->coefficients[8u * i + 3u] = ETA - r->coefficients[8u * i + 3u];
      r->coefficients[8u * i + 4u] = ETA - r->coefficients[8u * i + 4u];
      r->coefficients[8u * i + 5u] = ETA - r->coefficients[8u * i + 5u];
      r->coefficients[8u * i + 6u] = ETA - r->coefficients[8u * i + 6u];
      r->coefficients[8u * i + 7u] = ETA - r->coefficients[8u * i + 7u];
    }
  }
  else if(ETA == 4)
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      pCoeffs[2u * i + 0u] = ((uint32_t)a[i] & 0x0Fu);
      pCoeffs[2u * i + 1u] = ((uint32_t)a[i] >> 4u);
      r->coefficients[2u * i + 0u] = ETA - r->coefficients[2u * i + 0u];
      r->coefficients[2u * i + 1u] = ETA - r->coefficients[2u * i + 1u];
    }
  }
  else
  {
    /* No other ETA allowed, fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T1_Pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYT1_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Pack(uint8_t *r, const mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T1_Pack);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  const uint32_t* pCoeffs = (const uint32_t*)a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
  {
    r[5u*i+0u] = (uint8_t)(pCoeffs[4u*i+0u] >> 0u & 0xFFu);
    r[5u*i+1u] = (uint8_t)(pCoeffs[4u*i+0u] >> 8u & 0xFFu) | (uint8_t)(pCoeffs[4u*i+1u] << 2u & 0xFFu);
    r[5u*i+2u] = (uint8_t)(pCoeffs[4u*i+1u] >> 6u & 0xFFu) | (uint8_t)(pCoeffs[4u*i+2u] << 4u & 0xFFu);
    r[5u*i+3u] = (uint8_t)(pCoeffs[4u*i+2u] >> 4u & 0xFFu) | (uint8_t)(pCoeffs[4u*i+3u] << 6u & 0xFFu);
    r[5u*i+4u] = (uint8_t)(pCoeffs[4u*i+3u] >> 2u & 0xFFu);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T1_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T1_Unpack
 *
 * Description: Unpack packed version of polynomial t1 into 10-bit coefficients.
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *unpackedPoly: pointer to output polynomial
 *              - const uint8_t *packedPoly: byte array with bit-packed polynomial
 *
 * Data Integrity: Expunge(unpackedPoly + packedPoly)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Unpack(mcuxClMlDsa_Poly_t * unpackedPoly, const uint8_t * packedPoly)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T1_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("coefficients are 32 bit aligned")
  uint32_t *pUnpacked = (uint32_t *)unpackedPoly->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  const uint8_t *pPacked = packedPoly;

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pUnpacked);
    MCUX_CSSL_DI_DONOTOPTIMIZE(pPacked);

    pUnpacked[0] = ((uint32_t)pPacked[0] >> 0u);
    pUnpacked[0] |= ((uint32_t)pPacked[1] << 8u);
    pUnpacked[0] &= 0x3FFu;

    pUnpacked[1] = ((uint32_t)pPacked[1] >> 2u);
    pUnpacked[1] |= ((uint32_t)pPacked[2] << 6u);
    pUnpacked[1] &= 0x3FFu;

    pUnpacked[2] = ((uint32_t)pPacked[2] >> 4u);
    pUnpacked[2] |= ((uint32_t)pPacked[3] << 4u);
    pUnpacked[2] &= 0x3FFu;

    pUnpacked[3] = ((uint32_t)pPacked[3] >> 6u);
    pUnpacked[3] |= ((uint32_t)pPacked[4] << 2u);
    pUnpacked[3] &= 0x3FFu;

    pUnpacked += 4U;
    pPacked += 5U;

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_DI_EXPUNGE(T1UnpackUnpacked, (uintptr_t)pUnpacked - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(T1UnpackPacked, (uintptr_t)pPacked - MCUXCLMLDSA_POLYT1_PACKEDBYTES);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T1_Unpack,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLDSA_N / 4u));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T0_Pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYT0_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T0_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Pack(uint8_t *r, const mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T0_Pack);
  int32_t t[8];

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("t is 32 bit aligned")
  uint32_t* pT = (uint32_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()


  for(uint16_t i = 0u; i < MCUXCLMLDSA_N/8u; ++i)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("2^{D-1} - x for x in [-2^{D-1}, 2^{D-1}] is in [0, 2^D]")
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
    t[0u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+0u];
    t[1u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+1u];
    t[2u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+2u];
    t[3u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+3u];
    t[4u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+4u];
    t[5u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+5u];
    t[6u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+6u];
    t[7u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8u*i+7u];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    r[13u*i+ 0u]  =  (uint8_t)(pT[0u] & 0xFFu);
    r[13u*i+ 1u]  =  (uint8_t)((pT[0u] >>  8u) & 0xFFu);
    r[13u*i+ 1u] |=  (uint8_t)((pT[1u] <<  5u) & 0xFFu);
    r[13u*i+ 2u]  =  (uint8_t)((pT[1u] >>  3u) & 0xFFu);
    r[13u*i+ 3u]  =  (uint8_t)((pT[1u] >> 11u) & 0xFFu);
    r[13u*i+ 3u] |=  (uint8_t)((pT[2u] <<  2u) & 0xFFu);
    r[13u*i+ 4u]  =  (uint8_t)((pT[2u] >>  6u) & 0xFFu);
    r[13u*i+ 4u] |=  (uint8_t)((pT[3u] <<  7u) & 0xFFu);
    r[13u*i+ 5u]  =  (uint8_t)((pT[3u] >>  1u) & 0xFFu);
    r[13u*i+ 6u]  =  (uint8_t)((pT[3u] >>  9u) & 0xFFu);
    r[13u*i+ 6u] |=  (uint8_t)((pT[4u] <<  4u) & 0xFFu);
    r[13u*i+ 7u]  =  (uint8_t)((pT[4u] >>  4u) & 0xFFu);
    r[13u*i+ 8u]  =  (uint8_t)((pT[4u] >> 12u) & 0xFFu);
    r[13u*i+ 8u] |=  (uint8_t)((pT[5u] <<  1u) & 0xFFu);
    r[13u*i+ 9u]  =  (uint8_t)((pT[5u] >>  7u) & 0xFFu);
    r[13u*i+ 9u] |=  (uint8_t)((pT[6u] <<  6u) & 0xFFu);
    r[13u*i+10u]  =  (uint8_t)((pT[6u] >>  2u) & 0xFFu);
    r[13u*i+11u]  =  (uint8_t)((pT[6u] >> 10u) & 0xFFu);
    r[13u*i+11u] |=  (uint8_t)((pT[7u] <<  3u) & 0xFFu);
    r[13u*i+12u]  =  (uint8_t)((pT[7u] >>  5u) & 0xFFu);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T0_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T0_Unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *unpackedPoly: pointer to output polynomial
 *              - const uint8_t *packedPoly: byte array with bit-packed polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T0_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Unpack(mcuxClMlDsa_Poly_t * unpackedPoly, const uint8_t * packedPoly)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T0_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* pCoeffs = (uint32_t*)unpackedPoly->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0u; i < MCUXCLMLDSA_N/8u; ++i)
  {
    pCoeffs[8u*i+0u]  = ((uint32_t)packedPoly[13u*i+0u] | ((uint32_t)packedPoly[13u*i+1u] << 8u)) & 0x1FFFu;
    pCoeffs[8u*i+1u]  = (((uint32_t)packedPoly[13u*i+1u] >> 5u) | ((uint32_t)packedPoly[13u*i+2u] << 3u) | ((uint32_t)packedPoly[13u*i+3u] << 11u) ) & 0x1FFFu;
    pCoeffs[8u*i+2u]  = (((uint32_t)packedPoly[13u*i+3u] >> 2u) | ((uint32_t)packedPoly[13u*i+4u] << 6u) ) & 0x1FFFu;
    pCoeffs[8u*i+3u]  = (((uint32_t)packedPoly[13u*i+4u] >> 7u) | ((uint32_t)packedPoly[13u*i+5u] << 1u) | ((uint32_t)packedPoly[13u*i+6u] << 9u) ) & 0x1FFFu;
    pCoeffs[8u*i+4u]  = (((uint32_t)packedPoly[13u*i+6u] >> 4u) | ((uint32_t)packedPoly[13u*i+7u] << 4u) | ((uint32_t)packedPoly[13u*i+8u] << 12u) ) & 0x1FFFu;
    pCoeffs[8u*i+5u]  = (((uint32_t)packedPoly[13u*i+8u] >> 1u) | ((uint32_t)packedPoly[13u*i+9u] << 7u) ) & 0x1FFFu;
    pCoeffs[8u*i+6u]  = (((uint32_t)packedPoly[13u*i+9u] >> 6u) | ((uint32_t)packedPoly[13u*i+10u] << 2u) | ((uint32_t)packedPoly[13u*i+11u] << 10u) ) & 0x1FFFu;
    pCoeffs[8u*i+7u]  = (((uint32_t)packedPoly[13u*i+11u] >> 3u) | ((uint32_t)packedPoly[13u*i+12u] << 5u) ) & 0x1FFFu;

    unpackedPoly->coefficients[8u*i+0u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+0u];
    unpackedPoly->coefficients[8u*i+1u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+1u];
    unpackedPoly->coefficients[8u*i+2u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+2u];
    unpackedPoly->coefficients[8u*i+3u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+3u];
    unpackedPoly->coefficients[8u*i+4u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+4u];
    unpackedPoly->coefficients[8u*i+5u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+5u];
    unpackedPoly->coefficients[8u*i+6u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+6u];
    unpackedPoly->coefficients[8u*i+7u] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8u*i+7u];
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T0_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - uint8_t *r: pointer to output byte array
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Pack(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  const mcuxClMlDsa_Poly_t* a,
  const mcuxClMlDsa_Params_t* params)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Pack);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(params->gamma1, MCUXCLMLDSA_MLDSA44_GAMMA1, MCUXCLMLDSA_MLDSA87_GAMMA2);
  uint32_t i;
  int32_t t[4];

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("t is 32 bit aligned")
  uint32_t* pT = (uint32_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* record the amount of bytes about to be written */
  MCUX_CSSL_DI_RECORD(writeLength,
                     params->gamma1 == MCUXCLMLDSA_MLDSA44_GAMMA1 ? MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES
                                                                   : MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES);

  const uint16_t numLoops = MCUXCLMLDSA_N / (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1 ? 4U : 2U);
  MCUX_CSSL_DI_RECORD(writeDst, (uintptr_t)rBuf * numLoops);

  if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2 */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
    {
      uint8_t r[9u];
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("GAMMA1 - x for x in [-(GAMMA1 - 1), GAMMA1] is in [0, 2GAMMA - 1]")
       MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0u] = (int32_t)params->gamma1 - a->coefficients[4u * i + 0u];
      t[1u] = (int32_t)params->gamma1 - a->coefficients[4u * i + 1u];
      t[2u] = (int32_t)params->gamma1 - a->coefficients[4u * i + 2u];
      t[3u] = (int32_t)params->gamma1 - a->coefficients[4u * i + 3u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[0u] =  (uint8_t)(pT[0u] & 0xFFu);
      r[1u] =  (uint8_t)(pT[0u] >> 8u  & 0xFFu);
      r[2u] =  (uint8_t)(pT[0u] >> 16u & 0xFFu);
      r[2u] |= (uint8_t)(pT[1u] << 2u  & 0xFFu);
      r[3u] =  (uint8_t)(pT[1u] >> 6u  & 0xFFu);
      r[4u] =  (uint8_t)(pT[1u] >> 14u & 0xFFu);
      r[4u] |= (uint8_t)(pT[2u] << 4u  & 0xFFu);
      r[5u] =  (uint8_t)(pT[2u] >> 4u  & 0xFFu);
      r[6u] =  (uint8_t)(pT[2u] >> 12u & 0xFFu);
      r[6u] |= (uint8_t)(pT[3u] << 6u  & 0xFFu);
      r[7u] =  (uint8_t)(pT[3u] >> 2u  & 0xFFu);
      r[8u] =  (uint8_t)(pT[3u] >> 10u & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeOff, (i * 9u));
      MCUX_CSSL_DI_RECORD(writeSrc, r);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 9u, r, 9u));
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5 */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      uint8_t r[5u];
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("GAMMA1 - x for x in [-(GAMMA1 - 1), GAMMA1] is in [0, 2GAMMA - 1]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0u] = (int32_t)params->gamma1 - a->coefficients[2u * i + 0u];
      t[1u] = (int32_t)params->gamma1 - a->coefficients[2u * i + 1u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[0u] =  (uint8_t)(pT[0u] & 0xFFu);
      r[1u] =  (uint8_t)(pT[0u] >> 8u  & 0xFFu);
      r[2u] =  (uint8_t)(pT[0u] >> 16u & 0xFFu);
      r[2u] |= (uint8_t)(pT[1u] << 4u  & 0xFFu);
      r[3u] =  (uint8_t)(pT[1u] >> 4u  & 0xFFu);
      r[4u] =  (uint8_t)(pT[1u] >> 12u & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeOff, (i * 5u));
      MCUX_CSSL_DI_RECORD(writeSrc, r);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 5u, r, 5u));
    }
  }
  else
  {
    /* no other gamma allowed, fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack_17
 **************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack_17)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_17(int32_t *r, const uint8_t *a)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack_17);
  /* we process the result twice, once as unsigned and once as signed */
  MCUX_CSSL_DI_RECORD(zUnpack17R, (uintptr_t)r * 2U);
  MCUX_CSSL_DI_RECORD(zUnpack17A, (uintptr_t)a);

  const uint8_t *pA = a;
  int32_t *pRSigned = r;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  uint32_t* pR = (uint32_t*)r;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR won't overflow iff we point to a validly-sized subpart of z, we unpack 4 coefficents from 9 bytes")
  *pR = (uint32_t)*pA++;
  *pR |= ((uint32_t)*pA++ << 8u);
  *pR |= ((uint32_t)*pA << 16u);
  *pR &= 0x3FFFFu;
  pR++;

  *pR = ((uint32_t)*pA++ >> 2u);
  *pR |= ((uint32_t)*pA++ << 6u);
  *pR |= ((uint32_t)*pA << 14u);
  *pR &= 0x3FFFFu;
  pR++;

  *pR = ((uint32_t)*pA++ >> 4u);
  *pR |= ((uint32_t)*pA++ << 4u);
  *pR |= ((uint32_t)*pA << 12u);
  *pR &= 0x3FFFFu;
  pR++;

  *pR = ((uint32_t)*pA++ >> 6u);
  *pR |= ((uint32_t)*pA++ << 2u);
  *pR |= ((uint32_t)*pA << 10u);
  *pR &= 0x3FFFFu;

  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_DI_EXPUNGE(zUnpack17R, (uintptr_t)pR - 4U * 3U);
  MCUX_CSSL_DI_EXPUNGE(zUnpack17R, (uintptr_t)pRSigned - 4U * 3U);
  MCUX_CSSL_DI_EXPUNGE(zUnpack17A, (uintptr_t)pA - 8U);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Unpack_17);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack_19
 **************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack_19)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_19(int32_t *r, const uint8_t *a)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack_19);
  /* we process the result twice, once as unsigned and once as signed */
  MCUX_CSSL_DI_RECORD(zUnpack19R, (uintptr_t)r * 2U);
  MCUX_CSSL_DI_RECORD(zUnpack19A, (uintptr_t)a);

  const uint8_t *pA = a;
  int32_t *pRSigned = r;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  uint32_t* pR = (uint32_t*)r;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR won't overflow iff we point to a validly-sized subpart of z, we unpack 4 coefficents from 9 bytes")
  *pR = (uint32_t)*pA++;
  *pR |= ((uint32_t)*pA++ << 8u);
  *pR |= ((uint32_t)*pA << 16u);
  *pR &= 0xFFFFFu;
  pR++;

  *pR = ((uint32_t)*pA++ >> 4u);
  *pR |= ((uint32_t)*pA++ << 4u);
  *pR |= ((uint32_t)*pA << 12u);
  *pR &= 0xFFFFFu;

  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA65_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA65_GAMMA1 - *pRSigned;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_DI_EXPUNGE(zUnpack19R, (uintptr_t)pR - 4U);
  MCUX_CSSL_DI_EXPUNGE(zUnpack19R, (uintptr_t)pRSigned - 4U);
  MCUX_CSSL_DI_EXPUNGE(zUnpack19A, (uintptr_t)pA - 4U);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Unpack_19);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - mcuxClMlDsa_Poly_t *r: pointer to output polynomial
 *              - InputBuffer_t: buffer with bit-packed polynomial z
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 * Used in: Sign, Verify
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *r,
  mcuxCl_InputBuffer_t zBuf,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack);
  MCUX_CSSL_DI_RECORD(packingZUnpackR, (uintptr_t)r);
  MCUX_CSSL_DI_RECORD(packingZUnpackGamma, (uint32_t)params->gamma1);

  /* record the amount of bytes about to be read */
  MCUX_CSSL_DI_RECORD(readLength,
                     params->gamma1 == MCUXCLMLDSA_MLDSA44_GAMMA1 ? MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES
                                                                   : MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES);

  const uint16_t numLoops = MCUXCLMLDSA_N / (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1 ? 4U : 2U);

  int32_t *pR = r->coefficients;

  uint32_t i;
  if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2 */
  {
    uint8_t t[9u];
    MCUX_CSSL_DI_RECORD(readDst, (uintptr_t)t * numLoops);
    MCUX_CSSL_FP_LOOP_DECL(loop1);
    for (i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
    {
      MCUX_CSSL_DI_RECORD(readSrc, (uintptr_t)zBuf);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(zBuf, 0u, t, 9u));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_17(pR, t));
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Won't overflow, these pointers are valid within r and z")
      pR += 4u;
      MCUXCLBUFFER_UPDATE(zBuf, 9u);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      MCUX_CSSL_FP_LOOP_ITERATION(loop1, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_17));
    }
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, MCUXCLMLDSA_N / 4u));
  }
  else if (MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5 */
  {
    uint8_t t[5u];
    MCUX_CSSL_DI_RECORD(readDst, (uintptr_t)t * numLoops);
    MCUX_CSSL_FP_LOOP_DECL(loop2);
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      MCUX_CSSL_DI_RECORD(readSrc, (uintptr_t)zBuf);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(zBuf, 0u, t, 5u));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_19(pR, t));
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Won't overflow, these pointers are valid within r and z")
      pR += 2u;
      MCUXCLBUFFER_UPDATE(zBuf, 5u);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      MCUX_CSSL_FP_LOOP_ITERATION(loop2, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_19));
    }
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, MCUXCLMLDSA_N / 2u));
  }
  else
  {
    /* This should never be reached unless a fault attack happened. */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  /* DI balance normal cases */
  MCUX_CSSL_DI_EXPUNGE(packingZUnpackR, (uintptr_t)pR - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(packingZUnpackGamma, (uint32_t)params->gamma1);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W1_Pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - uint8_t *r: pointer to output byte array with at least
 *                            POLYW1_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W1_Pack(
  mcuxClSession_Handle_t session,
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W1_Pack);
  MCUX_CSSL_DI_RECORD(packingW1PackR, (uintptr_t)r);
  MCUX_CSSL_DI_RECORD(packingW1PackA, (uintptr_t)a);
  MCUX_CSSL_DI_RECORD(packingW1PackGamma, (uint32_t)params->gamma2);
  uint8_t *pR = r;
  uint16_t i;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  const uint32_t* pCoeffs = (const uint32_t*)a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)      /* Mode 2 */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
    {
      MCUX_CSSL_DI_DONOTOPTIMIZE(pR);
      pR[0u] = (uint8_t)(pCoeffs[0u] & 0xFFu);
      pR[0u] |= (uint8_t)(pCoeffs[1u] << 6u & 0xFFu);
      pR[1u] = (uint8_t)(pCoeffs[1u] >> 2u & 0xFFu);
      pR[1u] |= (uint8_t)(pCoeffs[2u] << 4u & 0xFFu);
      pR[2u] = (uint8_t)(pCoeffs[2u] >> 4u & 0xFFu);
      pR[2u] |= (uint8_t)(pCoeffs[3u] << 2u & 0xFFu);

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR and pCoeffs won't overflow if pointed at validly-sized w1 poly")
      pR += 3U;
      pCoeffs += 4U;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2)   /* Mode 3 or 5 */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      MCUX_CSSL_DI_DONOTOPTIMIZE(pR);
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR and pCoeffs won't overflow if pointed at validly-sized w1 poly")
      *pR = (uint8_t)(*pCoeffs++ & 0xFFu);
      *pR |= (uint8_t)(*pCoeffs++ << 4u & 0xFFu);
      pR++;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }
  }
  else
  {
    /* can't happen, fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  /* DI balance normal cases */
  MCUX_CSSL_DI_EXPUNGE(packingW1PackR,
                      (uintptr_t)pR
                          - (params->gamma2 == MCUXCLMLDSA_MLDSA44_GAMMA2
                                 ? MCUXCLMLDSA_MLDSA44_POLYW1_PACKEDBYTES
                                 : MCUXCLMLDSA_MLDSA65_POLYW1_PACKEDBYTES));
  MCUX_CSSL_DI_EXPUNGE(packingW1PackA, (uintptr_t)pCoeffs - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(packingW1PackGamma, (uint32_t)params->gamma2);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W1_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W1_Unpack
 *
 * Description: Unpack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - mcuxClSession_Handle_t session: Session handle
 *              - mcuxClMlDsa_Poly_t *a:   pointer to output polynomial
 *              - const uint8_t *r:       pointer to input byte array with at least POLYW1_PACKEDBYTES bytes
 *              - params:                 ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W1_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *a,
  const uint8_t *r,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W1_Unpack);
  uint16_t i;

  if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)    /* Mode 2: range [0, 15] */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 4u; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
      uint32_t* pCoeffs = (uint32_t*)&a->coefficients[4u*i + 0u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      pCoeffs[0] = ((uint32_t)r[3u*i + 0u] & 0x3Fu);
      pCoeffs[1] = (((uint32_t)r[3u*i + 0u] >> 6u) | (((uint32_t)r[3u*i + 1u] & 0xFu) << 2u));
      pCoeffs[2] = (((uint32_t)r[3u*i + 1u] >> 4u) | (((uint32_t)r[3u*i + 2u] & 0x3u) << 4u));
      pCoeffs[3] = ((uint32_t)r[3u*i + 2u] >> 2u);
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2)     /* Mode 3 or 5: [0, 43] */
  {
    for(i = 0u; i < MCUXCLMLDSA_N / 2u; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
      uint32_t* pCoeffs = (uint32_t*)&a->coefficients[2u*i + 0u];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      pCoeffs[0] = ((uint32_t)r[i] & 0xFu);
      pCoeffs[1] = ((uint32_t)r[i] >> 4u);
    }
  }
  else
  {
    /* can't happen unless fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W1_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W_Pack
 *
 * Description: Pack full polynomial into 768 bytes
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *w: pointer to input polynomial
 *              - uint8_t *a: output byte array for w with at least
 *                            3*MCUXCLMLDSA_N = 768 bytes
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Pack(uint8_t *a, const mcuxClMlDsa_Poly_t *w)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W_Pack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  const uint32_t* wCoeffs = (const uint32_t*)w->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    a[3u*i+0u] = (uint8_t)(wCoeffs[i] >> 0u  & 0xFFu);
    a[3u*i+1u] = (uint8_t)(wCoeffs[i] >> 8u  & 0xFFu);
    a[3u*i+2u] = (uint8_t)(wCoeffs[i] >> 16u & 0xFFu);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W_Unpack
 *
 * Description: Unpack full polynomial from 768 bytes
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *w: pointer to output polynomial
 *              - uint8_t *a: input byte array for w with at least
 *                            3*MCUXCLMLDSA_N = 768 bytes
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Unpack(mcuxClMlDsa_Poly_t *w, const uint8_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* wCoeffs = (uint32_t*)w->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    wCoeffs[i] = (((uint32_t)a[3u*i+0u]) | (((uint32_t)a[3u*i+1u]) << 8u) | (((uint32_t)a[3u*i+2u]) << 16u));
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_C_Pack
 *
 * Description: c is a polynomial with 256 coefficients, of which TAU < 64
 *              are in {-1,1}. We store this into 256 bits, where each
 *              set bit determines the coefficient being non-zero, and 64 > TAU
 *              bits that determine their sign.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to input polynomial
 *              - uint8_t *cPacked: output byte array for c with at least
 *                                   32 + 8 = 40 bytes
 *              - params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_C_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Pack(
  uint8_t *cPacked,
  const mcuxClMlDsa_Poly_t *c,
  const mcuxClMlDsa_Params_t *const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_C_Pack);
  MCUX_CSSL_DI_RECORD(packingCPackCPacked, (uintptr_t)cPacked);
  MCUX_CSSL_DI_RECORD(packingCPackC, (uintptr_t)c);
  MCUX_CSSL_DI_RECORD(packingCPackParams, (uintptr_t)params);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("c->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pC = c->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_DI_RECORD(cPackedAddr, (uintptr_t) cPacked);
  MCUX_CSSL_DI_RECORD(cPackedSize, MCUXCLMLDSA_C_PACKED_BYTES);
  MCUXCLMEMORY_SET_INT(cPacked, 0u, MCUXCLMLDSA_C_PACKED_BYTES);

  uint8_t sign = 0u, signInc = 0u;
  uint8_t signsPos = 0u;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for (uint16_t i = 0U; i < MCUXCLMLDSA_N; i++)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pC);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pC/signPos won't overflow because we have at most TAU/N elements")
    signInc = (*pC != 0) ? 1u : 0u;  // get if the coeff is equal to 0
    MCUX_CSSL_DI_RECORD(packingCPackTau, signInc);
    sign = ((*pC++) - 1 != 0) ? 1u : 0u; // get if the sign is pos or neg. 1 if neg.
    cPacked[i >> 3U] |= signInc << (i & 0x7U);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Recovering signed numbers which are represented as compressed byte array")
    cPacked[(MCUXCLMLDSA_N >> 3U) + (signsPos >> 3U)] |= (sign & signInc) << (signsPos & 0x7U);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    signsPos += signInc;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_DI_EXPUNGE(packingCPackCPacked, (uintptr_t)cPacked);
  MCUX_CSSL_DI_EXPUNGE(packingCPackC, (uintptr_t)pC - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(packingCPackTau, (uint32_t)params->tau);
  MCUX_CSSL_DI_EXPUNGE(packingCPackParams, (uintptr_t)params);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_C_Pack,
    MCUXCLMEMORY_SET_INT_FP_EXPECT,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_C_Unpack
 *
 * Description: c is a polynomial with 256 coefficients, of which TAU < 64
 *              are in {-1,1}. We retrieve this from 256 bits, where each
 *              set bit determines the coefficient being non-zero, and 64 > TAU
 *              bits that determine their sign.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to output polynomial
 *              - const uint8_t *cPacked: output byte array for c with at least
 *                                   32 + 8 = 40 bytes
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_C_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Unpack(
  mcuxClMlDsa_Poly_t *c,
  const uint8_t *cPacked,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_C_Unpack);
  MCUX_CSSL_DI_RECORD(packingCUnpackC, (uintptr_t)c);
  MCUX_CSSL_DI_RECORD(packingCUnpackCPacked, (uintptr_t)cPacked);
  MCUX_CSSL_DI_RECORD(packingCUnpackParams, (uintptr_t)params);

  int32_t *pC = c->coefficients;
  const uint8_t *pPacked = cPacked;

  uint16_t i, j;
  uint64_t signs;

  /* Initialize signs */
  signs = ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 0u] << (8u*0u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 1u] << (8u*1u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 2u] << (8u*2u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 3u] << (8u*3u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 4u] << (8u*4u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 5u] << (8u*5u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 6u] << (8u*6u)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3u) + 7u] << (8u*7u));


  for(i = 0u; i < MCUXCLMLDSA_N >> 3u; ++i)
  {
    for(j = 0u; j < 8u; ++j)
    {
      /* If bit is set (m) then set to -1 if sign bit is set or to +1 is not set, 0 otherwise. */
      uint8_t m = (*pPacked >> j) & (uint8_t)1u;
      uint64_t s = signs & 1u;
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will stay within polynomial bounds and thus not overflow")
      *pC++ = (1 - 2 * ((int32_t)s)) * (int32_t)m;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      signs >>= m;
    }
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will stay within packed polynomial bounds and thus not overflow")
    pPacked++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  }

  for(i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    if (0 != c->coefficients[i])
    {
      MCUX_CSSL_DI_RECORD(packingCUnpackTau, 1U);
    }
  }

  /* Check the first loop, i.e., by checking that pC and pPacked advanced like expected */
  MCUX_CSSL_DI_EXPUNGE(packingCUnpackC, (uintptr_t)pC - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(packingCUnpackCPacked, (uintptr_t)pPacked - 32U);
  /* Check that we've seen tau 1's, individually */
  MCUX_CSSL_DI_EXPUNGE(packingCUnpackTau, (uint32_t)params->tau);
  MCUX_CSSL_DI_EXPUNGE(packingCUnpackParams, (uintptr_t)params);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_C_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_H_Unpack
 *
 * Description: Unpack h[i] of signature sig = (c, z, h).
 *
 * Arguments:   - Session
                - mcuxClMlDsa_Poly_t *pH: output hint h
 *              - uint16_t i: index of h in hint vector
 *              - hintBuf: pointer to start of bit-packed signature
 *              - const mcuxClMlDsa_Params_t *pParams: ML-DSA parameter set structure
 *
 * Returns MCUXCLSIGNATURE_STATUS_NOT_OK in case of malformed h
 *
 * Data Integrity: Expunge(pParams + pH)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_H_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Packing_H_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t* pH,
  uint16_t i,
  uint8_t* const pHPacked,
  mcuxCl_InputBuffer_t hintBuf,
  const mcuxClMlDsa_Params_t* pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_H_Unpack);
  uint16_t j, k;
  uint16_t secCounter;

  /* read the hints from the signature to a workarea buffer */
  MCUX_CSSL_DI_RECORD(readParams, hintBuf);
  MCUX_CSSL_DI_RECORD(readParams, pHPacked);
  MCUX_CSSL_DI_RECORD(readParams, (uint32_t)pParams->omega + (uint32_t)pParams->k);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(hintBuf, 0U, pHPacked, (uint32_t)pParams->omega + (uint32_t)pParams->k));

  /* Decode h */
  if(i == 0u)
  {
    k = 0u;
  }
  else
  {
    k = pHPacked[pParams->omega + i - 1u];
  }

  /* Clear coefficients in h, and balance calls with proper DI_RECORDs */
  MCUX_CSSL_DI_RECORD(memClearHDst, (uint8_t*) pH->coefficients);
  MCUX_CSSL_DI_RECORD(memClearHLen, MCUXCLMLDSA_POLY_SIZE);
  MCUXCLMEMORY_CLEAR_INT((uint8_t*) pH->coefficients,MCUXCLMLDSA_POLY_SIZE);

  secCounter = 0x00u;

  /* delimiter indices are ordered for strong unforgeability requirement */
  if((pHPacked[pParams->omega + i] < k) || (pHPacked[pParams->omega + i] > pParams->omega))
  {
    MCUX_CSSL_DI_EXPUNGE(packingHUnpackH, (uintptr_t)pH);
    MCUX_CSSL_DI_EXPUNGE(packingHUnpackParams, (uintptr_t)pParams);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_NOT_OK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
      MCUXCLMEMORY_CLEAR_INT_FP_EXPECT);
  }

  const uint8_t *pHI = pHPacked + k;
  MCUX_CSSL_DI_RECORD(PackingHUnpackHintIndices, (uintptr_t)pHI);
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(j = k; j < pHPacked[pParams->omega + i]; ++j)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pHI);
    /* Coefficients are ordered for strong unforgeability */
    if(j > k && pHPacked[j] <= pHPacked[j - 1u])
    {
      MCUX_CSSL_DI_EXPUNGE(packingHUnpackH, (uintptr_t)pHI - ((uint32_t)j - (uint32_t)k));
      MCUX_CSSL_DI_EXPUNGE(packingHUnpackH, (uintptr_t)pH);
      MCUX_CSSL_DI_EXPUNGE(packingHUnpackParams, (uintptr_t)pParams);
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_NOT_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
        MCUXCLMEMORY_CLEAR_INT_FP_EXPECT,
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, ((uint32_t)j - (uint32_t)k)));
    }
    else
    {
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(secCounter, 0u, MCUXCLMLDSA_MLDSA87_OMEGA, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
      secCounter++;
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pHI won't overflow, hints are max omega bytes long")
      pH->coefficients[*pHI++] = 1;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }
  MCUX_CSSL_DI_EXPUNGE(PackingHUnpackHintIndices, (uintptr_t)pHI - (uintptr_t)pHPacked[pParams->omega + i] + (uint32_t)k);

  if(secCounter != pHPacked[pParams->omega + i] - k)
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_DI_EXPUNGE(packingHUnpackH, (uintptr_t)pH);
  MCUX_CSSL_DI_EXPUNGE(packingHUnpackParams, (uintptr_t)pParams);
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    MCUXCLMEMORY_CLEAR_INT_FP_EXPECT,
    MCUX_CSSL_FP_CONDITIONAL(k < pHPacked[pParams->omega + i],
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, ((uint32_t)pHPacked[pParams->omega + i] - (uint32_t)k))));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_SK_Unpack
 *
 * Description: Partially unpack secret key sk = (rho, key, tr, s1, s2, t0).
 *              Unpacks rho, tr and key - t0, s1 and s2 are done on the fly.
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const uint8_t tr[]: output byte array for tr
 *              - const uint8_t key[]: output byte array for key
 *              - uint8_t sk[]: byte array containing bit-packed sk
 *
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_SK_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_SK_Unpack(uint8_t *rho, uint8_t *tr, uint8_t *key, const uint8_t *sk)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_SK_Unpack);

  /* Securely copy data from sk into rho, and balance calls with proper DI_RECORDs */
  MCUX_CSSL_DI_RECORD(memCopySecureRhoDst, rho);
  MCUX_CSSL_DI_RECORD(memCopySecureRhoSrc, sk);
  MCUX_CSSL_DI_RECORD(memCopySecureRhoLen, MCUXCLMLDSA_SEEDBYTES);
  MCUXCLMEMORY_COPY_SECURE_INT(rho,
                              sk,
                              MCUXCLMLDSA_SEEDBYTES);

  /* Securely copy data from sk into key, and balance calls with proper DI_RECORDs */
  MCUX_CSSL_DI_RECORD(memCopySecureKeyDst, key);
  MCUX_CSSL_DI_RECORD(memCopySecureKeySrc, &sk[MCUXCLMLDSA_SEEDBYTES]);
  MCUX_CSSL_DI_RECORD(memCopySecureKeyLen, MCUXCLMLDSA_SEEDBYTES);
  MCUXCLMEMORY_COPY_SECURE_INT(key,
                              &sk[MCUXCLMLDSA_SEEDBYTES],
                              MCUXCLMLDSA_SEEDBYTES);

  /* Securely copy data from sk into tr, and balance calls with proper DI_RECORDs */
  MCUX_CSSL_DI_RECORD(memCopySecureTrDst, tr);
  MCUX_CSSL_DI_RECORD(memCopySecureTrSrc, &sk[2U * MCUXCLMLDSA_SEEDBYTES]);
  MCUX_CSSL_DI_RECORD(memCopySecureTrLen, MCUXCLMLDSA_TRBYTES);
  MCUXCLMEMORY_COPY_SECURE_INT(tr,
                              &sk[2U * MCUXCLMLDSA_SEEDBYTES],
                              MCUXCLMLDSA_TRBYTES);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_SK_Unpack,
                            MCUXCLMEMORY_COPY_SECURE_INT_FP_EXPECT,
                            MCUXCLMEMORY_COPY_SECURE_INT_FP_EXPECT,
                            MCUXCLMEMORY_COPY_SECURE_INT_FP_EXPECT);
}
