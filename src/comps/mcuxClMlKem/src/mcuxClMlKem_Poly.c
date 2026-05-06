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
 * @file:   mcuxClMlKem_Poly.c
 * @brief:  Polynomial arithmetic functions
 */

#include <mcuxClSession_Types.h>
#include <mcuxClMlKem.h>
#include <mcuxClKem.h>

#include <internal/mcuxClMlKem_Utils.h>
#include <internal/mcuxClMlKem_Poly.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClMemory_Compare_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>

/**
 * \brief  mcuxClMlKem_Poly_Csubq
 *
 * This function applies conditional subtraction of q to each coefficient
 *    of a polynomial. For details of conditional subtraction of q see comments in reduce.c
 *
 * \param[in/out]    r                  Pointer to input/output polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Csubq)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Csubq(mcuxClMlKem_Poly_t * r)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Csubq);

  for(uint32_t i = 0u; i < MCUXCLMLKEM_N; i++)
  {
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(r->coeffs[i], INT16_MIN + (int16_t)MCUXCLMLKEM_Q, INT16_MAX - (int16_t)MCUXCLMLKEM_Q, 0u)
    r->coeffs[i] -= (int16_t)MCUXCLMLKEM_Q;

    MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_SHIFT()
    int32_t temp = (int32_t)r->coeffs[i] >> 31;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_SHIFT()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("Constant time algorithm relies on logical AND on signed number and is correct given two's complement representation on target platform")
    temp &= (int32_t)MCUXCLMLKEM_Q;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(r->coeffs[i] + temp, 0 - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q, 0u)
    r->coeffs[i] += (int16_t)temp;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Csubq);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Compress, mcuxClMlKem_Poly_Compress_Func_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  mcuxClMlKem_Poly_t *a,
  mcuxClMlKem_Params_t pParams
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Compress);
  uint8_t t[8];

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Csubq(a));

  if(128u == pParams->polycompressedbytes)
  {
    uint8_t r[4];

    for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
    {
      for(uint32_t j = 0u; j < 8u; j++)
      {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
        uint32_t coeff = (uint32_t)(int32_t)a->coeffs[8u*i+j];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(coeff, 0u, MCUXCLMLKEM_Q, MCUXCLKEM_STATUS_ERROR)
        coeff <<= 4u;
        coeff += MCUXCLMLKEM_CEIL_Q_DIV_2;
        coeff *= MCUXCLMLKEM_2_EXP_28_FLOOR_DIV_Q;
        coeff >>= 28u;
        t[j] = (uint8_t)(coeff & 0xFu);
      }
      r[0] = (uint8_t)(((uint32_t)t[0] | ((uint32_t)t[1] << 4)) & 0xFFu);
      r[1] = (uint8_t)(((uint32_t)t[2] | ((uint32_t)t[3] << 4)) & 0xFFu);
      r[2] = (uint8_t)(((uint32_t)t[4] | ((uint32_t)t[5] << 4)) & 0xFFu);
      r[3] = (uint8_t)(((uint32_t)t[6] | ((uint32_t)t[7] << 4)) & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeParams, rBuf);
      MCUX_CSSL_DI_RECORD(writeParams, i * 4u);
      MCUX_CSSL_DI_RECORD(writeParams, r);
      MCUX_CSSL_DI_RECORD(writeParams, 4u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 4u, r, 4u));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq));
  }
  if(160u == pParams->polycompressedbytes)
  {
    uint8_t r[5];

    for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
    {
      for(uint32_t j = 0u; j < 8u; j++)
      {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
        uint64_t coeff = (uint64_t)(int64_t)a->coeffs[8u*i+j];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(coeff, 0u, MCUXCLMLKEM_Q, MCUXCLKEM_STATUS_ERROR)
        coeff <<= 5u;
        coeff += MCUXCLMLKEM_FLOOR_Q_DIV_2;
        coeff *= MCUXCLMLKEM_2_EXP_27_CEIL_DIV_Q;
        coeff >>= 27u;
        t[j] = (uint8_t)(coeff & 0x1Fu);
      }
      r[0] = (uint8_t)((((uint32_t)t[0] >> 0) | (t[1] << 5)              ) & 0xFFu);
      r[1] = (uint8_t)((((uint32_t)t[1] >> 3) | (t[2] << 2) | (t[3] << 7)) & 0xFFu);
      r[2] = (uint8_t)((((uint32_t)t[3] >> 1) | (t[4] << 4)              ) & 0xFFu);
      r[3] = (uint8_t)((((uint32_t)t[4] >> 4) | (t[5] << 1) | (t[6] << 6)) & 0xFFu);
      r[4] = (uint8_t)((((uint32_t)t[6] >> 2) | (t[7] << 3)              ) & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeParams, rBuf);
      MCUX_CSSL_DI_RECORD(writeParams, i * 5u);
      MCUX_CSSL_DI_RECORD(writeParams, r);
      MCUX_CSSL_DI_RECORD(writeParams, 5u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 5u, r, 5u));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq));
  }

  /* Should never reach here. */
  MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Decompress)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Decompress(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Poly_t *r,
  mcuxCl_InputBuffer_t aBuf,
  mcuxClMlKem_Params_t pParams
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Decompress);

  if(128u == pParams->polycompressedbytes)
  {
    uint8_t a;
    for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 2u; i++)
    {
      MCUX_CSSL_DI_RECORD(readParams, aBuf);
      MCUX_CSSL_DI_RECORD(readParams, i);
      MCUX_CSSL_DI_RECORD(readParams, &a);
      MCUX_CSSL_DI_RECORD(readParams, 1u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(aBuf, i, &a, 1u));
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Recovering signed numbers which are represented as compressed byte array")
      r->coeffs[2u*i+0u] = (int16_t)(uint32_t)((((((uint32_t)a & 0xFu) * MCUXCLMLKEM_Q) + 8u) >> 4)           & 0xFFFFu);
      r->coeffs[2u*i+1u] = (int16_t)(uint32_t)(((((((uint32_t)a & 0xFFu) >> 4u) * MCUXCLMLKEM_Q) + 8u) >> 4)  & 0xFFFFu);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Decompress, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK);
  }
  else if(160u == pParams->polycompressedbytes)
  {
    uint8_t t[8];
    uint8_t a[5];

    for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
    {
      MCUX_CSSL_DI_RECORD(readParams, aBuf);
      MCUX_CSSL_DI_RECORD(readParams, i * 5u);
      MCUX_CSSL_DI_RECORD(readParams, a);
      MCUX_CSSL_DI_RECORD(readParams, 5u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(aBuf, i * 5u, a, 5u));
      t[0] = (uint8_t)(( (uint32_t)a[0] >> 0)                           & 0xFFu);
      t[1] = (uint8_t)((((uint32_t)a[0] >> 5) | ((uint32_t)a[1] << 3))  & 0xFFu);
      t[2] = (uint8_t)(( (uint32_t)a[1] >> 2)                           & 0xFFu);
      t[3] = (uint8_t)((((uint32_t)a[1] >> 7) | ((uint32_t)a[2] << 1))  & 0xFFu);
      t[4] = (uint8_t)((((uint32_t)a[2] >> 4) | ((uint32_t)a[3] << 4))  & 0xFFu);
      t[5] = (uint8_t)(( (uint32_t)a[3] >> 1)                           & 0xFFu);
      t[6] = (uint8_t)((((uint32_t)a[3] >> 6) | ((uint32_t)a[4] << 2))  & 0xFFu);
      t[7] = (uint8_t)(( (uint32_t)a[4] >> 3)                           & 0xFFu);

      for(uint32_t j = 0u; j < 8u; j++)
      {
        uint32_t temp = ((((uint32_t)t[j] & 31u) * MCUXCLMLKEM_Q + 16u) >> 5) & 0xFFFFu;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Recovering signed numbers which are represented as compressed byte array")
        r->coeffs[8u*i+j] = (int16_t)temp;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      }
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Decompress, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK);
  }
  else
  {
    /* Should never reach here. */
    MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
  }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_To_Bytes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_To_Bytes(uint8_t * const r, mcuxClMlKem_Poly_t * a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_To_Bytes);

  uint16_t t0, t1;

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Csubq(a));

  /* Every polynomial has degree MCUXCLMLKEM_N = 256
   * and each coefficient is modulo MCUXCLMLKEM_Q = 3329 (12 bits).
   * Hence, one can store two coefficients in 3 bytes.
   */
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 2u; i++)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Conversion of signed integer to unsigned format for serialization purpose")
    t0 = (uint16_t)a->coeffs[2u*i];
    t1 = (uint16_t)a->coeffs[2u*i+1u];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    r[3u*i+0u] = (uint8_t)(((uint32_t)t0 >> 0u) & 0xFFu);
    r[3u*i+1u] = (uint8_t)(((((uint32_t)t0 >> 8u) & 0xFu) | ((t1 << 4u) & 0xF0u)) & 0xFFu);
    r[3u*i+2u] = (uint8_t) (((uint32_t)t1 >> 4u) & 0xFFu);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_To_Bytes,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_From_Msg)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_From_Msg(mcuxClMlKem_Poly_t * r, const uint8_t *msg)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_From_Msg);

  /* Converts a 32-byte message to a polynomial.
   * This is done by taking each bit from the input message
   * and putting either 0 or (MCUXCLMLKEM_Q+1)/2 in each coefficient
   * of the output polynomial.
   * MCUXCLMLKEM_N = 256 coefficients means 256 bits (= 32 bytes) of input.
   */
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
  {
    for (uint32_t j = 0u; j < 8u; j++)
    {
      int16_t mask = (int16_t)(0 - (int16_t)(uint32_t)(((uint32_t)msg[i] >> j) & 1u));  /* mask is in { 0, -1 }        */
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("Constant time algorithm relies on logical AND on signed number and correct given two's complement representation on target platform")
      r->coeffs[8u * i + j] = mask & (((int16_t)MCUXCLMLKEM_Q + 1) / 2);   /* coefficient is 0 or (Q+1)/2 */
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()
    }
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_From_Msg);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_To_Msg)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_To_Msg(uint8_t * const msg, mcuxClMlKem_Poly_t * a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_To_Msg);

  uint32_t t;

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Csubq(a));

  /* Converts a MCUXCLMLKEM_N = 256 degree polynomial to a 256-bit
   * MCUXCLMLKEM_N = 256 coefficients means 256 bits (= 32 bytes) of input.
   * This is done by taking each coefficient from the polynomial
   * and mapping this to either 0 or 1 in the output message.
   */
  for (uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
  {
    msg[i] = 0;
    for (uint32_t j = 0u; j < 8u; j++)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as byte array for storage and transfer purposes")
      t = (uint32_t)(uint16_t)a->coeffs[8u * i + j];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(t, 0u, MCUXCLMLKEM_Q, MCUXCLKEM_STATUS_ERROR)
      t <<= 1u;
      t += MCUXCLMLKEM_CEIL_Q_DIV_2;
      t *= MCUXCLMLKEM_2_EXP_28_FLOOR_DIV_Q;
      t >>= 28u;
      t &= 1u;
      msg[i] = (uint8_t)((msg[i] | (t << j)) & 0xFFu);
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_To_Msg,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Cbd2)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Cbd2(mcuxClMlKem_Poly_t * r, const uint8_t buf[2u * MCUXCLMLKEM_N / 4u])
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Cbd2);

  uint32_t t, d;
  int16_t a, b;

  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 8u; i++)
  {
    t = ((uint32_t)(buf[4u*i+3u]) << 24U) | ((uint32_t)(buf[4u*i + 2u]) << 16U) | ((uint32_t)(buf[4u*i + 1u]) << 8U) | (uint32_t)(buf[4u*i]);
    d  = t & 0x55555555u;
    d += (t>>1) & 0x55555555u;

    for(uint32_t j = 0u; j < 8u; j++)
    {
      uint32_t temp = (d >> (4u * j + 0u)) & 0x3u;
      a = (int16_t)temp;
      temp = (d >> (4u * j + 2u)) & 0x3u;
      b = (int16_t)temp;
      r->coeffs[8u*i+j] = a - b;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Cbd2);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Cbd3)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Cbd3(mcuxClMlKem_Poly_t * r, const uint8_t buf[3*MCUXCLMLKEM_N/4])
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Cbd3);

  uint32_t t,d;
  int16_t a,b;

  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 4u; i++)
  {
    /* Extract the first 3 bytes. */
    t = (((uint32_t)(buf[i*3u + 2u]) << 16U) | ((uint32_t)(buf[i*3u + 1u]) << 8U) | (uint32_t)(buf[i*3u + 0u])) & 0xFFFFFFU;
    d  =  t      & 0x00249249U;
    d += (t>>1U) & 0x00249249U;
    d += (t>>2U) & 0x00249249U;

    for(uint32_t j = 0u; j < 4u; j++)
    {
      uint32_t tmp = (d >> (6u * j + 0u)) & 0x7u;
      a = (int16_t) tmp;
      tmp = (d >> (6u * j + 3u)) & 0x7u;
      b = (int16_t) tmp;
      r->coeffs[4u*i+j] = a - b;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Cbd3);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Get_Noise_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)mcuxClMlKem_Poly_Get_Noise_Eta1(
                             mcuxClSession_Handle_t session,
                             mcuxClMlKem_Poly_t * r,
                             const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                             uint8_t nonce,
                             mcuxClMlKem_Params_t pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Get_Noise_Eta1);

  /* |buf| = MLKEM_ETA1*MLKEM_N/4 = 3*64 = 192 bytes for K=2 and
    = 2*64 = 128 bytes for K={3, 4} */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, buf, mcuxClSession_allocateWords_cpuWa(session, 192u / sizeof(uint32_t)));

  uint32_t bufsize = (uint32_t)pParams->eta1 * MCUXCLMLKEM_N / 4u;

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_PRF, mcuxClMlKem_PRF(session, buf, (uint16_t)bufsize, seed, nonce));
  /* Check the return code of retCode_PRF */
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != retCode_PRF)
  {
    MCUXCLSESSION_ERROR(session, retCode_PRF);
  }

  if(2u == pParams->eta1)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Cbd2(r, buf));

    mcuxClSession_freeWords_cpuWa(session, 192u / sizeof(uint32_t));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Get_Noise_Eta1, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_PRF),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Cbd2));
  }
  else if(3u == pParams->eta1)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Cbd3(r, buf));

    mcuxClSession_freeWords_cpuWa(session, 192u / sizeof(uint32_t));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Get_Noise_Eta1, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_PRF),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Cbd3));
  }
  else
  {
    /* Should never reach here. */
    MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
  }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Get_Noise_Eta2)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)mcuxClMlKem_Poly_Get_Noise_Eta2(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClMlKem_Poly_t * r,
                                                          const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                          uint8_t nonce)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Get_Noise_Eta2);

  /* |buf| = MCUXCLMLKEM_ETA2*MCUXCLMLKEM_N/4 = 128 bytes. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, buf, mcuxClSession_allocateWords_cpuWa(session, ((MCUXCLMLKEM_ETA2 * MCUXCLMLKEM_N) / 4u) / sizeof(uint32_t)));

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_PRF, mcuxClMlKem_PRF(session, buf, MCUXCLMLKEM_ETA2*MCUXCLMLKEM_N / 4u, seed, nonce));
  /* Check the return code of retCode_PRF */
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != retCode_PRF)
  {
    MCUXCLSESSION_ERROR(session, retCode_PRF);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Cbd2(r, buf));

  mcuxClSession_freeWords_cpuWa(session, ((MCUXCLMLKEM_ETA2 * MCUXCLMLKEM_N) / 4u) / sizeof(uint32_t));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Get_Noise_Eta2, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_PRF),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Cbd2));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_NTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_NTT(mcuxClMlKem_Poly_t * r)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_NTT);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_NTT(r->coeffs));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Reduce(r));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_NTT,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_NTT),
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Reduce));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_To_Mont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_To_Mont(mcuxClMlKem_Poly_t * r)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_To_Mont);

  /* We work in the Montgomery domain with Montgomery constant R=2^16 mod MLKEM_Q.
   * To convert to Montgomery domain one can perform a Montgomery multiplication
   * with R^2 = 2^32 mod MLKEM_Q since
   *   MontMul(R^2, a) = (a*R^2)/R = a*R mod MLKEM_Q
   */
  uint64_t temp = ((uint64_t)1 << 32) % MCUXCLMLKEM_Q;
  const int16_t f = (int16_t)temp;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret, mcuxClMlKem_Montgomery_Reduce((int32_t)r->coeffs[i] * f));
    r->coeffs[i] = ret;
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Montgomery_Reduce));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_To_Mont,
          MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Reduce(mcuxClMlKem_Poly_t * r)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Reduce);

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N; i++)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret, mcuxClMlKem_Barrett_Reduce(r->coeffs[i]));
    r->coeffs[i] = ret;
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Barrett_Reduce));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Reduce,
          MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Add)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Add(mcuxClMlKem_Poly_t * r, const mcuxClMlKem_Poly_t * a, const mcuxClMlKem_Poly_t * b)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Add);

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N; i++)
  {
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a->coeffs[i], 0 - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q, 0u)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(b->coeffs[i], 0 - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q, 0u)
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coeffs and b->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Add,
              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Sub)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Sub(mcuxClMlKem_Poly_t * r, const mcuxClMlKem_Poly_t * a, const mcuxClMlKem_Poly_t * b)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Sub);

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N; i++)
  {
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a->coeffs[i], 0 - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q, 0u)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(b->coeffs[i], 0 - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q, 0u)
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coeffs and b->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Sub,
              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Compress_Gen, mcuxClMlKem_Poly_Compress_Func_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress_Gen(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  mcuxClMlKem_Poly_t *a,
  mcuxClMlKem_Params_t pParams
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Compress_Gen);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Poly_Csubq(a));

  if(pParams->polyveccompressedbytes == (pParams->k * 352u))
  {
    uint16_t t[8u];
    uint8_t r[11u];

    MCUX_CSSL_FP_LOOP_DECL(loop_1);
    for(uint32_t j = 0u; j < MCUXCLMLKEM_N / 8u; j++)
    {
      MCUX_CSSL_FP_LOOP_DECL(loop_2);
      for(uint32_t k = 0u; k < 8u; k++)
      {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
        uint64_t coeff = (uint64_t)(int64_t)a->coeffs[8u * j + k];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
        coeff <<= 11u;
        coeff += MCUXCLMLKEM_FLOOR_Q_DIV_2;
        coeff *= MCUXCLMLKEM_2_EXP_31_CEIL_DIV_Q;
        coeff >>= 31u;
        t[k] = (uint16_t)(coeff & 0x7ffu);
        MCUX_CSSL_FP_LOOP_ITERATION(loop_2);
      }

      r[0] =  (uint8_t)(((uint32_t)t[0] >> 0)                             & 0xFFu);
      r[1] =  (uint8_t)((((uint32_t)t[0] >> 8) | ((uint32_t)t[1] << 3))   & 0xFFu);
      r[2] =  (uint8_t)((((uint32_t)t[1] >> 5) | ((uint32_t)t[2] << 6))   & 0xFFu);
      r[3] =  (uint8_t)((((uint32_t)t[2] >> 2))                           & 0xFFu);
      r[4] =  (uint8_t)((((uint32_t)t[2] >> 10) | ((uint32_t)t[3] << 1))  & 0xFFu);
      r[5] =  (uint8_t)((((uint32_t)t[3] >> 7) | ((uint32_t)t[4] << 4))   & 0xFFu);
      r[6] =  (uint8_t)((((uint32_t)t[4] >> 4) | ((uint32_t)t[5] << 7))   & 0xFFu);
      r[7] =  (uint8_t)((((uint32_t)t[5] >> 1))                           & 0xFFu);
      r[8] =  (uint8_t)((((uint32_t)t[5] >> 9) | ((uint32_t)t[6] << 2))   & 0xFFu);
      r[9] =  (uint8_t)((((uint32_t)t[6] >> 6) | ((uint32_t)t[7] << 5))   & 0xFFu);
      r[10] = (uint8_t)((((uint32_t)t[7] >> 3))                           & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeParams, rBuf);
      MCUX_CSSL_DI_RECORD(writeParams, j * 11u);
      MCUX_CSSL_DI_RECORD(writeParams, r);
      MCUX_CSSL_DI_RECORD(writeParams, 11u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, j * 11u, r, 11u));
      MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, 8u));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress_Gen,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq),
                              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N / 8u));
  }
  if(pParams->polyveccompressedbytes == ((uint32_t)pParams->k * 320u))
  {
    uint16_t t[4u];
    uint8_t r[5u];

    MCUX_CSSL_FP_LOOP_DECL(loop_1);
    for(uint32_t j = 0u; j < MCUXCLMLKEM_N / 4u; j++)
    {
      MCUX_CSSL_FP_LOOP_DECL(loop_2);
      for(uint32_t k = 0u; k < 4u; k++)
      {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
        uint64_t coeff = (uint64_t)(int64_t)a->coeffs[4u * j + k];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
        coeff <<= 10u;
        coeff += MCUXCLMLKEM_CEIL_Q_DIV_2;
        coeff *= MCUXCLMLKEM_2_EXP_32_FLOOR_DIV_Q;
        coeff >>= 32u;
        t[k] = (uint16_t)(coeff & 0x3ffu);
        MCUX_CSSL_FP_LOOP_ITERATION(loop_2);
      }

      r[0] = (uint8_t)(( (uint32_t)t[0] >> 0)                & 0xFFu);
      r[1] = (uint8_t)((((uint32_t)t[0] >> 8) | (t[1] << 2)) & 0xFFu);
      r[2] = (uint8_t)((((uint32_t)t[1] >> 6) | (t[2] << 4)) & 0xFFu);
      r[3] = (uint8_t)((((uint32_t)t[2] >> 4) | (t[3] << 6)) & 0xFFu);
      r[4] = (uint8_t)(( (uint32_t)t[3] >> 2)                & 0xFFu);

      MCUX_CSSL_DI_RECORD(writeParams, rBuf);
      MCUX_CSSL_DI_RECORD(writeParams, j * 5u);
      MCUX_CSSL_DI_RECORD(writeParams, r);
      MCUX_CSSL_DI_RECORD(writeParams, 5u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, j * 5u, r, 5u));
      MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, 4u));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress_Gen,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Csubq),
                              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N / 4u));
  }

  /* Invalid parameters */
  /* Should never reach here. */
  MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Decompress_Gen)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Decompress_Gen(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Poly_t *r,
  mcuxCl_InputBuffer_t aBuf,
  mcuxClMlKem_Params_t pParams
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Decompress_Gen);

  if(pParams->polyveccompressedbytes == ((uint32_t)pParams->k * 352u))
  {
    uint16_t t[8u];
    uint8_t a[11u];

    MCUX_CSSL_FP_LOOP_DECL(loop_1);
    for(uint32_t j = 0u; j < MCUXCLMLKEM_N / 8u; j++)
    {
      MCUX_CSSL_DI_RECORD(readParams, aBuf);
      MCUX_CSSL_DI_RECORD(readParams, (j * 11u));
      MCUX_CSSL_DI_RECORD(readParams, a);
      MCUX_CSSL_DI_RECORD(readParams, 11u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(aBuf, (j * 11u), a, 11u));
      t[0] = (uint16_t)((((uint32_t)a[0] >> 0u) | ((uint32_t)a[1] << 8u))                            & 0xFFFFu);
      t[1] = (uint16_t)((((uint32_t)a[1] >> 3u) | ((uint32_t)a[2] << 5u))                            & 0xFFFFu);
      t[2] = (uint16_t)((((uint32_t)a[2] >> 6u) | ((uint32_t)a[3] << 2u) | ((uint32_t)a[4] << 10u))  & 0xFFFFu);
      t[3] = (uint16_t)((((uint32_t)a[4] >> 1u) | ((uint32_t)a[5] << 7u))                            & 0xFFFFu);
      t[4] = (uint16_t)((((uint32_t)a[5] >> 4u) | ((uint32_t)a[6] << 4u))                            & 0xFFFFu);
      t[5] = (uint16_t)((((uint32_t)a[6] >> 7u) | ((uint32_t)a[7] << 1u) | ((uint32_t)a[8] << 9u))   & 0xFFFFu);
      t[6] = (uint16_t)((((uint32_t)a[8] >> 2u) | ((uint32_t)a[9] << 6u))                            & 0xFFFFu);
      t[7] = (uint16_t)((((uint32_t)a[9] >> 5u) | ((uint32_t)a[10] << 3u))                           & 0xFFFFu);

      MCUX_CSSL_FP_LOOP_DECL(loop_2);
      for (uint32_t k = 0u; k < 8u; k++)
      {
        r->coeffs[8u * j + k] = (int16_t)(uint32_t)((((uint32_t)t[k] & 0x7FFu) * MCUXCLMLKEM_Q + 1024u) >> 11);
        MCUX_CSSL_FP_LOOP_ITERATION(loop_2);
      }

      MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, 8u));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Decompress_Gen,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N / 8u));
  }
  if(pParams->polyveccompressedbytes == (pParams->k * 320u))
  {
    uint16_t t[4u];
    uint8_t a[5u];

    MCUX_CSSL_FP_LOOP_DECL(loop_1);
    for(uint32_t j = 0u; j < MCUXCLMLKEM_N / 4u; j++)
    {
      MCUX_CSSL_DI_RECORD(readParams, aBuf);
      MCUX_CSSL_DI_RECORD(readParams, (j * 5u));
      MCUX_CSSL_DI_RECORD(readParams, a);
      MCUX_CSSL_DI_RECORD(readParams, 5u);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(aBuf, (j * 5u), a, 5u));
      t[0] = (uint16_t)((((uint32_t)a[0] >> 0u) | ((uint32_t)a[1] << 8u)) & 0xFFFFu);
      t[1] = (uint16_t)((((uint32_t)a[1] >> 2u) | ((uint32_t)a[2] << 6u)) & 0xFFFFu);
      t[2] = (uint16_t)((((uint32_t)a[2] >> 4u) | ((uint32_t)a[3] << 4u)) & 0xFFFFu);
      t[3] = (uint16_t)((((uint32_t)a[3] >> 6u) | ((uint32_t)a[4] << 2u)) & 0xFFFFu);

      MCUX_CSSL_FP_LOOP_DECL(loop_2);
      for(uint32_t k = 0u; k < 4u; k++)
      {
        r->coeffs[4u * j + k] = (int16_t)(uint32_t)((((uint32_t)t[k] & 0x3FFu) * MCUXCLMLKEM_Q + 512u) >> 10);
        MCUX_CSSL_FP_LOOP_ITERATION(loop_2);
      }
      MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, 4u));
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Decompress_Gen,
                              MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
                              MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N / 4u));
  }

  /* Should never reach here. */
  MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Compress_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Compress_Eta1(uint8_t * const r, const mcuxClMlKem_Poly_t * sk)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Compress_Eta1);

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t j = 0u; j < MCUXCLMLKEM_N >> 3u; j++)
  { /* 3 bits per coefficient, 8 coefficients per 3 bytes */
     MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("sk->coeffs->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
    int32_t temp0 = ((int32_t)sk->coeffs[8u * j + 0u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp0, 1, 5, 0u)
    int32_t temp1 = ((int32_t)sk->coeffs[8u * j + 1u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp1, 1, 5, 0u)
    int32_t temp2 = ((int32_t)sk->coeffs[8u * j + 2u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp2, 1, 5, 0u)
    r[3u * j] = (uint8_t)((
        (uint32_t)temp0 | ((uint32_t)temp1 << 3u) | (((uint32_t)temp2 & 0x3u) << 6u)) & 0xFFu);

    int32_t temp3 = ((int32_t)sk->coeffs[8u * j + 3u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp3, 1, 5, 0u)
    int32_t temp4 = ((int32_t)sk->coeffs[8u * j + 4u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp4, 1, 5, 0u)
    int32_t temp5 = ((int32_t)sk->coeffs[8u * j + 5u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp5, 1, 5, 0u)
    r[3u * j + 1u] = (uint8_t)((
      ((uint32_t)temp2 >> 2u) | ((uint32_t)temp3 << 1u) | ((uint32_t)temp4 << 4u) | (((uint32_t)temp5 & 0x1u) << 7u)) & 0xFFu);

    int32_t temp6 = ((int32_t)sk->coeffs[8u * j + 6u] + 3);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp6, 1, 5, 0u)
    int32_t temp7 = ((int32_t)sk->coeffs[8u * j + 7u] + 3);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp7, 1, 5, 0u)
    r[3u * j + 2u] = (uint8_t)((
      (((uint32_t)temp5 & 0x6u) >> 1u) | ((uint32_t)temp6 << 2u) | ((uint32_t)temp7 << 5u)) & 0xFFu);
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Compress_Eta1,
            MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, (MCUXCLMLKEM_N >> 3)));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Decompress_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Decompress_Eta1(mcuxClMlKem_Poly_t * sk, const uint8_t *packedsk)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Decompress_Eta1);

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t j = 0u; j < MCUXCLMLKEM_N >> 3u; j++)
  { /* 3 bits per coefficient, 8 coefficients per 3 bytes */
    uint32_t temp = (uint32_t)packedsk[3u * j] & 0x7u;
    sk->coeffs[8u * j + 0u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = (uint32_t)packedsk[3u * j] >> 3u & 0x7u;
    sk->coeffs[8u * j + 1u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = ((((uint32_t)packedsk[3u * j] >> 6u) & 0x3u) | (((uint32_t)packedsk[3u * j + 1u] & 0x1u) << 2u));
    sk->coeffs[8u * j + 2u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = (((uint32_t)packedsk[3u * j + 1u] >> 1) & 0x7u);
    sk->coeffs[8u * j + 3u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = (((uint32_t)packedsk[3u * j + 1u] >> 4) & 0x7u);
    sk->coeffs[8u * j + 4u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = ((((uint32_t)packedsk[3u * j + 1u] >> 7) & 0x1u) | (((uint32_t)packedsk[3u * j + 2u] & 0x3u) << 1));
    sk->coeffs[8u * j + 5u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = (((uint32_t)packedsk[3u * j + 2u] >> 2) & 0x7u);
    sk->coeffs[8u * j + 6u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    temp = (((uint32_t)packedsk[3u * j + 2u] >> 5) & 0x7u);
    sk->coeffs[8u * j + 7u] =  (int16_t)(int32_t)((int32_t)temp - 3);
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Decompress_Eta1,
            MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, (MCUXCLMLKEM_N >> 3)));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Compress_Cmp, mcuxClMlKem_Poly_Compress_Op_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)
mcuxClMlKem_Poly_Compress_Cmp(mcuxClSession_Handle_t session,
                             mcuxClMlKem_Params_t pParams,
                             mcuxClMlKem_Poly_t *pPoly,
                             mcuxCl_Buffer_t buf,
                             mcuxClMlKem_Poly_Compress_Func_t cmprFn,
                             uint32_t len,
                             uint8_t *wa,
                             mcuxClMemory_Status_t *rc)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Compress_Cmp);

  /* compress poly into wa */
  MCUXCLBUFFER_INIT_RW(waBuf, NULL, wa, len);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Compress_Gen1, cmprFn(session, waBuf, pPoly, pParams));
  if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK != ret_Poly_Compress_Gen1)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress_Cmp,
                              ret_Poly_Compress_Gen1,
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Gen));
  }

  /* re-use pPoly to hold compressed reference u polynomial */
  MCUX_CSSL_DI_RECORD(readParams, buf);
  MCUX_CSSL_DI_RECORD(readParams, (uint8_t *)pPoly);
  MCUX_CSSL_DI_RECORD(readParams, len);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(buf, 0u, (uint8_t *)pPoly, len));

  mcuxClMemory_Status_t retMemCompare1 = MCUXCLMEMORY_STATUS_NOT_EQUAL;

  MCUX_CSSL_DI_RECORD(memCompare, wa);
  MCUX_CSSL_DI_RECORD(memCompare, (uint8_t *)pPoly);
  MCUX_CSSL_DI_RECORD(memCompare, len);
  MCUXCLMEMORY_COMPARE_INT(retMemCompare1, wa, (uint8_t *)pPoly, len);

  /* The outcome of the comparison is secret */
  *rc |= (MCUXCLMEMORY_STATUS_EQUAL ^ retMemCompare1);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress_Cmp, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUXCLMEMORY_COMPARE_INT_FP_EXPECT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Compress_Write, mcuxClMlKem_Poly_Compress_Op_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress_Write(mcuxClSession_Handle_t session,
                                                                             mcuxClMlKem_Params_t pParams,
                                                                             mcuxClMlKem_Poly_t *pPoly,
                                                                             mcuxCl_Buffer_t buf,
                                                                             mcuxClMlKem_Poly_Compress_Func_t cmprFn,
                                                                             uint32_t len UNUSED_PARAM,
                                                                             uint8_t *wa UNUSED_PARAM,
                                                                             mcuxClMemory_Status_t *rc UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Compress_Write);

  /* Compress poly into buf */
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Poly_Compress_Gen2, cmprFn(session, buf, pPoly, pParams));

  if(MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK == ret_Poly_Compress_Gen2)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Compress_Write, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK);
  }

  /* Should never reach here. */
  MCUXCLSESSION_FAULT(session, MCUXCLKEM_STATUS_FAULT_ATTACK);
}
