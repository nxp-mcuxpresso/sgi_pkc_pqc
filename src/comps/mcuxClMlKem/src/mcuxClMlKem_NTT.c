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
 * @file:   mcuxClMlKem_NTT.c
 * @brief:  Modes for the NTT
 *
 */

#include <mcuxClXof_Types.h>
#include <mcuxClSession_Types.h>
#include <mcuxClMlKem.h>
#include <mcuxClKem.h>
#include <internal/mcuxClMlKem_Utils.h>
#include <internal/mcuxClMlKem_Poly.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClXof_Internal.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>

/* Macro to Montgomery reduction and does Montgomery multiplication. */
#define FQMUL(_A,_B) \
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_TRUNCATION() \
  mcuxClMlKem_Montgomery_Reduce((int32_t)((int16_t)(_A))*((int16_t)(_B))) \
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_TRUNCATION()


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Montgomery_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int16_t)mcuxClMlKem_Montgomery_Reduce(const int32_t a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Montgomery_Reduce);

  /* Truncate input to avoid signed overflow undefined behaviour */
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_TRUNCATION()
  int16_t lsBits = (int16_t)a;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_TRUNCATION()

  /* Calculate a*MCUXCLMLKEM_QINV and truncate the result to int16 */
  int32_t u = (int32_t)lsBits * (int32_t)MCUXCLMLKEM_QINV;
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_TRUNCATION()
  lsBits = (int16_t)u;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_TRUNCATION()

  /* Calculate ((a - (u*MCUXCLMLKEM_Q)) >> 16) and truncate the result to int16 */
  /* NOTE: sign extension of uint16_t to int32_t is required for correct algorithm execution */
  u = (int32_t)lsBits * (int32_t)MCUXCLMLKEM_Q;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER((int64_t)a - (int64_t)u, MCUXCLMLKEM_RESULT_BEFORE_RED_MIN, MCUXCLMLKEM_RESULT_BEFORE_RED_MAX, 0)
  int32_t aRed = a - u;
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_SHIFT()
  aRed = aRed >> 16;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_SHIFT()

  lsBits = (int16_t)aRed;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Montgomery_Reduce, lsBits);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Barrett_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int16_t)mcuxClMlKem_Barrett_Reduce(const int16_t a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Barrett_Reduce);

  uint32_t u = (((uint32_t)1u << 26u) + MCUXCLMLKEM_Q / 2u) / MCUXCLMLKEM_Q;
  const int16_t v = (int16_t)u;

  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_SHIFT()
  int32_t s = ((int32_t)v * a) >> 26;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_SHIFT()
  int16_t t = (int16_t)s;

  /* Calculate t*MCUXCLMLKEM_Q and truncate the result to int16 */
  s = (int32_t)t * (int32_t)MCUXCLMLKEM_Q;
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_TRUNCATION()
  t = (int16_t)s;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_TRUNCATION()

  /* Calculate a-t and truncate the result to int16 */
  s = (int32_t)a - (int32_t)t;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(s, 0, (int32_t)MCUXCLMLKEM_Q, 0)
  int16_t ret = (int16_t)s;

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Barrett_Reduce, ret);
}

static const int16_t mcuxClMlKem_Zetas[128] = {   2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
                                                 3158,  622, 1577,  182,  962, 2127, 1855, 1468,
                                                  573, 2004,  264,  383, 2500, 1458, 1727, 3199,
                                                 2648, 1017,  732,  608, 1787,  411, 3124, 1758,
                                                 1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
                                                  516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
                                                 2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
                                                 2931,  961, 1821, 2604,  448, 2264,  677, 2054,
                                                 2226,  430,  555,  843, 2078,  871, 1550,  105,
                                                  422,  587,  177, 3094, 3038, 2869, 1574, 1653,
                                                 3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
                                                 1739,  644, 2457,  349,  418,  329, 3173, 3254,
                                                  817, 1097,  603,  610, 1322, 2044, 1864,  384,
                                                 2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
                                                 2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
                                                 3221, 3021,  996,  991,  958, 1869, 1522, 1628  };

static const int16_t mcuxClMlKem_Zetas_Inv[128] = { 1701, 1807, 1460, 2371, 2338, 2333, 308,  108,
                                                  2851,  870,  854, 1510, 2535, 1278, 1530, 1185,
                                                  1659, 1187, 3109,  874, 1335, 2111,  136, 1215,
                                                  2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
                                                    75,  156, 3000, 2911, 2980,  872, 2685, 1590,
                                                  2210,  602, 1846,  777,  147, 2170, 2551,  246,
                                                  1676, 1755,  460,  291,  235, 3152, 2742, 2907,
                                                  3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
                                                  1275, 2652, 1065, 2881,  725, 1508, 2368,  398,
                                                   951,  247, 1421, 3222, 2499,  271,   90,  853,
                                                  1860, 3203, 1162, 1618,  666,  320,    8, 2813,
                                                  1544,  282, 1838, 1293, 2314,  552, 2677, 2106,
                                                  1571,  205, 2918, 1542, 2721, 2597, 2312,  681,
                                                   130, 1602, 1871,  829, 2946, 3065, 1325, 2756,
                                                  1861, 1474, 1202, 2367, 3147, 1752, 2707,  171,
                                                  3127, 3042, 1907, 1836, 1517,  359,  758, 1441  };

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_NTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_NTT(int16_t r[256])
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_NTT);

  uint16_t len, start, j, k;
  int16_t t, zeta;

  k = 1;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(len = MCUXCLMLKEM_N / 2u; len >= 2u; len >>= 1u)
  {
    MCUX_CSSL_FP_LOOP_DECL(loop_2);
    for(start = 0u; start < MCUXCLMLKEM_N; start += 2u * len)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("There are in total 1+2+4+8+16+32+64=127 iterations, for values of len between 2 and 128.")
      zeta = mcuxClMlKem_Zetas[k++];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(start, 0u, MCUXCLMLKEM_N - 2u * len)
      MCUX_CSSL_FP_LOOP_DECL(loop_3);
      for(j = start; j < start + len; ++j)
      {
        MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret_MulRed, FQMUL(zeta, r[j + len]));
        t = ret_MulRed;
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(t, - (int16_t)MCUXCLMLKEM_Q + 1, (int16_t)MCUXCLMLKEM_Q - 1)
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(r[j + len], - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q)
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(r[j], - (int16_t)MCUXCLMLKEM_Q, (int16_t)MCUXCLMLKEM_Q)
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
        MCUX_CSSL_FP_LOOP_ITERATION(loop_3, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Montgomery_Reduce));
      }
      MCUX_CSSL_FP_LOOP_ITERATION(loop_2, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_3, len));
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, ((MCUXCLMLKEM_N - 1U) / (2U * (uint32_t)len)) + 1U));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_NTT,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_LOG2_N - 1U)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_InvNTT_To_Mont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_InvNTT_To_Mont(mcuxClMlKem_Poly_t * r)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_InvNTT_To_Mont);

  uint16_t start, len, j, k;
  int16_t t, zeta;

  k = 0u;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(len = 2u; len <= MCUXCLMLKEM_N / 2u; len <<= 1u)
  {
    MCUX_CSSL_FP_LOOP_DECL(loop_2);
    for(start = 0u; start < MCUXCLMLKEM_N; start += 2u * len)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("There are in total 64+32+16+8+4+2+1=127 iterations, for values of len between 2 and 128.")
      zeta = mcuxClMlKem_Zetas_Inv[k++];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(start, 0u, MCUXCLMLKEM_N - 2u * len)
      MCUX_CSSL_FP_LOOP_DECL(loop_3);
      for(j = start; j < start + len; ++j)
      {
        t = r->coeffs[j];
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_OUT_OF_BOUNDS_ACCESS("j + len will never exceed MLKEM_N and overrun r->coeffs. The MISRA checker fails to understand this.")
        MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret_AddRed, mcuxClMlKem_Barrett_Reduce(t + r->coeffs[j + len]));
        r->coeffs[j] = ret_AddRed;
        MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret_SubRed, FQMUL(zeta, t - r->coeffs[j + len]));
        r->coeffs[j + len] = ret_SubRed;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OUT_OF_BOUNDS_ACCESS()

        MCUX_CSSL_FP_LOOP_ITERATION(loop_3,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Barrett_Reduce),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Montgomery_Reduce));
      }
      MCUX_CSSL_FP_LOOP_ITERATION(loop_2, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_3, len));
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_LOOP_ITERATIONS(loop_2, ((MCUXCLMLKEM_N - 1U) / (2U * (uint32_t)len)) + 1U));
  }

  MCUX_CSSL_FP_LOOP_DECL(loop_4);
  for (j = 0; j < MCUXCLMLKEM_N; ++j)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(int16_t, ret_MulRed, FQMUL(r->coeffs[j], mcuxClMlKem_Zetas_Inv[127]));
    r->coeffs[j] = ret_MulRed;
    MCUX_CSSL_FP_LOOP_ITERATION(loop_4, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Montgomery_Reduce));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_InvNTT_To_Mont,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_LOG2_N - 1U),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_4, MCUXCLMLKEM_N));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Basemul)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Basemul(int16_t R[2], const int16_t a[2], const int16_t b[2], const int16_t zeta)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Basemul);

  int16_t r0, r1;
  r0  = FQMUL(a[1], b[1]);
  int32_t temp  = (int32_t)FQMUL(r0, zeta);
  temp += (int32_t)FQMUL(a[0], b[0]);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp, 0 - (int32_t)MCUXCLMLKEM_Q * 2, (int32_t)MCUXCLMLKEM_Q * 2, 0u)
  r0 = (int16_t)temp;

  temp  = (int32_t)FQMUL(a[0], b[1]);
  temp += (int32_t)FQMUL(a[1], b[0]);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp, 0 - (int32_t)MCUXCLMLKEM_Q * 2, (int32_t)MCUXCLMLKEM_Q * 2, 0u)
  r1 = (int16_t)temp;
  R[0] = r0;
  R[1] = r1;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Basemul);
}

/**
 * \brief ML-KEM rej uniform
 *
 * This function runs rejection sampling on uniform random bytes to generate
 * uniform random integers mod q
 *
 * \param[in]       r                Pointer to output buffer of at least len elements
 * \param[in]       len              Requested number of 16-bit integers (uniform mod q)
 * \param[in]       buf              Pointer to input buffer of buflen bytes (assumed to be uniform random bytes)
 * \param[in]       buflen           Length of input buffer in bytes
 *
 * \return returns number of sampled 16-bit integers (at most len)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Rej_Uniform)
static MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClMlKem_Rej_Uniform(int16_t * const r, const uint16_t len, const uint8_t *buf, const uint16_t buflen)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Rej_Uniform);

  uint16_t ctr = 0;
  uint16_t pos = 0;
  uint32_t val0, val1;

  while((ctr < len) && ((pos + 3u) <= buflen))
  {
    val0 = (((uint32_t)buf[pos + 0u] >> 0) | ((uint32_t)buf[pos + 1u] << 8)) & 0xFFFu;
    val1 = (((uint32_t)buf[pos + 1u] >> 4) | ((uint32_t)buf[pos + 2u] << 4)) & 0xFFFu;
    pos += 3u;

    if(val0 < MCUXCLMLKEM_Q)
    {
      r[ctr++] = (int16_t)val0;
    }
    if((ctr < len) && (val1 < MCUXCLMLKEM_Q))
    {
      r[ctr++] = (int16_t)val1;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Rej_Uniform, ctr);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Mul_Streamed_Matrix)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Mul_Streamed_Matrix(
                                                            mcuxClSession_Handle_t session,
                                                            mcuxClXof_Context_t pContext,
                                                            mcuxClMlKem_Poly_t * pkpv,
                                                            const mcuxClMlKem_Poly_t * skpv,
                                                            const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                            uint8_t row,
                                                            uint8_t col,
                                                            uint8_t transposed)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Mul_Streamed_Matrix);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, buf, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_BLOCK_SIZE_SHAKE_128 / sizeof(uint32_t)));
  /* |cbuf| = 2*5 = 10 bytes -> round up to word = 12 */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Need to create buffer object with more specialized type, cast is safe on aligned buffer")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(int16_t*, cbuf, mcuxClSession_allocateWords_cpuWa(session, (12u) / sizeof(uint32_t)));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(0u != transposed)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Stream128_Absorb1, mcuxClMlKem_Stream128_Absorb(session, pContext, seed, row, col));
    if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Stream128_Absorb1)
    {
      MCUXCLSESSION_ERROR(session, ret_Stream128_Absorb1);
    }
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Stream128_Absorb2, mcuxClMlKem_Stream128_Absorb(session, pContext, seed, col, row));
    if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Stream128_Absorb2)
    {
      MCUXCLSESSION_ERROR(session, ret_Stream128_Absorb2);
    }
  }

  uint32_t coff = 0;
  uint32_t ctr = 0u;
  while(ctr < MCUXCLMLKEM_N)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Stream128_Squeeze));
    MCUX_CSSL_FP_FUNCTION_CALL(squeezeRet, mcuxClMlKem_Stream128_Squeeze(session, pContext, buf, MCUXCLXOF_BLOCK_SIZE_SHAKE_128));
    if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != squeezeRet)
    {
      MCUXCLSESSION_ERROR(session, squeezeRet);
    }

    /* Convert buffer to 4 coefficients at a time */
    uint32_t k = 0u;
    while((k + 2u < MCUXCLXOF_BLOCK_SIZE_SHAKE_128) && (ctr < MCUXCLMLKEM_N))
    {
      /* Use 3 bytes to find at most 2 coefficients */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Rej_Uniform));
      MCUX_CSSL_FP_FUNCTION_CALL(nsamples, mcuxClMlKem_Rej_Uniform(cbuf + coff, 2u, buf + k, 3u));
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(coff, 0u, 3u, 0u)
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(nsamples, 0u, 2u, 0u)
      coff += nsamples;

      if(3u < coff)
      { /* 4 or 5 coefficients generated */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Basemul) * 2u);
        int16_t zeta = (int16_t)mcuxClMlKem_Zetas[64u + (ctr >> 2)];
        MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_TRUNCATION()
        int16_t zetaNeg = (int16_t)(0 - zeta);
        MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_TRUNCATION()
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("skpv->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Basemul(&pkpv->coeffs[ctr + 0u], &cbuf[0], &skpv->coeffs[ctr], zeta));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Basemul(&pkpv->coeffs[ctr + 2u], &cbuf[2], &skpv->coeffs[ctr + 2u], zetaNeg));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

        ctr += 4u;

        coff %= 4u;
        if(1u == coff)
        { /* 5th coefficient remaining */
          cbuf[0] = cbuf[4];
        }
      }

      k = k + 3u;
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(k, 0u, MCUXCLXOF_BLOCK_SIZE_SHAKE_128 + 3u + 2u, 0u)
    }
  }

  mcuxClSession_freeWords_cpuWa(session, (MCUXCLXOF_BLOCK_SIZE_SHAKE_128 / sizeof(uint32_t))
                                        + (12u / sizeof(uint32_t)));


  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Poly_Mul_Streamed_Matrix, MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Stream128_Absorb)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Poly_Mul_Streamed_Skpk)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Mul_Streamed_Skpk(mcuxClMlKem_Poly_t * bp,
                                                                  const mcuxClMlKem_Poly_t * sp,
                                                                  const uint8_t *skpk,
                                                                  const uint16_t j)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Poly_Mul_Streamed_Skpk);

  int16_t t[4];
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Pointer will be used for mapping integers stored as byte array (for storage and/or transfer purposes) back to original signed type")
  uint16_t *pT = (uint16_t *)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 4u; i++)
  {
    pT[0] = (uint16_t)(((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 0u]       | ((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 1u] & 0x0fu) << 8u) & 0xFFFFu);
    pT[1] = (uint16_t)(((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 1u] >> 4u | ((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 2u] & 0xffu) << 4u) & 0xFFFFu);
    pT[2] = (uint16_t)(((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 3u]       | ((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 4u] & 0x0fu) << 8u) & 0xFFFFu);
    pT[3] = (uint16_t)(((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 4u] >> 4u | ((uint32_t)(skpk + j * MCUXCLMLKEM_POLYBYTES)[6u * i + 5u] & 0xffu) << 4u) & 0xFFFFu);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMlKem_Basemul(bp->coeffs + 4u * i,
                         t,
                         MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("sp->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
                         sp->coeffs + 4u * i,
                         MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
                         mcuxClMlKem_Zetas[64u + i])
    );
    int16_t temp = mcuxClMlKem_Zetas[64u + i];

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(temp, 0, (int16_t)MCUXCLMLKEM_Q, 0u)
    int16_t zetasNeg = 0 - temp;
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Basemul(
      (int16_t*)&bp->coeffs + 4u * i + 2u,
      (int16_t*)&t + 2u,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("&sp->coeffs of type int16_t ( const *)[256] cast to type int16_t const * is needed")
      (const int16_t*)&sp->coeffs + 4u * i + 2u,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      zetasNeg
    ));

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Basemul),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Basemul)
      );
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Poly_Mul_Streamed_Skpk,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, (MCUXCLMLKEM_N / 4u)));
}
