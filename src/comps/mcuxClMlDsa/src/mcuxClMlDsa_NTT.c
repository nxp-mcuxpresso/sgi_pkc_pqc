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
 * @file mcuxClMlDsa_NTT.c
 * @brief Implementing the number-theoretic transform (NTT) and related
 * functions for fast polynomial operations in @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClMlDsa_Internal.h>

/**
 * @brief
 * A pre-computed list of the powers of zeta in NTT computations.
 */
static const int32_t mcuxClMlDsa_Zetas[MCUXCLMLDSA_N] =
{
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/**
 * @brief
 * Montgomery reduction of a single finite field element.
 *
 * For finite field element a with -Q * 2^{31} <= a <= +Q * 2^31,
 * compute r \equiv a * 2^{-32} (mod Q) such that -Q < r < Q.
 *
 * @param[in] a Input finite field element.
 *
 * @pre
 * The input a must satisfy -Q * 2^{31} <= a <= +Q * 2^31.
 *
 * @post
 * The output r satisfies r = a * 2^{-32} (mod Q) and -Q < r < Q.
 *
 * @return
 * The value r satisfying the above condition.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_MontgomeryReduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int32_t) mcuxClMlDsa_NTT_MontgomeryReduce(
  const int64_t a
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_MontgomeryReduce);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("shifting a signed integer")
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a, -((int64_t) MCUXCLMLDSA_Q << 31), (int64_t) MCUXCLMLDSA_Q << 31, 0)
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()

  int32_t t = 0;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Truncated upper bits are not needed. If a value of integral type is truncated to a shorter signed integral type, the result is obtained by discarding an appropriate number of most significant bits.")
  t = (int32_t) ((int64_t)(int32_t) a * (int32_t) MCUXCLMLDSA_QINV);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("shifting a signed integer")
  t = mcuxClMlDsa_SignedHi64_ToLo32(a - ((int64_t) t * (int32_t) MCUXCLMLDSA_Q));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(t, INT32_MIN, INT32_MAX, 0)
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_NTT_MontgomeryReduce, t);
}

MCUX_CSSL_ANALYSIS_START_SUPPRESS_NESTED_COMMENTS("Links are allowed in comments.")
/**
 * @brief
 * In-place forward NTT computation.
 *
 * For implementation details, see Algorithm 35 (p.36) of
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf
 *
 * @param[in,out] pA Pointer to input/output polynomial.
 *
 * @pre
 * pA is not in the NTT domain.
 *
 * @post
 * pA is in the NTT domain.
 */
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NESTED_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_ForwardNTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_ForwardNTT(
  mcuxClMlDsa_Poly_t* const pA
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_ForwardNTT);
  MCUX_CSSL_DI_RECORD(forwardNttZetas, (uintptr_t)mcuxClMlDsa_Zetas);

  int32_t zeta;

  const int32_t* pZeta = &mcuxClMlDsa_Zetas[0U];

  MCUX_CSSL_FP_LOOP_DECL(loop1);
  for (uint16_t len = MCUXCLMLDSA_N >> 1U; len > 0u; len >>= 1U)
  {
    MCUX_CSSL_DI_RECORD(forwardNttA, (uintptr_t) pA->coefficients);
    MCUX_CSSL_FP_LOOP_DECL(loop2);
    for (uint16_t start = 0U; start < MCUXCLMLDSA_N; start += 2U * len)
    {
      MCUX_CSSL_FP_LOOP_DECL(loop3);
      zeta = *(++pZeta);

      for (uint16_t j = start; j < start + len; ++j)
      {
        MCUX_CSSL_FP_FUNCTION_CALL(int32_t, t,
          mcuxClMlDsa_NTT_MontgomeryReduce((int64_t) zeta * pA->coefficients[j + len])
        );
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(t, -(int32_t) MCUXCLMLDSA_Q, (int32_t) MCUXCLMLDSA_Q, 0)
        pA->coefficients[j + len] = pA->coefficients[j] - t;
        pA->coefficients[j] = pA->coefficients[j] + t;
        MCUX_CSSL_FP_LOOP_ITERATION(loop3,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_MontgomeryReduce)
        );
      }
      MCUX_CSSL_FP_LOOP_ITERATION(loop2,
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop3, len)
      );
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop1,
      MCUX_CSSL_FP_LOOP_ITERATIONS(loop2,
        (((MCUXCLMLDSA_N - 1U) / (2U * (uint32_t)len)) + 1U)
      )
    );
  }

  /* Check that the zeta pointer was incremented by 255 */
  MCUX_CSSL_DI_EXPUNGE(forwardNttZetas, (uintptr_t) pZeta - 4U * (MCUXCLMLDSA_N - 1U));
  MCUX_CSSL_DI_EXPUNGE(forwardNttA, (uintptr_t) pA->coefficients * MCUXCLMLDSA_LOG2_N);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_ForwardNTT,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, MCUXCLMLDSA_LOG2_N)
  );
}

MCUX_CSSL_ANALYSIS_START_SUPPRESS_NESTED_COMMENTS("Links are allowed in comments.")
/**
 * @brief
 * In-place inverse NTT calculation, and multiplication by 2^32.
 *
 * For implementation details, see Algorithm 36 (p.37) of
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf
 *
 * @param[in,out] pA Pointer to input/output polynomial.
 *
 * @pre
 * pA is in the NTT domain.
 *
 * @post
 * pA is converted back from the NTT domain.
 */
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NESTED_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_InverseNTTToMont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_InverseNTTToMont(
  mcuxClMlDsa_Poly_t* const pA
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_InverseNTTToMont);
  MCUX_CSSL_DI_RECORD(forwardNttZetas, (uintptr_t) mcuxClMlDsa_Zetas);
  MCUX_CSSL_DI_RECORD(forwardNttA, (uintptr_t) pA);

  const int32_t* pZeta = &mcuxClMlDsa_Zetas[MCUXCLMLDSA_N];
  int32_t* pACur = pA->coefficients;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Pointer casting in suppression macro because comparing a pointer to a constant int")
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(pZeta, 0u, UINT32_MAX - MCUXCLMLDSA_POLY_SIZE - sizeof(int32_t) + 1U)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(pACur, 0u, UINT32_MAX - MCUXCLMLDSA_POLY_SIZE - sizeof(int32_t) + 1U)
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  int32_t t, zeta;

  MCUX_CSSL_FP_LOOP_DECL(loop1);
  for (uint16_t len = 1U; len < MCUXCLMLDSA_N; len <<= 1U)
  {
    MCUX_CSSL_DI_RECORD(forwardNttCoeffs, (uintptr_t) pA->coefficients);
    MCUX_CSSL_FP_LOOP_DECL(loop2);
    for (uint16_t start = 0U; start < MCUXCLMLDSA_N - 1U; start += 2U * len)
    {
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(start, 0U, MCUXCLMLDSA_N - 2U, 0);
      zeta = *(--pZeta);
      /* smallest and biggest value in zetas */
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(zeta, -(int32_t) MCUXCLMLDSA_Q / 2, (int32_t) MCUXCLMLDSA_Q / 2, 0)
      zeta = -zeta;
      MCUX_CSSL_FP_LOOP_DECL(loop3);
      for (uint16_t j = start; j < start + len; ++j)
      {
        t = pA->coefficients[j];
        pA->coefficients[j] = t + pA->coefficients[j + len];
        pA->coefficients[j + len] = t - pA->coefficients[j + len];
        MCUX_CSSL_FP_FUNCTION_CALL(int32_t, res,
          mcuxClMlDsa_NTT_MontgomeryReduce((int64_t) zeta * pA->coefficients[j + len]));
        pA->coefficients[j + len] = res;
        MCUX_CSSL_FP_LOOP_ITERATION(loop3,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_MontgomeryReduce));
      }
      MCUX_CSSL_FP_LOOP_ITERATION(loop2,
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop3, len)
      );
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop1,
      MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, (uint16_t)MCUXCLMLDSA_N / (2U * (uint32_t)len)));
  }

  MCUX_CSSL_FP_LOOP_DECL(loop4);
  for (uint16_t j = 0U; j < MCUXCLMLDSA_N; ++j)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(int32_t, res,
      mcuxClMlDsa_NTT_MontgomeryReduce((int64_t) MCUXCLMLDSA_F * *pACur));
    *pACur++ = res;
    MCUX_CSSL_FP_LOOP_ITERATION(loop4, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_MontgomeryReduce));
  }

  /* We go backwards, but the first zeta is unused */
  MCUX_CSSL_DI_EXPUNGE(forwardNttZetas, (uintptr_t) pZeta - sizeof(uint32_t));
  MCUX_CSSL_DI_EXPUNGE(forwardNttCoeffs, (uintptr_t) pA->coefficients * MCUXCLMLDSA_LOG2_N);
  MCUX_CSSL_DI_EXPUNGE(forwardNttA, (uintptr_t) pACur - sizeof(uint32_t) * MCUXCLMLDSA_N); /* final loop */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_InverseNTTToMont,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, MCUXCLMLDSA_LOG2_N),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop4, MCUXCLMLDSA_N)
  );
}

/**
 * @brief
 * Multiplication in the NTT domain and division by 2^{32}.
 *
 * Performs pointwise multiplication of polynomials in the NTT
 * domain representation and multiplies the resulting polynomial
 * by 2^{-32}.
 *
 * @param[out] pC Pointer to output polynomial.
 * @param[in] pA Pointer to first input polynomial.
 * @param[in] pB Pointer to second input polynomial.
 *
 * @pre
 * Both pA and pB are already in the NTT domain.
 *
 * @post
 * pC is the pointwise multiplication of pA and pB, divided by 2^{32}.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_PointwiseMontgomery)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_PointwiseMontgomery(
  mcuxClMlDsa_Poly_t* const pC,
  const mcuxClMlDsa_Poly_t* const pA,
  const mcuxClMlDsa_Poly_t* const pB
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_PointwiseMontgomery);
  MCUX_CSSL_DI_RECORD(polyPointWiseMontA, (uintptr_t) pA);
  MCUX_CSSL_DI_RECORD(polyPointWiseMontB, (uintptr_t) pB);
  MCUX_CSSL_DI_RECORD(polyPointWiseMontC, (uintptr_t) pC);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pA->coefficients and pB->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t* pACur = pA->coefficients;
  const int32_t* pBCur = pB->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  int32_t* pCCur = pC->coefficients;

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for (uint16_t i = 0U; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("An overflow in pointer arithmetic on pACur/pBCur/pCCur would mean an invalid address in ROM")
    MCUX_CSSL_FP_FUNCTION_CALL(int32_t, res,
      mcuxClMlDsa_NTT_MontgomeryReduce(((int64_t)*pACur++) * (*pBCur++)));
    *pCCur++ = res;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_MontgomeryReduce)
    );
  }

  MCUX_CSSL_DI_EXPUNGE(polyPointWiseMontA, (uintptr_t)pACur - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyPointWiseMontB, (uintptr_t)pBCur - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyPointWiseMontC, (uintptr_t)pCCur - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N)
  );
}
