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
 * @file mcuxClMlDsa_Poly.c
 * @brief Implementing polynomial arithmetic in @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClCore_Macros.h>
#include <mcuxClMlDsa.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxClBuffer.h>

#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClXof_Internal.h>

/**
 * @brief
 * Center a 32-bit finite field element around 0.
 *
 * For finite field element a with a <= 2^{31} - 2^{22} - 1,
 * compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
 *
 * @param[in]       a               Input finite field element
 *
 * @return Returns the reduced value r between -6283009 and 6283007.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Reduce_Coefficient)
static MCUX_CSSL_FP_PROTECTED_TYPE(int32_t) mcuxClMlDsa_Poly_Reduce_Coefficient(const int32_t a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Reduce_Coefficient);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a, 0, INT32_MAX - 0x400000, 0) /* 0x400000 == 1 << 22 */

  int32_t t = 0;
  MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  t = mcuxClMlDsa_SSHR32((a + ((int32_t)1 << 22)), 23U);
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(t, 0, INT32_MAX >> 23, 0)
  t = a - t * (int32_t) MCUXCLMLDSA_Q;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_Reduce_Coefficient, t);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Reduce
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283009,6283007].
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a: pointer to input/output polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Reduce(mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Reduce);
  MCUX_CSSL_DI_RECORD(polyReduceA, (uintptr_t)a);
  int32_t *pA = a->coefficients;

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("polynomials have MCUXCLMLDSA_N coefficients, won't overflow")
    MCUX_CSSL_FP_FUNCTION_CALL(int32_t, result, mcuxClMlDsa_Poly_Reduce_Coefficient(*pA));
    *pA++ = result;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Reduce_Coefficient));
  }

  MCUX_CSSL_DI_EXPUNGE(polyReduceA, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Reduce, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Caddq
 *
 * Description: For all coefficients of in/out polynomial add Q if
 *              coefficient is negative.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a: pointer to input/output polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Caddq)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Caddq(mcuxClMlDsa_Poly_t *a)
{
  /* Initialize function */
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Caddq);
  MCUX_CSSL_DI_RECORD(polyCaddQParams, (uintptr_t)a);
  int32_t *pA = a->coefficients;

  /* Initialize for-loop FP */
  MCUX_CSSL_FP_LOOP_DECL(loop);

  /* Update each coefficient one by one */
  for (uint16_t i = 0U; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
    /* Check that the coefficients of a are between -Q and Q */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pA won't overflow, within bounds of a valid polynomial in memory")
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(*pA, -(int32_t) MCUXCLMLDSA_Q, (int32_t) MCUXCLMLDSA_Q)

    /* Add q to negative coefficients, using twos complement format */
    MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
    *pA += mcuxClMlDsa_SSHR32(*pA, 31U) & (int32_t) MCUXCLMLDSA_Q;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()

    pA++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    /* Update for-loop FP */
    MCUX_CSSL_FP_LOOP_ITERATION(loop);
  }

  MCUX_CSSL_DI_EXPUNGE(polyCaddQParams, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);

  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Caddq,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to output polynomial
 *              - const mcuxClMlDsa_Poly_t *a: pointer to first summand
 *              - const mcuxClMlDsa_Poly_t *b: pointer to second summand
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Add)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Add(mcuxClMlDsa_Poly_t *c, const mcuxClMlDsa_Poly_t *a, const mcuxClMlDsa_Poly_t *b)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Add);
  MCUX_CSSL_DI_RECORD(polyAddA, (uintptr_t)a);
  MCUX_CSSL_DI_RECORD(polyAddB, (uintptr_t)b);
  MCUX_CSSL_DI_RECORD(polyAddC, (uintptr_t)c);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pA = a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pB = b->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  int32_t *pC = c->coefficients;

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pC);
    MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
    MCUX_CSSL_DI_DONOTOPTIMIZE(pB);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("wont overflow, polynomials are already allocated")
    *pC++ = (*pA++) + (*pB++);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop);
  }

  MCUX_CSSL_DI_EXPUNGE(polyAddA, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyAddB, (uintptr_t)pB - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyAddC, (uintptr_t)pC - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Add, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to output polynomial
 *              - const mcuxClMlDsa_Poly_t *a: pointer to first input polynomial
 *              - const mcuxClMlDsa_Poly_t *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Sub)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Sub(mcuxClMlDsa_Poly_t *c, const mcuxClMlDsa_Poly_t *a, const mcuxClMlDsa_Poly_t *b)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Sub);
  MCUX_CSSL_DI_RECORD(polySubA, (uintptr_t)a);
  MCUX_CSSL_DI_RECORD(polySubB, (uintptr_t)b);
  MCUX_CSSL_DI_RECORD(polySubC, (uintptr_t)c);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pA = a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pB = b->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  int32_t *pC = c->coefficients;

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pC);
    MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
    MCUX_CSSL_DI_DONOTOPTIMIZE(pB);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pA, pB and pC pointers stay within bound of a polynomial, won't overflow")
    *pC++ = (*pA++) - (*pB++);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop);
  }

  MCUX_CSSL_DI_EXPUNGE(polySubA, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polySubB, (uintptr_t)pB - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polySubC, (uintptr_t)pC - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Sub, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Shiftl
 *
 * Description: Multiply polynomial by 2^D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-D} in absolute value.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a: pointer to input/output polynomial
 *
 * Data Integrity: Expunge(a)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Shiftl)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Shiftl(mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Shiftl);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pA are 32 bit aligned")
  uint32_t *pA = (uint32_t *)a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will stay within polynomial bounds")
    *pA <<= MCUXCLMLDSA_D;
    pA++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop);
  }

  MCUX_CSSL_DI_EXPUNGE(polyShift1A, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Shiftl, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Power2Round_Coefficient
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 *              Assumes a to be standard representative.
 *
 * Arguments:   - int32_t a: input element
 *              - int32_t *a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Power2Round_Coefficient)
static MCUX_CSSL_FP_PROTECTED_TYPE(int32_t) mcuxClMlDsa_Poly_Power2Round_Coefficient(int32_t *a0, const int32_t a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Power2Round_Coefficient);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a, INT32_MIN, INT32_MAX - (int32_t)MCUXCLMLDSA_SHL_MLDSA_D, 0)
  int32_t a1 = a + (int32_t) MCUXCLMLDSA_SHL_MLDSA_D - 1;
  a1 = mcuxClMlDsa_SSHR32(a1, MCUXCLMLDSA_D);
  MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER((int64_t) a - ((int64_t)(a1) << MCUXCLMLDSA_D), INT32_MIN, INT32_MAX, 0)
  *a0 = a - (a1 << MCUXCLMLDSA_D);
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_Power2Round_Coefficient, a1);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Power2Round
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute c0, c1 such that c mod Q = c1*2^D + c0
 *              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a1: pointer to output polynomial with coefficients c1
 *              - mcuxClMlDsa_Poly_t *a0: pointer to output polynomial with coefficients c0
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Power2Round)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Power2Round(
  mcuxClMlDsa_Poly_t *a1,
  mcuxClMlDsa_Poly_t *a0,
  const mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Power2Round);
  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(int32_t, coefficient, mcuxClMlDsa_Poly_Power2Round_Coefficient(&a0->coefficients[i], a->coefficients[i]));
    MCUX_CSSL_FP_LOOP_ITERATION(loop, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Power2Round_Coefficient));
    a1->coefficients[i] = coefficient;
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Power2Round, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Decompose_Coefficient
 *
 * Description: For finite field element a, compute high and low bits a0, a1 such
 *              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
 *              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
 *              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
 *              representative.
 *
 * Arguments:   - Session
                - const int32_t a: input element
 *              - int32_t *a0: pointer to output element a0
 *              - int32_t *a1: pointer to output element a1
 *              - const mcuxClMlDsa_Params_t* const params: pointer to ML-DSA parameter set structure
 *
 * Returns void
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Decompose_Coefficient)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Decompose_Coefficient(
  mcuxClSession_Handle_t session,
  int32_t *a0,
  int32_t *a1,
  const int32_t a,
  const mcuxClMlDsa_Params_t* const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Decompose_Coefficient);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(a, -(int32_t) MCUXCLMLDSA_Q, (int32_t) MCUXCLMLDSA_Q)

  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(params->gamma2, MCUXCLMLDSA_MLDSA44_GAMMA2, MCUXCLMLDSA_MLDSA87_GAMMA2)
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pA1 are 32 bit aligned")
  uint32_t* pA1 = (uint32_t*)a1;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  *a1  = mcuxClMlDsa_SSHR32((a + 127), 7U);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(*a1, (-(int32_t) MCUXCLMLDSA_Q + 127) >> 7U, ((int32_t) MCUXCLMLDSA_Q + 127) >> 7)
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pA1[0], 0u, (uint32_t) MCUXCLMLDSA_Q)
  if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)
  {
    pA1[0] = ((pA1[0] * 11275u + ((uint32_t)1u << 23u)) >> 24u);
    MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
    *a1 ^= mcuxClMlDsa_SSHR32((43 - *a1), 31U) & *a1;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  }
  else if((MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2) /* || ((MCUXCLMLDSA_MLDSA87_GAMMA2 == params->gamma2)) */)
  {
    pA1[0] = ((pA1[0] * 1025u + ((uint32_t)1u << 21u)) >> 22u);
    pA1[0] = pA1[0] & 15u;
  }
  else
  {
    /* fault attack, return asap */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(*a1, -(int32_t) MCUXCLMLDSA_Q, (int32_t) MCUXCLMLDSA_Q)
  *a0  = a - *a1*2*(int32_t)params->gamma2;
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(*a0, -(int32_t) MCUXCLMLDSA_Q, (int32_t) MCUXCLMLDSA_Q)
  MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
  *a0 -= (mcuxClMlDsa_SSHR32((((int32_t) MCUXCLMLDSA_Q - 1) / 2 - *a0), 31U)) & (int32_t) MCUXCLMLDSA_Q;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Decompose_Coefficient);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Decompose
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
 *              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
 *              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - Session
                - mcuxClMlDsa_Poly_t *a1: pointer to output polynomial with coefficients c1
 *              - mcuxClMlDsa_Poly_t *a0: pointer to output polynomial with coefficients c0
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t* const params: pointer to ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Decompose)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Decompose(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *a1,
  mcuxClMlDsa_Poly_t *a0,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t* const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Decompose);
  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_FP_LOOP_ITERATION(loop, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Decompose_Coefficient));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Decompose_Coefficient(
      session,
      &a0->coefficients[i],
      &a1->coefficients[i],
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      a->coefficients[i],
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      params
    ));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Decompose, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_UseHint_Coefficient
 *
 * Description: Correct high bits according to hint.
 *
 * Arguments:   - Session
                - const int32_t a: input element
 *              - int32_t *b: pointer to output element
 *              - const uint16_t hint: hint bit
 *              - const mcuxClMlDsa_Params_t* const params: pointer to ML-DSA parameter set structure
 *
 * Returns corrected high bits.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_UseHint_Coefficient)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UseHint_Coefficient(
  mcuxClSession_Handle_t session,
  int32_t *b,
  const int32_t a,
  const uint16_t hint,
  const mcuxClMlDsa_Params_t* const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_UseHint_Coefficient);
  int32_t a0 = 0;
  int32_t a1 = 0;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pB are 32 bit aligned")
  uint32_t* pB = (uint32_t *)b;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_Decompose_Coefficient(session, &a0, &a1, a, params));

  if(hint == 0u)
  {
    *b = a1;
  }
  else if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)
  {
    if(a0 > 0)
    {
      *b = ((a1 == 43) ? 0 : a1 + 1);
    }
    else
    {
      *b = ((a1 == 0) ? 43 : a1 - 1);
    }
  }
  else if((MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2) /* || (MCUXCLMLDSA_MLDSA87_GAMMA2 == params->gamma2) */)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will not overflow because high bits are in [0, floor(q/2^d)]")
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(a1, 0,  (int32_t)MCUXCLMLDSA_Q / (2 * (int32_t)params->gamma2))
    if(a0 > 0)
    {
      pB[0] = ((uint32_t)a1 + 1u) & 15u;
    }
    else
    {
      pB[0] = ((uint32_t)a1 - 1u) & 15u;
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  }
  else
  {
    // do nothing, just Misra balance
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_UseHint_Coefficient,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_Decompose_Coefficient));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_UseHint
 *
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 *
 * Arguments:   - Session
                - mcuxClMlDsa_Poly_t *pB: pointer to output polynomial with corrected high bits
 *              - const mcuxClMlDsa_Poly_t *pA: pointer to input polynomial
 *              - const mcuxClMlDsa_Poly_t *pH: pointer to input hint polynomial
 *              - const mcuxClMlDsa_Params_t* const pParams: pointer to ML-DSA parameter set structure
 *
 * Data Integrity: Expunge(pB + pA + pH + pParams)
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_UseHint)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UseHint(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *pB,
  const mcuxClMlDsa_Poly_t *pA,
  const mcuxClMlDsa_Poly_t *pH,
  const mcuxClMlDsa_Params_t *const pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_UseHint);

  int32_t *b = pB->coefficients;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pA->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *a = pA->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *h = pH->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_FP_LOOP_DECL(loop);
  for(uint16_t i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(b);
    MCUX_CSSL_DI_DONOTOPTIMIZE(a);
    MCUX_CSSL_DI_DONOTOPTIMIZE(h);
    MCUX_CSSL_FP_LOOP_ITERATION(loop, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_UseHint_Coefficient));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("a, b and h are of type mcuxClMlDsa_Poly_t and therefore have MCUXCLMLDSA_N coefficients")
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(*h, 0, 1)
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_UseHint_Coefficient(session, b, *a, (uint16_t)(*h), pParams));
    b++;
    a++;
    h++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  }

  MCUX_CSSL_DI_EXPUNGE(polyUseHintB, (uintptr_t)b - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyUseHintA, (uintptr_t)a - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyUseHintH, (uintptr_t)h - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyUseHintpParams, pParams);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_UseHint, MCUX_CSSL_FP_LOOP_ITERATIONS(loop, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_CheckNorm
 *
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input coefficients were reduced by mcuxClMlDsa_Poly_Reduce_Coefficient().
 *
 * Arguments:   - Session
 *              - const mcuxClMlDsa_Poly_t *a: pointer to polynomial
 *              - int32_t B: norm bound
 *
 * Data Integrity: Expunge(a + B)
 *
 * Returns MCUXCLSIGNATURE_STATUS_NOT_OK if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 **************************************************/
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_CheckNorm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Poly_CheckNorm(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Poly_t *a,
  const int32_t B)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_CheckNorm);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pA = a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  uint16_t i;
  int32_t t = 0;

  /* Additional counter keeping track if absolute values are ok. */
  uint32_t check = 0u;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(i = 0u; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pA won't overflow because it has MCUXCLMLDSA_N coefficients")
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pA, -6283009, 6283007, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK)
    /* Absolute value */
    t = mcuxClMlDsa_SSHR32(*pA, 31U);
    MCUX_CSSL_ANALYSIS_START_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()
    t = *pA - (t & 2 * (*pA));
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_TWOS_COMPLEMENT_REPRESENTATION()

    /* When returning OK this should always be zero */
    check |= ((uint32_t)(t >= B) << (i % 32u));

    if(B <= t)
    {
      /* DI balance this early exit since it can lead to a normal satus, e.g., during signing */
      MCUX_CSSL_DI_EXPUNGE(polyCheckNormPtr, (uintptr_t)pA - (4U * (uint32_t)i));
      MCUX_CSSL_DI_EXPUNGE(polyCheckNormBound, (uint32_t)B);
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_CheckNorm, MCUXCLSIGNATURE_STATUS_NOT_OK,
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, i));
    }

    pA++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  /* When we reach here check should always be zero: if not, FA occurred. */
  if(0U != check)
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_DI_EXPUNGE(polyCheckNormPtr, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyCheckNormBound, (uint32_t)B);
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_CheckNorm, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLDSA_N));
}

/**
 * @brief ML-DSA sample coefficients in [0, Q-1] (with rejection sampling)
 *
 * Sample uniformly random coefficients in [0, Q-1] by
 * performing rejection sampling on array of random bytes.
 *
 * @param[out]      a               Pointer to output array
 * @param[in]       len             Number of coefficients to be sampled
 * @param[in]       buf             Pointer to buf array of random bytes
 * @param[in]       buflen          Length of array of random bytes
 *
 * @return Returns the number of sampled coefficients. Can be smaller than len
 * if not enough random bytes were given.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_RejUniform)
static MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClMlDsa_Poly_RejUniform(int32_t *a, const uint16_t len, const uint8_t *buf, const uint16_t buflen)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_RejUniform);

  uint32_t t = 0u;
  uint16_t ctr = 0U;
  uint16_t pos = 0U;
  while (ctr < len && pos + 3U <= buflen)
  {
    t  = buf[pos++];
    t |= (uint32_t) buf[pos++] << 8U;
    t |= (uint32_t) buf[pos++] << 16U;
    t &= 0x7FFFFFU;

    if (t < MCUXCLMLDSA_Q)
    {
      a[ctr++] = (int32_t)t;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_RejUniform, ctr);
}


/*******************************************************************************
 * Name:        mcuxClMlDsa_Poly_MatrixMultiplyAccumulate                   *
 *                                                                             *
 * Description: Perform a single polynomial multiplication between a public    *
 *              matrix element at certain index (determined by nonce), and a   *
 *              secret key element s1. The matrix element is generated         *
 *              coefficient-wise from seed and multiplied on-the-fly to avoid  *
 *              storing the whole polynomial in memory. The result is          *
 *              accumulated to a                                               *
 *                                                                             *
 * Arguments:   - a:          pointer to output polynomial (can equal s1)      *
 *              - s1:         pointer to input polynomial                      *
 *              - seed:       pointer to input seed                            *
 *                            (of length MCUXCLMLDSA_SEEDBYTES bytes)      *
 *              - nonce:      index of matrix element                          *
 *              - buf:        ...                                              *
 *              - session:    ...                                              *
 *              - pXofContext: ...                                             *
 ******************************************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_MatrixMultiplyAccumulate(
  mcuxClMlDsa_Poly_t *a,
  mcuxClMlDsa_Poly_t *s1,
  const uint8_t *seed,
  uint16_t nonce,
  uint8_t *buf,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate);
  MCUX_CSSL_DI_RECORD(polyMatAccA, (uintptr_t)a);
  MCUX_CSSL_DI_RECORD(polyMatAccS1, (uintptr_t)s1);
  int32_t *pA = a->coefficients;
  int32_t *pS1 = s1->coefficients;

  MCUXCLBUFFER_INIT_RO(seedBuf, NULL, seed, MCUXCLMLDSA_SEEDBYTES);
  MCUXCLBUFFER_INIT_RO(nonceBuf, NULL, (uint8_t*) &nonce, sizeof(nonce));
  MCUXCLBUFFER_INIT(outBuf, NULL, buf, MCUXCLMLDSA_SHAKE128_RATE);

  /* Initialize shake context pXofContext */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pXofContext,
                                                        mcuxClXof_Algorithm_Shake_128,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                        NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                        0U));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_SEEDBYTES);
  /* Absorb the seed into the shake context */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           seedBuf,
                                                           MCUXCLMLDSA_SEEDBYTES));

   /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, nonceBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, 2U);
  /* Absorb the nonce into the shake context */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           nonceBuf,
                                                           2U));


  /* Check of functions called up to this point */
  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  int32_t t = 0;
  uint16_t numberOfSampledCoeffs;
  uint16_t ctr = 0U;
  while (ctr < MCUXCLMLDSA_N)
  {
    /* Balance DI for mcuxClXof_generate_internal() */
    MCUX_CSSL_DI_RECORD(xofGenerateParams, outBuf);
    MCUX_CSSL_DI_RECORD(xofGenerateParams, MCUXCLMLDSA_SHAKE128_RATE);
    /* Squeeze shake context into buf */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                              pXofContext,
                                                              outBuf,
                                                              (uint32_t) MCUXCLMLDSA_SHAKE128_RATE));

    /* Check of functions called up to this point */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));

    /* Go through buffer 3 bytes at a time */
    for (uint16_t j = 0U; j + 2U < MCUXCLMLDSA_SHAKE128_RATE; j = j + 3U)
    {
      MCUX_CSSL_DI_DONOTOPTIMIZE(pA);
      MCUX_CSSL_DI_DONOTOPTIMIZE(pS1);
      if (ctr >= MCUXCLMLDSA_N)
      {
        break;
      }
      /* Sample max 1 element from 3 bytes */
      MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, result, mcuxClMlDsa_Poly_RejUniform(&t, 1U, buf + j, 3U));
      numberOfSampledCoeffs = result;
      if (0U != numberOfSampledCoeffs) /* Multiply if element is not rejected */
      {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("these pointers won't overflow because we increment them at most MCUXCLMLDSA_N - 1 times")
        MCUX_CSSL_FP_FUNCTION_CALL(int32_t, res, mcuxClMlDsa_NTT_MontgomeryReduce((int64_t)t * *pS1));
        *pA += res;
        pA++;
        pS1++;
        ctr++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      }
      MCUX_CSSL_FP_EXPECT(
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_RejUniform),
         MCUX_CSSL_FP_CONDITIONAL(0U != numberOfSampledCoeffs, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_MontgomeryReduce)));
    }
  }

  MCUX_CSSL_DI_EXPUNGE(polyMattAccA, (uintptr_t)pA - MCUXCLMLDSA_POLY_SIZE);
  MCUX_CSSL_DI_EXPUNGE(polyMattAccS1, (uintptr_t)pS1 - MCUXCLMLDSA_POLY_SIZE);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate);
}

/**
 * @brief ML-DSA sample random values in [-eta, eta]
 *
 * Sample uniformly random coefficients in [-eta, eta] by performing
 * rejection sampling on array of random bytes.
 * Returns the number of sampled coefficients in ctr, which can be smaller
 * than len if not enough random bytes were given.
 *
 * @param[in]       session         Session handle
 * @param[out]      a               Pointer to output array
 * @param[out]      ctr             Pointer to the number of sampled coefficients
 * @param[in]       len             Number of coefficients to be sampled
 * @param[in]       buf             Pointer to buf array of random bytes
 * @param[in]       buflen          Length of array of random bytes
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_RejEta)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_RejEta(
  mcuxClSession_Handle_t session,
  int32_t *a,
  uint16_t *ctr,
  const uint16_t len,
  const uint8_t *buf,
  const uint16_t buflen,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_RejEta);
  uint16_t pos = 0u;
  uint32_t t0, t1;

  *ctr = 0u;
  if(params->eta == 2u)
  {
    while(*ctr < len && pos < buflen)
    {
      t0 = (uint32_t)buf[pos] & 0x0Fu;
      t1 = ((uint32_t)buf[pos++] >> 4u);

      if(t0 < 15u)
      {
        t0 = t0 - (205u * t0 >> 10u) * 5u;
        a[(*ctr)++] = 2 - (int32_t)t0;
      }
      if(t1 < 15u && *ctr < len)
      {
        t1 = t1 - (205u * t1 >> 10u) * 5u;
        a[(*ctr)++] = 2 - (int32_t)t1;
      }
    }
  }
  else if(params->eta == 4u)
  {
    while(*ctr < len && pos < buflen)
    {
      t0 = (uint32_t)buf[pos] & 0x0Fu;
      t1 = ((uint32_t)buf[pos++] >> 4u);

      if(t0 < 9u)
      {
        a[(*ctr)++] = 4 - (int32_t)t0;
      }
      if(t1 < 9u && *ctr < len)
      {
        a[(*ctr)++] = 4 - (int32_t)t1;
      }
    }
  }
  else
  {
    /* fault attack */
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_RejEta);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_UniformEta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-ETA,ETA] by performing rejection sampling on the
 *              output stream from SHAKE256(seed|nonce).
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a: pointer to output polynomial
 *              - const uint8_t seed[]: byte array with seed of length CRHBYTES
 *              - uint16_t nonce: 2-byte nonce
 *              - const mcuxClMlDsa_Params_t* params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_UniformEta)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UniformEta(
  mcuxClMlDsa_Poly_t *a,
  const uint8_t *seed,
  uint16_t nonce,
  uint8_t *buf,
  const mcuxClMlDsa_Params_t *params,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_UniformEta);

  MCUXCLBUFFER_INIT_RO(seedBuf, NULL, seed, MCUXCLMLDSA_CRHBYTES);
  MCUXCLBUFFER_INIT_RO(nonceBuf, NULL, (uint8_t*) &nonce, sizeof(nonce));
  MCUXCLBUFFER_INIT(outBuf, NULL, buf, MCUXCLMLDSA_SHAKE256_RATE);

  /* Initialize shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pXofContext,
                                                        mcuxClXof_Algorithm_Shake_256,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                        NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                        0U));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  /* Absorb seed into the shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           seedBuf,
                                                           MCUXCLMLDSA_CRHBYTES));


  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, nonceBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, 2U);
  /* Absorb nonce into the shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           nonceBuf,
                                                           2U));

  MCUX_CSSL_FP_EXPECT(
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  uint16_t ctr = 0U, tctr;
  while (ctr < MCUXCLMLDSA_N)
  {
    /* Balance DI for mcuxClXof_generate_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, outBuf);
    MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_SHAKE256_RATE);
    /* Squeeze shake into buf */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                              pXofContext,
                                                              outBuf,
                                                              MCUXCLMLDSA_SHAKE256_RATE));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Poly_RejEta(session,
                                                          a->coefficients + ctr,
                                                          &tctr,
                                                          MCUXCLMLDSA_N - ctr,
                                                          buf,
                                                          MCUXCLMLDSA_SHAKE256_RATE,
                                                          params));
    ctr += tctr;
    MCUX_CSSL_FP_EXPECT(
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Poly_RejEta));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_UniformEta);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_UniformGamma1
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
 *              of SHAKE256(seed|nonce).
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a: pointer to output polynomial
 *              - const uint8_t seed[]: byte array with seed of length CRHBYTES
 *              - uint16_t nonce: 16-bit nonce
 *              - buf: ...
 *              - const mcuxClMlDsa_Params_t* params: ML-DSA parameter set structure
 *              - session: ...
 *              - pXofContext: ...
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_UniformGamma1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UniformGamma1(
  mcuxClMlDsa_Poly_t *a,
  const uint8_t *seed,
  uint16_t nonce,
  uint8_t *buf,
  const mcuxClMlDsa_Params_t *params,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_UniformGamma1);
  uint16_t i, j, off, ctr = 0U;
  uint16_t buflen = 0U;
  uint16_t UNPACK_BLOCK_SIZE;

  MCUXCLBUFFER_INIT_RO(seedBuf, NULL, seed, MCUXCLMLDSA_CRHBYTES);
  MCUXCLBUFFER_INIT_RO(nonceBuf, NULL, (uint8_t*) &nonce, sizeof(nonce));

  if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2: 1 << 17 */
  {
    UNPACK_BLOCK_SIZE = 9U;
  }
  else if (MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5: 1 << 19 */
  {
    UNPACK_BLOCK_SIZE = 5U;
  }
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  /* Initialize shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pXofContext,
                                                        mcuxClXof_Algorithm_Shake_256,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                        NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                        0U));

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_CRHBYTES);
  /* Absorb seed into shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           seedBuf,
                                                           MCUXCLMLDSA_CRHBYTES));


  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, nonceBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, 2U);
  /* Absorb nonce into shake state */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           nonceBuf,
                                                           2U));

  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal));

  while (ctr < MCUXCLMLDSA_N)
  {
    /* Take remaining bytes from previous buffer */
    off = buflen % UNPACK_BLOCK_SIZE;
    for (i = 0U; i < off; ++i)
    {
      buf[i] = buf[buflen - off + i];
    }

    MCUXCLBUFFER_INIT(pOutOffBuf, NULL, buf + off, MCUXCLMLDSA_SHAKE256_RATE);
    /* Balance DI for mcuxClXof_generate_internal() */
    MCUX_CSSL_DI_RECORD(xofProcessParams, pOutOffBuf);
    MCUX_CSSL_DI_RECORD(xofProcessParams, MCUXCLMLDSA_SHAKE256_RATE);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session, pXofContext, pOutOffBuf, MCUXCLMLDSA_SHAKE256_RATE));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_SIGNED_TO_UNSIGNED_MAY_RESULT_TO_MISINTERPRETED_DATA("MCUXCLMLDSA_SHAKE256_RATE is defined as 136U, no data lost. ")
    buflen = (uint16_t)MCUXCLMLDSA_SHAKE256_RATE + off;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_SIGNED_TO_UNSIGNED_MAY_RESULT_TO_MISINTERPRETED_DATA()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));

    if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2: 1 << 17 */
    {
      /* Go through buffer UNPACK_BLOCK_SIZE bytes at a time */
      for (j = 0U; j + UNPACK_BLOCK_SIZE - 1U < buflen; j = j + UNPACK_BLOCK_SIZE)
      {
        if (ctr >= MCUXCLMLDSA_N)
        {
          break;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_17(a->coefficients + ctr, buf + j));
        ctr += 4U;
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_17));
      }
    }
    else if (MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5: 1 << 19 */
    {
      /* Go through buffer UNPACK_BLOCK_SIZE bytes at a time */
      for (j = 0u; j + UNPACK_BLOCK_SIZE - 1U < buflen; j = j + UNPACK_BLOCK_SIZE)
      {
        if (ctr >= MCUXCLMLDSA_N)
        {
          break;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_19(a->coefficients + ctr, buf + j));
        ctr += 2U;
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_19));
      }
    }
    else
    {
      MCUXCLSESSION_FAULT(session, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_UniformGamma1);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_MakeHint
 *
 * Description: Compute hint bit indicating whether the low bits of the
 *              input element overflow into the high bits.
 *
 * Arguments:   - int32_t a0: low bits of input element
 *              - int32_t a1: high bits of input element
 *              - const mcuxClMlDsa_Params_t* const params: pointer to ML-DSA parameter set structure
 *
 * Returns 1 if overflow.
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_MakeHint)
MCUX_CSSL_FP_PROTECTED_TYPE(uint8_t) mcuxClMlDsa_Poly_MakeHint(int32_t a0, int32_t a1, const mcuxClMlDsa_Params_t* const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_MakeHint);
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(params->gamma2, MCUXCLMLDSA_MLDSA44_GAMMA2, MCUXCLMLDSA_MLDSA87_GAMMA2, 0);
  if(a0 > (int32_t)params->gamma2 || a0 < -(int32_t)params->gamma2 || (a0 == -(int32_t)params->gamma2 && a1 != 0))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_MakeHint, 1u);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Poly_MakeHint, 0u);
}

/*************************************************
 * Name:        mcuxClMlDsa_Poly_Challenge
 *
 * Description: Implementation of H. Samples polynomial with TAU nonzero
 *              coefficients in {-1,1} using the output stream of
 *              SHAKE256(seed).
 *
 * Arguments:   - mcuxClSession_Handle_t session:    session handle
 *              - mcuxClXof_Context_t pXofContext:   pointer to a SHAKE256 context.
 *              - mcuxClMlDsa_Poly_t* c:             output challenge polynomial.
 *              - uint8_t* seed:                    public seed.
 *              - uint8_t* buf:                     shake output buffer.
 *              - mcuxClMlDsa_Params_t* params:      parameters.
 *              - uint8_t negated:                  boolean indicating whether to output c negated.
 *
 * Data Integrity: Expunge(c + seedBuf + pParams)
 *
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Poly_Challenge)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Challenge(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext,
  mcuxClMlDsa_Poly_t* const c,
  mcuxCl_InputBuffer_t seedBuf,
  uint8_t* const buf,
  const mcuxClMlDsa_Params_t* const params,
  const uint8_t negated)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Poly_Challenge);

  /* Balance DI for mcuxClXof_process_internal() */
  MCUX_CSSL_DI_RECORD(xofProcessParams, seedBuf);
  MCUX_CSSL_DI_RECORD(xofProcessParams, params->cTildeSize);

  const uint32_t halfShake256Rate = (uint32_t) MCUXCLMLDSA_SHAKE256_RATE / 2U;
  MCUXCLBUFFER_INIT(outBuf1, NULL, buf, halfShake256Rate);
  MCUXCLBUFFER_INIT(outBuf2, NULL, buf + halfShake256Rate, halfShake256Rate);

  /* Balance DI for two-pass mcuxClXof_generate_internal() */
  MCUX_CSSL_DI_RECORD(xofGenerateParams, outBuf1);
  MCUX_CSSL_DI_RECORD(xofGenerateParams, halfShake256Rate);
  MCUX_CSSL_DI_RECORD(xofGenerateParams, outBuf2);
  MCUX_CSSL_DI_RECORD(xofGenerateParams, halfShake256Rate);

  /* Perform an initialization of a shake context */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_init_internal(session,
                                                        pXofContext,
                                                        mcuxClXof_Algorithm_Shake_256,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL pointer is unused because the length is 0")
                                                        NULL,
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                        0U));
  /* Absorb the seed into the shake context */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_process_internal(session,
                                                           pXofContext,
                                                           seedBuf,
                                                           (uint32_t)params->cTildeSize));

  /* Squeeze the shake context into buf in two passes (for increased security) */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                            pXofContext,
                                                            outBuf1,
                                                            halfShake256Rate));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                            pXofContext,
                                                            outBuf2,
                                                            halfShake256Rate));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NESTED_COMMENTS("Links are allowed in comments.")
  /*****************************
   * Begin SampleInBall(rho), aka inside-out version of Fisher-Yates shuffle
   * See https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf, page 10
   ****************************/
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NESTED_COMMENTS()

  /* Initialize a table of signs for the challenge entries */
  uint8_t signs[8U];
  MCUX_CSSL_DI_RECORD(signsTable, (uintptr_t)signs);
  MCUX_CSSL_DI_RECORD(bufTable, (uintptr_t)buf);
  MCUX_CSSL_DI_RECORD(bufTableSize, 8U);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(signs, buf, 8U));

  /* Initialize variables for the SampleInBall algorithm */
  uint16_t b = 0U;
  uint8_t j = 0U;

  /* Skip the first 8 bytes of buf as they were used for the signs above */
  uint16_t pos = 8U;

  /* Initialize challenge vector to all zeros, and balance memory calls accordingly */
  MCUX_CSSL_DI_RECORD(memClearChallengeDst, (uint8_t*) c->coefficients);
  MCUX_CSSL_DI_RECORD(memClearChallengeLen, MCUXCLMLDSA_POLY_SIZE);
  MCUXCLMEMORY_CLEAR_INT((uint8_t *)c->coefficients, MCUXCLMLDSA_POLY_SIZE);

  /* Loop over i from 256 - tau up to 255 */
  /* Note: 39 <= tau <= 60 (depending on security level) so 196 <= i <= 255 */
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for (uint16_t i = MCUXCLMLDSA_N - params->tau; i < MCUXCLMLDSA_N; ++i)
  {
    MCUX_CSSL_FP_BRANCH_DECL(bByteCheckBranch);

    /* The following loop is to sample one uniformly random element b in {0, 1, ..., i} */
    do
    {
      /* If we used up all of the squeezed bytes for random sampling,
         generate a new batch of MCUXCLMLDSA_SHAKE256_RATE bytes */
      if (pos >= MCUXCLMLDSA_SHAKE256_RATE)
      {
        /**
         * To get here, we must have sampled MCUXCLMLDSA_SHAKE256_RATE numbers
         * uniformly at random between 0 and 255, none of which were below 0 and i,
         * where i is between 256 - tau >= 196 and 255. This is therefore quite a rare
         * event (probability ~ 2^(-50)), but we cover that situation below.
         */

        /* Balance DI for mcuxClXof_generate_internal() */
        MCUX_CSSL_DI_RECORD(xofGenerateParams, outBuf1);
        MCUX_CSSL_DI_RECORD(xofGenerateParams, outBuf2);
        MCUX_CSSL_DI_RECORD(xofGenerateParams, MCUXCLMLDSA_SHAKE256_RATE);
        /* Squeeze additional randomness into buf */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                                  pXofContext,
                                                                  outBuf1,
                                                                  halfShake256Rate));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClXof_generate_internal(session,
                                                                  pXofContext,
                                                                  outBuf2,
                                                                  halfShake256Rate));

        /* Security check about function calls up to this point */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal));

        /* Start from the beginning of this new batch */
        pos = 0U;
      }

      /* Use the next byte to sample a uniformly random element below 2^8 = 256 */
      b = (uint16_t) buf[pos++];
      MCUX_CSSL_DI_RECORD(bByteDI, b);

      /* Use this as our random b in {0, 1, ..., i} if this value is at most i; otherwise try again */
      if (b <= i)
      {
        MCUX_CSSL_FP_BRANCH_POSITIVE(bByteCheckBranch);
        break;
      }
      MCUX_CSSL_DI_EXPUNGE(bByteDI, b);
    } while (true);

    /* Move c[b] to c[i] as in the SampleInBall algorithm */
    c->coefficients[i] = c->coefficients[b];

    /* Take next sign bit s in {0,1} and map it to a challenge entry c[b] in {-1,1} */
    /* Use the mapping 0 --> 1 and 1 --> -1 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Recovering signed numbers which are represented as compressed byte array")
    uint8_t s = (signs[j >> 3U] >> (j & 0x7U)) & (1U); // recover the correct sign bit
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    s ^= negated;
    c->coefficients[b] = 1 - 2 * (int32_t)s;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("wont overflow, have TAU atmost")
    j += 1U;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    MCUX_CSSL_DI_RECORD(polyChallengeTau, (uintptr_t)buf);
    MCUX_CSSL_DI_EXPUNGE(bByteDI, b);
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1, MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(bByteCheckBranch, b <= i));
  }

  /*****************************
   * End SampleInBall(rho)
   ****************************/

  MCUX_CSSL_DI_EXPUNGE(polyChallengeTau, (uint32_t)params->tau * (uintptr_t)buf);
  MCUX_CSSL_DI_EXPUNGE(polyChallengeC, (uintptr_t)c);
  MCUX_CSSL_DI_EXPUNGE(polyChallengeSeed, (uintptr_t)seedBuf);
  MCUX_CSSL_DI_EXPUNGE(polyChallengeParams, (uintptr_t)params);

  /* Exit function */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Poly_Challenge,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init_internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process_internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate_internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int),
                            MCUXCLMEMORY_CLEAR_INT_FP_EXPECT,
                            MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, params->tau));
}
