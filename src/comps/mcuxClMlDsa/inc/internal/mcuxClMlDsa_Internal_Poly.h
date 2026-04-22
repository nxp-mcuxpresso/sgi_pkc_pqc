/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Internal_Poly.h
 * @brief Interface for polynomial arithmetic in @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_POLY_H_
#define MCUXCLMLDSA_INTERNAL_POLY_H_

#include <mcuxClSession_Types.h>     /* mcuxClSession_Handle_t */
#include <mcuxClXof_Types.h>         /* mcuxClXof_Context_t */
#include <mcuxClMlDsa_Types.h>

#include <internal/mcuxClMlDsa_Internal_Types.h>

/**
 * @brief ML-DSA center polynomial coefficients around 0
 *
 * Inplace reduction of all coefficients of input polynomial to
 * representative in [-6283009,6283007] (approx. [-3Q/4, +3Q/4]).
 *
 * @param[in,out]   r               Pointer to input/output polynomial
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Reduce(mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA add Q to negative coefficients of a polynomial
 *
 * For all coefficients of the input/output polynomial a, add Q
 * (in-place) if the corresponding coefficient is negative.
 *
 * @param[in,out]   a               Pointer to input/output polynomial
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Caddq)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Caddq(mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA add/subtract polynomials without modular reduction
 *
 * Add/subtract the two input polynomials a, b to compute the output
 * polynomial c = a +/- b. No modular reduction is performed.
 *
 * @param[out]      c               Pointer to output polynomial c
 * @param[in]       a               Pointer to first input polynomial a
 * @param[in]       b               Pointer to second input polynomial b to be added to/subtracted from a
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Add)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Add(
  mcuxClMlDsa_Poly_t *c,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Poly_t *b);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Sub)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Sub(
  mcuxClMlDsa_Poly_t *c,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Poly_t *b);

/**
 * @brief ML-DSA multiply polynomial with 2^D (shift left)
 *
 * Multiply polynomial (in-place) by 2^D, without modular reduction.
 * Here D=13 is the ML-DSA parameter d.
 * Assumes input coefficients to be less than 2^{31-D} in absolute value.
 *
 * @pre |a[i]| <= 2^{31-D}
 *
 * @param[in,out]   a               Pointer to input/output polynomial
 *
 * Data Integrity: Expunge(a)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Shiftl)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Shiftl(mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA split polynomial into low and high order bits mod Q
 *
 * For all coefficients a of the input polynomial, computes a0, a1
 * such that a mod Q = a1 * 2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 * Here D=13 is the ML-DSA parameter d.
 * Internally makes use of the function mcuxClMlDsa_Poly_Power2Round_Coefficient
 * which does this computation of a single a1 given elements a0, a.
 *
 * @param[out]      a1              Pointer to output polynomial a1
 * @param[out]      a0              Pointer to output polynomial a0
 * @param[in]       a               Pointer to input polynomial a
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Power2Round)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Power2Round(
  mcuxClMlDsa_Poly_t *a1,
  mcuxClMlDsa_Poly_t *a0,
  const mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA polynomial decomposition into low/high bits
 *
 * For all coefficients c of the input polynomial, compute high and low
 * bits c0, c1 such c mod Q = c1 * alpha + c0 with -alpha / 2 < c0 <= alpha / 2
 * except c1 = (Q - 1) / alpha where we set c1 = 0 and
 * -alpha / 2 <= c0 = (c mod Q) - Q < 0.
 * Internally makes use of the function mcuxClMlDsa_Poly_Decompose_Coefficient which
 * does the above computation for a single coefficient.
 *
 * @param[in]       session         Session handle
 * @param[out]      a1              Pointer to output polynomial a1 with coefficients c1
 * @param[out]      a0              Pointer to output polynomial a0 with coefficients c0
 * @param[in]       a               Pointer to input polynomial a with coefficients c
 * @param[in]       params          Pointer to ML-DSA parameter set structure
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Decompose)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Decompose(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *a1,
  mcuxClMlDsa_Poly_t *a0,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t* const params);

/**
 * @brief ML-DSA correct high bits of polynomial using hint
 *
 * Use hint polynomial h to correct the high bits of a polynomial a,
 * and store the corrected polynomial in the output polynomial b.
 * Internally, the outside function mcuxClMlDsa_Poly_UseHint
 * makes use of mcuxClMlDsa_Poly_UseHint_Coefficient to correct high bits
 * of a single element a according to a hint bit hint.
 *
 * @param[in]       session         Session handle
 * @param[out]      pB              Pointer to output polynomial with corrected high bits
 * @param[in]       pA              Pointer to input polynomial
 * @param[in]       pH              Pointer to input hint polynomial
 * @param[in]       pParams         Pointer to ML-DSA parameter set structure
 *
 * @return void
 *
 * Data Integrity: Expunge(pB + pA + pH + pParams)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_UseHint)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UseHint(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *pB,
  const mcuxClMlDsa_Poly_t *pA,
  const mcuxClMlDsa_Poly_t *pH,
  const mcuxClMlDsa_Params_t *const pParams);

/**
 * @brief ML-DSA check polynomial infinity norm against bound
 *
 * Check infinity norm of input polynomial a against given bound B.
 * Assumes input coefficients of a were reduced by mcuxClMlDsa_Poly_Reduce_Coefficient().
 *
 * @pre a[i] has been reduced with mcuxClMlDsa_Poly_Reduce_Coefficient()
 * @pre B <= (Q-1)/8
 *
 * @param[in]       session         Session handle
 * @param[in]       a               Pointer to input polynomial
 * @param[in]       B               Norm bound of at most (Q-1)/8
 *
 * Data Integrity: Expunge(a + B)
 *
 * @return Returns an explicit status code on failure
 *
 * @retval MCUXCLSIGNATURE_STATUS_OK          The norm is strictly smaller than B
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_CheckNorm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Poly_CheckNorm(
  mcuxClSession_Handle_t session,
  const mcuxClMlDsa_Poly_t *a,
  const int32_t B);

/**
 * @brief ML-DSA multiplication of matrix element with key element (and accumulate)
 *
 * Perform a single polynomial multiplication between a public
 * matrix element at certain index (determined by nonce), and a
 * secret key element s1. The matrix element is generated
 * coefficient-wise from seed and multiplied on-the-fly to avoid
 * storing the whole polynomial in memory. The result is
 * accumulated to a.
 *
 * @param[out]      a               Pointer to output polynomial (can equal s1)
 * @param[in]       s1              Pointer to input polynomial
 * @param[in]       seed            Pointer to input seed (of MCUXCLMLDSA_SEEDBYTES bytes)
 * @param[in]       nonce           Index of matrix element
 * @param[in,out]   buf             Pointer to buf array of random bytes
 * @param[in,out]   session         Handle for the current CL session
 * @param[in,out]   pXofContext     Handle for the current Xof context
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_MatrixMultiplyAccumulate)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_MatrixMultiplyAccumulate(
  mcuxClMlDsa_Poly_t *a,
  mcuxClMlDsa_Poly_t *s1,
  const uint8_t* seed,
  uint16_t nonce,
  uint8_t * buf,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext);

/**
 * @brief ML-DSA sample polynomial with uniformly random coefficients bounded by eta/gamma1
 *
 * Sample polynomial with uniformly random coefficients in [-x+1, x]
 * for x in {eta, gamma1} by unpacking output stream of SHAKE256(seed|nonce).
 *
 * @param[out]      a               Pointer to output polynomial
 * @param[in]       seed            Pointer to byte array containing seed of length CRHBYTES
 * @param[in]       nonce           16-bit nonce
 * @param[in,out]   buf             Pointer to buf array of random bytes
 * @param[in]       params          Pointer to ML-DSA parameter set
 * @param[in,out]   session         Handle for the current CL session
 * @param[in,out]   pXofContext     Handle for the current Xof context
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_UniformEta)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UniformEta(
  mcuxClMlDsa_Poly_t *a,
  const uint8_t* seed,
  uint16_t nonce,
  uint8_t * buf,
  const mcuxClMlDsa_Params_t *params,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_UniformGamma1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_UniformGamma1(
  mcuxClMlDsa_Poly_t *a,
  const uint8_t* seed,
  uint16_t nonce,
  uint8_t * buf,
  const mcuxClMlDsa_Params_t *params,
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext);

/**
 * @brief ML-DSA compute hint bit
 *
 * Compute hint bit indicating whether the low bits of the
 * input element overflow into the high bits.
 *
 * @param[in]       a0              Low bits of input element
 * @param[in]       a1              High bits of input element
 * @param[in]       params          Pointer to ML-DSA parameter set structure
 *
 * @return Returns whether there was an overflow
 *
 * @retval 1        Yes, there was an overflow
 * @retval 0        No, there was no overflow
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_MakeHint)
MCUX_CSSL_FP_PROTECTED_TYPE(uint8_t) mcuxClMlDsa_Poly_MakeHint(
  int32_t a0,
  int32_t a1,
  const mcuxClMlDsa_Params_t* const params);

/**
 * @brief ML-DSA sample challenge polynomial
 *
 * Implementation of H. Samples polynomial with params->tau nonzero
 * coefficients in {-1,1} using the output stream of SHAKE256(seed).
 *
 * @param[in,out]   session         Handle for the current CL session
 * @param[in,out]   pXofContext     Current Xof context
 * @param[in,out]   c               Pointer to output polynomial
 * @param[in]       seedBuf         Pointer to byte array containing seed
 * @param[in,out]   buf             Pointer to buf
 * @param[in]       params          Pointer to ML-DSA parameter set
 * @param[in]       negated         Whether to output c negated.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Poly_Challenge)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Poly_Challenge(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pXofContext,
  mcuxClMlDsa_Poly_t* const c,
  mcuxCl_InputBuffer_t seedBuf,
  uint8_t* const buf,
  const mcuxClMlDsa_Params_t* const params,
  const uint8_t negated);

#endif /* MCUXCLMLDSA_INTERNAL_POLY_H_ */
