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
 * @file:  mcuxClMlKem_Poly.h
 * @brief: Interface for polynomial arithmetic of the crypto library ML-KEM component
 *
 */

#ifndef MCUXCLMLKEM_POLY_H_
#define MCUXCLMLKEM_POLY_H_

#include <mcuxClBuffer.h>
#include <mcuxClMlKem.h>
#include <mcuxClToolchain.h>
#include <mcuxClXof_Types.h>
#include <mcuxClMemory_Types.h>

#include <internal/mcuxClMlKem_Internal.h>

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
  int16_t coeffs[MCUXCLMLKEM_N];
} mcuxClMlKem_Poly_t;

/**
 * @brief ML-KEM Montgomery Reduce
 *
 * This function performs montgomery reduction; given a 32-bit integer a,
 *               computes 16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * @param[in/out]   a          Input integer to be reduced; has to be in {-q2^15,...,q2^15-1}
 *
 * @return returns integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Montgomery_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int16_t) mcuxClMlKem_Montgomery_Reduce(const int32_t a);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
/**
 * @brief ML-KEM Barrett Reduce
 *
 * This function performs inplace number-theoretic transform (NTT) in Rq.
 *               input is in standard order, output is in bitreversed order
 *
 * @param[in/out]   a         Pointer to input/output vector of
 *
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Barrett_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int16_t) mcuxClMlKem_Barrett_Reduce(const int16_t a);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

/**
 * @brief ML-KEM NTT
 *
 * This function performs inplace number-theoretic transform (NTT) in Rq.
 *               input is in standard order, output is in bitreversed order
 *
 * @param[n/out]   r          Pointer to input/output vector of elements of Zq
 *
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_NTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_NTT(int16_t r[256]);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

/**
 * @brief ML-KEM Basemul
 *
 * This function performs base multipy
 *
 * @param[out]      R         Pointer to output vector
 * @param[in]       a         Pointer to input polynomial
 * @param[in]       b         Pointer to input polynomial
 * @param[in]       zeta      Zeta
 *
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Basemul)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Basemul(int16_t R[2], const int16_t a[2], const int16_t b[2], const int16_t zeta);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

/**
 * @brief Function pointer of generic compression function.
 *
 * @param[in]    session  Handle for the current CL session
 * @param[out]   buf      Output buffer to to compress into
 * @param[in]    pPoly    Pointer to poly to compress
 * @param[in]    pParams  Parameters structure
  */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClMlKem_Poly_Compress_Func_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) (*mcuxClMlKem_Poly_Compress_Func_t) (
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t buf,
  mcuxClMlKem_Poly_t *pPoly,
  mcuxClMlKem_Params_t pParams
));

/**
 * @brief mcuxClMlKem_Poly_Compress
 *
 * This function performs poly compress
 *
 * @param[in]       session          Handle for the current CL session
 * @param[out]      r                Pointer to output byte array (of length MCUXCLMLKEM_POLYCOMPRESSEDBYTES)
 * @param[in]       a                Pointer to input polynomial
 * @param[in]       pParams          Pointer to ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Compress, mcuxClMlKem_Poly_Compress_Func_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  mcuxClMlKem_Poly_t *a,
  mcuxClMlKem_Params_t pParams
);

/**
 * @brief mcuxClMlKem_Poly_Decompress
 *
 * This function performs de-serialization and subsequent decompression of a polynomial; approximate inverse of poly_compress
 *
 * @param[in]       session          Handle for the current CL session
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       a                Pointer to input byte array (of length MCUXCLMLKEM_POLYCOMPRESSEDBYTES bytes)
 * @param[in]       pParams          Pointer to ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Decompress)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Decompress(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Poly_t *r,
  mcuxCl_InputBuffer_t aBuf,
  mcuxClMlKem_Params_t pParams
);

/**
 * @brief mcuxClMlKem_To_Bytes
 *
 * This function performs serialization of a polynomial
 *
 * @param[out]      r                Pointer to output byte array (needs space for MCUXCLMLKEM_POLYBYTES bytes)
 * @param[in]       a                Pointer to input polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_To_Bytes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_To_Bytes(uint8_t * const r, mcuxClMlKem_Poly_t * a);

/**
 * @brief mcuxClMlKem_From_Msg
 *
 * This function performs the conversion of a 32-byte message to polynomial
 *
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       msg              Pointer to input message (of MCUXCLMLKEM_SYMBYTES bytes)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_From_Msg)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_From_Msg(mcuxClMlKem_Poly_t * r, const uint8_t *msg);

/**
 * @brief mcuxClMlKem_To_Msg
 *
 * This function performs the conversion of a polynomial to 32-byte message.
 *
 * @param[out]       msg              Pointer to output message
 * @param[in]        r                Pointer to input polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_To_Msg)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_To_Msg(uint8_t * const msg, mcuxClMlKem_Poly_t * a);

/**
 * @brief mcuxClMlKem_Poly_Get_Noise_Eta1
 *
 * This function sample a polynomial deterministically from a seed and a nonce,
 *       with output polynomial close to centered binomial distribution with parameter MCUXCLMLKEM_ETA1
 *
 * @param[in]       session          Handle for the current CL session
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       seed             Pointer to input seed (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       nonce            One-byte input nonce
 * @param[in]       pParams          ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Get_Noise_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Get_Noise_Eta1(
                                                         mcuxClSession_Handle_t session,
                                                         mcuxClMlKem_Poly_t *r,
                                                         const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                         uint8_t nonce,
                                                         mcuxClMlKem_Params_t pParams);

/**
 * @brief mcuxClMlKem_Poly_Get_Noise_Eta2
 *
 *  This function sample a polynomial deterministically from a seed and a nonce,
 *        with output polynomial close to centered binomial distribution with parameter MCUXCLMLKEM_ETA2
 *
 * @param[in]       session          Handle for the current CL session
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       seed             Pointer to input seed (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       nonce            One-byte input nonce
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Get_Noise_Eta2)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Get_Noise_Eta2(
                                                         mcuxClSession_Handle_t session,
                                                         mcuxClMlKem_Poly_t *r,
                                                         const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                         uint8_t nonce);

/**
 * @brief mcuxClMlKem_Poly_NTT
 *
 * This function computes negacyclic number-theoretic transform (NTT) of a polynomial in place;
 *      inputs assumed to be in normal order, output in bitreversed order
 *
 * @param[in/out]   r                Pointer to in/output polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_NTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_NTT(mcuxClMlKem_Poly_t * r);

/**
 * @brief ML-KEM Poly invNTT to Mont
 *
 *  This function Computes inverse of negacyclic number-theoretic transform (NTT)
 *  of a polynomial in place; inputs assumed to be in bitreversed order, output in normal order
 *
 * @param[in/out]   r                Pointer to in/output polynomial
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_InvNTT_To_Mont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_InvNTT_To_Mont(mcuxClMlKem_Poly_t * r);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

/**
 * @brief mcuxClMlKem_Poly_To_Mont
 *
 * This function performs inplace conversion of all coefficients of a polynomial
 *     from normal domain to Montgomery domain
 *
 * @param[in/out]   r                Pointer to in/output polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_To_Mont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_To_Mont(mcuxClMlKem_Poly_t * r);

/**
 * @brief mcuxClMlKem_Poly_Reduce
 *
 * This function applies Barrett reduction to all coefficients of a polynomial
 *    for details of the Barrett reduction see comments in reduce.c
 *
 * @param[in/out]   r                Pointer to in/output polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Reduce)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Reduce(mcuxClMlKem_Poly_t * r);

/**
 * @brief mcuxClMlKem_Poly_Add
 *
 * This function adds two polynomials
 *
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       a                Pointer to first input polynomial
 * @param[in]       b                Pointer to second input polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Add)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Add(mcuxClMlKem_Poly_t * r, const mcuxClMlKem_Poly_t * a, const mcuxClMlKem_Poly_t * b);

/**
 * @brief mcuxClMlKem_Poly_Sub
 *
 *  * This function subtracts two polynomials.
 *
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       a                Pointer to first input polynomial
 * @param[in]       b                Pointer to second input polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Sub)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Sub(mcuxClMlKem_Poly_t * r, const mcuxClMlKem_Poly_t * a, const mcuxClMlKem_Poly_t * b);

/**
 * @brief mcuxClMlKem_Poly_Compress_Gen
 *
 * This function compresses ciphertext polynomial from 256 uint16_t coefficients to 256*{10, 10, 11} bits, storing in
 *      {320, 320, 352} bytes. This involves *rounding* as specified in the ML-KEM spec, so loses precision.
 *
 * @param[in]       session          Handle for the current CL session
 * @param[out]      r                Pointer to output buffer (of mcuxCl_POLYCOMPRESSEDBYTES_GEN(x) bytes)
 * @param[in]       a                Pointer to input polynomial
 * @param[in]       pParams          ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Compress_Gen, mcuxClMlKem_Poly_Compress_Func_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress_Gen(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  mcuxClMlKem_Poly_t *a,
  mcuxClMlKem_Params_t pParams
);

/**
 * @brief mcuxClMlKem_Poly_Decompress_Gen
 *
 * This function decompresses buffer of {320, 320, 352} bytes into polynomial.
 *
 * @param[out]      r                Pointer to output polynomial
 * @param[in]       a                Pointer to input buffer (of mcuxCl_POLYCOMPRESSEDBYTES_GEN(x) bytes)
 * @param[in]       pParams          ML-KEM parameter set structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK           Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Decompress_Gen)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Decompress_Gen(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Poly_t *r,
  mcuxCl_InputBuffer_t aBuf,
  mcuxClMlKem_Params_t pParams
);

/**
 * @brief ML-KEM poly Mul streamed matrix
 *
 * This function perform a single polynomial multiplication between a public matrix element at index (i,j) or (j,i) depending on the
 * transposed flag, and a secret key element skpv. The matrix element is generated coefficient-wise from seed and multiplied
 * on-the-fly to avoid storing the whole polynomial in memory.
 *
 * @param[in]       session          Handle for the current CL session
 * @param[in]       pContext         Pointer to context
 * @param[out]      pkpv             Pointer to output polynomial (can equal skpv)
 * @param[in]       skpv             Pointer to input polynomial
 * @param[in]       seed             Pointer to input seed (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       row              Row (or column if transposed) of matrix element
 * @param[in]       col              Column (or row if transposed) of matrix element
 * @param[in]       transposed       Flag determining whether matrix is transposed
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK          Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Mul_Streamed_Matrix)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Mul_Streamed_Matrix(
  mcuxClSession_Handle_t session,
  mcuxClXof_Context_t pContext,
  mcuxClMlKem_Poly_t *pkpv,
  const mcuxClMlKem_Poly_t *skpv,
  const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
  uint8_t row,
  uint8_t col,
  uint8_t transposed);

/**
 * @brief ML-KEM poly Mul streamed secret key public
 *
 * This function perform a single polynomial multiplication between a polynomial and another one that is stored as the j-th element
 * in a byte array representing MCUXCLMLKEM_K polynomials. The polynomial is generated from the array coefficient-wise and multiplied
 * on-the-fly to avoid storing the whole polynomial in memory.
 *
 * @param[out]      bp               Pointer to output polynomial
 * @param[in]       sp               Pointer to (memory for) expanded polynomial
 * @param[in]       skpk             Pointer to public key or secret key byte array
 * @param[in]       j                Element to determine which polynomials in the length K vectors to multiply
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Mul_Streamed_Skpk)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Mul_Streamed_Skpk(mcuxClMlKem_Poly_t * bp, const mcuxClMlKem_Poly_t * sp, const uint8_t *skpk, const uint16_t j);

/**
 * @brief mcuxClMlKem_Poly_Compress_Eta1
 *
 * This function perform compress poly with 256 coefficients in {-2,...,2} to 96 bytes
 *
 * @param[out]      r                Pointer to output buffer (of 96 bytes)
 * @param[in]       sk               Pointer to input polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Compress_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Compress_Eta1(uint8_t * const r, const mcuxClMlKem_Poly_t * sk);

/**
 * @brief mcuxClMlKem_Poly_Decompress_Eta1
 *
 * This function perform decompress 96 bytes into poly  with 256 coefficients in {-2,...,2}
 * @param[in]      r                Pointer to input buffer (of 96 bytes)
 * @param[out]     packedsk         Pointer to output polynomial
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Poly_Decompress_Eta1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Poly_Decompress_Eta1(mcuxClMlKem_Poly_t * sk, const uint8_t *packedsk);

/**
 * @brief Function pointer to operate on compressed polynomials (e.g. compare/write)
 *
 * @param[in]       session   Handle for the current CL session
 * @param[in]       pParams   Parameters structure
 * @param[in,out]   pPoly     Pointer to poly to compress (and optionally compare)
 * @param[in,out]   buf       Buffer to to compress into / compare compression against
 * @param[in]       cmprFn    Function pointer to the compression function
 * @param[in]       len       Length of the compressed polynomial that is being compressed/compared.
 * @param[out]      wa        Workearea requirement (in case of comparing)
 * @param[in,out]   rc        Comparison value (in case of comparing)
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClMlKem_Poly_Compress_Op_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) (*mcuxClMlKem_Poly_Compress_Op_t) (
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Params_t pParams,
  mcuxClMlKem_Poly_t *pPoly,
  mcuxCl_Buffer_t buf,
  mcuxClMlKem_Poly_Compress_Func_t cmprFn,
  uint32_t len,
  uint8_t *wa,
  mcuxClMemory_Status_t *rc
));

/**
 * @brief Function to compare re-encrypted polynomials of u, v to reference polynomials
 *
 * @param[in]       session  Handle for the current CL session
 * @param[in]       pParams  Parameters structure
 * @param[in]       pPoly    Pointer to poly to compare against
 * @param[in]       buf      Buffer to to compare against
 * @param[in]       cmprFn   Function pointer to the compression function
 * @param[in]       len      Length of the compressed polynomial that is being compared.
 * @param[out]      wa       Workearea requirement (of size len, below)
 * @param[in,out]   rc       Pointer to comparison value
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK          Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Encrypt_Op, mcuxClMlKem_Poly_Compress_Op_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress_Cmp(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Params_t pParams,
  mcuxClMlKem_Poly_t *pPoly,
  mcuxCl_Buffer_t buf,
  mcuxClMlKem_Poly_Compress_Func_t cmprFn,
  uint32_t len,
  uint8_t* wa,
  mcuxClMemory_Status_t *rc
);

/**
 * @brief Function to write encrypted polynomials of u, v to an output buffer.
 *
 * @param[in]       session  Handle for the current CL session
 * @param[in]       pParams  Parameters structure
 * @param[in]       pPoly    Pointer to poly to compress
 * @param[out]      buf      Buffer to to compress into
 * @param[in]       cmprFn   Function pointer to the compression function
 * @param[in]       len      Length of the compressed polynomial (not used)
 * @param[out]      wa       Workearea requirement (not used, so zero)
 * @param[in,out]   rc       Pointer to comparison value (unused)
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK          Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlKem_Encrypt_Op, mcuxClMlKem_Poly_Compress_Op_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Poly_Compress_Write(
  mcuxClSession_Handle_t session,
  mcuxClMlKem_Params_t pParams,
  mcuxClMlKem_Poly_t *pPoly,
  mcuxCl_Buffer_t buf,
  mcuxClMlKem_Poly_Compress_Func_t cmprFn,
  uint32_t len UNUSED_PARAM,
  uint8_t* wa UNUSED_PARAM,
  mcuxClMemory_Status_t *rc UNUSED_PARAM
);

#endif   /* MCUXCLMLKEM_POLY_H_ */
