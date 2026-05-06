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
 * @file mcuxClMlDsa_Internal_Constants.h
 * @brief Internal constants used in @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_CONSTANTS_H_
#define MCUXCLMLDSA_INTERNAL_CONSTANTS_H_

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_General
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief ML-DSA parameters and macros that apply to all modes.
 */
#define MCUXCLMLDSA_PKC_T0                       (          0U )     /** Index of first PKC workarea used for calculations in ML-DSA Verify. */
#define MCUXCLMLDSA_PKC_T1                       (          1U )     /** Index of second PKC workarea used for calculations in ML-DSA Verify. */
#define MCUXCLMLDSA_UPTRT_SIZE                   (          2U )     /** Size of PKC workarea table used in ML-DSA Verify. */
#define MCUXCLMLDSA_N                            (        256U )     /** The polynomial ring dimension n; the number of coefficients in a polynomial. */
#define MCUXCLMLDSA_LOG2_N                       (          8U )     /** The logarithm of the polynomial ring dimension n. Used for NTT butterflies. */
#define MCUXCLMLDSA_Q                            (    8380417U )     /** The prime modulus q = 2^23 - 2^13 + 1. */
#define MCUXCLMLDSA_QINV                         (   58728449U )     /** The modular inverse q^(-1) mod 2^32. Used in NTT computations. */
#define MCUXCLMLDSA_F                            (      41978U )     /** The constant f = 2^64 / 256 mod q. Used in Montgomery reductions in NTT computations. */
#define MCUXCLMLDSA_D                            (         13U )     /** The number of dropped bits from t. */
#define MCUXCLMLDSA_SHL_MLDSA_D                  (     0x1000U )     /** Equal to 2^d, where d is the number of dropped bits from t. */
#define MCUXCLMLDSA_POLY_W_SIZE                  (        768U )     /** The memory size of polynomials in reduced form. Each of n = 256 coefficients uses ceil(log_2(q)) = 3 bytes. */
#define MCUXCLMLDSA_POLY_SIZE                    (       1024U )     /** The memory size of polynomials in expanded form. Each of n = 256 coefficients uses sizeof(int32_t) = 4 bytes. */
#define MCUXCLMLDSA_SHAKE128_RATE                (        168U )     /** The rate for hashing with SHAKE-128, in bytes. */
#define MCUXCLMLDSA_SHAKE256_RATE                (        136U )     /** The rate for hashing with SHAKE-256, in bytes. */
#define MCUXCLMLDSA_C_PACKED_BYTES               (         40U )     /** The size of the packed challenge, in bytes (32 bytes indicating zero/non-zero indices, 8 bytes for non-zero signs). */
#define MCUXCLMLDSA_RNGBYTES                     (         32U )     /** The memory size of the randomness used in "hedged" deterministic signing. */
#define MCUXCLMLDSA_SEEDBYTES                    (         32U )     /** The memory size of the random seed used for one-way hashing, in bytes. */
#define MCUXCLMLDSA_TRBYTES                      (         64U )     /** The memory size of the hashed publicKey. */
#define MCUXCLMLDSA_CTILDEBYTES                  (         32U )     /** The memory size of challenge representative */
#define MCUXCLMLDSA_CTILDEMAX_BYTES              (         64U )     /** The maximum (ML-DSA & MLDSA) memory size of ctilde used for one-way hashing, in bytes. */
#define MCUXCLMLDSA_CRHBYTES                     (         64U )     /** The memory size of the random seed used for collision-resistant hashing, in bytes. */
#define MCUXCLMLDSA_POLYT1_PACKEDBYTES           (        320U )     /** The memory size of a single polynomial in the packed t_1 (part of the public key) in bytes. */
#define MCUXCLMLDSA_POLYT0_PACKEDBYTES           (        416U )     /** The memory size of a single polynomial in the packed t_0 (part of the private key) in bytes. */
#define MCUXCLMLDSA_KEYGEN_XOF_OUT_BUFFER_SIZE   (        168U )     /** The buffer size for calling functions from Xof in KeyGen, in bytes. Computed as MAX(MCUXCLMLDSA_SHAKE128_RATE, MCUXCLMLDSA_SHAKE256_RATE). */
#define MCUXCLMLDSA_SIGN_XOF_OUT_BUFFER_SIZE     (        168U )     /** The buffer size for calling functions from Xof in Sign, in bytes. Computed as MAX(MCUXCLMLDSA_SHAKE128_RATE, (MCUXCLMLDSA_SHAKE256_RATE + 9)). */
#define MCUXCLMLDSA_CHALLENGE_NEGATIVE           (          1U )     /** Option to mcuxClMlDsa_Poly_Challenge to generate the negated challenge (i.e, for verify) */
#define MCUXCLMLDSA_CHALLENGE_POSITIVE           (          0U )     /** Option to mcuxClMlDsa_Poly_Challenge to generate the positive challenge (i..e, for sign) */

/**
 * For calculating max_attempts in signature generation, the probability of a
 * single abort is approximately:
 *
 *    p1 = 1 - exp[−256 * beta * (L / gamma_1 + K / gamma_2)].
 *
 * To make sure that the overall probability of an abort is at most 2^(-128),
 * we therefore wish to choose parameters and a number of attempts x such that:
 *
 *    p1^x <= 2^(-128).
 *
 * Therefore, after x >= -128 / log2(p1) attempts, we make sure that the
 * signature generation succeeds with probability at least 1 - 2^(-128).
 * The below Sage script can be used to reproduce the given parameters,
 * setting parameters from modes [2, 3, 5].
 *
 *    beta = [78, 196, 120]
 *    gamma_1 = [131072, 524288, 524288]
 *    gamma_2 = [95232, 261888, 261888]
 *    k = [4, 6, 8]
 *    l = [4, 5, 7]
 *    for i in range(3):
 *      x = 1 - exp(-256 * beta[i] * (l[i] / gamma_1[i] + k[i] / gamma_2[i]))
 *      rep = -128 / log(x, 2)
 *      print(rep.n().ceil())
 *
 *    (Output: 332, 406, 296)
 */

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_Mode2
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief ML-DSA parameters and macros that are specific for mode 2.
 */
#define MCUXCLMLDSA_MLDSA44_K                    (          4U )     /** The number of rows of the matrix A (mode 2). */
#define MCUXCLMLDSA_MLDSA44_L                    (          4U )     /** The number of columns of the matrix A (mode 2). */
#define MCUXCLMLDSA_MLDSA44_ETA                  (          2U )     /** The coefficients in the private key are in the range [-eta, eta] (mode 2). */
#define MCUXCLMLDSA_MLDSA44_BETA                 (         78U )     /** Maximum infinity norm of c*s1 and c*s2 in bound check due to challenge multiplied by private key, computed as tau * eta (mode 2). */
#define MCUXCLMLDSA_MLDSA44_TAU                  (         39U )     /** The number of non-zero coefficients in the challenge (mode 2). */
#define MCUXCLMLDSA_MLDSA44_GAMMA1               (     131072U )     /** The coefficient range of y (y is in the range [-gamma1+1, gamma1]), equal to 2^17 (mode 2). */
#define MCUXCLMLDSA_MLDSA44_GAMMA2               (      95232U )     /** The low-order rounding range, computed as (Q - 1) / 88 < 2^17 (mode 2). */
#define MCUXCLMLDSA_MLDSA44_OMEGA                (         80U )     /** Maximum number of 1's in the hint vector (mode 2). */
#define MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES    (        576U )     /** The memory to store one packed entry (out of L) of z, computed as n * ceil(log2(2*gamma1)) bits (mode 2). */
#define MCUXCLMLDSA_MLDSA44_POLYW1_PACKEDBYTES   (        192U )     /** The memory to store a single polynomial w_1 in packed form, computed as 6 bits (entries in [0, 43]) for each of n coefficents (mode 2). */
#define MCUXCLMLDSA_MLDSA44_POLYETA_PACKEDBYTES  (         96U )     /** The memory to store a single polynomial with n coefficients in [-eta, eta], computed as n * ceil(log2(2*eta + 1)) bits (mode 2). */
#define MCUXCLMLDSA_MLDSA44_MAX_ATTEMPTS         (        331U )     /** The maximum number of attempts in signature generation to guarantee a failure rate <= 2^(-128) (mode 2). */
#define MCUXCLMLDSA_MLDSA44_POLYVECH_PACKEDBYTES (         84U )     /** The memory used for storing the hint part of the signature, computed as omega + k (mode 2). */

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_Mode3
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief ML-DSA parameters and macros that are specific for mode 3.
 */
#define MCUXCLMLDSA_MLDSA65_K                    (          6U )     /** The number of rows of the matrix A (mode 3). */
#define MCUXCLMLDSA_MLDSA65_L                    (          5U )     /** The number of columns of the matrix A (mode 3). */
#define MCUXCLMLDSA_MLDSA65_ETA                  (          4U )     /** The coefficients in the private key are in the range [-eta, eta] (mode 3). */
#define MCUXCLMLDSA_MLDSA65_BETA                 (        196U )     /** Maximum infinity norm of c*s1 and c*s2 in bound check due to challenge multiplied by private key, computed as tau * eta (mode 3). */
#define MCUXCLMLDSA_MLDSA65_TAU                  (         49U )     /** The number of non-zero coefficients in the challenge (mode 3). */
#define MCUXCLMLDSA_MLDSA65_GAMMA1               (     524288U )     /** The coefficient range of y (y is in the range [-gamma1+1, gamma1]), equal to 2^19 (mode 3). */
#define MCUXCLMLDSA_MLDSA65_GAMMA2               (     261888U )     /** The low-order rounding range, computed as (Q - 1) / 32 = 2^18 - 2^8 (mode 3). */
#define MCUXCLMLDSA_MLDSA65_OMEGA                (         55U )     /** Maximum number of 1's in the hint vector (mode 3). */
#define MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES    (        640U )     /** The memory to store one packed entry (out of L) of z, computed as n * ceil(log2(2*gamma1)) bits (mode 3). */
#define MCUXCLMLDSA_MLDSA65_POLYW1_PACKEDBYTES   (        128U )     /** The memory to store a single polynomial w_1 in packed form, computed as 4 bits (entries in [0, 15]) for each of n coefficents (mode 3). */
#define MCUXCLMLDSA_MLDSA65_POLYETA_PACKEDBYTES  (        128U )     /** The memory to store a single polynomial with n coefficients in [-eta, eta], computed as n * ceil(log2(2*eta + 1)) bits (mode 3). */
#define MCUXCLMLDSA_MLDSA65_MAX_ATTEMPTS         (        406U )     /** The maximum number of attempts in signature generation to guarantee a failure rate <= 2^(-128) (mode 3). */
#define MCUXCLMLDSA_MLDSA65_POLYVECH_PACKEDBYTES (         61U )     /** The memory used for storing the hint part of the signature, computed as omega + k (mode 3). */

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_Mode5
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief ML-DSA parameters and macros that are specific for mode 5.
 */
#define MCUXCLMLDSA_MLDSA87_K                    (          8U )     /** The number of rows of the matrix A (mode 5). */
#define MCUXCLMLDSA_MLDSA87_L                    (          7U )     /** The number of columns of the matrix A (mode 5). */
#define MCUXCLMLDSA_MLDSA87_ETA                  (          2U )     /** The coefficients in the private key are in the range [-eta, eta] (mode 5). */
#define MCUXCLMLDSA_MLDSA87_BETA                 (        120U )     /** Maximum infinity norm of c*s1 and c*s2 in bound check due to challenge multiplied by private key, computed as tau * eta (mode 5). */
#define MCUXCLMLDSA_MLDSA87_TAU                  (         60U )     /** The number of non-zero coefficients in the challenge (mode 5). */
#define MCUXCLMLDSA_MLDSA87_GAMMA1               (     524288U )     /** The coefficient range of y (y is in the range [-gamma1+1, gamma1]), equal to 2^19 (mode 5). */
#define MCUXCLMLDSA_MLDSA87_GAMMA2               (     261888U )     /** The low-order rounding range, computed as (Q - 1) / 32 = 2^18 - 2^8 (mode 5). */
#define MCUXCLMLDSA_MLDSA87_OMEGA                (         75U )     /** Maximum number of 1's in the hint vector (mode 5). */
#define MCUXCLMLDSA_MLDSA87_POLYZ_PACKEDBYTES    (        640U )     /** The memory to store one packed entry (out of L) of z, computed as n * log2(2*gamma1) bits (mode 5). */
#define MCUXCLMLDSA_MLDSA87_POLYW1_PACKEDBYTES   (        128U )     /** The memory to store a single polynomial w_1 in packed form, computed as 4 bits (entries in [0, 15]) for each of n coefficents (mode 5). */
#define MCUXCLMLDSA_MLDSA87_POLYETA_PACKEDBYTES  (         96U )     /** The memory to store a single polynomial with n coefficients in [-eta, eta], computed as n * ceil(log2(2*eta + 1)) bits (mode 5). */
#define MCUXCLMLDSA_MLDSA87_MAX_ATTEMPTS         (        295U )     /** The maximum number of attempts in signature generation to guarantee a failure rate <= 2^(-128) (mode 5). */
#define MCUXCLMLDSA_MLDSA87_POLYVECH_PACKEDBYTES (         83U )     /** The memory used for storing the hint part of the signature, computed as omega + k (mode 5). */

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_Crc
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief CRC values for ML-DSA parameter sets.
 */
#define MCUXCLMLDSA_MODE44_PARAMS_CRC            ( 0xd7362fd9U )
#define MCUXCLMLDSA_MODE65_PARAMS_CRC            ( 0xb9152379U )
#define MCUXCLMLDSA_MODE87_PARAMS_CRC            ( 0x8a73c145U )

/**
 * @defgroup mcuxClMlDsa_Internal_Constants_Modes
 * @ingroup mcuxClMlDsa_Internal_Constants
 * @brief Selection of different modes: padding (4 nibbles) || wrapper mode || API mode || (ML-DSA) mode (2 nibbles)
 */
#define MCUXCLMLDSA_SELECT_APIMODE_CTX           ( 0x00000100U )     /** Select API mode for (external API) context: for pure this yields 0; for pre-hash this yields 1 */
#define MCUXCLMLDSA_SELECT_MODE                  ( 0x000000ffU )     /** Select mode */
#define MCUXCLMLDSA_SELECT_APIMODE               ( 0x00000f00U )     /** Select API mode */

#endif /* MCUXCLMLDSA_INTERNAL_CONSTANTS_H_ */
