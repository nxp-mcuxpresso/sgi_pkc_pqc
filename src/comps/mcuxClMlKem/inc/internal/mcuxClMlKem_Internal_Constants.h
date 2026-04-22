/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Internal_Constants.h
 * @brief: Internal constants crypto library ML-KEM component
 *
 */
#ifndef MCUXCLMLKEM_INTERNAL_CONSTANTS_H_
#define MCUXCLMLKEM_INTERNAL_CONSTANTS_H_

#include<mcuxCsslAnalysis.h>

/* Place your internal type and function definitions here. */
#define MCUXCLMLKEM_N                                               (256U)
#define MCUXCLMLKEM_LOG2_N                                          (8U)
#define MCUXCLMLKEM_Q                                               (3329U)
#define MCUXCLMLKEM_QINV                                            (62209U)  /* MLKEM_Q^-1 mod 2^16 */
#define MCUXCLMLKEM_ETA2                                            (2U)
#define MCUXCLMLKEM_2POW16                                          (0x10000) /* 2^16 for signed operations */
#define MCUXCLMLKEM_RESULT_BEFORE_RED_MIN                           (0LL - (int64_t)MCUXCLMLKEM_Q * MCUXCLMLKEM_2POW16) /* -MLKEM_Q << 16 */
#define MCUXCLMLKEM_RESULT_BEFORE_RED_MAX                           ((int64_t)MCUXCLMLKEM_Q * MCUXCLMLKEM_2POW16) /*  MLKEM_Q << 16 */

/* Constants required to do unsigned integer division without DIV instructions */
#define MCUXCLMLKEM_FLOOR_Q_DIV_2                                   (1664U)    /* floor(MLKEM_Q / 2) */
#define MCUXCLMLKEM_CEIL_Q_DIV_2                                    (1665U)    /* ceil(MLKEM_Q / 2) */
#define MCUXCLMLKEM_2_EXP_27_CEIL_DIV_Q                             (40318U)   /* round == ceil( 1U << 27 / MLKEM_Q) */
#define MCUXCLMLKEM_2_EXP_28_FLOOR_DIV_Q                            (80635U)   /* round == floor(1U << 28 / MLKEM_Q) */
#define MCUXCLMLKEM_2_EXP_31_CEIL_DIV_Q                             (645084U)  /* round == ceil( 1U << 31 / MLKEM_Q) */
#define MCUXCLMLKEM_2_EXP_32_FLOOR_DIV_Q                            (1290167U) /* round == floor(1U << 32 / MLKEM Q) */

#define MCUXCLMLKEM_SSBYTES                                         (32U) /* size in bytes of shared key */
#define MCUXCLMLKEM_SYMBYTES                                        (32U) /* size in bytes of hashes, and seeds */
#define MCUXCLMLKEM_POLYBYTES                                       (384U)

/* The three main ML-KEM parameter sets and their parameters are summarized below
 *                                                     MLKEM_K
 *                                        2                3                     4
 * MLKEM_ETA1                             3                2                     2
 * MLKEM_POLYCOMPRESSEDBYTES             128              128                   160
 * MLKEM_POLYVECCOMPRESSEDBYTES    (MLKEM_K*320)    (MLKEM_K*320)          (MLKEM_K * 352)
 *
 * MLKEM_INDCPA_SECRETKEYBYTES           768             1152                  1536
 * MLKEM_INDCPA_PUBLICKEYBYTES           800             1184                  1568
 * MLKEM_INDCPA_BYTES                    768             1088                  1568
 *
 * MLKEM_SECRETKEYBYTES                  832             1216                  1600
 * MLKEM_PUBLICKEYBYTES                  800             1184                  1568
 * MLKEM_CIPHERTEXTBYTES                 768             1088                  1568
 *
 * The macros below automagically provide the correct values.
 */

#define MCUXCLMLKEM_ETA1(k)                     (3U - ((k) - 1U)/2U)
#define MCUXCLMLKEM_POLYCOMPRESSEDBYTES(k)      (128U + (((k) >> 2U) << 5U))
#define MCUXCLMLKEM_POLYVECCOMPRESSEDBYTES(k)   ((k) * (320U + (((k) >> 2U) << 5U)))

#define MCUXCLMLKEM_POLYVECBYTES(k)             ((k) * MCUXCLMLKEM_POLYBYTES)
#define MCUXCLMLKEM_POLYCOMPRESSEDBYTES_GEN(k)  (320U + (((k) >> 2U) << 5U))

#define MCUXCLMLKEM_INDCPA_PUBLICKEYBYTES(k)    (MCUXCLMLKEM_POLYVECBYTES(k) + MCUXCLMLKEM_SYMBYTES)
#define MCUXCLMLKEM_INDCPA_SECRETKEYBYTES(k)    (MCUXCLMLKEM_POLYVECBYTES(k))
#define MCUXCLMLKEM_INDCPA_BYTES(k)             (MCUXCLMLKEM_POLYVECCOMPRESSEDBYTES(k) + MCUXCLMLKEM_POLYCOMPRESSEDBYTES(k))

#define MCUXCLMLKEM_SECRETKEYBYTES(k)           (MCUXCLMLKEM_INDCPA_SECRETKEYBYTES(k) + 2U * MCUXCLMLKEM_SYMBYTES)
#define MCUXCLMLKEM_PUBLICKEYBYTES(k)           (MCUXCLMLKEM_INDCPA_PUBLICKEYBYTES(k))
#define MCUXCLMLKEM_CIPHERTEXTBYTES(k)          (MCUXCLMLKEM_INDCPA_BYTES(k))

/* Internal error codes */
#define MCUXCLMLKEM_INTERNAL_STATUS_OK                     ((mcuxClKem_Status_t) 0x00622E03u)
/* Internal return status OK for the INDCPA functions */
#define MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK              ((mcuxClKem_Status_t) 0x00622E07u)
/* Internal return status OK for the POLY functions */
#define MCUXCLMLKEM_INTERNAL_STATUS_POLY_OK                ((mcuxClKem_Status_t) 0x00622E0Bu)

#endif /* MCUXCLMLKEM_INTERNAL_CONSTANTS_H_ */
