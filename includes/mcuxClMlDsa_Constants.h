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
 * @file mcuxClMlDsa_Constants.h
 * @brief Constant definitions of the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_Constants mcuxClMlDsa_Constants
 * @ingroup mcuxClMlDsa
 * @brief Constants used in the @ref mcuxClMlDsa component.
 * @{
 */

#ifndef MCUXCLMLDSA_CONSTANTS_H_
#define MCUXCLMLDSA_CONSTANTS_H_

#include <mcuxClSignature_Constants.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MCUXCLMLDSA_MLDSA44_SK_LEN         (       2560U )   /** Secret key length for ML-DSA-44. */
#define MCUXCLMLDSA_MLDSA65_SK_LEN         (       4032U )   /** Secret key length for ML-DSA-65. */
#define MCUXCLMLDSA_MLDSA87_SK_LEN         (       4896U )   /** Secret key length for ML-DSA-87. */

#define MCUXCLMLDSA_MLDSA44_PK_LEN         (       1312U )   /** Public key length for ML-DSA-44. */
#define MCUXCLMLDSA_MLDSA65_PK_LEN         (       1952U )   /** Public key length for ML-DSA-65. */
#define MCUXCLMLDSA_MLDSA87_PK_LEN         (       2592U )   /** Public key length for ML-DSA-87. */

#define MCUXCLMLDSA_MLDSA44_SIG_LEN        (       2420U )   /** Signature length for ML-DSA-44. */
#define MCUXCLMLDSA_MLDSA65_SIG_LEN        (       3309U )   /** Signature length for ML-DSA-65. */
#define MCUXCLMLDSA_MLDSA87_SIG_LEN        (       4627U )   /** Signature length for ML-DSA-87. */

/* ML-DSA c tilde sizes */
#define MCUXCLMLDSA_MLDSA44_CTILDE_SIZE    (         32U )
#define MCUXCLMLDSA_MLDSA65_CTILDE_SIZE    (         48U )
#define MCUXCLMLDSA_MLDSA87_CTILDE_SIZE    (         64U )

/**
 * @defgroup mcuxClMlDsa_Constants_Modes
 * @ingroup mcuxClMlDsa_Constants
 * @brief ML-DSA parameter sets. The upper byte is reserved for future use (RFU).
 */
#define MCUXCLMLDSA_POS_MODE               (  0U )                                  /** Position within word of the choice between parameter set 44, 65 or 87 */
#define MCUXCLMLDSA_POS_APIMODE            (  8U )                                  /** Position within word of the choice between pure and pre-hash mode */

#define MCUXCLMLDSA_MODE_44                ((uint32_t)44U  << MCUXCLMLDSA_POS_MODE )          /** ML-DSA-44 */
#define MCUXCLMLDSA_MODE_65                ((uint32_t)65U  << MCUXCLMLDSA_POS_MODE )          /** ML-DSA-65 */
#define MCUXCLMLDSA_MODE_87                ((uint32_t)87U  << MCUXCLMLDSA_POS_MODE )          /** ML-DSA-87 */
#define MCUXCLMLDSA_MODE_PURE              ((uint32_t)0x0U << MCUXCLMLDSA_POS_APIMODE )       /** Mode using the pure functionality in the external API */
#define MCUXCLMLDSA_MODE_PREHASH           ((uint32_t)0xfU << MCUXCLMLDSA_POS_APIMODE )       /** Mode using the pre-hash functionality in the external API */

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_CONSTANTS_H_ */
