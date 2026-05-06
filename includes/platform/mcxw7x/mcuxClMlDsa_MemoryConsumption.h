/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_MemoryConsumption.h
 * @brief Common type definitions of the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_MemoryConsumption mcuxClMlDsa_MemoryConsumption
 * @brief Memory consumption of ML-DSA operations.
 * @ingroup mcuxClMlDsa
 * @{
 */

#ifndef MCUXCLMLDSA_MEMORYCONSUMPTION_H_
#define MCUXCLMLDSA_MEMORYCONSUMPTION_H_


#define MCUXCLMLDSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE  (16u)

#define MCUXCLMLDSA_MLDSA44_KEYGEN_SIZEOF_WA_CPU     ( 3428U )
#define MCUXCLMLDSA_MLDSA65_KEYGEN_SIZEOF_WA_CPU     ( 3716U )
#define MCUXCLMLDSA_MLDSA87_KEYGEN_SIZEOF_WA_CPU     ( 3716U )

#define MCUXCLMLDSA_MLDSA44_SIGN_SIZEOF_WA_CPU       ( 6336U )
#define MCUXCLMLDSA_MLDSA65_SIGN_SIZEOF_WA_CPU       ( 7872U )
#define MCUXCLMLDSA_MLDSA87_SIGN_SIZEOF_WA_CPU       ( 9408U )

#define MCUXCLMLDSA_MLDSA44_VERIFY_SIZEOF_WA_CPU     ( 3312U )
#define MCUXCLMLDSA_MLDSA65_VERIFY_SIZEOF_WA_CPU     ( 3292U )
#define MCUXCLMLDSA_MLDSA87_VERIFY_SIZEOF_WA_CPU     ( 3312U )
#define MCUXCLMLDSA_VERIFY_SIZEOF_WA_PKC             ( 4096U )

#define MCUXCLMLDSA_MLDSA44_WORKAREASIZE_MAX         ( 6336U )
#define MCUXCLMLDSA_MLDSA65_WORKAREASIZE_MAX         ( 7872U )
#define MCUXCLMLDSA_MLDSA87_WORKAREASIZE_MAX         ( 9408U )
#define MCUXCLMLDSA_WORKAREASIZE_MAX                 ( 9408U )

/** @} */

#endif /* MCUXCLMLDSA_MEMORYCONSUMPTION_H_ */
