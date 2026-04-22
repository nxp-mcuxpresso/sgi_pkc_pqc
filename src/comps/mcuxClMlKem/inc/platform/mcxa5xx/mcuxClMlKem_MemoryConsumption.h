/*--------------------------------------------------------------------------*/
/* Copyright 2022-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_MemoryConsumption.h
 * @brief: Common type definitions of the @ref mcuxClMlKem component
 *
 * @defgroup mcuxClMlKem_MemoryConsumption mcuxClMlKem_MemoryConsumption
 * @brief Memory consumption of ML-KEM operations.
 * @ingroup mcuxClMlKem
 * @{
 */

#ifndef MCUXCLMLKEM_MEMORYCONSUMPTION_H_
#define MCUXCLMLKEM_MEMORYCONSUMPTION_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define MCUXCLMLKEM_KEYGEN_512_SIZEOF_WA_CPU         ( 2244U )
#define MCUXCLMLKEM_KEYGEN_768_SIZEOF_WA_CPU         ( 2340U )
#define MCUXCLMLKEM_KEYGEN_1024_SIZEOF_WA_CPU        ( 2436U )

#define MCUXCLMLKEM_ENCAPSULATION_512_SIZEOF_WA_CPU  ( 2308U )
#define MCUXCLMLKEM_ENCAPSULATION_768_SIZEOF_WA_CPU  ( 2404U )
#define MCUXCLMLKEM_ENCAPSULATION_1024_SIZEOF_WA_CPU ( 2500U )

#define MCUXCLMLKEM_DECAPSULATION_512_SIZEOF_WA_CPU  ( 2340U )
#define MCUXCLMLKEM_DECAPSULATION_768_SIZEOF_WA_CPU  ( 2436U )
#define MCUXCLMLKEM_DECAPSULATION_1024_SIZEOF_WA_CPU ( 2532U )

#define MCUXCLMLKEM_WORKAREASIZE_MAX                 ( 2532U )

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_MEMORYCONSUMPTION_H_ */
