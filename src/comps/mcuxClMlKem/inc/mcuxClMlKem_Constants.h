/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Constants.h
 * @brief: Constant definitions of the @ref mcuxClMlKem component
 *
 * @defgroup mcuxClMlKem_Constants mcuxClMlKem_Constants
 * @ingroup mcuxClMlKem
 * @brief Constants used in the @ref mcuxClMlKem component.
 * @{
 */

#ifndef MCUXCLMLKEM_CONSTANTS_H_
#define MCUXCLMLKEM_CONSTANTS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClMlKem_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* ML-KEM modes */
#define MCUXCLMLKEM_MODE_MLKEM512                   ( (mcuxClMlKem_Mode_t) 0x33u )
#define MCUXCLMLKEM_MODE_MLKEM768                   ( (mcuxClMlKem_Mode_t) 0xC3U )
#define MCUXCLMLKEM_MODE_MLKEM1024                  ( (mcuxClMlKem_Mode_t) 0x3CU )

/* ML-KEM key and message sizes */
#define MCUXCLMLKEM_MLKEM_512_SK_LEN                ( 832U  )
#define MCUXCLMLKEM_MLKEM_768_SK_LEN                ( 1216U )
#define MCUXCLMLKEM_MLKEM_1024_SK_LEN               ( 1600U )

#define MCUXCLMLKEM_MLKEM_512_PK_LEN                ( 800U  )
#define MCUXCLMLKEM_MLKEM_768_PK_LEN                ( 1184U )
#define MCUXCLMLKEM_MLKEM_1024_PK_LEN               ( 1568U )

#define MCUXCLMLKEM_MLKEM_512_CT_LEN                ( 768U  )
#define MCUXCLMLKEM_MLKEM_768_CT_LEN                ( 1088U )
#define MCUXCLMLKEM_MLKEM_1024_CT_LEN               ( 1568U )

#define MCUXCLMLKEM_MLKEM_SHARED_SECRET_LEN         ( 32U )

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_CONSTANTS_H_ */
