/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025-2026 NXP                                            */
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

/** @file  mcuxClKem_Constants.h
 *  @brief Constants for use with the mcuxClKem component */

#ifndef MCUXCLKEM_CONSTANTS_H_
#define MCUXCLKEM_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClKem_Constants mcuxClKem_Constants
 * @brief Constants of @ref mcuxClKem component
 * @ingroup mcuxClKem
 * @{
 */

/* Error codes */
#define MCUXCLKEM_STATUS_OK                       ((mcuxClKem_Status_t) 0x00612E03u)
#define MCUXCLKEM_STATUS_ERROR                    ((mcuxClKem_Status_t) 0x00615330u)
#define MCUXCLKEM_STATUS_ERROR_MEMORY_ALLOCATION  ((mcuxClKem_Status_t) 0x0061534Fu)
#define MCUXCLKEM_STATUS_INVALID_PARAMS           ((mcuxClKem_Status_t) 0x006153F8u)
#define MCUXCLKEM_STATUS_FAULT_ATTACK             ((mcuxClKem_Status_t) 0x0061F0F0u)

/** @}*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEM_CONSTANTS_H_ */
