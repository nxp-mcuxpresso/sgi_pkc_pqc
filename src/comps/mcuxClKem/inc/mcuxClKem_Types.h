/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

/** @file  mcuxClKem_Types.h
 *  @brief Type definitions for the mcuxClKem component
 */

#ifndef MCUXCLKEM_TYPES_H_
#define MCUXCLKEM_TYPES_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClKem_Types mcuxClKem_Types
 * @brief Types used by the Kem operations.
 * @ingroup mcuxClKem
 * @{
 */

/**
 * @brief Kem mode/algorithm descriptor structure
 *
 * This structure captures all the information that the Kem interfaces need
 * to know about a particular Kem mode/algorithm.
 */
struct mcuxClKem_ModeDescriptor;

/**
 * @brief Kem mode/algorithm descriptor type
 *
 * This type captures all the information that the Kem interfaces need to
 * know about a particular Kem mode/algorithm.
 */
typedef struct mcuxClKem_ModeDescriptor mcuxClKem_ModeDescriptor_t;

/**
 * @brief Kem mode/algorithm type
 *
 * This type is used to refer to a Kem mode/algorithm.
 */
typedef const mcuxClKem_ModeDescriptor_t * const mcuxClKem_Mode_t;


/**
 * @brief Kem status code
 *
 * This type provides information about the status of the Kem operation that
 * has been performed.
 */
typedef uint32_t mcuxClKem_Status_t;

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEM_TYPES_H_ */
