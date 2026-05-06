/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Types.h
 * @brief: Type definitions of the @ref mcuxClMlKem component
 *
 * @defgroup mcuxClMlKem_KeyTypes mcuxClMlKem_KeyTypes
 * @brief Key types used by the ML-KEM operations.
 * @ingroup mcuxClMlKem
 * @{
 */

#ifndef MCUXCLMLKEM_KEYTYPES_H_
#define MCUXCLMLKEM_KEYTYPES_H_

#include <mcuxCsslAnalysis.h>
#include <mcuxClKey.h>

#ifdef __cplusplus
extern "C"
{
#endif

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/* Public Key types */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem512_Public;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem768_Public;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem1024_Public;

/* Private Key types */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem512_Private;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem768_Private;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem1024_Private;

/* Shared Secret type */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKemSharedSecret;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()

static const mcuxClKey_Type_t mcuxClKey_Type_MlKem512_Public = &mcuxClKey_TypeDescriptor_MlKem512_Public;
static const mcuxClKey_Type_t mcuxClKey_Type_MlKem768_Public = &mcuxClKey_TypeDescriptor_MlKem768_Public;
static const mcuxClKey_Type_t mcuxClKey_Type_MlKem1024_Public = &mcuxClKey_TypeDescriptor_MlKem1024_Public;

/* Private Key types */
static const mcuxClKey_Type_t mcuxClKey_Type_MlKem512_Private = &mcuxClKey_TypeDescriptor_MlKem512_Private;
static const mcuxClKey_Type_t mcuxClKey_Type_MlKem768_Private = &mcuxClKey_TypeDescriptor_MlKem768_Private;
static const mcuxClKey_Type_t mcuxClKey_Type_MlKem1024_Private = &mcuxClKey_TypeDescriptor_MlKem1024_Private;

/* Shared Secret type */
static const mcuxClKey_Type_t mcuxClKey_Type_MlKemSharedSecret = &mcuxClKey_TypeDescriptor_MlKemSharedSecret;

MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()
/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_KEYTYPES_H_ */
