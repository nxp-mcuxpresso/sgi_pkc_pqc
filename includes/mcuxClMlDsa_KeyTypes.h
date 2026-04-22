/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_KeyTypes.h
 * @brief Key type definitions of the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_KeyTypes mcuxClMlDsa_KeyTypes
 * @brief Key types used by the ML-DSA operations.
 * @ingroup mcuxClMlDsa
 * @{
 */

#ifndef MCUXCLMLDSA_KEYTYPES_H_
#define MCUXCLMLDSA_KEYTYPES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <mcuxCsslAnalysis.h>
#include <mcuxClKey_Types.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSignature_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa44_Public;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa65_Public;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa87_Public;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa44_Private;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa65_Private;
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa87_Private;

static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa44_Public = &mcuxClKey_TypeDescriptor_MlDsa44_Public;
static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa65_Public = &mcuxClKey_TypeDescriptor_MlDsa65_Public;
static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa87_Public = &mcuxClKey_TypeDescriptor_MlDsa87_Public;
static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa44_Private = &mcuxClKey_TypeDescriptor_MlDsa44_Private;
static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa65_Private = &mcuxClKey_TypeDescriptor_MlDsa65_Private;
static const mcuxClKey_Type_t mcuxClKey_Type_MlDsa87_Private = &mcuxClKey_TypeDescriptor_MlDsa87_Private;

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_TYPES_H_ */
