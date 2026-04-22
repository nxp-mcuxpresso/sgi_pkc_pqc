/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Types.h
 * @brief Type definitions of the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_Types mcuxClMlDsa_Types
 * @brief Types used by the ML-DSA operations.
 * @ingroup mcuxClMlDsa
 * @{
 */

#ifndef MCUXCLMLDSA_TYPES_H_
#define MCUXCLMLDSA_TYPES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <mcuxCsslAnalysis.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMlDsa_KeyTypes.h>
#include <mcuxClMlDsa_Constants.h>

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSignature_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Key generation modes */
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa44;
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa65;
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_MlDsa87;

/**
 * \implements{REQ_1714478,REQ_1714481,REQ_1714482,REQ_1714483}
 */
static mcuxClKey_Generation_t mcuxClKey_keyGeneration_MlDsa44 = &mcuxClKey_GenerationDescriptor_MlDsa44;
static mcuxClKey_Generation_t mcuxClKey_keyGeneration_MlDsa65 = &mcuxClKey_GenerationDescriptor_MlDsa65;
static mcuxClKey_Generation_t mcuxClKey_keyGeneration_MlDsa87 = &mcuxClKey_GenerationDescriptor_MlDsa87;

/**
 * @brief
 * Options type to select different modes of ML-DSA.
 * \implements{REQ_1714479,REQ_1714480,REQ_1714481,REQ_1714482,REQ_1714483}
 */
typedef uint32_t mcuxClMlDsa_Options_t;


MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_TYPES_H_ */
