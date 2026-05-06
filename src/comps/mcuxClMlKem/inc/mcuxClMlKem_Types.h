/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2026 NXP                                            */
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
 * @defgroup mcuxClMlKem_Types mcuxClMlKem_Types
 * @brief Types used by the ML-KEM operations.
 * @ingroup mcuxClMlKem
 * @{
 */

#ifndef MCUXCLMLKEM_TYPES_H_
#define MCUXCLMLKEM_TYPES_H_

#include <mcuxClMlKem_KeyTypes.h>
#include <mcuxClKey_Types.h>

#include <mcuxClKem_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint8_t mcuxClMlKem_Mode_t;

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()

/**
 * \brief ML-KEM Key generation Descriptors
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem512;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714484,REQ_1714487}
 */
static mcuxClKey_Generation_t mcuxClMlKem_KeyGeneration_512 = &mcuxClKey_KeyGenerationDescriptor_MlKem512;


MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem768;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714484,REQ_1714488}
 */
static mcuxClKey_Generation_t mcuxClMlKem_KeyGeneration_768 = &mcuxClKey_KeyGenerationDescriptor_MlKem768;

MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_KeyGenerationDescriptor_MlKem1024;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714484,REQ_1714489}
 */
static mcuxClKey_Generation_t mcuxClMlKem_KeyGeneration_1024 = &mcuxClKey_KeyGenerationDescriptor_MlKem1024;


MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem512;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714485,REQ_1714486,REQ_1714487}
 */
static mcuxClKem_Mode_t mcuxClMlKem_Mode_512 = &mcuxClKem_ModeDescriptor_MlKem512;


MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem768;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714485,REQ_1714486,REQ_1714488}
 */
static mcuxClKem_Mode_t mcuxClMlKem_Mode_768 = &mcuxClKem_ModeDescriptor_MlKem768;


MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKem_ModeDescriptor_t mcuxClKem_ModeDescriptor_MlKem1024;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * \implements{REQ_1714485,REQ_1714486,REQ_1714489}
 */
static mcuxClKem_Mode_t mcuxClMlKem_Mode_1024 = &mcuxClKem_ModeDescriptor_MlKem1024;

MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_TYPES_H_ */
