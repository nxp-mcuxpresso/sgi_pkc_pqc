/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
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
 * @file mcuxClMlKem_KeyEncodings.h
 * @brief Key encodings used by the @ref mcuxClMlKem component.
 *
 * @defgroup mcuxClMlKem_KeyEncoding mcuxClMlKem_KeyEncoding
 * @ingroup mcuxClMlKem
 * @brief Key encodings used in the @ref mcuxClMlKem component.
 * @{
 */

#ifndef MCUXCLMLKEM_KEYENCODINGS_H_
#define MCUXCLMLKEM_KEYENCODINGS_H_
#include <mcuxCsslAnalysis.h>

#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()

/**
 * @brief Plain key encoding descriptor for ML-KEM keys.
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
extern const mcuxClKey_EncodingDescriptor_t mcuxClMlKem_Key_Encoding_Descriptor_Plain;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
/**
 * @brief Plain key encoding for ML-KEM keys.
 */
static const mcuxClKey_Encoding_t mcuxClMlKem_Key_Encoding_Plain = &mcuxClMlKem_Key_Encoding_Descriptor_Plain;

MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* MCUXCLMLKEM_KEYENCODINGS_H_ */
