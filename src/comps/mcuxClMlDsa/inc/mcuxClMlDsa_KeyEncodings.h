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
 * @file mcuxClMlDsa_KeyEncodings.h
 * @brief Key encodings used by the @ref mcuxClMlDsa component.
 *
 * @defgroup mcuxClMlDsa_KeyEncoding mcuxClMlDsa_KeyEncoding
 * @ingroup mcuxClMlDsa
 * @brief Key encodings used in the @ref mcuxClMlDsa component.
 * @{
 */

#ifndef MCUXCLMLDSA_KEYENCODINGS_H_
#define MCUXCLMLDSA_KEYENCODINGS_H_

#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C"
{
#endif

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()

/**
 * @brief Plain key encoding descriptor for ML-DSA keys.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClMlDsa_Key_Encoding_Descriptor_Plain;
/**
 * @brief Plain key encoding for ML-DSA keys.
 */
static const mcuxClKey_Encoding_t mcuxClMlDsa_Key_Encoding_Plain = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain;

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_KEYENCODINGS_H_ */
