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
 * @file mcuxClMlDsa_KeyTypes.c
 * @brief Implementation of @ref mcuxClMlDsa related key type descriptors.
 *
 */

#include <mcuxClMlDsa_Constants.h>
#include <mcuxClMlDsa_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClKey_Constants.h>
#include <mcuxClMlDsa_KeyEncodings.h>

#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClMemory_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Key Type descriptors */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa44_Public  =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLDSA_MLDSA44_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa65_Public  =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLDSA_MLDSA65_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa87_Public  =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLDSA_MLDSA87_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa44_Private =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLDSA_MLDSA44_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa65_Private =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLDSA_MLDSA65_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlDsa87_Private =
{
  .algoId = MCUXCLKEY_ALGO_ID_MLDSA | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLDSA_MLDSA87_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlDsa_Key_Encoding_Descriptor_Plain
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

