/*--------------------------------------------------------------------------*/
/* Copyright 2024, 2026 NXP                                                 */
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
 * @file: mcuxClMlKem_KeyTypes.c
 * @brief: Key encoding mechanisms for ML-KEM
 *
 */
#include <mcuxCsslAnalysis.h>

#include <mcuxClKey_Constants.h>
#include <mcuxClMlKem.h>
#include <mcuxClKey_Types.h>

#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMlKem_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Public Key descriptors */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem512_Public = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLKEM_MLKEM_512_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem768_Public = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLKEM_MLKEM_768_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem1024_Public = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLMLKEM_MLKEM_1024_PK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

/* Private Key descriptors */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem512_Private = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLKEM_MLKEM_512_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem768_Private = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLKEM_MLKEM_768_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKem1024_Private = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLMLKEM_MLKEM_1024_SK_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

/* Shared secret descriptor */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_MlKemSharedSecret = {
  .algoId = MCUXCLKEY_ALGO_ID_MLKEM | MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY,
  .size = MCUXCLMLKEM_MLKEM_SHARED_SECRET_LEN,
  .info = NULL,
  .plainEncoding = &mcuxClMlKem_Key_Encoding_Descriptor_Plain
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
