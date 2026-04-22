/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024, 2026 NXP                                            */
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
 * @file:   mcuxClMlKem_Params.c
 * @brief:  Params descriptors for ML-KEM
 *
 */
#include <mcuxCsslAnalysis.h>

#include <mcuxClMlKem.h>
#include <internal/mcuxClMlKem_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/*
 * Parameters and sizes for ML-KEM modes 2, 3, 4
 */
const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem512 = {
  .polycompressedbytes = MCUXCLMLKEM_POLYCOMPRESSEDBYTES(2u),
  .polyveccompressedbytes = MCUXCLMLKEM_POLYVECCOMPRESSEDBYTES(2u),
  .polyvecbytes = MCUXCLMLKEM_POLYVECBYTES(2u),
  .polycompressedbytes_gen = MCUXCLMLKEM_POLYCOMPRESSEDBYTES_GEN(2u),
  .secretkeybytes = MCUXCLMLKEM_SECRETKEYBYTES(2u),
  .publickeybytes = MCUXCLMLKEM_PUBLICKEYBYTES(2u),
  .ciphertextbytes = MCUXCLMLKEM_CIPHERTEXTBYTES(2u),
  .eta1 = MCUXCLMLKEM_ETA1(2u),
  .k = 2u,
  .mode = MCUXCLMLKEM_MODE_MLKEM512
};

const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem768  = {
  .polycompressedbytes = MCUXCLMLKEM_POLYCOMPRESSEDBYTES(3u),
  .polyveccompressedbytes = MCUXCLMLKEM_POLYVECCOMPRESSEDBYTES(3u),
  .polyvecbytes = MCUXCLMLKEM_POLYVECBYTES(3u),
  .polycompressedbytes_gen = MCUXCLMLKEM_POLYCOMPRESSEDBYTES_GEN(3u),
  .secretkeybytes = MCUXCLMLKEM_SECRETKEYBYTES(3u),
  .publickeybytes = MCUXCLMLKEM_PUBLICKEYBYTES(3u),
  .ciphertextbytes = MCUXCLMLKEM_CIPHERTEXTBYTES(3u),
  .eta1 = MCUXCLMLKEM_ETA1(3u),
  .k = 3u,
  .mode = MCUXCLMLKEM_MODE_MLKEM768
};

const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem1024 = {
  .polycompressedbytes = MCUXCLMLKEM_POLYCOMPRESSEDBYTES(4u),
  .polyveccompressedbytes = MCUXCLMLKEM_POLYVECCOMPRESSEDBYTES(4u),
  .polyvecbytes = MCUXCLMLKEM_POLYVECBYTES(4u),
  .polycompressedbytes_gen = MCUXCLMLKEM_POLYCOMPRESSEDBYTES_GEN(4u),
  .secretkeybytes = MCUXCLMLKEM_SECRETKEYBYTES(4u),
  .publickeybytes = MCUXCLMLKEM_PUBLICKEYBYTES(4u),
  .ciphertextbytes = MCUXCLMLKEM_CIPHERTEXTBYTES(4u),
  .eta1 = MCUXCLMLKEM_ETA1(4u),
  .k = 4u,
  .mode = MCUXCLMLKEM_MODE_MLKEM1024
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
