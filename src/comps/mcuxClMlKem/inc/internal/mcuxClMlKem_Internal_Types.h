/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file:  mcuxClMlKem_Internal_Types.h
 * @brief: Internal type definitions of the crypto library ML-KEM component
 *
 */

#ifndef MCUXCLMLKEM_INTERNAL_TYPES_H_
#define MCUXCLMLKEM_INTERNAL_TYPES_H_

#ifdef __cplusplus
extern "C"
{
#endif

/* ML-KEM Params struct */
struct mcuxClMlKem_Params
{
  uint16_t polycompressedbytes;
  uint16_t polyveccompressedbytes;
  uint16_t polyvecbytes;
  uint16_t polycompressedbytes_gen;

  uint16_t secretkeybytes;
  uint16_t publickeybytes;
  uint16_t ciphertextbytes;

  uint8_t eta1;
  uint8_t k;
  mcuxClMlKem_Mode_t mode;
};

/* ML-KEM Params Descriptor type */
typedef struct mcuxClMlKem_Params mcuxClMlKem_ParamsDescriptor_t;

typedef const mcuxClMlKem_ParamsDescriptor_t * const mcuxClMlKem_Params_t;

/* Declarations for Param Descriptors for all parameter sets */
extern const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem512;
extern const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem768;
extern const mcuxClMlKem_ParamsDescriptor_t mcuxClMlKem_ParamsDescriptor_MlKem1024;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLKEM_INTERNAL_TYPES_H_ */
