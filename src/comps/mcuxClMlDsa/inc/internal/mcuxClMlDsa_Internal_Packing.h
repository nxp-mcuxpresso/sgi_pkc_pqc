/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Internal_Packing.h
 * @brief Interface for (un)packing operations in @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_PACKING_H_
#define MCUXCLMLDSA_INTERNAL_PACKING_H_

#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClMlDsa_Types.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>

/**
 * @brief ML-DSA pack polynomial with coefficients bounded by params->eta
 *
 * Pack a polynomial with coefficients in [-eta,eta].
 *
 * @param[in]       session         Session handle
 * @param[out]      r               Pointer to packed version of polynomial
 * @param[in]       a               Pointer to unpacked version of polynomial
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Eta_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Pack(
  mcuxClSession_Handle_t session,
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params);

/**
 * @brief ML-DSA unpack polynomial with coefficients bounded by params->eta
 *
 * Unpack a polynomial with coefficients in [-eta,eta].
 *
 * @param[in]       session         Session handle
 * @param[out]      r               Pointer to unpacked version of polynomial
 * @param[in]       a               Pointer to packed version of polynomial
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Eta_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *r,
  const uint8_t *a,
  const mcuxClMlDsa_Params_t *params);

/**
 * @brief ML-DSA pack t1 into 10-bit values
 *
 * Pack t1 from unpacked version into 10-bit coefficients.
 * Output coefficients are standard representatives.
 *
 * @param[out]      r               Pointer to packed version of t0
 * @param[in]       a               Pointer to unpacked version of t0
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_T1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Pack(
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA unpack t1 from 10-bit values
 *
 * Unpack t1 from packed version of 10-bit coefficients.
 * Output coefficients are standard representatives.
 *
 * @param[out]      unpackedPoly    Pointer to unpacked version of t0
 * @param[in]       packedPoly      Pointer to packed version of t0
 *
 * Data Integrity: Expunge(unpackedPoly + packedPoly)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_T1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Unpack(
  mcuxClMlDsa_Poly_t * unpackedPoly,
  const uint8_t * packedPoly);

/**
 * @brief ML-DSA pack t0
 *
 * Pack polynomial t0 with coefficients in [-2^{D-1}+1, 2^{D-1}], where
 * D=13 is the ML-DSA parameter d.
 *
 * @param[out]      r               Pointer to packed version of t0
 * @param[in]       a               Pointer to unpacked version of t0
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_T0_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Pack(
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a);

/**
 * @brief ML-DSA unpack t0
 *
 * Unpack polynomial t0 with coefficients in [-2^{D-1}+1, 2^{D-1}], where
 * D=13 is the ML-DSA parameter d.
 *
 * @param[out]      unpackedPoly    Pointer to unpacked version of t0
 * @param[in]       packedPoly      Pointer to packed version of t0
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_T0_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Unpack(
  mcuxClMlDsa_Poly_t *unpackedPoly,
  const uint8_t *packedPoly);

/**
 * @brief ML-DSA pack z with coefficients bounded by +/-params->gamma1
 *
 * Pack polynomial z with coefficients in [-gamma1+1, gamma1].
 *
 * @param[in]       session         Session handle
 * @param[out]      rBuf            Pointer to packed version of z
 * @param[in]       a               Pointer to unpacked version of z
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Z_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Pack(
  mcuxClSession_Handle_t session,
  mcuxCl_Buffer_t rBuf,
  const mcuxClMlDsa_Poly_t* a,
  const mcuxClMlDsa_Params_t* params);

/**
 * @brief ML-DSA unpack z with coefficients bounded by +/-params->gamma1
 *
 * Unpack polynomial z with coefficients in [-gamma1+1, gamma1].
 * Internally calls either one of two functions, depending on gamma1:
 *   - mcuxClMlDsa_Packing_Z_Unpack_17 if gamma1 = 2^17;
 *   - mcuxClMlDsa_Packing_Z_Unpack_19 if gamma1 = 2^19.
 *
 * @param[in]       session         Session handle
 * @param[out]      r               Pointer to unpacked version of z
 * @param[in]       a               Pointer to packed version of z
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Z_Unpack_17)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_17(
  int32_t *r,
  const uint8_t *a);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Z_Unpack_19)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_19(
  int32_t *r,
  const uint8_t *a);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_Z_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t* r,
  mcuxCl_InputBuffer_t zBuf,
  const mcuxClMlDsa_Params_t* params);

/**
 * @brief ML-DSA pack polynomial w1
 *
 * Pack polynomial w1.
 * - For params->gamma2 = 95232, the range of the coefficients is [0, 15].
 * - For params->gamma2 = 261888, the range of the coefficients is [0, 43].
 *
 * @param[in]       session         Session handle
 * @param[out]      r               Pointer to packed version of w1
 * @param[in]       a               Pointer to unpacked version of w1
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_W1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W1_Pack(
  mcuxClSession_Handle_t session,
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params);

/**
 * @brief ML-DSA unpack polynomial w1
 *
 * Unpack polynomial w1.
 * - For params->gamma2 = 95232, the range of the coefficients is [0, 15].
 * - For params->gamma2 = 261888, the range of the coefficients is [0, 43].
 *
 * @param[in]       session         Session handle
 * @param[out]      a               Pointer to unpacked version of w1
 * @param[in]       r               Pointer to packed version of w1
 * @param[in]       params          Pointer to ML-DSA parameter set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_W1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W1_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t *a,
  const uint8_t *r,
  const mcuxClMlDsa_Params_t *params);

/**
 * @brief ML-DSA pack w
 *
 * Pack full polynomial w into 3 * 256 = 768 bytes, covering the
 * 256 coefficients of the polynomial.
 *
 * @param[out]      a               Pointer to packed version of w
 * @param[in]       w               Pointer to unpacked version of w
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_W_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Pack(
  uint8_t *a,
  const mcuxClMlDsa_Poly_t *w);

/**
 * @brief ML-DSA unpack w
 *
 * Unpack full polynomial w from 3 * 256 = 768 bytes, covering the
 * 256 coefficients of the polynomial.
 *
 * @param[out]      w               Pointer to unpacked version of w
 * @param[in]       a               Pointer to packed version of w
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_W_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Unpack(
  mcuxClMlDsa_Poly_t *w,
  const uint8_t *a);

/**
 * @brief ML-DSA pack challenge c
 *
 * c is a polynomial with 256 coefficients, of which TAU < 64
 * coefficients are in {-1,1}, and the rest are 0. We retrieve
 * the 256 coefficients from 256 + 64 packed bits, where the first
 * 256 bits describe if the coefficient is 0 or not, and the last
 * 64 bits indicate whether these <=64 set bits (in order) are +/-1.
 * Note that a 1 in the last 64 bits of cPacked indicates a -1 in c,
 * while a 0 in the last 64 bits indicates a 1 in c.
 *
 * @param[out]      cPacked         Pointer to packed version of c
 * @param[in]       c               Pointer to unpacked version of c
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_C_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Pack(
  uint8_t *cPacked,
  const mcuxClMlDsa_Poly_t *c,
  const mcuxClMlDsa_Params_t *const params);

/**
 * @brief ML-DSA unpack challenge c
 *
 * c is a polynomial with 256 coefficients, of which TAU < 64
 * coefficients are in {-1,1}, and the rest are 0. We retrieve
 * the 256 coefficients from 256 + 64 packed bits, where the first
 * 256 bits describe if the coefficient is 0 or not, and the last
 * 64 bits indicate whether these <=64 set bits (in order) are +/-1.
 * Note that a 1 in the last 64 bits of cPacked indicates a -1 in c,
 * while a 0 in the last 64 bits indicates a 1 in c.
 *
 * @param[out]      c               Pointer to unpacked version of c
 * @param[in]       cPacked         Pointer to packed version of c
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_C_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Unpack(
  mcuxClMlDsa_Poly_t *c,
  const uint8_t *cPacked,
  const mcuxClMlDsa_Params_t *params);

/**
 * @brief ML-DSA unpack h
 *
 * Unpack h[i] of signature sig = (c, z, h).
 *
 * @param[in]       session         Session handle
 * @param[in]       pH              Pointer to output hint h
 * @param[in]       i               Index of h in hint vector
 * @param[in]       pHPacked        Workarea to read packed hints into
 * @param[in]       hintBuf         Buffer to hint in the signature
 * @param[out]      pParams         Pointer to ML-DSA parameter set structure
 *
 * @return Returns an explicit status code on failure
 *
 * @retval MCUXCLSIGNATURE_STATUS_OK          Everything ok
 *
 * @post Data Integrity: Expunge(pParams + pH)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_H_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Packing_H_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t* pH,
  uint16_t i,
  uint8_t* const pHPacked,
  mcuxCl_InputBuffer_t hintBuf,
  const mcuxClMlDsa_Params_t* pParams);

/**
 * @brief ML-DSA unpack secret key
 *
 * Partially unpack secret key sk = (rho, tr, key, t0, s1, s2).
 * Unpacks rho, tr and key - t0, s1 and s2 are done on the fly.
 *
 * @param[out]      rho             Pointer to output byte array for rho
 * @param[out]      tr              Pointer to output byte array for tr
 * @param[out]      key             Pointer to output byte array for key
 * @param[in]       sk              Pointer to byte array containing bit-packed secret key
 *
 * @return void
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_Packing_SK_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_SK_Unpack(
  uint8_t* rho,
  uint8_t* tr,
  uint8_t* key,
  const uint8_t *sk);

#endif /* MCUXCLMLDSA_INTERNAL_PACKING_H_ */
