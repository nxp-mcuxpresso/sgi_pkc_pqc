/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file mcuxClMlDsa_Internal_Types.h
 * @brief Internal type definitions for the @ref mcuxClMlDsa component.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_TYPES_H_
#define MCUXCLMLDSA_INTERNAL_TYPES_H_

#include <mcuxClBuffer.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClHash_Types.h>
#include <internal/mcuxClMlDsa_Internal_Constants.h>


/**
 * @brief Type used to indicate the ML-DSA mode (44, 65, 87), the API mode (PURE and PREHASH).
 * The structure is as follows: RFU (5 nibbles) || API mode (nibble) || ML-DSA mode (1 byte).
 * Explicit internal ML-DSA modes are described in Internal_Constants.h.
 */
typedef uint32_t mcuxClMlDsa_Mode_t;

/**
 * @brief
 * Polynomial struct type.
 * The N (= 256) coefficients of a polynomial are stored
 * as signed 32-bit integers.
 */
typedef struct
{
  int32_t coefficients[MCUXCLMLDSA_N];
} mcuxClMlDsa_Poly_t;

/**
 * @brief
 * ML-DSA parameters struct type.
 * The elements are ordered to make sure memory reads are
 * as much aligned as possible.
 *
 * @note
 * Reordering/resizing these fields will invalidate the CRCs that are
 * hardcoded in Internal_Constants.h.
 *
 * If the parameter structure does get changed, the CRC can be recomputed by
 * running Verify and outputting the actual CRC rather than the error code
 * when the CRC is not a match in a test. The right CRC can then be read out
 * and copied into Internal_Constants.h accordingly.
 */
typedef struct mcuxClMlDsa_Params_t
{
  uint32_t gamma1;                  /** The coefficient range of y. */
  uint32_t gamma2;                  /** The low-order rounding range. */
  uint32_t signature_bytes;         /** The number of bytes needed to store the signature. */

  mcuxClMlDsa_Mode_t mode;           /** The ML-DSA mode (44, 65, 87). */

  uint16_t cTildeSize;              /** The size of c tilde */
  uint16_t trSize;                  /** The size of the hash of the public key */

  uint16_t publickey_bytes;         /** The number of bytes needed to store the public key. */
  uint16_t secretkey_bytes;         /** The number of bytes needed to store the private/secret key. */
  uint16_t polyz_packedbytes;       /** The number of bytes needed to store one packed entry (out of L) of z. */
  uint16_t polyw1_packedbytes;      /** The number of bytes needed to store w_1 in packed form. */
  uint16_t polyeta_packedbytes;     /** The number of bytes needed to store polynomials with n coefficients in [-eta, eta]. */
  uint16_t max_attempts;            /** The maximum number of attempts in signature generation to guarantee a failure rate <= 2^(-128). */

  uint8_t k;                        /** The number of rows of the matrix A. */
  uint8_t l;                        /** The number of columns of the matrix A. */
  uint8_t eta;                      /** The range of entries in the private key. */
  uint8_t beta;                     /** Maximum offset in bound check due to challenge multiplied by private key. */
  uint8_t tau;                      /** The number of non-zero entries in the challenge. */
  uint8_t omega;                    /** Maximum number of 1's in the hint vector. */
  uint8_t polyvech_packedbytes;     /** The memory used for storing the hint part of the signature. */

  uint32_t crc;                     /** The checksum of the ML-DSA parameter structure, used for data integrity protection. */
} mcuxClMlDsa_Params_t;

/**
 * @brief
 * ML-DSA specific protocol descriptor structure for
 * signature generation/verification with @ref mcuxClSignature.
 */
struct mcuxClMlDsa_Signature_ProtocolDescriptor
{
  mcuxClMlDsa_Mode_t mode;                           /** Type used to indicate the ML-DSA mode (44, 65, 87), the API mode (PURE, PRE-HASH) and the wrapper mode (INTERNAL, EXTERNAL) */
  mcuxClHash_AlgorithmDescriptor_t *pPreHashAlgo;    /** If PRE-HASH is used, the algorithm that is used to pre-hash the message; otherwise NULL. */
  mcuxCl_InputBuffer_t ctx;                          /** User provided context string; otherwise NULL. */
  uint8_t ctxLength;                                /** Length of the user provided context string; otherwise 0U. */
};


#endif /* MCUXCLMLDSA_INTERNAL_TYPES_H_ */
