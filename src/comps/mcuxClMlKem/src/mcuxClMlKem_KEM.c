/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file:   mcuxClMlKem_KEM.c
 * @brief:  Functions for the KEM
 *
 */

#include <mcuxClCore_Macros.h>

#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMlKem.h>
#include <mcuxClKem.h>
#include <mcuxClRandom.h>
#include <mcuxClSession_Types.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMlKem_Indcpa.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClMlKem_Utils.h>
#include <internal/mcuxClPrng_Internal_Functions.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClXof_Internal.h>


#include <mcuxClKem_Constants.h>
#include <internal/mcuxClKem_Internal_Types.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_castToParams)
static mcuxClMlKem_Params_t mcuxClMlKem_castToParams(const void* pWa)
{
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
  return (mcuxClMlKem_Params_t) pWa;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_KeyGen_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_KeyGen_Internal(mcuxClSession_Handle_t session,
                                                            mcuxClKey_Generation_t mode,
                                                            mcuxClKey_Handle_t privateKey,
                                                            mcuxClKey_Handle_t publicKey,
                                                            const uint8_t d[MCUXCLMLKEM_SYMBYTES],
                                                            uint8_t z[MCUXCLMLKEM_SYMBYTES])
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_KeyGen_Internal);

  mcuxClMlKem_Params_t pParams = mcuxClMlKem_castToParams(mode->pProtocolDescriptor);
  /* Ideally, we would not get a raw pointer from the key, but we still need to hash the public key into the secret key */
  uint8_t *pPublicKey = mcuxClKey_getKeyData(publicKey);
  MCUXCLBUFFER_INIT_RO(publicKeyBuf, session, pPublicKey, mcuxClKey_getSize(publicKey));

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->secretkeybytes, MCUXCLMLKEM_SYMBYTES, MCUXCLMLKEM_SECRETKEYBYTES(3u), MCUXCLKEM_STATUS_ERROR)

  /* Write random z to sk */
  uint32_t zOff = (uint32_t)pParams->secretkeybytes - MCUXCLMLKEM_SYMBYTES;
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privateKey));
  MCUXCLKEY_STORE_FP(
    session,
    privateKey,
    z,
    MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE
      | MCUXCLKEY_ENCODING_SPEC_MLKEM_SK_Z
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(zOff / (uint16_t)sizeof(uint32_t))
      | MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t)));


  /* Generate IND-CPA keypair */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams contains only algorithm-specific constants that are defined inside of the CL")
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Generate_Keys, mcuxClMlKem_Indcpa_Generate_Keys(session, publicKey, privateKey, d, pParams));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Generate_Keys)
  {
    MCUXCLSESSION_ERROR(session, ret_Generate_Keys);
  }

  /* Hash public key and include digest into private key */
  uint32_t outSize = 0u;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams->publickeybytes is an algorithm-specific constant that is defined inside of the CL")
  /* re-use z to hold a hash the public key */
  MCUXCLBUFFER_INIT_RW(hashPk, NULL, z, 0u);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Hash_compute,
                            mcuxClHash_compute(session,
                                              mcuxClHash_Algorithm_Sha3_256,
                                              publicKeyBuf,
                                              pParams->publickeybytes,
                                              hashPk,
                                              &outSize));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLHASH_STATUS_OK != ret_Hash_compute)
  {
    MCUXCLSESSION_ERROR(session, ret_Hash_compute);
  }

  /* Write H(pk) to sk */
  uint32_t hashPkOff = (uint32_t)pParams->secretkeybytes - 2u * MCUXCLMLKEM_SYMBYTES;
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privateKey));
  MCUXCLKEY_STORE_FP(
    session,
    privateKey,
    z,
    MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_MLKEM_SK_H_PK |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET(hashPkOff / sizeof(uint32_t)) |
      MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE(MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t))
  );


  /* Link Keypair */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_linkKeyPair(session, privateKey, publicKey));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_KeyGen_Internal,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Indcpa_Generate_Keys),
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_linkKeyPair));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_KeyGen, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_KeyGen(mcuxClSession_Handle_t session,
                                                                mcuxClKey_Generation_t mode,
                                                                mcuxClKey_Handle_t privateKey,
                                                                mcuxClKey_Handle_t publicKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_KeyGen);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t *, zd, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * MCUXCLMLKEM_SYMBYTES)));

  MCUXCLBUFFER_INIT_RW(zdBuf, NULL, zd, 2U * MCUXCLMLKEM_SYMBYTES);

  /* Init z and d using low entropy randomness */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(zd, 2U * MCUXCLMLKEM_SYMBYTES));

  /* Sample z and d */
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Hash_Randombytes, mcuxClRandom_generate(session, zdBuf, 2U * MCUXCLMLKEM_SYMBYTES));
  if(MCUXCLRANDOM_STATUS_OK != ret_Hash_Randombytes)
  {
    MCUXCLSESSION_ERROR(session, ret_Hash_Randombytes);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_KeyGen_Internal(session,
                                                            mode,
                                                            privateKey,
                                                            publicKey,
                                                            /* z */ zd,
                                                            /* d */ zd + MCUXCLMLKEM_SYMBYTES));

  /* Free up z and d */
  mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(2U * MCUXCLMLKEM_SYMBYTES));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_KeyGen,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_KeyGen_Internal)
    );
}

/**
 * @brief Helper function to check the encapsulation inputs according to FIPS 203, Section 7.2
 *
 * @param[in]    key            Handle of the secret key
 * @param[in]    pPublicKey     Pointer to the loaded public key
 * @param[in]    pParams        Pointer to parameter structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLKEM_STATUS_OK             Kem operation successful
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Encaps_CheckInputs)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)
mcuxClMlKem_Encaps_CheckInputs(mcuxClKey_Handle_t     key,
                              const uint8_t*        pPublicKey,
                              mcuxClMlKem_Params_t   pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Encaps_CheckInputs);

  /* 1. Encapsulation key length check */
  if(mcuxClKey_getKeyContainerSize(key) != pParams->publickeybytes)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encaps_CheckInputs, MCUXCLKEM_STATUS_INVALID_PARAMS);
  }

  /* 2. Decode check: each decoded coefficient must be < q */
  mcuxClKem_Status_t result = MCUXCLKEM_STATUS_OK;
  uint16_t val0 = 0u;
  uint16_t val1 = 0u;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint32_t i = 0u; i < MCUXCLMLKEM_N / 2u; i++)
  {
    val0 = ((uint16_t)pPublicKey[3u * i + 0u]       | ((uint16_t)pPublicKey[3u * i + 1u] & 0x0fu) << 8u) & 0xFFFFu;
    val1 = ((uint16_t)pPublicKey[3u * i + 1u] >> 4u | ((uint16_t)pPublicKey[3u * i + 2u] & 0xffu) << 4u) & 0xFFFFu;
    if((val0 >= MCUXCLMLKEM_Q) || (val1 >= MCUXCLMLKEM_Q))
    {
      result = MCUXCLKEM_STATUS_INVALID_PARAMS;
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encaps_CheckInputs, result,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_N / 2u));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Encaps_Internal)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encaps_Internal(mcuxClSession_Handle_t session,
                                                                         const uint8_t* pPublicKey,
                                                                         mcuxClMlKem_Params_t  pParams,
                                                                         const uint8_t m[MCUXCLMLKEM_SYMBYTES],
                                                                         mcuxClKey_Handle_t sharedKey,
                                                                         mcuxCl_Buffer_t pOut,
                                                                         uint32_t *const pOutSize)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Encaps_Internal);

  /* buf will be the backing memory for both m || H(pk) initially and (K, r) after hashing */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, kr, mcuxClSession_allocateWords_cpuWa(session, (2u * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)));


  MCUXCLBUFFER_INIT_RW(krBuf, session, kr, 2U * MCUXCLMLKEM_SYMBYTES);
  MCUXCLBUFFER_DERIVE_RW(pkDigestBuf, krBuf, MCUXCLMLKEM_SYMBYTES);

  /* Init (K, r) = G(m || H(pk))  with low entropy randomness */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(kr, 2U * MCUXCLMLKEM_SYMBYTES));

  /* copy m into buf */
  MCUX_CSSL_DI_RECORD(copyMParams, kr);
  MCUX_CSSL_DI_RECORD(copyMParams, m);
  MCUX_CSSL_DI_RECORD(copyMParams, MCUXCLMLKEM_SYMBYTES);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(kr, m, MCUXCLMLKEM_SYMBYTES));

  /* Hash the public key in to buf */
  uint32_t outSize = 0u;
  MCUXCLBUFFER_INIT_RO(publicKeyBuf, session, pPublicKey, mcuxClKey_getSize(publicKey));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams->publickeybytes is an algorithm-specific constant that is defined inside of the CL")
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Hash_compute2, mcuxClHash_compute(session, mcuxClHash_Algorithm_Sha3_256, publicKeyBuf, pParams->publickeybytes, pkDigestBuf, &outSize));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLHASH_STATUS_OK != ret_Hash_compute2)
  {
    MCUXCLSESSION_ERROR(session, ret_Hash_compute2);
  }

  /* Generate (K, r) = G(m || H(pk)) (in place) */
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Hash_compute3, mcuxClHash_compute(session, mcuxClHash_Algorithm_Sha3_512, krBuf, 2u * MCUXCLMLKEM_SYMBYTES, krBuf, &outSize));
  if(MCUXCLHASH_STATUS_OK != ret_Hash_compute3)
  {
    MCUXCLSESSION_ERROR(session, ret_Hash_compute3);
  }

  mcuxClMemory_Status_t rc = 0u; /* This is only a placeholder for mcuxClMlKem_Encrypt */

  MCUXCLBUFFER_DERIVE_RW(ctBuf, pOut, 0u);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams contains only algorithm-specific constants that are defined inside of the CL")
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Indcpa_Encryption,
                            mcuxClMlKem_Encrypt(session,
                                               ctBuf,
                                               m,
                                               pPublicKey,
                                               kr + MCUXCLMLKEM_SYMBYTES, /* r (aka coins) */
                                               mcuxClMlKem_Poly_Compress_Write, /* upon encryption: write ciphertext poly to pOut */
                                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Write),
                                               pParams,
                                               &rc));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Indcpa_Encryption)
  {
    MCUXCLSESSION_ERROR(session, ret_Indcpa_Encryption);
  }

  /* Store the shared secret according to the key encoding  */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sharedKey));
  MCUXCLKEY_STORE_FP(
    session,
    sharedKey,
    kr, /* K is at beginning of kr */
    MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_SINGLE_PART
  );

  *pOutSize = (uint32_t)pParams->ciphertextbytes;

  mcuxClSession_freeWords_cpuWa(session, ((2u * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encaps_Internal,
                            MCUXCLKEM_STATUS_OK,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encrypt));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Encaps, mcuxClKem_encapsulateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Encaps(mcuxClSession_Handle_t session,
                                                                mcuxClKey_Handle_t key,
                                                                mcuxClKem_Mode_t mode,
                                                                mcuxClKey_Handle_t sharedKey,
                                                                mcuxCl_Buffer_t pOut,
                                                                uint32_t *const pOutSize)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Encaps);
  /* Load public key - retrieve pointer */
  uint8_t *pPublicKeyDest = NULL;

  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
  MCUXCLKEY_LOAD_FP(session, key, &pPublicKeyDest, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);

  const uint8_t *pPublicKey = (const uint8_t*)pPublicKeyDest;

  mcuxClMlKem_Params_t pParams = mcuxClMlKem_castToParams(mode->pAlgorithmDescriptor);

  /* Check encapsulation inputs */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encaps_CheckInputs));
  MCUX_CSSL_FP_FUNCTION_CALL(ret_CheckInputs, mcuxClMlKem_Encaps_CheckInputs(key, pPublicKey, pParams));
  if(MCUXCLKEM_STATUS_OK != ret_CheckInputs)
  {
    MCUXCLSESSION_ERROR(session, ret_CheckInputs);
  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, m, mcuxClSession_allocateWords_cpuWa(session, MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t)));

  /* Init m with low-entropy rng */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(m, MCUXCLMLKEM_SYMBYTES));

  /* Generate random m */
  MCUXCLBUFFER_INIT(mBuf, session, m, MCUXCLMLKEM_SYMBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_RandomGenerate, mcuxClRandom_generate(session, mBuf, MCUXCLMLKEM_SYMBYTES));
  if(MCUXCLRANDOM_STATUS_OK != ret_RandomGenerate)
  {
    MCUXCLSESSION_ERROR(session, ret_RandomGenerate);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(retInternalEncaps,
                            mcuxClMlKem_Encaps_Internal(session, pPublicKey, pParams, m, sharedKey, pOut, pOutSize));

  mcuxClSession_freeWords_cpuWa(session, MCUXCLMLKEM_SYMBYTES / sizeof(uint32_t));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Encaps, retInternalEncaps,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encaps_Internal));
}


/**
 * @brief Helper function to check the decapsulation inputs according to FIPS 203, Section 7.3
 *
 * @param[in]    session        Session handle
 * @param[in]    inSize         Size of the ciphertext input
 * @param[in]    key            Handle of the secret key
 * @param[in]    pPrivateKey    Pointer to the loaded secret key
 * @param[in]    pubKey         Handle of the public key
 * @param[in]    pPublicKey     Pointer to the loaded public key
 * @param[in]    pParams        Pointer to parameter structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLKEM_STATUS_OK                     Kem operation successful
 * @retval #MCUXCLKEM_STATUS_INVALID_PARAMS         Kem invalid params
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Decaps_CheckInputs)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)
mcuxClMlKem_Decaps_CheckInputs(mcuxClSession_Handle_t session,
                              uint32_t              inSize,
                              mcuxClKey_Handle_t     key,
                              const uint8_t*        pPrivateKey,
                              mcuxClKey_Handle_t     pubKey,
                              const uint8_t*        pPublicKey,
                              mcuxClMlKem_Params_t   pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Decaps_CheckInputs);

  /* 1. Chiphertext length check */
  if(inSize != pParams->ciphertextbytes)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps_CheckInputs, MCUXCLKEM_STATUS_INVALID_PARAMS);
  }

  /* 2. Decapsulation key length check */
  if((mcuxClKey_getKeyContainerSize(key) != pParams->secretkeybytes) || (mcuxClKey_getKeyContainerSize(pubKey) != pParams->publickeybytes))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps_CheckInputs, MCUXCLKEM_STATUS_INVALID_PARAMS);
  }

  /* 3. Hash check: hash the public key again and check against the digest passed via the secret key */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pHashBuffer, mcuxClSession_allocateWords_cpuWa(session, MCUXCLHASH_OUTPUT_SIZE_SHA3_256));

  uint32_t outSize = 0U;
  MCUXCLBUFFER_INIT_RO(hashReference, session, pPrivateKey + pParams->secretkeybytes - 2u * MCUXCLMLKEM_SYMBYTES, MCUXCLMLKEM_SYMBYTES);
  MCUXCLBUFFER_INIT_RO(publicKeyBuf, session, pPublicKey, pParams->publickeybytes);
  MCUXCLBUFFER_INIT(hashRecompute, session, pHashBuffer, MCUXCLHASH_OUTPUT_SIZE_SHA3_256);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute_internal));
  /* Balance DI for mcuxClHash_compute_internal() */
  MCUX_CSSL_DI_RECORD(hashRecomputeParams, publicKeyBuf);
  MCUX_CSSL_DI_RECORD(hashRecomputeParams, pParams->publickeybytes);
  MCUX_CSSL_DI_RECORD(hashRecomputeParams, hashRecompute);
  MCUX_CSSL_DI_RECORD(hashRecomputeParams, &outSize);
  MCUX_CSSL_FP_FUNCTION_CALL(retHashRecompute, mcuxClHash_compute_internal(session,
                                                                         mcuxClHash_Algorithm_Sha3_256,
                                                                         publicKeyBuf,
                                                                         pParams->publickeybytes,
                                                                         hashRecompute,
                                                                         &outSize));
  if(MCUXCLHASH_STATUS_OK != retHashRecompute)
  {
    MCUXCLSESSION_ERROR(session, retHashRecompute);
  }

  mcuxClMemory_Status_t cmp_status = MCUXCLMEMORY_STATUS_NOT_EQUAL;
  MCUX_CSSL_DI_RECORD(memCompare, hashReference);
  MCUX_CSSL_DI_RECORD(memCompare, hashRecompute);
  MCUX_CSSL_DI_RECORD(memCompare, MCUXCLMLKEM_SYMBYTES);
  MCUX_CSSL_FP_EXPECT(MCUXCLMEMORY_COMPARE_INT_FP_EXPECT);
  MCUXCLMEMORY_COMPARE_INT(cmp_status, hashReference, hashRecompute, MCUXCLMLKEM_SYMBYTES);

  if(MCUXCLMEMORY_STATUS_EQUAL != cmp_status)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps_CheckInputs, MCUXCLKEM_STATUS_INVALID_PARAMS);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps_CheckInputs, MCUXCLKEM_STATUS_OK);
}

/**
 * @brief Helper function to compute the shared key on rejection = J(z || c).
 *
 * @param[in]    session  Session handle
 * @param[out]   kBar     Buffer to the shared secret on rejection.
 * @param[in]    z        Buffer which holds z
 * @param[in]    ct       Buffer which holds the ciphertext
 * @param[in]    pParams  Pointer to parameter structure
 *
 * @return returns a mcuxClKem_Status_t status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_OK                 Kem operation successful
 * @retval MCUXCLxxx_STATUS_xxx                          The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Decaps_Rej_Key)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t)
mcuxClMlKem_Decaps_Rej_Key(mcuxClSession_Handle_t session,
                          mcuxCl_Buffer_t kBar,
                          mcuxCl_InputBuffer_t z,
                          mcuxCl_InputBuffer_t ct,
                          mcuxClMlKem_Params_t pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Decaps_Rej_Key);

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClXof_ContextDescriptor_t *, pContext, mcuxClSession_allocateWords_cpuWa(session, MCUXCLXOF_SHAKE256_CONTEXT_SIZE_IN_WORDS));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()


  MCUX_CSSL_FP_FUNCTION_CALL(ret_Xof_init_j, mcuxClXof_init(session, pContext, mcuxClXof_Algorithm_Shake_256, NULL, 0u));
  if(MCUXCLXOF_STATUS_OK != ret_Xof_init_j)
  {
    MCUXCLSESSION_ERROR(session, ret_Xof_init_j);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(ret_Xof_process_z, mcuxClXof_process(session, pContext, z, MCUXCLMLKEM_SYMBYTES));
  if(MCUXCLXOF_STATUS_OK != ret_Xof_process_z)
  {
    MCUXCLSESSION_ERROR(session, ret_Xof_process_z);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(ret_Xof_process_c, mcuxClXof_process(session, pContext, ct, pParams->ciphertextbytes));
  if(MCUXCLXOF_STATUS_OK != ret_Xof_process_c)
  {
    MCUXCLSESSION_ERROR(session, ret_Xof_process_c);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_mcuxClXof_generate, mcuxClXof_generate(session, pContext, kBar, MCUXCLMLKEM_SYMBYTES));
  if(MCUXCLXOF_STATUS_OK != retCode_mcuxClXof_generate)
  {
    MCUXCLSESSION_ERROR(session, retCode_mcuxClXof_generate);
  }

  mcuxClSession_freeWords_cpuWa(session, MCUXCLXOF_SHAKE256_CONTEXT_SIZE_IN_WORDS);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps_Rej_Key, MCUXCLMLKEM_INTERNAL_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Decaps, mcuxClKem_decapsulateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Decaps(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t     key,
  mcuxClKem_Mode_t       mode,
  mcuxCl_InputBuffer_t   pIn,
  uint32_t              inSize,
  mcuxClKey_Handle_t     sharedKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Decaps);

  /* Load private key */
  uint8_t *pPrivateKeyDest = NULL;
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
  MCUXCLKEY_LOAD_FP(session, key, &pPrivateKeyDest, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);
  const uint8_t *pPrivateKey = (const uint8_t*)pPrivateKeyDest;

  /* Get linked key data */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t)mcuxClKey_getLinkedData(key);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

  /* Load public key */
  uint8_t *pPublicKeyDest = NULL;
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(pubKey));
  MCUXCLKEY_LOAD_FP(session, pubKey, &pPublicKeyDest, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);
  const uint8_t *pPublicKey = (const uint8_t*)pPublicKeyDest;

  mcuxClMlKem_Params_t pParams = mcuxClMlKem_castToParams(mode->pAlgorithmDescriptor);

  /* Check decapsulation inputs */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decaps_CheckInputs));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams contains only algorithm-specific constants that are defined inside of the CL")
  MCUX_CSSL_FP_FUNCTION_CALL(ret_CheckInputs, mcuxClMlKem_Decaps_CheckInputs(session, inSize, key, pPrivateKey, pubKey, pPublicKey, pParams));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLKEM_STATUS_OK != ret_CheckInputs)
  {
    MCUXCLSESSION_ERROR(session, ret_CheckInputs);
  }

  /* 4*MCUXCLMLKEM_SYMBYTES used for KEM */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, buf, mcuxClSession_allocateWords_cpuWa(session, (2U * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t))); /* size of buf is 2*MCUXCLMLKEM_SYMBYTES = 64 bytes */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, kr, mcuxClSession_allocateWords_cpuWa(session, (2U * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)));  /* size of kr (contain key, coins) is 2*MCUXCLMLKEM_SYMBYTES = 64 bytes */

  MCUXCLBUFFER_INIT(bufBuf, session, buf, 2*MCUXCLMLKEM_SYMBYTES);
  MCUXCLBUFFER_INIT(krBuf, session, kr, 2*MCUXCLMLKEM_SYMBYTES);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams contains only algorithm-specific constants that are defined inside of the CL")
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Indcpa_Decryption, mcuxClMlKem_Decrypt(session, buf, pIn, pPrivateKey, pParams));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Indcpa_Decryption)
  {
    MCUXCLSESSION_ERROR(session, ret_Indcpa_Decryption);
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  /* Obtain hash of public key from private key structure */
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint8_t i = 0; i < MCUXCLMLKEM_SYMBYTES; i++)
  {
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pParams->secretkeybytes, MCUXCLMLKEM_SECRETKEYBYTES(2u), MCUXCLMLKEM_SECRETKEYBYTES(4u), MCUXCLKEM_STATUS_ERROR)
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams->secretkeybytes is an algorithm-specific constant that is defined inside of the CL")
    buf[MCUXCLMLKEM_SYMBYTES+i] = pPrivateKey[pParams->secretkeybytes-2U*MCUXCLMLKEM_SYMBYTES+i];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  uint32_t outSize = 0u; /* Output size filled by mcuxClHash_compute, but not needed in the following */
  /* Compute (K', r') = G(m' || H(pk)) */
  MCUX_CSSL_FP_FUNCTION_CALL(ret_compute,
                            mcuxClHash_compute(session,
                                              mcuxClHash_Algorithm_Sha3_512,
                                              bufBuf,
                                              2u * MCUXCLMLKEM_SYMBYTES,
                                              krBuf,
                                              &outSize));
  if(MCUXCLHASH_STATUS_OK != ret_compute)
  {
    MCUXCLSESSION_ERROR(session, ret_compute);
  }

  /* Coins are in kr+MCUXCLMLKEM_SYMBYTES */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("pParams contains only algorithm-specific constants that are defined inside of the CL")

  /* the outcome of the comparison is considered secret */
  mcuxClMemory_Status_t rc = 0u;

  /* Re-encryption of message for Fujisaki-Okamoto transformation */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST("cast buffer to input buffer, but we won't write to it")
  MCUXCLBUFFER_DERIVE_RW(ct, pIn, 0u);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST()
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Indcpa_Encryption,
                            mcuxClMlKem_Encrypt(session,
                                               ct,
                                               buf,
                                               pPublicKey,
                                               kr + MCUXCLMLKEM_SYMBYTES,
                                               mcuxClMlKem_Poly_Compress_Cmp, /* upon (re-)encryption: compress and compare reference ciphertext in ct */
                                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Poly_Compress_Cmp),
                                               pParams,
                                               &rc));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
  if(MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK != ret_Indcpa_Encryption)
  {
    MCUXCLSESSION_ERROR(session, ret_Indcpa_Encryption);
  }

  /* convert the comparison value to a boolean in constant time */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("rc is a return code, wrapping is expected and accepted")
  uint8_t fail = (uint8_t)(((~rc + 1u) >> ((sizeof(rc) << 3u) - 1u)) & 0xFFu);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  /* The following code should still treat "fail" as a secret */

  MCUXCLBUFFER_INIT_RO(zBuf, NULL, pPrivateKey + pParams->secretkeybytes - MCUXCLMLKEM_SYMBYTES, MCUXCLMLKEM_SYMBYTES);
  MCUXCLBUFFER_DERIVE_RW(kBar, krBuf, MCUXCLMLKEM_SYMBYTES);
  MCUX_CSSL_FP_FUNCTION_CALL(ret_Compute_Rej_Key, mcuxClMlKem_Decaps_Rej_Key(session, kBar, zBuf, pIn, pParams));
  if(MCUXCLMLKEM_INTERNAL_STATUS_OK != ret_Compute_Rej_Key)
  {
    MCUXCLSESSION_ERROR(session, ret_Compute_Rej_Key);
  }

  /* Conditionally overwrite Kbar with K' if re-encryption succeeded */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlKem_Cmov(kr + MCUXCLMLKEM_SYMBYTES, kr, MCUXCLMLKEM_SYMBYTES, (uint8_t)(~fail & 0x01u)));

  /* Store K' as shared secret */
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(sharedKey));
  MCUXCLKEY_STORE_FP(
    session,
    sharedKey,
    kr + MCUXCLMLKEM_SYMBYTES,
    MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE | MCUXCLKEY_ENCODING_SPEC_SINGLE_PART
  );

  mcuxClSession_freeWords_cpuWa(session,
                               ((2U * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t))
                                 + ((2U * MCUXCLMLKEM_SYMBYTES) / sizeof(uint32_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Decaps, MCUXCLKEM_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decrypt),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLKEM_SYMBYTES),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Encrypt),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Decaps_Rej_Key),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Cmov));
}
