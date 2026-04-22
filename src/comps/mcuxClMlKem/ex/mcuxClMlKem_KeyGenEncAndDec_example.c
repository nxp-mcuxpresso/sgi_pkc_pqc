/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @example: mcuxClMlKem_KeyGenEncAndDec_example.c
 * @brief: KEM example using ML-KEM
 *
 */

#include <mcuxClKey.h>
#include <mcuxClMlKem.h>
#include <mcuxClKem.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxCsslFlowProtection.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClExample_Session_Helper.h>

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                                     MCUXCLMLKEM_WORKAREASIZE_MAX))

MCUXCLEXAMPLE_FUNCTION(mcuxClMlKem_KeyGenEncAndDec_example)
{

  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Initialize session */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMLKEM_WORKAREASIZE_MAX, 0u);

  /* Buffers for private and public key pair */
  uint8_t privateKeyBuff[MCUXCLMLKEM_MLKEM_512_SK_LEN];
  uint8_t publicKeyBuff[MCUXCLMLKEM_MLKEM_512_PK_LEN];

  /******************************************/
  /* Initialize RNG                         */
  /******************************************/

  /* Initialize the RNG and Initialize the PRNG */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session,
      MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
      mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

  /**************************************************************************/
  /* Key setup                                                              */
  /**************************************************************************/

  /* Create and initialize key descriptor structure. */
  uint32_t keyDescPrivBuff[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t keyDescPriv = (mcuxClKey_Handle_t)&keyDescPrivBuff;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_prv_status, ki_prv_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ keyDescPriv,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_MlKem512_Private,
    /* uint8_t * pKeyData                    */ privateKeyBuff,
    /* uint32_t keyDataLength                */ sizeof(privateKeyBuff)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_prv_token) || (MCUXCLKEY_STATUS_OK != ki_prv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Create and initialize key descriptor structure. */
  uint32_t keyDescPubBuff[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t keyDescPub= (mcuxClKey_Handle_t)&keyDescPubBuff;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ keyDescPub,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_MlKem512_Public,
    /* uint8_t * pKeyData                    */ publicKeyBuff,
    /* uint32_t keyDataLength                */ sizeof(publicKeyBuff)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Keypair generation                                                     */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token, mcuxClKey_generate_keypair(
      /* mcuxClSession_Handle_t session:   */ session,
      /* mcuxClKey_Generation_t generation: */ mcuxClMlKem_KeyGeneration_512,
      /* mcuxClKey_Handle_t privKey:        */ keyDescPriv,
      /* mcuxClKey_Handle_t pubKey:         */ keyDescPub
  ));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != gkp_token) || (MCUXCLKEY_STATUS_OK != gkp_status))
  {
      return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Encapsulation                                                          */
  /**************************************************************************/

  uint8_t ciphertext[MCUXCLMLKEM_MLKEM_512_CT_LEN];
  uint8_t sharedSecret[MCUXCLMLKEM_MLKEM_SHARED_SECRET_LEN];

  MCUXCLBUFFER_INIT(ciphertextBuf, session, ciphertext, MCUXCLMLKEM_MLKEM_512_CT_LEN);

  uint32_t sizeofCt = 0u;

  uint32_t keyDescSharedSecretBuff[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t keyHandleSharedSecret = (mcuxClKey_Handle_t)&keyDescSharedSecretBuff;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_shr_status, ki_shr_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ keyHandleSharedSecret,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_MlKemSharedSecret,
    /* uint8_t * pKeyData                    */ sharedSecret,
    /* uint32_t keyDataLength                */ sizeof(sharedSecret)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_shr_token) || (MCUXCLKEY_STATUS_OK != ki_shr_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* ML-KEM encapsulation */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kem_encap_status, kem_encap_token, mcuxClKem_encapsulate(
                                                session,
                                                keyDescPub,
                                                mcuxClMlKem_Mode_512,
                                                keyHandleSharedSecret,
                                                ciphertextBuf,
                                                &sizeofCt
                                                ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKem_encapsulate) != kem_encap_token) || (MCUXCLKEM_STATUS_OK != kem_encap_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Decapsulation                                                          */
  /**************************************************************************/

  uint8_t sharedSecret2[MCUXCLMLKEM_MLKEM_SHARED_SECRET_LEN];

  uint32_t keyDescSharedSecretBuff2[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t keyHandleSharedSecret2 = (mcuxClKey_Handle_t)&keyDescSharedSecretBuff2;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_sec_status, ki_sec_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ keyHandleSharedSecret2,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_MlKemSharedSecret,
    /* uint8_t * pKeyData                    */ sharedSecret2,
    /* uint32_t keyDataLength                */ sizeof(sharedSecret2)));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_sec_token) || (MCUXCLKEY_STATUS_OK != ki_sec_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kem_decap_status, kem_decap_token, mcuxClKem_decapsulate(
                                                session,
                                                 keyDescPriv,
                                                 mcuxClMlKem_Mode_512,
                                                 ciphertextBuf,
                                                 sizeofCt,
                                                 keyHandleSharedSecret2));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKem_decapsulate) != kem_decap_token) || (MCUXCLKEM_STATUS_OK != kem_decap_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Compare the generated shared secrets                                   */
  /**************************************************************************/

  for(size_t i = 0; i < MCUXCLMLKEM_MLKEM_SHARED_SECRET_LEN; i++)
  {
    if(sharedSecret[i] != sharedSecret2[i])
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
