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
 * @example mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_Ctx_example.c
 * @brief Example application of the @ref mcuxClMlDsa signature algorithm.
 * Comprises of key generation, signing, and verifying the signature.
 * Tests the external API with pure mode and a non-empty context string.
 *
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClMlDsa.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClKey.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClSignature.h>

/**
* @brief Sample test vector: Message
*/
static const uint8_t message[32U] = {
    0xf8U, 0x5dU, 0x86U, 0x8aU, 0xe9U, 0xdbU, 0xc2U, 0x45U, 0x83U, 0x4fU, 0x78U, 0x18U, 0x38U, 0x27U, 0xf6U, 0xcdU, 0x87U, 0xffU, 0x19U, 0x92U, 0x85U, 0x3eU, 0x60U, 0xb7U, 0x8dU, 0x25U, 0x40U, 0xdcU, 0x6fU, 0x14U, 0xc2U, 0xc6U
};

/**
* @brief Sample test vector: Context
*/
static const uint8_t userContext[255U] = {
    0x9fU, 0x62U, 0xe2U, 0x7dU, 0xa9U, 0xf9U, 0x57U, 0xdbU, 0xebU, 0xd4U, 0x92U, 0x4fU, 0x5dU, 0x42U, 0xdfU, 0x55U, 0xc2U, 0x90U, 0x1fU, 0x82U, 0x1cU, 0xe4U, 0xf0U, 0x94U, 0xb7U, 0xcbU, 0xbeU, 0x4eU, 0x7fU, 0x92U, 0x70U, 0x18U,
    0xc6U, 0x65U, 0x6aU, 0xbbU, 0x4eU, 0xa7U, 0x72U, 0x18U, 0x52U, 0x6aU, 0xa6U, 0x0bU, 0xdaU, 0x9bU, 0x40U, 0xbaU, 0x32U, 0x5fU, 0x1dU, 0x25U, 0x6cU, 0xb4U, 0x6dU, 0x52U, 0xe8U, 0x62U, 0xfbU, 0x19U, 0x83U, 0x83U, 0x25U, 0xe6U,
    0xffU, 0x9fU, 0xbbU, 0xeeU, 0xf7U, 0x9dU, 0xe9U, 0xcbU, 0x55U, 0xdaU, 0x66U, 0xf1U, 0x82U, 0xa5U, 0x03U, 0x76U, 0xf9U, 0xd1U, 0xbbU, 0x6cU, 0xa0U, 0xc8U, 0xaeU, 0x7cU, 0xc7U, 0x08U, 0x29U, 0x2eU, 0x85U, 0xb3U, 0x78U, 0x23U,
    0x66U, 0xceU, 0x8aU, 0x99U, 0x1dU, 0x0cU, 0x1aU, 0x22U, 0xebU, 0x62U, 0xdaU, 0xc7U, 0xd2U, 0xbeU, 0x6dU, 0x05U, 0x17U, 0xcdU, 0x7dU, 0xb3U, 0xc5U, 0x2eU, 0xcaU, 0xb3U, 0x81U, 0x4cU, 0x8bU, 0x60U, 0x83U, 0x10U, 0x10U, 0x8aU,
    0x55U, 0xa1U, 0x06U, 0x11U, 0x47U, 0xd3U, 0xcdU, 0xdeU, 0x6aU, 0xb5U, 0xb3U, 0x1eU, 0xfaU, 0x92U, 0xaeU, 0x91U, 0x28U, 0xdcU, 0x9aU, 0x64U, 0x74U, 0x83U, 0xf5U, 0x45U, 0x12U, 0x7dU, 0x2aU, 0xcdU, 0x1cU, 0xdcU, 0x7bU, 0xc8U,
    0x06U, 0xd2U, 0x6aU, 0x50U, 0xfaU, 0x49U, 0x54U, 0xa2U, 0x04U, 0x8eU, 0x58U, 0x10U, 0x97U, 0x57U, 0x23U, 0xa9U, 0xbaU, 0xd9U, 0x71U, 0x1fU, 0xa3U, 0x53U, 0xbcU, 0xa8U, 0xd6U, 0x9dU, 0x80U, 0xdbU, 0x8dU, 0xf7U, 0x24U, 0x4fU,
    0x26U, 0x11U, 0xebU, 0x33U, 0x29U, 0x84U, 0x83U, 0xf1U, 0x07U, 0x78U, 0xe4U, 0x81U, 0x07U, 0xc8U, 0x2eU, 0xc3U, 0xa8U, 0xe9U, 0xe8U, 0x07U, 0x1cU, 0x04U, 0x7aU, 0x62U, 0xc7U, 0xcaU, 0x27U, 0xf4U, 0x5fU, 0xb0U, 0x3aU, 0xceU,
    0xd1U, 0x53U, 0x60U, 0x76U, 0xeeU, 0x7cU, 0xdaU, 0xe4U, 0xd0U, 0x93U, 0x75U, 0xaaU, 0xa7U, 0x1eU, 0x5fU, 0xacU, 0x86U, 0x7bU, 0x82U, 0xe2U, 0x7cU, 0x7eU, 0xc6U, 0x2fU, 0x55U, 0xe6U, 0x40U, 0x96U, 0x67U, 0xbaU, 0x7eU
};

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                                     MCUXCLMLDSA_MLDSA44_WORKAREASIZE_MAX))

MCUXCLEXAMPLE_FUNCTION(mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_Ctx_example)
{
    /******************************************/
    /* Set up the environment                 */
    /******************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    /* NOTE: Workarea size is to be specified in bytes */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
        MAX_CPUWA_SIZE,
        MCUXCLMLDSA_VERIFY_SIZEOF_WA_PKC);

    /******************************************/
    /* Initialize private and public key      */
    /******************************************/
    /* Allocate space for and initialize private key handle for a ML-DSA-44 private key */
    uint32_t privKeyDesc[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLKEY_DESCRIPTOR_SIZE)];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    uint32_t pPrivateKeyData[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA44_SK_LEN)];

    const mcuxClKey_Status_t ki_priv_status = mcuxClKey_init(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ privKey,
    /* mcuxClKey_Type_t type:          */ mcuxClKey_Type_MlDsa44_Private,
    /* uint8_t* pKeyData:             */ (uint8_t*) pPrivateKeyData,
    /* uint32_t keyDataLength:        */ sizeof(pPrivateKeyData));

    if(MCUXCLKEY_STATUS_OK != ki_priv_status)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Allocate space for and initialize public key handle for a ML-DSA-44 public key */
    uint32_t pubKeyDesc[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLKEY_DESCRIPTOR_SIZE)];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    uint32_t pPublicKeyData[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA44_PK_LEN)];

    const mcuxClKey_Status_t ki_pub_status = mcuxClKey_init(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ pubKey,
    /* mcuxClKey_Type_t type:          */ mcuxClKey_Type_MlDsa44_Public,
    /* uint8_t * pKeyData:            */ (uint8_t *) pPublicKeyData,
    /* uint32_t keyDataLength:        */ sizeof(pPublicKeyData));

    if(MCUXCLKEY_STATUS_OK != ki_pub_status)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************/
    /* Initialize RNG                         */
    /******************************************/

    /* Initialize the RNG and Initialize the PRNG */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session,
        MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
        mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

    /******************************************************************************/
    /* Key pair generation                                                        */
    /******************************************************************************/

    const mcuxClKey_Status_t gkp_status = mcuxClKey_generate_keypair(
        /* mcuxClSession_Handle_t pSession:   */ session,
        /* mcuxClKey_Generation_t generation: */ mcuxClKey_keyGeneration_MlDsa44,
        /* mcuxClKey_Handle_t privKey:        */ privKey,
        /* mcuxClKey_Handle_t pubKey:         */ pubKey
    );
    if(MCUXCLKEY_STATUS_OK != gkp_status)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************************************************/
    /* Set up mode constructor for signature generation and verification          */
    /******************************************************************************/

    /* Create the signature mode */
    uint8_t signatureModeBytes[MCUXCLSIGNATURE_MODE_SIZE];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClSignature_ModeDescriptor_t *pSignatureMode = (mcuxClSignature_ModeDescriptor_t *)signatureModeBytes;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    /* Create the protocol descriptor */
    uint8_t mlDsaProtocolDescriptorBytes[MCUXCLMLDSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClMlDsa_SignatureProtocolDescriptor_t *pMlDsaProtocolDescriptor = (mcuxClMlDsa_SignatureProtocolDescriptor_t *)mlDsaProtocolDescriptorBytes;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    /* Buffer for context */
    MCUXCLBUFFER_INIT_RO(ctxBuf, NULL, userContext, sizeof(userContext));

    /* Create the mode constructor */
    const mcuxClSignature_Status_t mode_status = mcuxClMlDsa_SignatureModeConstructor(
        /* mcuxClSignature_ModeDescriptor_t *pSignatureMode:               */ pSignatureMode,
        /* mcuxClMlDsa_SignatureProtocolDescriptor_t *pProtocolDescriptor: */ pMlDsaProtocolDescriptor,
        /* mcuxClMlDsa_Options_t options:                                  */ MCUXCLMLDSA_MODE_44 | MCUXCLMLDSA_MODE_PURE,
        /* const void* const pPreHashAlgo:                                */ NULL,
        /* mcuxCl_InputBuffer_t ctx:                                       */ ctxBuf,
        /* uint32_t ctxLength:                                            */ sizeof(userContext)
    );
    if(MCUXCLSIGNATURE_STATUS_OK != mode_status)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************************************************/
    /* Signature generation and verification                                      */
    /******************************************************************************/

    /* Buffer for the signature */
    uint8_t signature[MCUXCLMLDSA_MLDSA44_SIG_LEN] = {0U};
    uint32_t signatureSize;
    uint32_t* const pSignatureSize = &signatureSize;

    MCUXCLBUFFER_INIT_RO(msgBuf, NULL, message, sizeof(message));
    MCUXCLBUFFER_INIT(sigBuf, NULL, signature, sizeof(signature));

    /* Generate Signature */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_Sign, token_Sign, mcuxClSignature_sign(
        /* mcuxClSession_Handle_t session:   */ session,
        /* mcuxClKey_Handle_t key:           */ privKey,
        /* mcuxClSignature_Mode_t mode:      */ pSignatureMode,
        /* mcuxCl_InputBuffer_t pIn:         */ msgBuf,
        /* uint32_t inSize:                 */ sizeof(message),
        /* mcuxCl_Buffer_t pSignature:       */ sigBuf,
        /* uint32_t* const pSignatureSize:  */ pSignatureSize
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != token_Sign)
        || (MCUXCLSIGNATURE_STATUS_OK != result_Sign))
    {
        return MCUXCLEXAMPLE_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Verify Signature */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_Verify, token_Verify, mcuxClSignature_verify(
        /* mcuxClSession_Handle_t session:  */ session,
        /* mcuxClKey_Handle_t key:          */ pubKey,
        /* mcuxClSignature_Mode_t mode:     */ pSignatureMode,
        /* mcuxCl_InputBuffer_t pIn:        */ msgBuf,
        /* uint32_t inSize:                */ sizeof(message),
        /* mcuxCl_InputBuffer_t pSignature: */ sigBuf,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClSignature_sign")
        /* uint32_t signatureSize:         */ signatureSize
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != token_Verify)
        || (MCUXCLSIGNATURE_STATUS_OK != result_Verify))
    {
        return MCUXCLEXAMPLE_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}
