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
 * @example mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_Ctx_example.c
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
static const uint8_t userContext[32U] = {
    0x98U, 0xcaU, 0xc8U, 0xb0U, 0x08U, 0x62U, 0x55U, 0x42U, 0x3fU, 0x4fU, 0x02U, 0x69U, 0xc9U, 0xb8U, 0x71U, 0x88U, 0xbdU, 0x4dU, 0x43U, 0xceU, 0x8eU, 0x3dU, 0xc7U, 0x05U, 0xbfU, 0x34U, 0xbbU, 0x29U, 0xb0U, 0xb4U, 0xc6U, 0xd1U
};

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                                     MCUXCLMLDSA_MLDSA65_WORKAREASIZE_MAX))

MCUXCLEXAMPLE_FUNCTION(mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_Ctx_example)
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
    /* Allocate space for and initialize private key handle for a ML-DSA-65 private key */
    uint32_t privKeyDesc[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLKEY_DESCRIPTOR_SIZE)];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    uint32_t pPrivateKeyData[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA65_SK_LEN)];

    const mcuxClKey_Status_t ki_priv_status = mcuxClKey_init(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ privKey,
    /* mcuxClKey_Type_t type:          */ mcuxClKey_Type_MlDsa65_Private,
    /* uint8_t* pKeyData:             */ (uint8_t*) pPrivateKeyData,
    /* uint32_t keyDataLength:        */ sizeof(pPrivateKeyData));

    if(MCUXCLKEY_STATUS_OK != ki_priv_status)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Allocate space for and initialize public key handle for a ML-DSA-65 public key */
    uint32_t pubKeyDesc[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLKEY_DESCRIPTOR_SIZE)];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    uint32_t pPublicKeyData[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMLDSA_MLDSA65_PK_LEN)];

    const mcuxClKey_Status_t ki_pub_status = mcuxClKey_init(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ pubKey,
    /* mcuxClKey_Type_t type:          */ mcuxClKey_Type_MlDsa65_Public,
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
        /* mcuxClKey_Generation_t generation: */ mcuxClKey_keyGeneration_MlDsa65,
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
        /* mcuxClMlDsa_Options_t options:                                  */ MCUXCLMLDSA_MODE_65 | MCUXCLMLDSA_MODE_PURE,
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
    uint8_t signature[MCUXCLMLDSA_MLDSA65_SIG_LEN] = {0U};
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
