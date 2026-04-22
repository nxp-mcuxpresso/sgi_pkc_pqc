/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
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
 * @file: mcuxClMlKem_KeyEncodings.c
 * @brief: Key encoding mechanisms for ML-KEM
 *
 */

#include <mcuxClKey_Constants.h>
#include <mcuxClMlKem.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession.h>

#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_KeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_KeyStore_Plain(mcuxClSession_Handle_t session,
                                                                  mcuxClKey_Handle_t key,
                                                                  const uint8_t * pSrc,
                                                                  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_KeyStore_Plain);

  uint8_t *pData = mcuxClKey_getKeyData(key);
  uint32_t offset = 0u;
  uint32_t len = mcuxClKey_getSize(key);

  if(MCUXCLKEY_ENCODING_SPEC_CHUNK_PROCESSING_ENABLED == (spec & MCUXCLKEY_ENCODING_SPEC_CHUNK_MASK))
  {
    /* multi-part key, respect provided offset and len */
    offset = ((spec & MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET_MASK) >> MCUXCLKEY_ENCODING_SPEC_CHUNK_OFFSET_POS) * sizeof(uint32_t);
    len = ((spec & MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE_MASK) >> MCUXCLKEY_ENCODING_SPEC_CHUNK_SIZE_POS) * sizeof(uint32_t);
  }

  /* Record input data for mcuxClMemory_copy_int_{secure} */
  MCUX_CSSL_DI_RECORD(copyFn, pData + offset);
  MCUX_CSSL_DI_RECORD(copyFn, pSrc);
  MCUX_CSSL_DI_RECORD(copyFn, len);
  if(MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pData + offset, pSrc, len));
  }
  else if(MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pData + offset, pSrc, len));
  }
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_KeyStore_Plain);
}

const mcuxClKey_EncodingDescriptor_t mcuxClMlKem_Key_Encoding_Descriptor_Plain =
{
  .loadFunc = mcuxClKey_KeyLoad_Plain,
  .storeFunc = mcuxClMlKem_KeyStore_Plain,
  .flushFunc = NULL,
  .handleKeyChecksumsFunc = mcuxClKey_handleKeyChecksums_none,
  .protectionToken_loadFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_KeyLoad_Plain),
  .protectionToken_storeFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_KeyStore_Plain),
  .protectionToken_flushFunc = 0u,
  .protectionToken_handleKeyChecksumsFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_handleKeyChecksums_none)
};
