/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxClKem_Constants.h>
#include <mcuxClKem.h>

#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClKem_Internal_Types.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKem_encapsulate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClKem_encapsulate(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKem_Mode_t mode,
  mcuxClKey_Handle_t sharedKey,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutSize
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClKem_encapsulate, diRefValue, MCUXCLKEM_STATUS_FAULT_ATTACK);

  MCUX_CSSL_FP_FUNCTION_CALL(status, mode->encapsulateFct(
  /* mcuxClSession_Handle_t session */ session,
  /* mcuxClKey_Handle_t key         */ key,
  /* mcuxClKem_Mode_t mode          */ mode,
  /* mcuxClKey_Handle_t sharedKey   */ sharedKey,
  /* mcuxCl_Buffer_t pOut           */ pOut,
  /* uint32_t * const pOutSiz      */ pOutSize));

  MCUXCLSESSION_EXIT(session, mcuxClKem_encapsulate, diRefValue, status, MCUXCLKEM_STATUS_FAULT_ATTACK, mode->protection_token_encapsulate);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKem_decapsulate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClKem_decapsulate(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKem_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxClKey_Handle_t sharedKey
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClKem_decapsulate, diRefValue, MCUXCLKEM_STATUS_FAULT_ATTACK);

  MCUX_CSSL_FP_FUNCTION_CALL(status, mode->decapsulateFct(
  /* mcuxClSession_Handle_t session */  session,
  /* mcuxClKey_Handle_t key         */  key,
  /* mcuxClKem_Mode_t mode          */  mode,
  /* mcuxCl_InputBuffer_t pIn       */  pIn,
  /* uint32_t inSize               */  inSize,
  /* mcuxClKey_Handle_t sharedKey   */  sharedKey));

  MCUXCLSESSION_EXIT(session, mcuxClKem_decapsulate, diRefValue, status, MCUXCLKEM_STATUS_FAULT_ATTACK, mode->protection_token_decapsulate);
}



