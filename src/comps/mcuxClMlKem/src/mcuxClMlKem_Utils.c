/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file:   mcuxClMlKem_Utils.c
 * @brief:  Utils functions
 *
 */

#include <mcuxClKem.h>
#include <mcuxClMlKem.h>
#include <internal/mcuxClMlKem_Utils.h>
#include <internal/mcuxClMlKem_Internal.h>
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxCsslAnalysis.h>

/**
 * @brief mcuxClMlKem_Shake128_Absorb
 *
 * This function initialize the Shake128 state and absorbs seed || x || y
 *
 * @param[in]       session             Handle for the current CL session
 * @param[in]       pContext            Pointer to context
 * @param[in]       seed                Pointer to seed (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       x                   Matrix index
 * @param[in]       y                   Matrix index
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_OK             Absorb operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Shake128_Absorb)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Shake128_Absorb(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClXof_Context_t pContext,
                                                          const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                          uint8_t x,
                                                          uint8_t y)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Shake128_Absorb);

  uint8_t extseed[MCUXCLMLKEM_SYMBYTES+2];

  for(uint8_t i = 0u; i < MCUXCLMLKEM_SYMBYTES; i++)
  {
    extseed[i] = seed[i];
  }
  extseed[MCUXCLMLKEM_SYMBYTES]    = x;
  extseed[MCUXCLMLKEM_SYMBYTES+1u]  = y;

  MCUXCLBUFFER_INIT(extseedBuf, session, extseed, MCUXCLMLKEM_SYMBYTES+2);

  MCUX_CSSL_FP_FUNCTION_CALL(ret_Xof_init, mcuxClXof_init(session, pContext, mcuxClXof_Algorithm_Shake_128, NULL, 0u));

  if(MCUXCLXOF_STATUS_OK != ret_Xof_init)
  {
    MCUXCLSESSION_ERROR(session, ret_Xof_init);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(ret_Xof_process, mcuxClXof_process(session, pContext, extseedBuf, MCUXCLMLKEM_SYMBYTES + 2u));

  if(MCUXCLXOF_STATUS_OK != ret_Xof_process)
  {
      MCUXCLSESSION_ERROR(session, ret_Xof_process);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Shake128_Absorb, MCUXCLMLKEM_INTERNAL_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_process)
  );
}

/**
 * @brief mcuxClMlKem_Shake128_Absorb
 *
 * This function initialize the Shake128 state and absorbs seed || x || y
 *
 * @param[in]       session            Handle for the current CL session
 * @param[in]       pContext           Pointer to context
 * @param[in]       out                Pointer to output (of length nblocks*168 bytes)
 * @param[in]       noOfBytes          Number of output blocks
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_OK             Squeeze operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Shake128_Squeeze)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Shake128_Squeeze(
                                                              mcuxClSession_Handle_t session,
                                                              mcuxClXof_Context_t pContext,
                                                              uint8_t *const out,
                                                              uint16_t noOfBytes)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Shake128_Squeeze);

  MCUXCLBUFFER_INIT(outBuf, session, out, noOfBytes);

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_mcuxClXof_generate, mcuxClXof_generate(session, pContext, outBuf, (uint32_t)noOfBytes));

  if(MCUXCLXOF_STATUS_OK != retCode_mcuxClXof_generate)
  {
    MCUXCLSESSION_ERROR(session, retCode_mcuxClXof_generate);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Shake128_Squeeze, MCUXCLMLKEM_INTERNAL_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_generate));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Stream128_Absorb)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Stream128_Absorb(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClXof_Context_t pContext,
                                                          const uint8_t seed[MCUXCLMLKEM_SYMBYTES],
                                                          uint8_t x,
                                                          uint8_t y)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Stream128_Absorb);

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_Shake128_Absorb, mcuxClMlKem_Shake128_Absorb(session, pContext, seed, x, y));

  /* Check the return code of mcuxClMlKem_Shake128_Absorb */
  if(MCUXCLMLKEM_INTERNAL_STATUS_OK != retCode_Shake128_Absorb)
  {
    MCUXCLSESSION_ERROR(session, retCode_Shake128_Absorb);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Stream128_Absorb, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Shake128_Absorb));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Stream128_Squeeze)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Stream128_Squeeze(
                                                                mcuxClSession_Handle_t session,
                                                                mcuxClXof_Context_t pContext,
                                                                uint8_t *const out,
                                                                uint16_t noOfBytes)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Stream128_Squeeze);

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_Shake128_Squeeze, mcuxClMlKem_Shake128_Squeeze(session, pContext, out, noOfBytes));

  /* Check the return code of mcuxClMlKem_Shake128_Squeeze */
  if(MCUXCLMLKEM_INTERNAL_STATUS_OK != retCode_Shake128_Squeeze)
  {
    MCUXCLSESSION_ERROR(session, retCode_Shake128_Squeeze);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Stream128_Squeeze, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Shake128_Squeeze));
}

/**
 * @brief mcuxClMlKem_Shake256_PRF
 *
 * This function generates outlen output bytes from Shake256(key || nonce)
 *
 * @param[in]       session            Handle for the current CL session
 * @param[in]       pContext           Pointer to context
 * @param[in]       out                Pointer to output (of length outlen bytes)
 * @param[in]       outlen             Number of output bytes
 * @param[in]       key                Pointer to key (of length MCUXCLMLKEM_SYMBYTES bytes)
 * @param[in]       nonce              Nonce
 *
 * @return returns a status code
 * @retval #MCUXCLMLKEM_INTERNAL_STATUS_OK             Shake operation successful
 * @retval MCUXCLxxx_STATUS_xxx                        The function execution failed and the first internal error will be returned
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Shake256_PRF)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_Shake256_PRF
                                                        (mcuxClSession_Handle_t session,
                                                          uint8_t * const out,
                                                          uint16_t outlen,
                                                          const uint8_t key[MCUXCLMLKEM_SYMBYTES],
                                                          uint8_t nonce)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Shake256_PRF);

  uint8_t i;
  uint8_t extkey[MCUXCLMLKEM_SYMBYTES+1];

  for(i = 0; i < MCUXCLMLKEM_SYMBYTES; i++)
  {
    extkey[i] = key[i];
  }
  extkey[i] = nonce;

  MCUXCLBUFFER_INIT_RO(extkeyBuf, session, extkey, MCUXCLMLKEM_SYMBYTES+1);
  MCUXCLBUFFER_INIT(outBuf, session, out, outlen);
  MCUX_CSSL_FP_FUNCTION_CALL(retCode_XOF_Hash, mcuxClXof_compute(session, mcuxClXof_Algorithm_Shake_256, extkeyBuf, sizeof(extkey), NULL, 0u, outBuf, outlen));

  /* Check the return code of mcuxClXof_compute */
  if(MCUXCLXOF_STATUS_OK != retCode_XOF_Hash)
  {
    MCUXCLSESSION_ERROR(session, retCode_XOF_Hash);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_Shake256_PRF, MCUXCLMLKEM_INTERNAL_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_PRF)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKem_Status_t) mcuxClMlKem_PRF(mcuxClSession_Handle_t session,
                                                                    uint8_t * const out,
                                                                    uint16_t outlen,
                                                                    const uint8_t key[32],
                                                                    uint8_t nonce)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_PRF);

  MCUX_CSSL_FP_FUNCTION_CALL(retCode_Shake256_PRF, mcuxClMlKem_Shake256_PRF(session, out, outlen, key, nonce));

  /* Check the return code of mcuxClMlKem_Shake256_PRF */
  if(MCUXCLMLKEM_INTERNAL_STATUS_OK != retCode_Shake256_PRF)
  {
    MCUXCLSESSION_ERROR(session, retCode_Shake256_PRF);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlKem_PRF, MCUXCLMLKEM_INTERNAL_STATUS_INDCPA_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlKem_Shake256_PRF));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlKem_Cmov)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlKem_Cmov(uint8_t * const r, const uint8_t * const x, uint32_t len, uint8_t b)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlKem_Cmov);
  uint32_t i;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Wrap-around used as intended mechanism for constant-time masking")
  uint8_t mask = (uint8_t)((0u - b) & 0xFFu);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  for(i = 0u; i < len; i++)
  {
    r[i] ^= (mask & (r[i] ^ x[i]));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlKem_Cmov);
}
