/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file mcuxClMlDsa_Internal_InlineAssembly.h
 * @brief Internal inline assembly functions of the crypto library ML-DSA component
 *
 * @defgroup mcuxClMlDsa_Internal_InlineAssembly mcuxClMlDsa_Internal_InlineAssembly
 * @ingroup mcuxClMlDsa
 * @brief Internal inline assembly functions of the @ref mcuxClMlDsa component.
 * @{
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_INLINEASSEMBLY_H_
#define MCUXCLMLDSA_INTERNAL_INLINEASSEMBLY_H_

#include <mcuxClToolchain.h>

#ifdef __cplusplus
extern "C"
{
#endif


/**
 * @brief Performs a signed right shift operation using assembly instructions
 *
 * This function performs a signed right shift (arithmetic shift right) operation
 * using an inline assembly instruction. It shifts the value 'val32' right by 'shift'
 * positions, preserving the sign bit.
 *
 * @attention This function is necessary due to IAR compiler bug. Extended to
 *            armclang for consistency.
 *
 * @param[in] val32  The 32-bit value to be shifted
 * @param[in] shift  The number of positions to shift right
 * @return The shifted value
 */
#if defined(__IASMARM__) || defined(__ICCARM__)
static inline int32_t mcuxClMlDsa_SSHR32(int32_t val32, uint32_t shift) {
  __asm volatile("asr %0, %0, %1" : "+r"(val32) : "r"(shift));
  return val32;
}
#else
static inline ALWAYS_INLINE int32_t mcuxClMlDsa_SSHR32(int32_t val32, uint32_t shift) {
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_SHIFT()
  return val32 >> shift;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_SHIFT()
}
#endif /* defined(__ICCARM__) */


/**
 * @brief Moves the high 32 bits of a 64-bit value to a 32-bit signed value
 *
 * This function takes a 64-bit value and extracts the high 32 bits,
 * returning them as a 32-bit signed value. The sign is preserved.
 *
 * @note This function pairs with the mcuxClMlDsa_SSHR32 and allows to avoid
 *       rigth shift operation ">>" on signed numbers. Extended to armclang
 *       for consistency.
 *
 * @param[in] val64  The 64-bit value to be processed
 * @return A 32-bit signed value containing the high 32 bits of the input
 */
#if defined(__IASMARM__) || defined(__ICCARM__)
static inline ALWAYS_INLINE int32_t mcuxClMlDsa_SignedHi64_ToLo32(int64_t val64) {
  int32_t result;
  __asm(
    /* Move higher word to result */
    "mov %0, %R1 \n"
    : "=r"(result)
    : "r"(val64)
    :
  );
  return result;
}
#else
static inline int32_t mcuxClMlDsa_SignedHi64_ToLo32(int64_t val64) {
  MCUX_CSSL_ANALYSIS_START_PATTERN_SIGNED_SHIFT()
  return (int32_t)(val64 >> 32U);
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SIGNED_SHIFT()
}
#endif /* defined(__IASMARM__) || defined(__ICCARM__) */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMLDSA_INTERNAL_INLINEASSEMBLY_H_ */
