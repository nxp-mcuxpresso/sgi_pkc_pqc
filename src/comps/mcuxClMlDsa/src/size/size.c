/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file size.c
 * @brief Defining objects related to the memory usage in @ref mcuxClMlDsa.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClMlDsa_Constants.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>
#include <internal/mcuxClMlDsa_Internal_Constants.h>
#include <internal/mcuxClXofModes_Internal_Memory.h>
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#include <internal/mcuxClPkc_Internal_Types.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile struct mcuxClMlDsa_Signature_ProtocolDescriptor mcuxClMlDsa_Signature_ProtocolDescriptor_size;
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()

/* Sizes for polynomials in PKC or CPU workarea based on feature flag settings */
#if defined(MCUXCL_FEATURE_PKC_RAM_8KB)
#define MCUXCLMLDSA_VERIFY_PKC_WA_POLY       (MCUXCLMLDSA_POLY_SIZE * 8U)
#define MCUXCLMLDSA_VERIFY_CPU_WA_POLY(mode) \
  (((mode) == MCUXCLMLDSA_MODE_87) ? (MCUXCLMLDSA_POLY_SIZE * 2U) : (0U))
#elif defined(MCUXCL_FEATURE_PKC_RAM_4KB)
#define MCUXCLMLDSA_VERIFY_PKC_WA_POLY       (MCUXCLMLDSA_POLY_SIZE * 4U)
#define MCUXCLMLDSA_VERIFY_CPU_WA_POLY(mode) (MCUXCLMLDSA_POLY_SIZE * 2U)
#else
#define MCUXCLMLDSA_VERIFY_PKC_WA_POLY       (0U)
#define MCUXCLMLDSA_VERIFY_CPU_WA_POLY(mode) (MCUXCLMLDSA_POLY_SIZE * 2U)
#endif

/*******************************************************************************
 * Workarea sizes for ML-DSA API functions
 ******************************************************************************/

/* KeyGen */
#define MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(mode) \
    (   MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLY_SIZE)                          /* pS1 */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLY_SIZE)                          /* pT1 */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(2U * MCUXCLMLDSA_SEEDBYTES + MCUXCLMLDSA_CRHBYTES) /* pWa */ \
      + MCUXCLCORE_MAX( \
          MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLYT0_PACKEDBYTES), \
                        MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLYT1_PACKEDBYTES)), \
          MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL) /* shakeContext */ \
            + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_KEYGEN_XOF_OUT_BUFFER_SIZE)) /* xof output buffers (shake128/shake256) */ \
        /* Mode-dependent value: size of s1 + s2 packed */ \
      +   (((mode) == MCUXCLMLDSA_MODE_44) ? ((MCUXCLMLDSA_MLDSA44_L + 1U) * MCUXCLMLDSA_MLDSA44_POLYETA_PACKEDBYTES) \
        : (((mode) == MCUXCLMLDSA_MODE_65) ? ((MCUXCLMLDSA_MLDSA65_L + 1U) * MCUXCLMLDSA_MLDSA65_POLYETA_PACKEDBYTES) \
                                         : ((MCUXCLMLDSA_MLDSA87_L + 1U) * MCUXCLMLDSA_MLDSA87_POLYETA_PACKEDBYTES))) \
      /* All the following are internal functions */ \
      + MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE), /* XOF_HASH */ \
        MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SEEDBYTES + 2U),      /* Matrix Accumulate */ \
                      MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_CRHBYTES + 2U))))     /* Uniform ETA */

/* Sign */
#define MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(mode) \
    (   MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL)       /* shakeContext */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIGN_XOF_OUT_BUFFER_SIZE)           /* pXofOutBuf */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLY_SIZE)                          /* w0 */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_POLY_SIZE)                          /* w1 */ \
      /* Mode-dependent value: K * (Z_packed + W_packed) */                            /* mcuxClMlDsa_Poly_W_Packed_P */ \
      +   (((mode) == MCUXCLMLDSA_MODE_44) ? (MCUXCLMLDSA_MLDSA44_K * (MCUXCLMLDSA_MLDSA44_POLYZ_PACKEDBYTES + MCUXCLMLDSA_MLDSA44_POLYW1_PACKEDBYTES)) \
        : (((mode) == MCUXCLMLDSA_MODE_65) ? (MCUXCLMLDSA_MLDSA65_K * (MCUXCLMLDSA_MLDSA65_POLYZ_PACKEDBYTES + MCUXCLMLDSA_MLDSA65_POLYW1_PACKEDBYTES)) \
                                         : (MCUXCLMLDSA_MLDSA87_K * (MCUXCLMLDSA_MLDSA87_POLYZ_PACKEDBYTES + MCUXCLMLDSA_MLDSA87_POLYW1_PACKEDBYTES)))) \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SEEDBYTES)                          /* rho */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_TRBYTES)                            /* tr */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SEEDBYTES)                          /* key */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_CRHBYTES)                           /* mu */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_CRHBYTES)                           /* rhoprime */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_RNGBYTES)                           /* rng */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_C_PACKED_BYTES)                     /* c_packed */ \
      /* All the following are internal functions */ \
      + MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE), /* XOF_HASH */ \
        MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SEEDBYTES + 2U),      /* Matrix Accumulate */ \
        MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_CRHBYTES + 2U),       /* Uniform Gamma1 */ \
                      MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)))))  /* Random number generation */

/* Verify */
#define MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(mode) \
    (   MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL)      /* pShakeContext */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOFMODES_SHAKE256_CONTEXT_SIZE_INTERNAL)      /* pShakeContextMu */ \
      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SHAKE128_RATE)                      /* pHashOutBuf */ \
      + MCUXCLMLDSA_VERIFY_CPU_WA_POLY(mode)                                            /* Size of CPU polynomials */ \
      + MCUXCLMLDSA_VERIFY_SIZEOF_CPACKED                                               /* Size of cPacked (if required) */ \
      /* Mode-dependent value: size of hint vector */ \
      +   (((mode) == MCUXCLMLDSA_MODE_44) ? (MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_MLDSA44_OMEGA + MCUXCLMLDSA_MLDSA44_K)) \
        : (((mode) == MCUXCLMLDSA_MODE_65) ? (MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_MLDSA65_OMEGA + MCUXCLMLDSA_MLDSA65_K)) \
                                         : (MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_MLDSA87_OMEGA + MCUXCLMLDSA_MLDSA87_K)))) \
     /* All the following are internal functions */ \
      + MCUXCLCORE_MAX(MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE), /* XOF_HASH */ \
                      MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE) \
                      + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SEEDBYTES + 2U)))   /* Matrix Accumulate */

/* Size for cPacked depending on whether PKC RAM is used */
#define MCUXCLMLDSA_VERIFY_SIZEOF_CPACKED (0U) /* we don't need pack/unpack c in this case */

#define MCUXCLMLDSA_VERIFY_PKC_WA_DOUBLE_VERIFICATION (\
    ((MCUXCLMLDSA_UPTRT_SIZE) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLMLDSA_CTILDEMAX_BYTES))))

#define MCUXCLMLDSA_VERIFY_SIZEOF_WAPKC \
  MCUXCLCORE_MAX(MCUXCLMLDSA_VERIFY_PKC_WA_DOUBLE_VERIFICATION, MCUXCLMLDSA_VERIFY_PKC_WA_POLY)

/*******************************************************************************
 * Defines for the maximum sizes when using ML-DSA API functions
 ******************************************************************************/

#define MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU_MAX \
      MCUXCLCORE_MAX(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44), \
      MCUXCLCORE_MAX(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65), \
                    MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87)))

#define MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU_MAX \
      MCUXCLCORE_MAX(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44), \
      MCUXCLCORE_MAX(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65), \
                    MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87)))

#define MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU_MAX \
      MCUXCLCORE_MAX(MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44), \
      MCUXCLCORE_MAX(MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65), \
                    MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87)))

#define MCUXCLMLDSA_SIZEOF_WA_CPU_MAX(mode) \
      MCUXCLCORE_MAX(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(mode), \
      MCUXCLCORE_MAX(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(mode), \
                    MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(mode)))

#define MCUXCLMLDSA_SIZEOF_WA_CPU_MAX_INT \
      MCUXCLCORE_MAX(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU_MAX, \
      MCUXCLCORE_MAX(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU_MAX, \
                    MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU_MAX))

/*******************************************************************************
 * Memory allocation (arrays) for various functions
 ******************************************************************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile uint8_t mcuxClMlDsa_Keypair_44_WaCpu [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44))];
volatile uint8_t mcuxClMlDsa_Keypair_65_WaCpu [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65))];
volatile uint8_t mcuxClMlDsa_Keypair_87_WaCpu [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_KEYPAIR_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87))];

volatile uint8_t mcuxClMlDsa_Sign_44_WaCpu    [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44))];
volatile uint8_t mcuxClMlDsa_Sign_65_WaCpu    [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65))];
volatile uint8_t mcuxClMlDsa_Sign_87_WaCpu    [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIGN_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87))];

volatile uint8_t mcuxClMlDsa_Verify_44_WaCpu  [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_44))];
volatile uint8_t mcuxClMlDsa_Verify_65_WaCpu  [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_65))];
volatile uint8_t mcuxClMlDsa_Verify_87_WaCpu  [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_VERIFY_SIZEOF_WA_CPU(MCUXCLMLDSA_MODE_87))];
volatile uint8_t mcuxClMlDsa_Verify_WaPkc     [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_VERIFY_SIZEOF_WAPKC)];

volatile uint8_t mcuxClMlDsa_44_WaCpu         [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIZEOF_WA_CPU_MAX(MCUXCLMLDSA_MODE_44))];
volatile uint8_t mcuxClMlDsa_65_WaCpu         [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIZEOF_WA_CPU_MAX(MCUXCLMLDSA_MODE_65))];
volatile uint8_t mcuxClMlDsa_87_WaCpu         [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIZEOF_WA_CPU_MAX(MCUXCLMLDSA_MODE_87))];

volatile uint8_t mcuxClMlDsa_WaCpu            [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLDSA_SIZEOF_WA_CPU_MAX_INT)];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
