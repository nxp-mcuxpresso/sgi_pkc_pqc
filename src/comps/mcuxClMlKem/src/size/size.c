/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file:  size.c
 * @brief: This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <internal/mcuxClMlKem_Internal_Constants.h>
#include <mcuxClXof_Types.h>
#include <internal/mcuxClXof_Internal.h>
#include <internal/mcuxClXofModes_Internal_Memory.h>

#define MLKEM_K(mode)   ((mode == 1) ? 2 : ((mode == 3) ? 3 : 4) )

#define MCUXCLMLKEM_XOF_CONTEXT_SIZE    MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL
#define MCUXCLMLKEM_XOF_WACPUMAX        (MCUXCLXOF_STATE_SIZE_SHAKE + MCUXCLXOF_BLOCK_SIZE_SHAKE_128)

#define MCUXCLMLKEM_INDCPA_KEYGEN_SIZEOF_WA_CPU(mode) \
    (   192u \
      + MCUXCLMLKEM_XOF_CONTEXT_SIZE \
      + 2u*MCUXCLMLKEM_SYMBYTES \
      + 96u*MLKEM_K(mode) \
      + 4u*MCUXCLMLKEM_N )


#define MCUXCLMLKEM_INDCPA_ENCRYPTION_SIZEOF_WA_CPU(mode) \
    (   192u \
      + MCUXCLMLKEM_XOF_CONTEXT_SIZE \
      + MCUXCLMLKEM_SYMBYTES \
      + 96u*MLKEM_K(mode) \
      + 4u*MCUXCLMLKEM_N )


#define MCUXCLMLKEM_INDCPA_DECRYPTION_SIZEOF_WA_CPU(mode) \
    (   192u \
      + 4u*MCUXCLMLKEM_N )


#define MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(mode) \
    (   MCUXCLMLKEM_INDCPA_KEYGEN_SIZEOF_WA_CPU(mode) \
      + MCUXCLMLKEM_XOF_WACPUMAX /* Shake */)

#define MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(mode) \
    (   3u*MCUXCLMLKEM_SYMBYTES /* KEM */ \
      + MCUXCLMLKEM_INDCPA_ENCRYPTION_SIZEOF_WA_CPU(mode)  /* INDCPA Encryption */ \
      + MCUXCLMLKEM_XOF_WACPUMAX /* Shake */)

/* Max of decryption & re-encryption */
#define MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(mode) \
    (   4*MCUXCLMLKEM_SYMBYTES /* KEM */ \
      + MCUXCLCORE_MAX(MCUXCLMLKEM_INDCPA_ENCRYPTION_SIZEOF_WA_CPU(mode), \
                       MCUXCLMLKEM_INDCPA_DECRYPTION_SIZEOF_WA_CPU(mode)) \
      + MCUXCLMLKEM_XOF_WACPUMAX /* Shake */)

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClMlKem_Keygen_512_Sizeof_Wa_Cpu          [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(1))];
volatile uint8_t mcuxClMlKem_Keygen_768_Sizeof_Wa_Cpu          [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(3))];
volatile uint8_t mcuxClMlKem_Keygen_1024_Sizeof_Wa_Cpu         [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(5))];

volatile uint8_t mcuxClMlKem_Encapsulation_512_Sizeof_Wa_Cpu   [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(1))];
volatile uint8_t mcuxClMlKem_Encapsulation_768_Sizeof_Wa_Cpu   [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(3))];
volatile uint8_t mcuxClMlKem_Encapsulation_1024_Sizeof_Wa_Cpu  [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(5))];

volatile uint8_t mcuxClMlKem_Decapsulation_512_Sizeof_Wa_Cpu   [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(1))];
volatile uint8_t mcuxClMlKem_Decapsulation_768_Sizeof_Wa_Cpu   [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(3))];
volatile uint8_t mcuxClMlKem_Decapsulation_1024_Sizeof_Wa_Cpu  [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(5))];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()

/* Define the maximum workspace */
#define MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU_MAX         MCUXCLCORE_MAX(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(1), \
                                                           MCUXCLCORE_MAX(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(3), \
                                                                          MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU(5)))

#define MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU_MAX  MCUXCLCORE_MAX(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(1), \
                                                           MCUXCLCORE_MAX(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(3), \
                                                                          MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU(5)))

#define MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU_MAX  MCUXCLCORE_MAX(MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(1), \
                                                           MCUXCLCORE_MAX(MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(3), \
                                                                          MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU(5)))

#define MCUXCLMLKEM_SIZEOF_WA_CPU_MAX_INT                   MCUXCLCORE_MAX(MCUXCLMLKEM_KEYGEN_SIZEOF_WA_CPU_MAX, \
                                                           MCUXCLCORE_MAX(MCUXCLMLKEM_ENCAPSULATION_SIZEOF_WA_CPU_MAX, \
                                                                          MCUXCLMLKEM_DECAPSULATION_SIZEOF_WA_CPU_MAX))

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClMlKem_WorkAreaSize_Max[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLMLKEM_SIZEOF_WA_CPU_MAX_INT)];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
