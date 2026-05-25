#---------------------------------------------
# Copyright 2026 NXP.
# SPDX-License-Identifier: BSD-3-Clause
#---------------------------------------------

########################
#    Documentation     #
########################
if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.doc.mcxa5xx)
    mcux_add_source(
        SOURCES
                doc/mcxa5xx/html/*.*
                doc/mcxa5xx/html/search/*.*
                LICENSE.md
                ReleaseNotes_PQC.txt
                SBOM-MCU_DCI-DCI_SDK_V4.2.1_PQC.spdx.json
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )

    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.doc.mcxw7x)
    mcux_add_source(
        SOURCES
                doc/mcxw7x/html/*.*
                doc/mcxw7x/html/search/*.*
                LICENSE.md
                ReleaseNotes_PQC.txt
                SBOM-MCU_DCI-DCI_SDK_V4.2.1_PQC.spdx.json
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )

    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

########################
#    Platform specific #
########################

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.platform_pqc.mcxa5xx)
    mcux_add_source(
        SOURCES includes/platform/mcxa5xx/mcuxClMlDsa_MemoryConsumption.h
                includes/platform/mcxa5xx/mcuxClMlKem_MemoryConsumption.h

                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 includes/platform/mcxa5xx
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.platform_pqc.mcxw7x)
    mcux_add_source(
        SOURCES includes/platform/mcxw7x/mcuxClMlDsa_MemoryConsumption.h
                includes/platform/mcxw7x/mcuxClMlKem_MemoryConsumption.h

                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 includes/platform/mcxw7x
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

########################
#    Static lib        #
########################

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.static_lib.mcxa5xx)
    mcux_add_source(
        SOURCES static_library/mcxa5xx/libclns_pqc.a
                static_library/mcxa5xx/libclns_pqc.a.libsize
                static_library/mcxa5xx/libclns_pqc.a.objsize
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.static_lib.mcxw7x)
    mcux_add_source(
        SOURCES static_library/mcxw7x/libclns_pqc.a
                static_library/mcxw7x/libclns_pqc.a.libsize
                static_library/mcxw7x/libclns_pqc.a.objsize
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

########################
#    Components        #
########################

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.kem)
    mcux_add_source(
        SOURCES src/comps/mcuxClKem/src/mcuxClKem.c

                src/comps/mcuxClKem/inc/mcuxClKem.h
                src/comps/mcuxClKem/inc/mcuxClKem_Constants.h
                src/comps/mcuxClKem/inc/mcuxClKem_Functions.h
                src/comps/mcuxClKem/inc/mcuxClKem_Types.h
                src/comps/mcuxClKem/inc/internal/mcuxClKem_Internal_Types.h
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClKem/inc
                 src/comps/mcuxClKem/inc/internal
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.mldsa)
    mcux_add_source(
        SOURCES src/comps/mcuxClMlDsa/src/mcuxClMlDsa_ExternalApi.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyEncodings.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyGen.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyGenerationModes.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyTypes.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_ModeConstructor.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_NTT.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Packing.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Params.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Poly.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Sign.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Verify.c

                src/comps/mcuxClMlDsa/src/size/size.c

                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_Constants.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_KeyEncodings.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_KeyTypes.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_ModeConstructor.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_Types.h

                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Constants.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_ExternalApi.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Functions.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_InlineAssembly.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_NTT.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Packing.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Params.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Poly.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Types.h
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMlDsa/inc
                 src/comps/mcuxClMlDsa/inc/internal
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.mlkem)
    mcux_add_source(
        SOURCES src/comps/mcuxClMlKem/src/mcuxClMlKem_Indcpa.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_KEM.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_KemModes.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_KeyEncodings.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_KeyGenerationModes.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_KeyTypes.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_NTT.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_Params.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_Poly.c
                src/comps/mcuxClMlKem/src/mcuxClMlKem_Utils.c

                src/comps/mcuxClMlKem/src/size/size.c

                src/comps/mcuxClMlKem/inc/mcuxClMlKem.h
                src/comps/mcuxClMlKem/inc/mcuxClMlKem_Constants.h
                src/comps/mcuxClMlKem/inc/mcuxClMlKem_KeyEncodings.h
                src/comps/mcuxClMlKem/inc/mcuxClMlKem_KeyTypes.h
                src/comps/mcuxClMlKem/inc/mcuxClMlKem_Types.h

                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Indcpa.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Internal.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Internal_Constants.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Internal_Functions.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Internal_Types.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Poly.h
                src/comps/mcuxClMlKem/inc/internal/mcuxClMlKem_Utils.h
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMlKem/inc
                 src/comps/mcuxClMlKem/inc/internal
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()
########################
#    Examples          #
########################

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.examples_mldsa)
    mcux_add_source(
        SOURCES examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenDeterministic_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_Verify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_PreHash_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_PreHash_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_Verify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_PreHash_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_PreHash_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_Verify_example.c
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc//
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxClMlDsa
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.sgi_pkc_pqc.examples_mlkem)
    mcux_add_source(
        SOURCES examples/mcuxClMlKem/mcuxClMlKem_KeyGenEncAndDec_example.c
                BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxClMlKem
                 BASE_PATH ${SdkRootDirPath}/components/sgi_pkc/pqc/
    )
endif()
