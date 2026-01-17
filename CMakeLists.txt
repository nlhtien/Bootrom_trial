cmake_minimum_required(VERSION 3.15)

# =============================================================================
# Toolchain
# =============================================================================
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/toolchain.cmake)

# =============================================================================
# Project
# =============================================================================
project(BootROM
    VERSION 1.0
    DESCRIPTION "Boot ROM Firmware"
    LANGUAGES C ASM
)
# =============================================================================
# Build Options
# =============================================================================

# Build targets
option(BUILD_BOOTROM "Build BootROM firmware" ON)
option(BUILD_TESTING "Build unit tests" OFF)

# Feature switches
option(ENABLE_QEMU_SEMIHOSTING "Enable semihosting for QEMU output" OFF)
#option(ENABLE_CRYPTO_ACCEL "Enable hardware crypto acceleration hooks" OFF)

# Crypto feature selection
option(BOOTROM_ENABLE_AES "Enable AES encryption/decryption" ON)
option(BOOTROM_ENABLE_RSA "Enable RSA signature verification" ON)
option(BOOTROM_ENABLE_ECC "Enable ECC/ECDSA signature verification" ON)
option(BOOTROM_ENABLE_SHA256 "Enable SHA-256 hash" ON)
option(BOOTROM_ENABLE_SHA512 "Enable SHA-512 hash" OFF)

# Build quality
option(BOOTROM_SECURE_BOOT "Enable secure boot features" ON)
option(BOOTROM_ENABLE_LTO "Enable link-time optimization" ON)
option(BOOTROM_DEV_MODE "Enable BootROM dev mode" ON)

# Force SHA256 if RSA or ECC is enabled
if(BOOTROM_ENABLE_RSA OR BOOTROM_ENABLE_ECC)
    set(BOOTROM_ENABLE_SHA256 ON CACHE BOOL "" FORCE)
endif()

# Validate secure boot requirements
if(BOOTROM_SECURE_BOOT AND NOT (BOOTROM_ENABLE_RSA OR BOOTROM_ENABLE_ECC))
    message(FATAL_ERROR "Secure boot requires RSA or ECC signature verification enabled.")
endif()

# =============================================================================
# 1. C Standard
# =============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# =============================================================================
# 2. Target Architecture (ARM Cortex-R5F)
# =============================================================================
# -mcpu=cortex-r5       : Target ARM Cortex-R5
# -mthumb               : Generate Thumb-2 code (better code density)
# -mfloat-abi=hard      : Use hardware FPU registers
# -mfpu=vfpv3-d16       : Specify available FPU
set(CPU_FLAGS "-mcpu=cortex-r5 -mthumb -mfloat-abi=hard -mfpu=vfpv3-d16")

# =============================================================================
# 3. Compiler Options (BootROM-grade hygiene)
# =============================================================================
# -Wall -Wextra -Wpedantic            : Strict warnings
# -ffunction-sections -fdata-sections : Place each function/data into its own section for linker GC
# -fno-builtin                        : Do not emit compiler builtin libc calls
# -fno-strict-aliasing                : Avoid UB in low-level MMIO / type-punning code
# -fno-stack-protector                : Do not emit stack canary (__stack_chk_fail)
# -fno-unwind-tables                  : Do not emit exception unwind tables
# -fno-asynchronous-unwind-tables     : Do not emit async unwind info (.ARM.exidx)
# -fno-common                         : Enforce proper global definitions
set(COMMON_FLAGS
    "${CPU_FLAGS} -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -fno-builtin -fno-strict-aliasing -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-common -fvisibility=hidden"
)

# =============================================================================
# Feature-related compile definitions
# =============================================================================

if(ENABLE_QEMU_SEMIHOSTING)
    add_compile_definitions(BOOTROM_USE_SEMIHOSTING)
endif()

if(BOOTROM_SECURE_BOOT)
    add_compile_definitions(BOOTROM_USE_SECURE_BOOT)
endif()

if(BOOTROM_DEV_MODE)
    add_compile_definitions(BOOTROM_DEV_MODE)
endif()

if(BUILD_TESTING)
    add_compile_definitions(UNIT_TESTING)
    enable_testing()
endif()

# =============================================================================
# Optimization level
# =============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Debug: no optimization, full symbols
    add_compile_options(-g3 -O0 -DDEBUG)
else()
    # Release: optimize for size
    add_compile_options(-Os -DNDEBUG)
endif()

# Enable LTO in release builds
if(BOOTROM_ENABLE_LTO AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-flto)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
endif()

set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=c11")
set(CMAKE_ASM_FLAGS "${CPU_FLAGS} -x assembler-with-cpp")

# =============================================================================
# 4. Linker Options
# =============================================================================
# -nostdlib            : Do not link any system libraries
# -nostartfiles        : Do not use CRT startup files
# --gc-sections        : Remove unused sections
# --print-memory-usage : Print memory usage
# -Map                 : Generate map file
set(CMAKE_EXE_LINKER_FLAGS
    "${CPU_FLAGS} -T ${CMAKE_SOURCE_DIR}/bootrom/arch/arm/r5f/linker.ld -nostdlib -nostartfiles -Wl,--gc-sections -Wl,--print-memory-usage -Wl,-Map=bootrom.map"
)

# =============================================================================
# 5. Include Directories
# =============================================================================
include_directories(
    ${CMAKE_SOURCE_DIR}/bootrom/secure_boot
    ${CMAKE_SOURCE_DIR}/bootrom
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/include
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library
)

# =============================================================================
# mbedTLS Configuration
# =============================================================================
add_compile_definitions(MBEDTLS_CONFIG_FILE="${CMAKE_SOURCE_DIR}/bootrom/secure_boot/mbedtls_config.h")
add_compile_definitions(MBEDTLS_USE_PSA_CRYPTO=0)
add_compile_definitions(MBEDTLS_PSA_CRYPTO_CLIENT=0)
add_compile_definitions(MBEDTLS_PLATFORM_STD_SNPRINTF=mbedtls_platform_snprintf)

# =============================================================================
# 6. BootROM sources
# =============================================================================
set(BOOTROM_SOURCES
    bootrom/main.c
    bootrom/arch/arm/r5f/startup.S
    bootrom/platform/platform.c
    bootrom/drivers/uart.c
    bootrom/drivers/flash.c
    bootrom/drivers/watchdog.c
    bootrom/secure_boot/secure_boot_core.c
    bootrom/crypto/crypto_wrapper.c
)

# =============================================================================
# 7. mbedTLS minimal commercial subset (feature-based)
# =============================================================================

set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library)

set(MBEDTLS_MINIMAL_SOURCES
    # Core
    # ${MBEDTLS_DIR}/platform_util.c
    # ${MBEDTLS_DIR}/platform.c
    ${MBEDTLS_DIR}/constant_time.c
    # ${MBEDTLS_DIR}/memory_buffer_alloc.c
    # ${MBEDTLS_DIR}/base64.c
    # Big number
    ${MBEDTLS_DIR}/bignum.c
    ${MBEDTLS_DIR}/bignum_core.c
    ${MBEDTLS_DIR}/bignum_mod.c
    ${MBEDTLS_DIR}/bignum_mod_raw.c
    # Hashing
    ${MBEDTLS_DIR}/md.c
    # AS1N.1 and PK parsing
    # ${MBEDTLS_DIR}/asn1parse.c
    # ${MBEDTLS_DIR}/asn1write.c
    # OID / PEM / PK
    # ${MBEDTLS_DIR}/oid.c
    # ${MBEDTLS_DIR}/pem.c
    # ${MBEDTLS_DIR}/pk.c
    # ${MBEDTLS_DIR}/pk_wrap.c
    # ${MBEDTLS_DIR}/pkparse.c
    # ${MBEDTLS_DIR}/pk_ecc.c
)

# if(BOOTROM_DEV_MODE)
#     list(APPEND MBEDTLS_MINIMAL_SOURCES
#         ${MBEDTLS_DIR}/x509_crt.c
#     )
#     add_compile_definitions(BOOTROM_DEV_MODE)
# endif()

if(BOOTROM_ENABLE_AES)
    list(APPEND MBEDTLS_MINIMAL_SOURCES
        ${MBEDTLS_DIR}/aes.c
        ${MBEDTLS_DIR}/cipher.c
        ${MBEDTLS_DIR}/cipher_wrap.c
    )
    add_compile_definitions(BOOTROM_ENABLE_AES)
endif()

if(BOOTROM_ENABLE_RSA)
    list(APPEND MBEDTLS_MINIMAL_SOURCES
        ${MBEDTLS_DIR}/rsa.c
        ${MBEDTLS_DIR}/rsa_alt_helpers.c
    )
    add_compile_definitions(BOOTROM_ENABLE_RSA)
endif()

if(BOOTROM_ENABLE_ECC)
    list(APPEND MBEDTLS_MINIMAL_SOURCES
        ${MBEDTLS_DIR}/ecp.c
        ${MBEDTLS_DIR}/ecp_curves.c
        ${MBEDTLS_DIR}/ecdsa.c
    )
    add_compile_definitions(BOOTROM_ENABLE_ECC)
endif()

if(BOOTROM_ENABLE_SHA256)   
    list(APPEND MBEDTLS_MINIMAL_SOURCES
        ${MBEDTLS_DIR}/sha256.c
    )
    add_compile_definitions(BOOTROM_ENABLE_SHA256)
endif()

if(BOOTROM_ENABLE_SHA512)
    list(APPEND MBEDTLS_MINIMAL_SOURCES
        ${MBEDTLS_DIR}/sha512.c
    )
    add_compile_definitions(BOOTROM_ENABLE_SHA512)
endif()

# =============================================================================
# Final sources
# =============================================================================
set(SOURCES
    ${BOOTROM_SOURCES}
    ${MBEDTLS_MINIMAL_SOURCES}
)

# =============================================================================
# Build targets
# =============================================================================

if(BUILD_BOOTROM)
    add_executable(bootrom.elf ${SOURCES})
endif()

if(BUILD_TESTING)
    add_executable(test_runner
        bootrom/tests/test_main.c
        bootrom/tests/test_crypto.c
        bootrom/tests/test_secure_boot.c
        bootrom/tests/test_framework.c
        ${SOURCES}
    )
    target_compile_definitions(test_runner PRIVATE UNIT_TESTING)
    add_test(NAME unit_tests COMMAND test_runner)
endif()

# =============================================================================
# Tool discovery
# =============================================================================
if(NOT CMAKE_OBJCOPY)
    find_program(CMAKE_OBJCOPY arm-none-eabi-objcopy)
endif()

if(NOT CMAKE_OBJDUMP)
    find_program(CMAKE_OBJDUMP arm-none-eabi-objdump)
endif()

# =============================================================================
# Post-build
# =============================================================================
if(BUILD_BOOTROM)
    add_custom_command(TARGET bootrom.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary bootrom.elf bootrom.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex bootrom.elf bootrom.hex
        COMMAND ${CMAKE_OBJDUMP} -d bootrom.elf > bootrom.dis
        COMMAND arm-none-eabi-size bootrom.elf
        COMMENT "Post-build: Generating bin/hex/dis and printing size..."
    )
endif()

# =============================================================================
# Build summary
# =============================================================================
message(STATUS "-------------------------------------------------")
message(STATUS "Build Configuration Summary:")
message(STATUS "  Build Type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:        ${CMAKE_C_COMPILER}")
message(STATUS "  Target CPU:      Cortex-R5F")
message(STATUS "  Secure Boot:     ${BOOTROM_SECURE_BOOT}")
message(STATUS "  AES:             ${BOOTROM_ENABLE_AES}")
message(STATUS "  RSA:             ${BOOTROM_ENABLE_RSA}")
message(STATUS "  ECC:             ${BOOTROM_ENABLE_ECC}")
message(STATUS "  SHA256:          ${BOOTROM_ENABLE_SHA256}")
message(STATUS "  SHA512:          ${BOOTROM_ENABLE_SHA512}")
message(STATUS "  LTO:             ${BOOTROM_ENABLE_LTO}")
message(STATUS "  DEV_MODE:        ${BOOTROM_DEV_MODE}")
message(STATUS "  Linker Script:   bootrom/arch/arm/r5f/linker.ld")
message(STATUS "-------------------------------------------------")
