cmake_minimum_required(VERSION 3.15)

# Set toolchain file for cross-compilation
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/toolchain.cmake)

# Project Configuration
project(BootROM C ASM)

# ============================================================================
# Build Options
# ============================================================================

# Build targets
option(BUILD_BOOTROM "Build BootROM firmware" ON)
option(BUILD_TESTING "Build unit tests" OFF)
option(BUILD_DOCS "Build documentation" OFF)
option(BUILD_MBEDTLS_LIB "Build MbedTLS as static library" OFF)

# Feature options
option(ENABLE_QEMU_SEMIHOSTING "Enable semihosting for QEMU UART output" OFF)
option(ENABLE_DEBUG_LOGGING "Enable debug logging" ON)
option(ENABLE_CRYPTO_ACCEL "Enable hardware crypto acceleration" OFF)
option(ENABLE_SECURE_DEBUG "Enable secure debug features" OFF)

# Tool options
option(BUILD_SIGNING_TOOL "Build signing tool" ON)
option(USE_OPENSSL "Use OpenSSL for signing tool" ON)
option(USE_MBEDTLS "Use MbedTLS for signing tool" OFF)

# 1. C Standard Configuration
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 2. Target Architecture (ARM Cortex-R5F)
# -mcpu=cortex-r5: Target the R5 core
# -mthumb: Generate Thumb instructions (preferred for code density)
# -mfloat-abi=hard: Use hardware FPU registers
# -mfpu=vfpv3-d16: Specify the FPU unit available on the SoC
set(CPU_FLAGS "-mcpu=cortex-r5 -mthumb -mfloat-abi=hard -mfpu=vfpv3-d16")

# 3. Compiler Options
# -g3: Generate maximum debug information for GDB
# -ffunction-sections -fdata-sections: Allow linker to remove unused code
set(COMMON_FLAGS "${CPU_FLAGS} -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -fno-builtin -fno-strict-aliasing")

# Feature compilation flags
if(ENABLE_QEMU_SEMIHOSTING)
    add_compile_definitions(QEMU_SEMIHOSTING)
endif()

if(ENABLE_DEBUG_LOGGING)
    add_compile_definitions(DEBUG_LOGGING)
endif()

if(ENABLE_CRYPTO_ACCEL)
    add_compile_definitions(CRYPTO_ACCELERATION)
endif()

if(ENABLE_SECURE_DEBUG)
    add_compile_definitions(SECURE_DEBUG)
endif()

if(BUILD_TESTING)
    add_compile_definitions(UNIT_TESTING)
    enable_testing()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Debug Build: No optimization (-O0), full debug symbols
    add_compile_options(-g3 -O0 -DDEBUG)
else()
    # Release Build: Optimize for size (-Os)
    add_compile_options(-Os -DNDEBUG)
endif()

set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=c11")
set(CMAKE_ASM_FLAGS "${CPU_FLAGS} -x assembler-with-cpp")

# 4. Linker Options
# -nostdlib: Do not link standard system startup files
# --gc-sections: Remove unused sections to save ROM space
# --print-memory-usage: Display RAM/ROM usage after build
set(CMAKE_EXE_LINKER_FLAGS "${CPU_FLAGS} -T ${CMAKE_SOURCE_DIR}/bootrom/arch/arm/r5f/linker.ld -nostdlib -Wl,--gc-sections -Wl,--print-memory-usage")

# 5. Include Directories
include_directories(
    ${CMAKE_SOURCE_DIR}/bootrom/secure_boot  # Put secure_boot first to prioritize our config
    ${CMAKE_SOURCE_DIR}/bootrom
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/include
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library
)

# Definitions for mbedTLS - Use absolute path to our config
add_compile_definitions(MBEDTLS_CONFIG_FILE="${CMAKE_SOURCE_DIR}/bootrom/secure_boot/mbedtls_config.h")
add_compile_definitions(MBEDTLS_USE_PSA_CRYPTO=0)
add_compile_definitions(MBEDTLS_PSA_CRYPTO_CLIENT=0)

# 6. Source Files
set(SOURCES
    bootrom/main.c
    bootrom/arch/arm/r5f/startup.S
    bootrom/platform/platform.c
    bootrom/drivers/uart.c
    bootrom/drivers/flash.c
    bootrom/drivers/watchdog.c  # Added missing watchdog driver
    bootrom/secure_boot/secure_boot_core.c
    bootrom/crypto/crypto_wrapper.c
)

# --- IMPORTANT: mbedTLS Integration ---
file(GLOB MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/*.c")

# --- EXCLUDE FILES INCOMPATIBLE WITH BARE-METAL ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/net_sockets.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/timing.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_storage.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_its_file.c")

list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/lms.c")

# --- EXCLUDE X.509 FILES (not needed for BootROM) ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509_crt.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509_crl.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509_csr.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509.c")
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/pem.c")  # Keep for pkparse
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/base64.c")  # Keep for pem
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509_create.c")

list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_util.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509write_crt.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/x509write_csr.c")

# --- EXCLUDE UNUSED CIPHERS AND MODULES ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/aria.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/camellia.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/des.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/chacha20.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/chachapoly.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/poly1305.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ripemd160.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/sha1.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/sha3.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/sha512.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/md5.c")
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/md.c")  # Keep for md functions
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/padlock.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/aesce.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/aesni.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ecdsa.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/lmots.c")

# --- EXCLUDE ENTROPY AND RNG (using null entropy) ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/entropy.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/entropy_poll.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ctr_drbg.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/hmac_drbg.c")

# --- EXCLUDE UNUSED PK MODULES ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/pkcs12.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/pkcs5.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/pkcs7.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ecjpake.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/dhm.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ecdh.c")
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/oid.c")  # Include for OID functions
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/pk_wrap.c")  # Include for info structs

# --- EXCLUDE DEBUG AND UTILITY MODULES ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/debug.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/error.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/version.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/version_features.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/threading.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/mps_reader.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/mps_trace.c")
# list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/constant_time.c")  # Keep for ct functions
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/nist_kw.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/hkdf.c")

# --- EXCLUDE PSA DRIVERS AND UNUSED ---
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_driver_wrappers_no_static.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_ffdh.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_pake.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_se.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_slot_management.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_aead.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_cipher.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_client.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_ecp.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_hash.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_mac.c")
list(REMOVE_ITEM MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/psa_crypto_rsa.c")

file(GLOB TLS_SOURCES "${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/library/ssl_*.c")
foreach(tls_file ${TLS_SOURCES})
    list(REMOVE_ITEM MBEDTLS_SOURCES ${tls_file})
endforeach()

list(APPEND SOURCES ${MBEDTLS_SOURCES})

# Build MbedTLS as static library if requested
if(BUILD_MBEDTLS_LIB)
    add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
    target_include_directories(mbedtls PUBLIC ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/include)
    target_compile_definitions(mbedtls PRIVATE MBEDTLS_CONFIG_FILE="${CMAKE_SOURCE_DIR}/bootrom/secure_boot/mbedtls_config.h")
    target_compile_definitions(mbedtls PRIVATE MBEDTLS_USE_PSA_CRYPTO=0)
    target_compile_definitions(mbedtls PRIVATE MBEDTLS_PSA_CRYPTO_CLIENT=0)
endif()

# ============================================================================
# Build Targets
# ============================================================================

# BootROM firmware
if(BUILD_BOOTROM)
    add_executable(bootrom.elf ${SOURCES})
endif()

# Unit tests
if(BUILD_TESTING)
    add_executable(test_runner
        bootrom/tests/test_main.c
        bootrom/tests/test_crypto.c
        bootrom/tests/test_secure_boot.c
        bootrom/tests/test_framework.c
        bootrom/platform/platform.c
        bootrom/drivers/uart.c
        bootrom/drivers/flash.c
        bootrom/drivers/watchdog.c
        bootrom/secure_boot/secure_boot_core.c
        bootrom/crypto/crypto_wrapper.c
        ${MBEDTLS_SOURCES}
    )
    target_compile_definitions(test_runner PRIVATE UNIT_TESTING)
    add_test(NAME unit_tests COMMAND test_runner)
endif()

# 7. Executable Target (legacy - kept for compatibility)
if(NOT BUILD_BOOTROM AND NOT BUILD_TESTING)
    add_executable(bootrom.elf ${SOURCES})
endif()

# 8. Tool Discovery
# Ensure objcopy/objdump are found for post-build steps
if(NOT CMAKE_OBJCOPY)
    find_program(CMAKE_OBJCOPY arm-none-eabi-objcopy)
endif()

if(NOT CMAKE_OBJDUMP)
    find_program(CMAKE_OBJDUMP arm-none-eabi-objdump)
endif()

# 9. Post-build Actions
# Generate Binary (.bin), Hex (.hex), and Disassembly (.dis) files
if(BUILD_BOOTROM)
    add_custom_command(TARGET bootrom.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary bootrom.elf bootrom.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex bootrom.elf bootrom.hex
        COMMAND ${CMAKE_OBJDUMP} -d bootrom.elf > bootrom.dis
        COMMENT "Post-build: Generating binary, hex, and disassembly files..."
    )
endif()

# Print Build Configuration Status
message(STATUS "-------------------------------------------------")
message(STATUS "Build Configuration Summary:")
message(STATUS "  Build Type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:        ${CMAKE_C_COMPILER}")
message(STATUS "  Target CPU:      Cortex-R5F")
message(STATUS "  Linker Script:   bootrom/arch/arm/r5f/linker.ld")
message(STATUS "-------------------------------------------------")