cmake_minimum_required(VERSION 3.15)

# =============================================================================
# Project
# =============================================================================
project(BootSigner
    VERSION 1.0
    DESCRIPTION "Boot Image Signing Tool"
    LANGUAGES C
)

# =============================================================================
# Build options
# =============================================================================

option(BOOT_SIGNER_USE_OPENSSL "Use OpenSSL backend" ON)
option(BOOT_SIGNER_USE_MBEDTLS "Use MbedTLS backend" OFF)

if(BOOT_SIGNER_USE_OPENSSL AND BOOT_SIGNER_USE_MBEDTLS)
    message(FATAL_ERROR "Choose only one crypto backend: OpenSSL or MbedTLS")
endif()

if(NOT BOOT_SIGNER_USE_OPENSSL AND NOT BOOT_SIGNER_USE_MBEDTLS)
    message(FATAL_ERROR "Must select one crypto backend")
endif()

# =============================================================================
# C standard & build type
# =============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# =============================================================================
# Warning & optimization flags
# =============================================================================

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wformat=2
    -fno-common
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g3 -DDEBUG)
else()
    add_compile_options(-O2 -DNDEBUG)
endif()

# =============================================================================
# Sources
# =============================================================================

set(SOURCES
    main.c
)

# =============================================================================
# Crypto backend selection
# =============================================================================

if(BOOT_SIGNER_USE_OPENSSL)
    message(STATUS "BootSigner: using OpenSSL backend")

    find_package(OpenSSL REQUIRED)

    list(APPEND SOURCES
        image_builder_openssl.c
    )

    set(CRYPTO_LIBS OpenSSL::Crypto)

    add_compile_definitions(BOOT_SIGNER_USE_OPENSSL)

elseif(BOOT_SIGNER_USE_MBEDTLS)
    message(STATUS "BootSigner: using MbedTLS backend")

    if(NOT MBEDTLS_ROOT)
        set(MBEDTLS_ROOT "${CMAKE_SOURCE_DIR}/../../external/mbedtls"
            CACHE PATH "Path to MbedTLS")
    endif()

    list(APPEND SOURCES
        image_builder_mbedtls.c
    )

    set(MBEDTLS_CRYPTO_LIB
        ${MBEDTLS_ROOT}/library/libmbedcrypto.a
    )

    set(CRYPTO_LIBS ${MBEDTLS_CRYPTO_LIB})

    target_include_directories(${PROJECT_NAME} INTERFACE
        ${MBEDTLS_ROOT}/include
    )

    add_compile_definitions(BOOT_SIGNER_USE_MBEDTLS)
endif()

# =============================================================================
# Executable
# =============================================================================

add_executable(boot_signer
    ${SOURCES}
)

target_include_directories(boot_signer PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(boot_signer PRIVATE
    ${CRYPTO_LIBS}
)

# =============================================================================
# Install
# =============================================================================

install(TARGETS boot_signer
    RUNTIME DESTINATION bin
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "-------------------------------------------------")
message(STATUS "BootSigner build configuration:")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL:        ${BOOT_SIGNER_USE_OPENSSL}")
message(STATUS "  MbedTLS:        ${BOOT_SIGNER_USE_MBEDTLS}")
message(STATUS "-------------------------------------------------")
