cmake_minimum_required(VERSION 3.15)
project(BootSigner C)

# Options for crypto library
option(USE_MBEDTLS "Use MbedTLS for signing" OFF)
option(USE_OPENSSL "Use OpenSSL for signing" ON)

# Find dependencies
if(USE_MBEDTLS)
    # Use same MbedTLS as BootROM
    if(NOT MBEDTLS_ROOT)
        set(MBEDTLS_ROOT "${CMAKE_SOURCE_DIR}/../../external/mbedtls")
    endif()

    include_directories(${MBEDTLS_ROOT}/include)
    link_directories(${MBEDTLS_ROOT}/library)

    set(CRYPTO_SOURCES
        image_builder_mbedtls.c
    )

    set(CRYPTO_LIBS mbedcrypto)

elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)

    set(CRYPTO_SOURCES
        image_builder_openssl.c
    )

    set(CRYPTO_LIBS OpenSSL::Crypto)

else()
    message(FATAL_ERROR "Must choose either USE_MBEDTLS or USE_OPENSSL")
endif()

# Source files
set(SOURCES
    main.c
    ${CRYPTO_SOURCES}
)

# Create executable
add_executable(boot_signer ${SOURCES})

# Link libraries
target_link_libraries(boot_signer ${CRYPTO_LIBS})

# Include directories
target_include_directories(boot_signer PRIVATE ${CMAKE_SOURCE_DIR})

# Compiler flags
target_compile_options(boot_signer PRIVATE -Wall -Wextra -O2)

# Install
install(TARGETS boot_signer DESTINATION bin)