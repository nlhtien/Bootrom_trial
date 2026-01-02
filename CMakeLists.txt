cmake_minimum_required(VERSION 3.15)

project(BootROM C ASM)

# Set C/C++ standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Toolchain configuration
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR ARM)

# Compiler flags
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

# CPU-specific flags
set(CPU_FLAGS "-mcpu=cortex-r5 -mthumb -mfloat-abi=hard -mfpu=vfpv3-d16")

# Common flags
set(COMMON_FLAGS "${CPU_FLAGS} -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -fno-builtin -fno-strict-aliasing")
set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=c11")
set(CMAKE_ASM_FLAGS "${CPU_FLAGS} -x assembler-with-cpp")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CPU_FLAGS} -T ${CMAKE_SOURCE_DIR}/bootrom/arch/arm/r5f/linker.ld -nostdlib -Wl,--gc-sections -Wl,--print-memory-usage")

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/bootrom
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls/include
    ${CMAKE_SOURCE_DIR}/bootrom/external/mbedtls
    ${CMAKE_SOURCE_DIR}/bootrom/secure_boot  # For mbedtls_config.h
)

# Note: MbedTLS library sources should be added here or linked as a library
# Example: add_subdirectory(external/mbedtls) or target_link_libraries(bootrom.elf mbedtls)
add_compile_definitions(MBEDTLS_CONFIG_FILE="mbedtls_config.h")
# Define build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -DDEBUG)
else()
    add_compile_options(-Os -DNDEBUG)
endif()

# Source files
set(SOURCES
    bootrom/main.c
    bootrom/arch/arm/r5f/startup.S
    bootrom/platform/platform.c
    bootrom/drivers/uart.c
    bootrom/drivers/flash.c
    bootrom/secure_boot/secure_boot_core.c
    bootrom/crypto/crypto_wrapper.c
)

# Create executable
add_executable(bootrom.elf ${SOURCES})

# Set output name
set_target_properties(bootrom.elf PROPERTIES
    OUTPUT_NAME "bootrom"
    SUFFIX ".elf"
)

# Generate binary, hex, and disassembly files
add_custom_command(TARGET bootrom.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:bootrom.elf> ${CMAKE_BINARY_DIR}/bootrom.bin
    COMMAND ${CMAKE_OBJCOPY} -O ihex $<TARGET_FILE:bootrom.elf> ${CMAKE_BINARY_DIR}/bootrom.hex
    COMMAND ${CMAKE_OBJDUMP} -d $<TARGET_FILE:bootrom.elf> > ${CMAKE_BINARY_DIR}/bootrom.dis
    COMMENT "Generating binary, hex, and disassembly files"
)

# Find objcopy and objdump
find_program(CMAKE_OBJCOPY arm-none-eabi-objcopy)
find_program(CMAKE_OBJDUMP arm-none-eabi-objdump)

# Print information
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C flags: ${CMAKE_C_FLAGS}")
message(STATUS "Linker: ${CMAKE_EXE_LINKER_FLAGS}")
