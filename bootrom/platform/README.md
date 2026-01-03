# Platform Abstraction Layer

This directory provides platform-specific abstractions for the BootROM.

## Contents

- `platform.c/h`: Platform abstraction functions
- `platform_mbedtls.h`: MbedTLS platform configuration

## Functions

- `platform_delay_ms()`: Millisecond delay function
- `platform_get_boot_source()`: Determine boot source (QSPI, NAND, etc.)
- `platform_secure_storage_read()`: Read from secure storage (OTP, eFuse)

## Implementation

Currently contains stub implementations. In production, these should interface with the actual hardware platform features.</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/bootrom/platform/README.md