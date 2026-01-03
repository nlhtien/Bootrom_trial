# Cryptographic Wrappers

This directory provides cryptographic functions for the BootROM, implemented as wrappers around MbedTLS.

## Contents

- `crypto_wrapper.c`: Main crypto wrapper implementation
- `crypto_wrapper.h`: Header file with function declarations

## Supported Operations

- SHA-256 hashing
- AES-CBC decryption (for boot image decryption)
- RSA/ECC signature verification (for secure boot)
- Key management (stub implementations for secure storage)

## Key Management

In production, cryptographic keys should be stored in secure hardware (OTP, eFuse, or secure storage). The current implementation includes stub functions for key loading.

## Memory Management

Uses MbedTLS's static memory buffer allocator to avoid dynamic allocation in the BootROM environment.</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/bootrom/crypto/README.md