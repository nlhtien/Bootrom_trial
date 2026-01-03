# Secure Boot Core

This directory implements the core secure boot functionality for Stages 3 & 4.

## Contents

- `secure_boot_core.c/h`: Main secure boot implementation
- `mbedtls_config.h`: MbedTLS configuration for secure boot

## Security Features

- Image signature verification using RSA/ECC
- AES decryption of boot images
- Anti-rollback protection via version counters
- Zeroization of sensitive data before handoff

## Image Format

Boot images use a custom header format with magic number, version, signature, and encrypted payload.</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/bootrom/secure_boot/README.md