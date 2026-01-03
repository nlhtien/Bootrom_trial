# External Libraries

This directory contains external third-party libraries used by the BootROM.

## Contents

- `mbedtls/`: MbedTLS cryptographic library
  - Configured for BootROM use with static memory allocation
  - Supports AES, SHA-256, RSA, ECC operations

## Configuration

- `platform_mbedtls.h`: Platform-specific MbedTLS configuration
- `mbedtls_config.h`: MbedTLS feature configuration (in secure_boot/)

## Usage

MbedTLS is used through the crypto wrapper in `crypto/crypto_wrapper.c` to provide cryptographic primitives without dynamic memory allocation.

## Modifications from Upstream MbedTLS

This MbedTLS version is based on commit `107ea89daaefb9867ea9121002fbbdf926780e98` (v3.6.2) from the official MbedTLS repository. The following modifications have been made to make it compatible with the BootROM's bare-metal environment and build requirements:

### 1. **Build Exclusions in CMakeLists.txt**
To reduce binary size and avoid dependencies incompatible with bare-metal (e.g., filesystem, networking, entropy), the following source files are excluded from compilation:
- X.509 related: `x509*.c`, `x509_create.c`, `x509write*.c`
- SSL/TLS: All `ssl_*.c` files
- Entropy/RNG: `entropy*.c`, `ctr_drbg.c`, `hmac_drbg.c`
- PSA Crypto: `psa_*.c`, `psa_crypto*.c` (except some kept for compatibility)
- Unused ciphers: `aria.c`, `camellia.c`, `des.c`, `chacha*.c`, `poly1305.c`, `ripemd160.c`, `sha1.c`, `sha3.c`, `sha512.c`, `md5.c`
- Other: `debug.c`, `error.c`, `version*.c`, `threading.c`, `mps_*.c`, `nist_kw.c`, `hkdf.c`, `padlock.c`, `aesce.c`, `aesni.c`, `ecdsa.c`, `lmots.c`, `lmots.c`, `ecjpake.c`, `dhm.c`, `ecdh.c`, `pkcs12.c`, `pkcs5.c`, `pkcs7.c`

Note: Initially `oid.c` and `pk_wrap.c` were excluded but later included back to resolve linking errors for OID functions and PK info structs.

### 2. **Configuration Changes in secure_boot/mbedtls_config.h**
- **PSA Crypto Disabled**: `#undef MBEDTLS_PSA_CRYPTO_C`, `#undef MBEDTLS_PSA_CRYPTO_CLIENT`, `#undef MBEDTLS_USE_PSA_CRYPTO` to avoid RNG and dynamic dependencies.
- **Minimal Feature Set**: Enabled only AES (CBC), SHA256, RSA (PKCS#1 v1.5/2.1), ECC (P-256), static memory alloc. Disabled X.509, SSL, entropy, etc.
- **Bare-Metal Compatibility**: `#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS`, custom platform layer.

### 3. **Source Code Modifications**
- **oid.c**: Added `#include <limits.h>` to define `INT_MAX` and `UINT_MAX` for bare-metal compilers.
- **platform_mbedtls.h**: Stubbed `mbedtls_fprintf` and `mbedtls_snprintf` to avoid stdio dependencies.

### 4. **Linker and Build Adjustments**
- Increased BOOT_ROM size to 256KB in CMakeLists.txt.
- Modified linker script to avoid section overlaps (.data and .ARM.exidx).
- Added `_exit` stub in platform.c for bare-metal compatibility.

### Why These Changes?
- **Size Optimization**: Excluding unused modules reduces binary from ~500KB+ to ~37KB.
- **Bare-Metal Compatibility**: Removes filesystem/network dependencies, uses static alloc.
- **Security**: Minimal config reduces attack surface; focuses on essential crypto for secure boot.
- **Build Stability**: Resolves MbedTLS 3.x PSA conflicts and linking issues.

For projects with similar requirements (embedded secure boot with MbedTLS), replicate these exclusions, config changes, and source patches. Always verify against the target MbedTLS version for compatibility.</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/bootrom/external/README.md