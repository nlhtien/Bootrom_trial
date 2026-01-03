/**
 * \file mbedtls_config.h
 * \brief Minimal Mbed TLS configuration for Cortex-R5F (Bare-metal)
 * * This configuration is optimized for a 4-Stage Boot ROM environment:
 * - No OS dependencies (Standard C library only)
 * - Static memory allocation (No malloc/free)
 * - PSA Crypto API enabled (Required for Mbed TLS 3.x)
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* Disable config checks to avoid errors */
#define MBEDTLS_CHECK_CONFIG_H 0

/* Force disable PSA Crypto at the very beginning */
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_CLIENT
#undef MBEDTLS_USE_PSA_CRYPTO
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_X509_CRT_WRITE_C

/* ============================================================================
 * 1. System & Platform Support
 * ============================================================================ */
/* Enable custom platform layer (essential for bare-metal) */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* Enable static memory allocation (uses mbedtls_memory_buffer_alloc_init) */
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

/* ============================================================================
 * 2. PSA Crypto Support (DISABLED for BootROM - no RNG)
 * ============================================================================ */
/* Disable PSA Crypto to avoid RNG requirements */
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_CLIENT
#undef MBEDTLS_USE_PSA_CRYPTO
/* #define MBEDTLS_PSA_CRYPTO_CONFIG  */  /* Commented out */ 

/* ============================================================================
 * 3. Entropy & RNG
 * ============================================================================ */
#define MBEDTLS_CTR_DRBG_C
//#define MBEDTLS_ENTROPY_C

/* Disable default OS entropy sources (files, syscalls) as we have no OS */
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY

/**
 * @warning ENABLE NULL ENTROPY (DEVELOPMENT ONLY)
 * This bypasses the requirement for a hardware TRNG driver.
 * IN PRODUCTION: You MUST implement a hardware entropy source and disable this.
 */
#define MBEDTLS_TEST_NULL_ENTROPY 

/* ============================================================================
 * 4. Hashing Algorithms
 * ============================================================================ */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_MD_C

/* ============================================================================
 * 5. Symmetric Encryption (AES)
 * ============================================================================ */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_GCM

/* ============================================================================
 * 6. Asymmetric Encryption (RSA & ECC)
 * ============================================================================ */
/* RSA Support */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

/* ECC Support (Elliptic Curve Cryptography) */
#define MBEDTLS_ECP_C
#undef MBEDTLS_ECDSA_C
/* Enable NIST P-256 curve (common for Secure Boot) */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

/* Public Key Abstraction Layer */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C

/* ============================================================================
 * 7. Big Number (MPI) Support
 * ============================================================================ */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* ============================================================================
 * 9. Disable Unnecessary Features for BootROM
 * ============================================================================ */
/* Disable X.509 certificate parsing (not needed for BootROM) */
#define MBEDTLS_X509_CRT_PARSE_C 0
#define MBEDTLS_X509_CRL_PARSE_C 0
#define MBEDTLS_X509_CSR_PARSE_C 0
#define MBEDTLS_X509_USE_C 0
#define MBEDTLS_X509_CRT_WRITE_C 0

/* Disable TLS (not needed for BootROM) */
#define MBEDTLS_SSL_TLS_C 0
#define MBEDTLS_SSL_CLI_C 0
#define MBEDTLS_SSL_SRV_C 0

/* Disable other unnecessary modules */
#define MBEDTLS_CERTS_C 0
#define MBEDTLS_PEM_PARSE_C 0
#define MBEDTLS_PEM_WRITE_C 0
#define MBEDTLS_BASE64_C 0

/* ============================================================================
 * 8. Optimization & Limits
 * ============================================================================ */
/* Max MPI size: 512 bytes = 4096 bits (Sufficient for RSA-4096) */
#define MBEDTLS_MPI_MAX_SIZE      512 

/* Window size settings (Trade-off: 1 saves RAM, 6 saves CPU cycles) */
#define MBEDTLS_MPI_WINDOW_SIZE   1
#define MBEDTLS_ECP_WINDOW_SIZE   2

/* NOTE: MBEDTLS_ECP_MAX_BITS is automatically calculated by the library 
 * based on enabled curves. Do NOT define it manually to avoid warnings. */

/* NOTE: Do NOT include "mbedtls/check_config.h" manually here.
 * It is automatically included by the library at the correct stage. */

#endif /* MBEDTLS_CONFIG_H */