/**
 * \file mbedtls_config.h
 * \brief Minimal configuration for Cortex-R5F with PSA Support
 */
 #ifndef MBEDTLS_CONFIG_H
 #define MBEDTLS_CONFIG_H
 
 /* --- 1. System & Platform Support --- */
 #define MBEDTLS_PLATFORM_C
 #define MBEDTLS_PLATFORM_MEMORY
 #define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
 #define MBEDTLS_MEMORY_BUFFER_ALLOC_C
 
 /* --- 2. PSA Crypto Support (BẮT BUỘC CHO MBEDTLS 3.6) --- */
 /* Thiếu cái này là bị lỗi "unknown type name psa_key_id_t" */
 #define MBEDTLS_PSA_CRYPTO_C
 #define MBEDTLS_PSA_CRYPTO_CLIENT
 #define MBEDTLS_USE_PSA_CRYPTO
 #define MBEDTLS_PSA_CRYPTO_CONFIG /* Tự động cấu hình PSA dựa trên thuật toán */
 
 /* --- 3. Entropy & RNG (Bắt buộc phải có khi dùng PSA) --- */
 #define MBEDTLS_CTR_DRBG_C
 #define MBEDTLS_ENTROPY_C
 #define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
 /* Quan trọng: Dùng Entropy rỗng để bypass lỗi thiếu driver RNG */
 #define MBEDTLS_TEST_NULL_ENTROPY 
 
 /* --- 4. Algorithms --- */
 #define MBEDTLS_SHA256_C
 #define MBEDTLS_SHA224_C
 #define MBEDTLS_MD_C
 
 #define MBEDTLS_AES_C
 #define MBEDTLS_CIPHER_MODE_CBC
 #define MBEDTLS_CIPHER_MODE_CTR
 #define MBEDTLS_CIPHER_MODE_GCM
 #define MBEDTLS_CIPHER_C
 
 #define MBEDTLS_RSA_C
 #define MBEDTLS_PKCS1_V15
 #define MBEDTLS_PKCS1_V21
 
 #define MBEDTLS_ECP_C
 #define MBEDTLS_ECDSA_C
 #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
 
 #define MBEDTLS_PK_C
 #define MBEDTLS_PK_PARSE_C
 #define MBEDTLS_PK_WRITE_C
 
 /* --- 5. Big Number Support --- */
 #define MBEDTLS_BIGNUM_C
 #define MBEDTLS_OID_C
 #define MBEDTLS_ASN1_PARSE_C
 #define MBEDTLS_ASN1_WRITE_C
 
 /* --- 6. Optimization --- */
 #define MBEDTLS_MPI_MAX_SIZE      512
 #define MBEDTLS_MPI_WINDOW_SIZE   1
 #define MBEDTLS_ECP_WINDOW_SIZE   2
 #define MBEDTLS_ECP_MAX_BITS      256
 
 // #include "mbedtls/check_config.h" 
 
 #endif /* MBEDTLS_CONFIG_H */