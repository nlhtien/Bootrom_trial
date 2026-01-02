/**
 * @file crypto_wrapper.c
 * @brief Crypto Wrapper for MbedTLS Integration
 * 
 * Provides a thin wrapper around MbedTLS functions for use in BootROM
 * Uses MBEDTLS_MEMORY_BUFFER_ALLOC_C for static memory allocation
 */

#include "crypto_wrapper.h"
#include "secure_boot/mbedtls_config.h"  /* Include our config before MbedTLS headers */
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/memory_buffer_alloc.h"
#include <string.h>

/* Static buffer for MbedTLS memory allocation */
#define MBEDTLS_HEAP_SIZE (32 * 1024)  /* 32KB buffer for MbedTLS */
static uint8_t mbedtls_heap[MBEDTLS_HEAP_SIZE];
static int mbedtls_heap_initialized = 0;

/* Static context for AES operations */
static mbedtls_aes_context aes_ctx;

/* Platform-specific key storage (stub - should come from secure storage) */
static uint8_t aes_key[32];  /* AES-256 key */
static uint8_t public_key_der[512];  /* RSA public key in DER format */
static size_t public_key_der_len = 0;

/**
 * @brief Initialize crypto subsystem
 * @return 0 on success, negative on failure
 */
int crypto_init(void)
{
    /* Initialize MbedTLS memory buffer allocator */
    if (!mbedtls_heap_initialized) {
        mbedtls_memory_buffer_alloc_init(mbedtls_heap, sizeof(mbedtls_heap));
        mbedtls_heap_initialized = 1;
    }
    
    /* Initialize MbedTLS platform */
    mbedtls_platform_setup(NULL);
    
    /* Initialize AES context */
    mbedtls_aes_init(&aes_ctx);
    
    /* In production, keys should be loaded from secure storage */
    /* For now, this is a stub - keys should be provisioned during manufacturing */
    memset(aes_key, 0, sizeof(aes_key));
    
    return 0;
}

/**
 * @brief Cleanup crypto subsystem
 */
void crypto_cleanup(void)
{
    /* Zeroize AES context */
    mbedtls_aes_free(&aes_ctx);
    
    /* Zeroize keys */
    memset(aes_key, 0, sizeof(aes_key));
    memset(public_key_der, 0, sizeof(public_key_der));
    
    /* Free MbedTLS platform */
    mbedtls_platform_teardown(NULL);
    
    /* Note: MbedTLS buffer allocator heap is not zeroized here
     * as it may be used during cleanup. It will be zeroized
     * in secure_boot_cleanup() if needed. */
}

/**
 * @brief Compute SHA-256 hash
 * @param input Input data
 * @param input_len Length of input data
 * @param output Output buffer (32 bytes)
 * @return 0 on success, negative on failure
 */
int crypto_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output)
{
    mbedtls_sha256_context ctx;
    int ret;
    
    mbedtls_sha256_init(&ctx);
    ret = mbedtls_sha256_starts(&ctx, 0);  /* 0 = SHA-256, 1 = SHA-224 */
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        return ret;
    }
    
    ret = mbedtls_sha256_update(&ctx, input, input_len);
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        return ret;
    }
    
    ret = mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
    
    return ret;
}

/**
 * @brief AES-CBC decryption
 * @param encrypted Input encrypted data
 * @param decrypted Output decrypted data
 * @param len Length of data (must be multiple of 16)
 * @param iv Initialization vector (16 bytes)
 * @return 0 on success, negative on failure
 */
int crypto_aes_decrypt(const uint8_t *encrypted,
                        uint8_t *decrypted,
                        size_t len,
                        const uint8_t *iv)
{
    int ret;
    uint8_t iv_local[16];
    
    if (len % 16 != 0) {
        return -1;  /* Invalid length - must be multiple of AES block size */
    }
    
    /* Copy IV (it will be modified during decryption) */
    memcpy(iv_local, iv, 16);
    
    /* Set decryption key */
    ret = mbedtls_aes_setkey_dec(&aes_ctx, aes_key, 256);  /* AES-256 */
    if (ret != 0) {
        return ret;
    }
    
    /* Perform CBC decryption */
    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, len,
                                 iv_local, encrypted, decrypted);
    
    return ret;
}

/**
 * @brief Verify RSA or ECC signature
 * @param hash Hash of the data (32 bytes for SHA-256)
 * @param hash_len Length of hash (should be 32)
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 on success, negative on failure
 */
int crypto_verify_signature(const uint8_t *hash,
                             size_t hash_len,
                             const uint8_t *signature,
                             size_t signature_len)
{
    int ret;
    mbedtls_pk_context pk;
    
    if (public_key_der_len == 0) {
        return -1;  /* Public key not loaded */
    }
    
    mbedtls_pk_init(&pk);
    
    /* Parse public key */
    ret = mbedtls_pk_parse_public_key(&pk, public_key_der, public_key_der_len);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ret;
    }
    
    /* Verify signature */
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, hash_len,
                            signature, signature_len);
    
    mbedtls_pk_free(&pk);
    
    return ret;
}

/**
 * @brief Load AES key (stub - should come from secure storage)
 * @param key Pointer to key data
 * @param key_len Key length in bytes (16, 24, or 32)
 * @return 0 on success, negative on failure
 */
int crypto_set_aes_key(const uint8_t *key, size_t key_len)
{
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        return -1;
    }
    
    memcpy(aes_key, key, key_len);
    if (key_len < 32) {
        memset(aes_key + key_len, 0, 32 - key_len);
    }
    
    return 0;
}

/**
 * @brief Load public key (stub - should come from secure storage)
 * @param key_der Public key in DER format
 * @param key_len Length of key data
 * @return 0 on success, negative on failure
 */
int crypto_set_public_key(const uint8_t *key_der, size_t key_len)
{
    if (key_len > sizeof(public_key_der)) {
        return -1;
    }
    
    memcpy(public_key_der, key_der, key_len);
    public_key_der_len = key_len;
    
    return 0;
}
