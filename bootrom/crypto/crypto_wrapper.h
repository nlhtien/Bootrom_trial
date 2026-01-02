/**
 * @file crypto_wrapper.h
 * @brief Crypto Wrapper API Header
 */

#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize crypto subsystem
 * @return 0 on success, negative on failure
 */
int crypto_init(void);

/**
 * @brief Cleanup crypto subsystem
 */
void crypto_cleanup(void);

/**
 * @brief Compute SHA-256 hash
 * @param input Input data
 * @param input_len Length of input data
 * @param output Output buffer (32 bytes)
 * @return 0 on success, negative on failure
 */
int crypto_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output);

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
                        const uint8_t *iv);

/**
 * @brief Verify RSA or ECC signature
 * @param hash Hash of the data (32 bytes for SHA-256)
 * @param hash_len Length of hash
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 on success, negative on failure
 */
int crypto_verify_signature(const uint8_t *hash,
                             size_t hash_len,
                             const uint8_t *signature,
                             size_t signature_len);

/**
 * @brief Load AES key (stub - should come from secure storage)
 * @param key Pointer to key data
 * @param key_len Key length in bytes (16, 24, or 32)
 * @return 0 on success, negative on failure
 */
int crypto_set_aes_key(const uint8_t *key, size_t key_len);

/**
 * @brief Load public key (stub - should come from secure storage)
 * @param key_der Public key in DER format
 * @param key_len Length of key data
 * @return 0 on success, negative on failure
 */
int crypto_set_public_key(const uint8_t *key_der, size_t key_len);

#endif /* CRYPTO_WRAPPER_H */
