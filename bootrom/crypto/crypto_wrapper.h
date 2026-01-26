/**
 * @file crypto_wrapper.h
 * @brief BootROM Crypto Abstraction Layer Header
 */

#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/* Status & Definitions                                                  */
/* ===================================================================== */

/**
 * @brief Crypto Return Codes
 */
typedef enum {
    CRYPTO_RC_OK                =  0,  /**< Operation successful */
    CRYPTO_RC_FAIL              = -1,  /**< Generic failure */
    CRYPTO_RC_INVALID_ARG       = -2,  /**< Invalid argument (NULL ptr, bad len) */
    CRYPTO_RC_AUTH_FAIL         = -3,  /**< Signature/Tag verification failed */
    CRYPTO_RC_BUFFER_TOO_SMALL  = -4,  /**< Output buffer too small */
    CRYPTO_RC_HW_BUSY           = -5,  /**< Hardware engine busy/timeout */
    CRYPTO_RC_NOT_SUPPORTED     = -6,  /**< Algorithm/Feature disabled in config */
    CRYPTO_RC_KEY_ERROR         = -7   /**< Key invalid or missing */
} crypto_rc_t;

/**
 * @brief Supported Signature Algorithms for Unified API
 */
typedef enum {
    CRYPTO_ALG_RSA_SHA256 = 0x01,
    CRYPTO_ALG_RSA_SHA384 = 0x02,
    CRYPTO_ALG_ECDSA_SHA256 = 0x03,
    CRYPTO_ALG_ECDSA_SHA384 = 0x04
} crypto_algo_t;

/* ===================================================================== */
/* Lifecycle & Utilities                                                 */
/* ===================================================================== */

/**
 * @brief Initialize crypto subsystem.
 */
int crypto_init(void);

/**
 * @brief Deinitialize crypto subsystem and secure zeroize contexts.
 */
void crypto_cleanup(void);

/**
 * @brief Securely zeroize memory (prevents compiler optimization).
 */
void crypto_secure_zeroize(void *buf, size_t len);

/* ===================================================================== */
/* Hashing                                                               */
/* ===================================================================== */

int crypto_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output32);
int crypto_hash_sha384(const uint8_t *input, size_t input_len, uint8_t *output48);

/* ===================================================================== */
/* Symmetric Crypto (AES)                                                */
/* ===================================================================== */

/**
 * @brief AES-256-CBC Decryption (Legacy/Basic).
 */
int crypto_aes256_cbc_decrypt(const uint8_t *key,
                              const uint8_t *iv,
                              const uint8_t *encrypted,
                              uint8_t *decrypted,
                              size_t len);

/**
 * @brief AES-256-GCM Decryption (Authenticated Encryption).
 * @note Recommended for Secure Boot Images.
 */
int crypto_aes256_gcm_decrypt(const uint8_t *key,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *add, size_t add_len,
                              const uint8_t *tag, size_t tag_len,
                              const uint8_t *encrypted,
                              uint8_t *decrypted,
                              size_t len);

/**
 * @brief AES-256-CBC Decryption using Hardware Key Slot.
 */
int crypto_aes256_cbc_decrypt_keyslot(int keyslot,
                                      const uint8_t *iv,
                                      const uint8_t *encrypted,
                                      uint8_t *decrypted,
                                      size_t len);

/* ===================================================================== */
/* RNG & Key Management                                                  */
/* ===================================================================== */

/**
 * @brief Get random bytes from TRNG hardware.
 */
int crypto_rng_get_bytes(uint8_t *buf, size_t len);

/**
 * @brief Unwrap an encrypted key blob directly into a HW keyslot.
 */
int crypto_key_derive_blob(const uint8_t *wrapped_key, size_t wrapped_len, int dest_keyslot);

/* ===================================================================== */
/* Verification & Asymmetric                                             */
/* ===================================================================== */

/**
 * @brief Unified Signature Verification API.
 * @details Dispatches to specific implementation based on algo ID and build config.
 */
int crypto_verify_signature(crypto_algo_t algo,
                            const uint8_t *hash, size_t hash_len,
                            const uint8_t *signature, size_t sig_len,
                            const uint8_t *pubkey, size_t pubkey_len);

/**
 * @brief Verify SHA-256 hash of a Public Key (Root of Trust Check).
 */
int crypto_verify_pubkey_hash_sha256(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *expected_hash32);

/**
 * @brief Verify SHA-384 hash of a Public Key (Root of Trust Check).
 */
int crypto_verify_pubkey_hash_sha384(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *expected_hash48);

/* --- Primitive APIs (Direct calls if needed) --- */
int crypto_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
int crypto_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
int crypto_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
int crypto_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_WRAPPER_H */