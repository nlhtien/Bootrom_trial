/**
 * @file crypto_wrapper.c
 * @brief BootROM Crypto Wrapper Implementation
 */

#include "crypto_wrapper.h"
#include "crypto_config.h"
#include "crypto_common.h"
#include <string.h> /* For memset, memcmp */

/* -------------------------------------------------------------------------- */
/* Backend Selection                                                          */
/* -------------------------------------------------------------------------- */
#if defined(CRYPTO_BACKEND_SW)
    #include "backends/crypto_sw.h"
#elif defined(CRYPTO_BACKEND_PK)
    #include "backends/crypto_pk.h"
#elif defined(CRYPTO_BACKEND_PSA)
    #include "backends/crypto_psa.h"
#elif defined(CRYPTO_BACKEND_HW)
    #include "backends/crypto_hw.h"
#endif

/* -------------------------------------------------------------------------- */
/* Utilities                                                                  */
/* -------------------------------------------------------------------------- */

void crypto_secure_zeroize(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

/* -------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* -------------------------------------------------------------------------- */

int crypto_init(void)
{
    return crypto_backend_init();
}

void crypto_cleanup(void)
{
    crypto_backend_cleanup();
}

/* -------------------------------------------------------------------------- */
/* Hashing                                                                    */
/* -------------------------------------------------------------------------- */

int crypto_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output32)
{
#if defined(CONFIG_BOOTROM_ENABLE_SHA256)
    if (!input || !output32) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_hash_sha256(input, input_len, output32);
#else
    (void)input; (void)input_len; (void)output32;
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_hash_sha384(const uint8_t *input, size_t input_len, uint8_t *output48)
{
#if defined(CONFIG_BOOTROM_ENABLE_SHA512) /* SHA-384 usually shares engine with SHA-512 */
    if (!input || !output48) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_hash_sha384(input, input_len, output48);
#else
    (void)input; (void)input_len; (void)output48;
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

/* -------------------------------------------------------------------------- */
/* Symmetric Crypto                                                           */
/* -------------------------------------------------------------------------- */

int crypto_aes256_cbc_decrypt(const uint8_t *key,
                              const uint8_t *iv,
                              const uint8_t *encrypted,
                              uint8_t *decrypted,
                              size_t len)
{
#if defined(CONFIG_BOOTROM_ENABLE_AES)
    if (!key || !iv || !encrypted || !decrypted || (len % 16 != 0) || (len == 0)) {
        return CRYPTO_RC_INVALID_ARG;
    }
    return crypto_backend_aes256_cbc_decrypt(key, iv, encrypted, decrypted, len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_aes256_gcm_decrypt(const uint8_t *key,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *add, size_t add_len,
                              const uint8_t *tag, size_t tag_len,
                              const uint8_t *encrypted,
                              uint8_t *decrypted,
                              size_t len)
{
#if defined(CONFIG_BOOTROM_ENABLE_AES) /* GCM usually implies AES support */
    if (!key || !iv || !tag || !encrypted || !decrypted) return CRYPTO_RC_INVALID_ARG;
    if (iv_len == 0 || tag_len == 0) return CRYPTO_RC_INVALID_ARG;

    /* Check if Backend supports GCM via internal define or return NOT_SUPPORTED */
    return crypto_backend_aes256_gcm_decrypt(key, iv, iv_len, add, add_len, tag, tag_len, encrypted, decrypted, len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_aes256_cbc_decrypt_keyslot(int keyslot,
                                      const uint8_t *iv,
                                      const uint8_t *encrypted,
                                      uint8_t *decrypted,
                                      size_t len)
{
#if defined(CONFIG_BOOTROM_ENABLE_AES) && defined(CRYPTO_BACKEND_HW)
    if (!iv || !encrypted || !decrypted || (len % 16 != 0)) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_aes256_cbc_decrypt_keyslot(keyslot, iv, encrypted, decrypted, len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

/* -------------------------------------------------------------------------- */
/* RNG & Key Management                                                       */
/* -------------------------------------------------------------------------- */

int crypto_rng_get_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return CRYPTO_RC_INVALID_ARG;
    /* Normally TRNG is always enabled if HW supports it */
    return crypto_backend_rng_get_bytes(buf, len);
}

int crypto_key_derive_blob(const uint8_t *wrapped_key, size_t wrapped_len, int dest_keyslot)
{
#if defined(CRYPTO_BACKEND_HW)
    if (!wrapped_key || wrapped_len == 0 || dest_keyslot < 0) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_key_derive_blob(wrapped_key, wrapped_len, dest_keyslot);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

/* -------------------------------------------------------------------------- */
/* Verification & Asymmetric                                                  */
/* -------------------------------------------------------------------------- */

int crypto_verify_signature(crypto_algo_t algo,
                            const uint8_t *hash, size_t hash_len,
                            const uint8_t *signature, size_t sig_len,
                            const uint8_t *pubkey, size_t pubkey_len)
{
    switch (algo) {
        /* ----- RSA SECTION ----- */
#if defined(CONFIG_BOOTROM_ENABLE_RSA)
        case CRYPTO_ALG_RSA_SHA256:
        #if defined(CONFIG_BOOTROM_ENABLE_SHA256)
            if (hash_len != 32) return CRYPTO_RC_INVALID_ARG;
            return crypto_rsa_verify_sha256(hash, signature, sig_len, pubkey, pubkey_len);
        #else
            return CRYPTO_RC_NOT_SUPPORTED;
        #endif

        case CRYPTO_ALG_RSA_SHA384:
        #if defined(CONFIG_BOOTROM_ENABLE_SHA512)
            if (hash_len != 48) return CRYPTO_RC_INVALID_ARG;
            return crypto_rsa_verify_sha384(hash, signature, sig_len, pubkey, pubkey_len);
        #else
            return CRYPTO_RC_NOT_SUPPORTED;
        #endif
#endif /* ENABLE_RSA */

        /* ----- ECDSA SECTION ----- */
#if defined(CONFIG_BOOTROM_ENABLE_ECDSA)
        case CRYPTO_ALG_ECDSA_SHA256:
        #if defined(CONFIG_BOOTROM_ENABLE_SHA256)
            if (hash_len != 32) return CRYPTO_RC_INVALID_ARG;
            return crypto_ecdsa_verify_sha256(hash, signature, sig_len, pubkey, pubkey_len);
        #else
            return CRYPTO_RC_NOT_SUPPORTED;
        #endif

        case CRYPTO_ALG_ECDSA_SHA384:
        #if defined(CONFIG_BOOTROM_ENABLE_SHA512)
            if (hash_len != 48) return CRYPTO_RC_INVALID_ARG;
            return crypto_ecdsa_verify_sha384(hash, signature, sig_len, pubkey, pubkey_len);
        #else
            return CRYPTO_RC_NOT_SUPPORTED;
        #endif
#endif /* ENABLE_ECDSA */

        default:
            return CRYPTO_RC_NOT_SUPPORTED;
    }
}

/* ... Primitives ... */

int crypto_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
#if defined(CONFIG_BOOTROM_ENABLE_RSA) && defined(CONFIG_BOOTROM_ENABLE_SHA256)
    if (!hash32 || !signature || !pubkey) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_rsa_verify_sha256(hash32, signature, sig_len, pubkey, pubkey_len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
#if defined(CONFIG_BOOTROM_ENABLE_RSA) && defined(CONFIG_BOOTROM_ENABLE_SHA512)
    if (!hash48 || !signature || !pubkey) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_rsa_verify_sha384(hash48, signature, sig_len, pubkey, pubkey_len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
#if defined(CONFIG_BOOTROM_ENABLE_ECDSA) && defined(CONFIG_BOOTROM_ENABLE_SHA256)
    if (!hash32 || !signature || !pubkey) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_ecdsa_verify_sha256(hash32, signature, sig_len, pubkey, pubkey_len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
#if defined(CONFIG_BOOTROM_ENABLE_ECDSA) && defined(CONFIG_BOOTROM_ENABLE_SHA512)
    if (!hash48 || !signature || !pubkey) return CRYPTO_RC_INVALID_ARG;
    return crypto_backend_ecdsa_verify_sha384(hash48, signature, sig_len, pubkey, pubkey_len);
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

/* ... Root of Trust Checks ... */

int crypto_verify_pubkey_hash_sha256(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *expected_hash32)
{
#if defined(CONFIG_BOOTROM_ENABLE_SHA256)
    uint8_t current_hash[32];
    int ret;
    if (!pubkey || !expected_hash32) return CRYPTO_RC_INVALID_ARG;

    ret = crypto_hash_sha256(pubkey, pubkey_len, current_hash);
    if (ret != CRYPTO_RC_OK) return ret;

    if (memcmp(current_hash, expected_hash32, 32) != 0) return CRYPTO_RC_AUTH_FAIL;
    return CRYPTO_RC_OK;
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}

int crypto_verify_pubkey_hash_sha384(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *expected_hash48)
{
#if defined(CONFIG_BOOTROM_ENABLE_SHA512)
    uint8_t current_hash[48];
    int ret;
    if (!pubkey || !expected_hash48) return CRYPTO_RC_INVALID_ARG;

    ret = crypto_hash_sha384(pubkey, pubkey_len, current_hash);
    if (ret != CRYPTO_RC_OK) return ret;

    if (memcmp(current_hash, expected_hash48, 48) != 0) return CRYPTO_RC_AUTH_FAIL;
    return CRYPTO_RC_OK;
#else
    return CRYPTO_RC_NOT_SUPPORTED;
#endif
}