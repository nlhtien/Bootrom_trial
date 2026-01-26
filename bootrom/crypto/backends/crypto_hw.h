/**
 * @file crypto_hw.h
 * @brief Hardware Crypto Engine Backend (Stub/Template)
 */

#ifndef CRYPTO_HW_H
#define CRYPTO_HW_H

#include <stdint.h>
#include <stddef.h>

/* --- Lifecycle --- */
int crypto_backend_init(void);
void crypto_backend_cleanup(void);

/* --- Hardware Hashing --- */
int crypto_backend_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output32);
int crypto_backend_hash_sha384(const uint8_t *input, size_t input_len, uint8_t *output48);

/* --- Hardware AES Engine --- */
/* Raw Key Mode */
int crypto_backend_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                                      const uint8_t *encrypted, uint8_t *decrypted,
                                      size_t len);

int crypto_backend_aes256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                      const uint8_t *add, size_t add_len,
                                      const uint8_t *tag, size_t tag_len,
                                      const uint8_t *encrypted, uint8_t *decrypted,
                                      size_t len);

/* Hardware Keyslot Mode (eFuse/OTP Key) */
int crypto_backend_aes256_cbc_decrypt_keyslot(int keyslot, const uint8_t *iv,
                                              const uint8_t *enc, uint8_t *dec,
                                              size_t len);

/* --- Hardware PKA (Public Key Accelerator) --- */
int crypto_backend_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

/* --- TRNG & Key Management --- */
int crypto_backend_rng_get_bytes(uint8_t *buf, size_t len);
int crypto_backend_key_derive_blob(const uint8_t *wrapped_key, size_t w_len, int dest_slot);

#endif /* CRYPTO_HW_H */