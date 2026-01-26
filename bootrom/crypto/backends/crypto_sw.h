/**
 * @file crypto_sw.h
 * @brief Software Crypto Backend (Basic Standard MbedTLS 3.x)
 */

#ifndef CRYPTO_SW_H
#define CRYPTO_SW_H

#include <stdint.h>
#include <stddef.h>

/* --- Lifecycle --- */
int crypto_backend_init(void);
void crypto_backend_cleanup(void);

/* --- Hashing --- */
int crypto_backend_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output32);
int crypto_backend_hash_sha384(const uint8_t *input, size_t input_len, uint8_t *output48);

/* --- AES Decryption --- */
int crypto_backend_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                                      const uint8_t *encrypted, uint8_t *decrypted,
                                      size_t len);

int crypto_backend_aes256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                      const uint8_t *add, size_t add_len,
                                      const uint8_t *tag, size_t tag_len,
                                      const uint8_t *encrypted, uint8_t *decrypted,
                                      size_t len);

/* --- Hardware Stubs (Required for linker) --- */
int crypto_backend_aes256_cbc_decrypt_keyslot(int keyslot, const uint8_t *iv,
                                              const uint8_t *enc, uint8_t *dec,
                                              size_t len);
int crypto_backend_rng_get_bytes(uint8_t *buf, size_t len);
int crypto_backend_key_derive_blob(const uint8_t *w_key, size_t w_len, int slot);

/* --- RSA Verify (PKCS#1 v1.5) --- */
int crypto_backend_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

/* --- ECDSA Verify (SECP256R1 & SECP384R1) --- */
int crypto_backend_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

#endif /* CRYPTO_SW_H */