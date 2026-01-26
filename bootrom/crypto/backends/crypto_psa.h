/**
 * @file crypto_psa.h
 * @brief PSA Crypto Backend (ARM Platform Security Architecture)
 */

#ifndef CRYPTO_PSA_H
#define CRYPTO_PSA_H

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

/* --- RSA Verify (PSA API) --- */
int crypto_backend_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

/* --- ECDSA Verify (PSA API) --- */
int crypto_backend_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

int crypto_backend_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);

/* --- Stubs / PSA Specifics --- */
int crypto_backend_aes256_cbc_decrypt_keyslot(int keyslot, const uint8_t *iv,
                                              const uint8_t *enc, uint8_t *dec,
                                              size_t len);
int crypto_backend_rng_get_bytes(uint8_t *buf, size_t len);
int crypto_backend_key_derive_blob(const uint8_t *w_key, size_t w_len, int slot);

#endif /* CRYPTO_PSA_H */