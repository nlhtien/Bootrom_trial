/**
 * @file crypto_pk.c
 * @brief High-Level Crypto Backend (Commercial Grade)
 */

#include "crypto_pk.h"
#include "secure_boot/mbedtls_config.h"

/* --- High-Level Abstractions --- */
#include "mbedtls/pk.h"       /* Generic Public Key (RSA & ECC) */
#include "mbedtls/md.h"       /* Generic Message Digest (Hash) */
#include "mbedtls/aes.h"      /* AES Primitive (No generic layer needed for BootROM) */
#include "mbedtls/gcm.h"      /* AES-GCM */

#include "mbedtls/platform_util.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform.h"
#include <string.h>

/* --- Helper Macro (Safe Casting) --- */
#define CAST_U8(ptr) ((const unsigned char *)(const void *)(ptr))

/* --- Return Codes --- */
#define PK_OK   0
#define PK_ERR -1

/* --- Heap Management --- */
#ifndef MBEDTLS_HEAP_SIZE
#define MBEDTLS_HEAP_SIZE (64 * 1024)
#endif
static uint8_t g_heap[MBEDTLS_HEAP_SIZE];
static int g_heap_init = 0;

int crypto_backend_init(void) {
    if (!g_heap_init) {
        mbedtls_memory_buffer_alloc_init(g_heap, sizeof(g_heap));
        g_heap_init = 1;
    }
    return PK_OK;
}
void crypto_backend_cleanup(void) { /* No-op */ }

/* -------------------------------------------------------------------------- */
/* GENERIC HASHING (Using MD Layer instead of SHA specific)                   */
/* -------------------------------------------------------------------------- */

static int _md_hash_generic(mbedtls_md_type_t type, const uint8_t *in, size_t len, uint8_t *out)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(type);
    int ret = PK_ERR;

    if (md_info == NULL) return PK_ERR;

    /* High-level MD API (One-shot calculation) */
    /* Note: mbedtls_md combines init, update, finish in one call if available, 
       but for standard 3.x we use context flow */
    
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, md_info, 0) == 0 &&
        mbedtls_md_starts(&ctx) == 0 &&
        mbedtls_md_update(&ctx, CAST_U8(in), len) == 0 &&
        mbedtls_md_finish(&ctx, CAST_U8(out)) == 0) {
        ret = PK_OK;
    }

    mbedtls_md_free(&ctx);
    return ret;
}

int crypto_backend_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output32) {
    return _md_hash_generic(MBEDTLS_MD_SHA256, input, input_len, output32);
}

int crypto_backend_hash_sha384(const uint8_t *input, size_t input_len, uint8_t *output48) {
    return _md_hash_generic(MBEDTLS_MD_SHA384, input, input_len, output48);
}

/* -------------------------------------------------------------------------- */
/* AES DECRYPTION (Primitive)                                                 */
/* -------------------------------------------------------------------------- */
/* PK layer does not handle symmetric crypto, so we keep AES primitive */

int crypto_backend_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                                      const uint8_t *enc, uint8_t *dec, size_t len) {
    mbedtls_aes_context ctx;
    uint8_t iv_copy[16];
    int ret = PK_ERR;
    mbedtls_aes_init(&ctx);
    memcpy(iv_copy, iv, 16);
    
    if (mbedtls_aes_setkey_dec(&ctx, CAST_U8(key), 256) == 0 &&
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv_copy, CAST_U8(enc), CAST_U8(dec)) == 0) {
        ret = PK_OK;
    }
    mbedtls_aes_free(&ctx);
    return ret;
}

int crypto_backend_aes256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                      const uint8_t *add, size_t add_len,
                                      const uint8_t *tag, size_t tag_len,
                                      const uint8_t *enc, uint8_t *dec, size_t len) {
    mbedtls_gcm_context ctx;
    int ret = PK_ERR;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, CAST_U8(key), 256) == 0 &&
        mbedtls_gcm_auth_decrypt(&ctx, len, CAST_U8(iv), iv_len, CAST_U8(add), add_len,
                                 CAST_U8(tag), tag_len, CAST_U8(enc), CAST_U8(dec)) == 0) {
        ret = PK_OK;
    }
    mbedtls_gcm_free(&ctx);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* UNIFIED PK VERIFY (RSA & ECDSA) - High Level Only                          */
/* -------------------------------------------------------------------------- */

static int _pk_verify_generic(mbedtls_md_type_t md_alg,
                              const uint8_t *hash, size_t hash_len,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t *pk_der, size_t der_len)
{
    mbedtls_pk_context pk;
    int ret = PK_ERR;

    mbedtls_pk_init(&pk);

    /* 1. Parse Key (Auto-detect RSA or ECC from ASN.1 OID) */
    if (mbedtls_pk_parse_public_key(&pk, CAST_U8(pk_der), der_len) != 0) {
        goto out;
    }

    /* 2. Verify Signature 
     * NOTE: Signature MUST be in ASN.1 format for ECDSA.
     * PK layer handles RSA padding verification automatically.
     */
    if (mbedtls_pk_verify(&pk, md_alg, 
                          CAST_U8(hash), hash_len, 
                          CAST_U8(sig), sig_len) == 0) {
        ret = PK_OK;
    }

out:
    mbedtls_pk_free(&pk);
    return ret;
}

/* --- RSA Implementations --- */
int crypto_backend_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    return _pk_verify_generic(MBEDTLS_MD_SHA256, hash32, 32, signature, sig_len, pubkey, pubkey_len);
}

int crypto_backend_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    return _pk_verify_generic(MBEDTLS_MD_SHA384, hash48, 48, signature, sig_len, pubkey, pubkey_len);
}

/* --- ECDSA Implementations --- */
int crypto_backend_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    return _pk_verify_generic(MBEDTLS_MD_SHA256, hash32, 32, signature, sig_len, pubkey, pubkey_len);
}

int crypto_backend_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    return _pk_verify_generic(MBEDTLS_MD_SHA384, hash48, 48, signature, sig_len, pubkey, pubkey_len);
}

/* --- Stubs --- */
int crypto_backend_aes256_cbc_decrypt_keyslot(int k, const uint8_t *i, const uint8_t *e, uint8_t *d, size_t l) {
    (void)k; (void)i; (void)e; (void)d; (void)l; return PK_ERR;
}
int crypto_backend_rng_get_bytes(uint8_t *b, size_t l) {
    (void)b; (void)l; return PK_ERR;
}
int crypto_backend_key_derive_blob(const uint8_t *w, size_t l, int s) {
    (void)w; (void)l; (void)s; return PK_ERR;
}