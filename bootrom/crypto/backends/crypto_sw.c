/**
 * @file crypto_sw.c
 * @brief Software Crypto Backend (Standard MbedTLS 3.x)
 */

#include "crypto_sw.h"
#include "secure_boot/mbedtls_config.h"

/* Standard MbedTLS Includes */
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform.h"
#include <string.h>

/* --- Return Codes & Config --- */
#define SW_OK   0
#define SW_ERR -1

/* Fixed RSA Exponent: 65537 (0x10001) */
static const uint8_t g_rsa_e[] = { 0x01, 0x00, 0x01 };
#define CAST_U8(ptr) ((const unsigned char *)(const void *)(ptr))

/* Heap Buffer */
#define HEAP_SIZE (64 * 1024)
static uint8_t g_heap[HEAP_SIZE];
static int g_heap_init = 0;

/* ------------------------------------------------------------------------- */
/* Lifecycle */
/* ------------------------------------------------------------------------- */
int crypto_backend_init(void) {
    if (!g_heap_init) {
        mbedtls_memory_buffer_alloc_init(g_heap, sizeof(g_heap));
        g_heap_init = 1;
    }
    return SW_OK;
}
void crypto_backend_cleanup(void) { /* No-op for ROM */ }

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
int crypto_backend_hash_sha256(const uint8_t *in, size_t len, uint8_t *out) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts(&ctx, 0) || 
        /* THÊM CAST_U8 */
        mbedtls_sha256_update(&ctx, CAST_U8(in), len) || 
        /* THÊM CAST_U8 */
        mbedtls_sha256_finish(&ctx, CAST_U8(out))) {
        mbedtls_sha256_free(&ctx); return SW_ERR;
    }
    mbedtls_sha256_free(&ctx);
    return SW_OK;
}

int crypto_backend_hash_sha384(const uint8_t *in, size_t len, uint8_t *out) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    if (mbedtls_sha512_starts(&ctx, 1) || /* 1 = SHA-384 */
        /* THÊM CAST_U8 */
        mbedtls_sha512_update(&ctx, CAST_U8(in), len) || 
        /* THÊM CAST_U8 */
        mbedtls_sha512_finish(&ctx, CAST_U8(out))) {
        mbedtls_sha512_free(&ctx); return SW_ERR;
    }
    mbedtls_sha512_free(&ctx);
    return SW_OK;
}

/* ------------------------------------------------------------------------- */
/* AES Decryption */
/* ------------------------------------------------------------------------- */
int crypto_backend_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                                      const uint8_t *enc, uint8_t *dec, size_t len) {
    mbedtls_aes_context ctx;
    uint8_t iv_copy[16];
    int ret = SW_ERR;
    mbedtls_aes_init(&ctx);
    memcpy(iv_copy, iv, 16);
    
    /* THÊM CAST_U8 cho key, enc, dec */
    if (mbedtls_aes_setkey_dec(&ctx, CAST_U8(key), 256) == 0 &&
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv_copy, CAST_U8(enc), CAST_U8(dec)) == 0) {
        ret = SW_OK;
    }
    mbedtls_aes_free(&ctx);
    return ret;
}

int crypto_backend_aes256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                      const uint8_t *add, size_t add_len,
                                      const uint8_t *tag, size_t tag_len,
                                      const uint8_t *enc, uint8_t *dec, size_t len) {
    mbedtls_gcm_context ctx;
    int ret = SW_ERR;
    mbedtls_gcm_init(&ctx);

    /* THÊM CAST_U8 toàn bộ các pointer tham số */
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, CAST_U8(key), 256) == 0 &&
        mbedtls_gcm_auth_decrypt(&ctx, len, 
                                 CAST_U8(iv), iv_len, 
                                 CAST_U8(add), add_len, 
                                 CAST_U8(tag), tag_len, 
                                 CAST_U8(enc), CAST_U8(dec)) == 0) {
        ret = SW_OK;
    }
    mbedtls_gcm_free(&ctx);
    return ret;
}

/* ------------------------------------------------------------------------- */
/* RSA Helper & Functions (MbedTLS 3.x Standard) */
/* ------------------------------------------------------------------------- */
static int _rsa_verify_common(uint8_t *hash, size_t hash_len, 
                              mbedtls_md_type_t md_type,
                              const uint8_t *sig, const uint8_t *pk_n, size_t n_len) 
{
    mbedtls_rsa_context rsa;
    int ret = SW_ERR;

    /* 1. Init & Config (Default PKCS#1 v1.5) */
    mbedtls_rsa_init(&rsa);
    size_t rsa_len = mbedtls_rsa_get_len(&rsa);
    if (n_len != rsa_len) {
        goto out; /* Invalid Key Length */
    }
    /* 2. Import Public Key (Raw N, Fixed E=65537) */
    if (mbedtls_rsa_import_raw(&rsa, CAST_U8(pk_n), n_len, NULL, 0, NULL, 0, NULL, 0,
                               g_rsa_e, sizeof(g_rsa_e)) != 0) {
        goto out;
    }

    /* 3. Complete Key (Calculate len, check validity) */
    if (mbedtls_rsa_complete(&rsa) != 0) {
        goto out;
    }

    /* 4. Verify Signature */
    if (mbedtls_rsa_pkcs1_verify(&rsa,
                                 md_type, 
                                 (unsigned int)hash_len, 
                                 CAST_U8(hash),
                                 CAST_U8(sig)) == 0) {
        ret = SW_OK;
    }

out:
    mbedtls_rsa_free(&rsa);
    return ret;
}

int crypto_backend_rsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    (void)sig_len; /* In RSA, sig_len usually equals pubkey_len */
    return _rsa_verify_common(hash32, 32, MBEDTLS_MD_SHA256, signature, pubkey, pubkey_len);
}

int crypto_backend_rsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                     size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    (void)sig_len;
    return _rsa_verify_common(hash48, 48, MBEDTLS_MD_SHA384, signature, pubkey, pubkey_len);
}

/* ------------------------------------------------------------------------- */
/* ECDSA Helper & Functions (Fixed for MbedTLS 3.x Opaque Structs) */
/* ------------------------------------------------------------------------- */
static int _ecdsa_verify_common(int curve_id, const uint8_t *hash, size_t hash_len,
                                const uint8_t *sig, size_t sig_len,
                                const uint8_t *pk, size_t pk_len) 
{
    /* Thay vì dùng mbedtls_ecdsa_context (bị ẩn), ta khai báo rời Group và Point */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    int ret = SW_ERR;
    size_t param_len = sig_len / 2;

    /* Init các cấu trúc rời */
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r); 
    mbedtls_mpi_init(&s);

    /* 1. Load Curve (SECP256R1, etc.) vào biến grp */
    if (mbedtls_ecp_group_load(&grp, (mbedtls_ecp_group_id)curve_id) != 0) goto out;

    /* 2. Import Public Key Point vào biến Q (dùng grp để kiểm tra tính hợp lệ) */
    if (mbedtls_ecp_point_read_binary(&grp, &Q, CAST_U8(pk), pk_len) != 0) goto out;

    /* 3. Parse Raw Signature (R || S) */
    if (mbedtls_mpi_read_binary(&r, CAST_U8(sig), param_len) != 0 ||
        mbedtls_mpi_read_binary(&s, CAST_U8(sig) + param_len, param_len) != 0) goto out;

    /* 4. Verify dùng các biến rời */
    /* Hàm này nhận trực tiếp group, point Q, r, s */
    if (mbedtls_ecdsa_verify(&grp, CAST_U8(hash), hash_len, &Q, &r, &s) == 0) {
        ret = SW_OK;
    }

out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r); 
    mbedtls_mpi_free(&s);
    return ret;
}

int crypto_backend_ecdsa_verify_sha256(const uint8_t *hash32, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    /* SECP256R1 id is usually 3 (MBEDTLS_ECP_DP_SECP256R1) */
    return _ecdsa_verify_common(MBEDTLS_ECP_DP_SECP256R1, hash32, 32, 
                                signature, sig_len, pubkey, pubkey_len);
}

int crypto_backend_ecdsa_verify_sha384(const uint8_t *hash48, const uint8_t *signature,
                                       size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    /* SECP384R1 id is usually 4 (MBEDTLS_ECP_DP_SECP384R1) */
    return _ecdsa_verify_common(MBEDTLS_ECP_DP_SECP384R1, hash48, 48, 
                                signature, sig_len, pubkey, pubkey_len);
}

/* ------------------------------------------------------------------------- */
/* Stubs (Always Fail for SW) */
/* ------------------------------------------------------------------------- */
int crypto_backend_aes256_cbc_decrypt_keyslot(int k, const uint8_t *i, const uint8_t *e, uint8_t *d, size_t l) {
    (void)k; (void)i; (void)e; (void)d; (void)l; return SW_ERR;
}
int crypto_backend_rng_get_bytes(uint8_t *b, size_t l) {
    (void)b; (void)l; return SW_ERR;
}
int crypto_backend_key_derive_blob(const uint8_t *w, size_t l, int s) {
    (void)w; (void)l; (void)s; return SW_ERR;
}