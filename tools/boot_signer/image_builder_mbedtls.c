#include "image_builder.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int build_signed_image(const char *input_file, const char *output_file,
                      const char *private_key_file, const char *aes_key_file) {

    int ret = -1;
    FILE *fp = NULL;
    uint8_t *input_data = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *key_data = NULL;

    // Initialize MbedTLS contexts
    mbedtls_pk_context pk;
    mbedtls_aes_context aes_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_aes_init(&aes_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    do {
        // 1. Load input binary
        fp = fopen(input_file, "rb");
        if (!fp) {
            printf("❌ Cannot open input file: %s\n", input_file);
            break;
        }

        fseek(fp, 0, SEEK_END);
        size_t input_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        input_data = malloc(input_size);
        if (!input_data) {
            printf("❌ Memory allocation failed\n");
            break;
        }

        size_t read_size = fread(input_data, 1, input_size, fp);
        fclose(fp);
        fp = NULL;

        if (read_size != input_size) {
            printf("❌ Failed to read input file\n");
            break;
        }

        printf("📁 Loaded input binary: %zu bytes\n", input_size);

        // 2. Load AES key (32 bytes)
        fp = fopen(aes_key_file, "rb");
        if (!fp) {
            printf("❌ Cannot open AES key file: %s\n", aes_key_file);
            break;
        }

        uint8_t aes_key[32];
        read_size = fread(aes_key, 1, 32, fp);
        fclose(fp);
        fp = NULL;

        if (read_size != 32) {
            printf("❌ AES key must be 32 bytes\n");
            break;
        }

        printf("🔑 Loaded AES key\n");

        // 3. Generate random IV using MbedTLS
        uint8_t iv[16];
        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
        if (ret != 0) {
            printf("❌ CTR-DRBG seed failed: -0x%04x\n", -ret);
            break;
        }

        ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
        if (ret != 0) {
            printf("❌ IV generation failed: -0x%04x\n", -ret);
            break;
        }

        printf("🎲 Generated random IV\n");

        // 4. Encrypt payload with AES-256-CBC using MbedTLS
        size_t encrypted_size = ((input_size + 15) / 16) * 16; // Pad to block size
        encrypted_data = malloc(encrypted_size);
        if (!encrypted_data) {
            printf("❌ Memory allocation failed\n");
            break;
        }

        memset(encrypted_data, 0, encrypted_size); // PKCS#7 padding
        memcpy(encrypted_data, input_data, input_size);
        uint8_t pad_value = 16 - (input_size % 16);
        for (size_t i = input_size; i < encrypted_size; i++) {
            encrypted_data[i] = pad_value;
        }

        ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 256);
        if (ret != 0) {
            printf("❌ AES key setup failed: -0x%04x\n", -ret);
            break;
        }

        uint8_t iv_copy[16];
        memcpy(iv_copy, iv, 16);
        ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, encrypted_size,
                                   iv_copy, encrypted_data, encrypted_data);
        if (ret != 0) {
            printf("❌ AES encryption failed: -0x%04x\n", -ret);
            break;
        }

        printf("🔒 Encrypted payload: %zu bytes\n", encrypted_size);

        // 5. Calculate SHA-256 hash of encrypted data using MbedTLS
        uint8_t hash[32];
        mbedtls_sha256(encrypted_data, encrypted_size, hash, 0); // 0 = SHA-256

        printf("🔢 Calculated SHA-256 hash\n");

        // 6. Load private key and sign hash using MbedTLS
        fp = fopen(private_key_file, "rb");
        if (!fp) {
            printf("❌ Cannot open private key file: %s\n", private_key_file);
            break;
        }

        fseek(fp, 0, SEEK_END);
        size_t key_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        key_data = malloc(key_size);
        if (!key_data) {
            printf("❌ Memory allocation failed\n");
            fclose(fp);
            break;
        }

        read_size = fread(key_data, 1, key_size, fp);
        fclose(fp);
        fp = NULL;

        if (read_size != key_size) {
            printf("❌ Failed to read private key\n");
            break;
        }

        ret = mbedtls_pk_parse_key(&pk, key_data, key_size, NULL, 0);
        if (ret != 0) {
            printf("❌ Private key parsing failed: -0x%04x\n", -ret);
            break;
        }

        uint8_t signature[256]; // RSA-2048 signature buffer
        size_t sig_len;

        ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, signature, &sig_len,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            printf("❌ Signature generation failed: -0x%04x\n", -ret);
            break;
        }

        printf("✍️  Generated RSA signature: %zu bytes\n", sig_len);

        // 7. Create image header (same format as BootROM expects)
        image_header_t header;
        memset(&header, 0, sizeof(header));
        header.magic = IMAGE_MAGIC;
        header.version = IMAGE_VERSION;
        header.image_size = encrypted_size;
        header.image_version = 1; // Can be parameterized
        memcpy(header.iv, iv, 16);
        memcpy(header.signature, signature, 256);

        printf("📄 Created image header\n");

        // 8. Write output file: header + encrypted data
        fp = fopen(output_file, "wb");
        if (!fp) {
            printf("❌ Cannot create output file: %s\n", output_file);
            break;
        }

        size_t written = fwrite(&header, 1, sizeof(header), fp);
        if (written != sizeof(header)) {
            printf("❌ Failed to write header\n");
            fclose(fp);
            break;
        }

        written = fwrite(encrypted_data, 1, encrypted_size, fp);
        if (written != encrypted_size) {
            printf("❌ Failed to write encrypted data\n");
            fclose(fp);
            break;
        }

        fclose(fp);
        fp = NULL;

        printf("💾 Wrote signed image: %s\n", output_file);
        ret = 0;

    } while(0);

    // Cleanup
    if (fp) fclose(fp);
    if (input_data) free(input_data);
    if (encrypted_data) free(encrypted_data);
    if (key_data) free(key_data);

    mbedtls_pk_free(&pk);
    mbedtls_aes_free(&aes_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}