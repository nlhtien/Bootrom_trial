#include "image_builder.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int build_signed_image(const char *input_file, const char *output_file,
                      const char *private_key_file, const char *aes_key_file) {

    int ret = -1;
    FILE *fp = NULL;
    uint8_t *input_data = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *signature = NULL;

    do {
        // 1. Load input binary
        fp = fopen(input_file, "rb");
        if (!fp) {
            printf("Cannot open input file: %s\n", input_file);
            break;
        }

        fseek(fp, 0, SEEK_END);
        size_t input_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        input_data = malloc(input_size);
        if (!input_data) {
            printf("Memory allocation failed\n");
            break;
        }

        size_t read_size = fread(input_data, 1, input_size, fp);
        fclose(fp);
        fp = NULL;

        if (read_size != input_size) {
            printf("Failed to read input file\n");
            break;
        }

        printf("Loaded input binary: %zu bytes\n", input_size);

        // 2. Load AES key (32 bytes)
        fp = fopen(aes_key_file, "rb");
        if (!fp) {
            printf("Cannot open AES key file: %s\n", aes_key_file);
            break;
        }

        uint8_t aes_key[32];
        read_size = fread(aes_key, 1, 32, fp);
        fclose(fp);
        fp = NULL;

        if (read_size != 32) {
            printf("AES key must be 32 bytes\n");
            break;
        }

        printf("Loaded AES key\n");

        // 3. Generate random IV
        uint8_t iv[16];
        if (RAND_bytes(iv, 16) != 1) {
            printf("IV generation failed\n");
            break;
        }

        printf("Generated random IV\n");

        // 4. Encrypt payload with AES-256-CBC using OpenSSL
        size_t encrypted_size = ((input_size + 15) / 16) * 16; // Pad to block size
        encrypted_data = malloc(encrypted_size);
        if (!encrypted_data) {
            printf("Memory allocation failed\n");
            break;
        }

        // PKCS#7 padding
        memset(encrypted_data, 0, encrypted_size);
        memcpy(encrypted_data, input_data, input_size);
        uint8_t pad_value = 16 - (input_size % 16);
        for (size_t i = input_size; i < encrypted_size; i++) {
            encrypted_data[i] = pad_value;
        }

        EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
        if (!cipher_ctx) {
            printf("EVP_CIPHER_CTX creation failed\n");
            break;
        }

        if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
            printf("AES init failed\n");
            EVP_CIPHER_CTX_free(cipher_ctx);
            break;
        }

        int out_len;
        if (EVP_EncryptUpdate(cipher_ctx, encrypted_data, &out_len, encrypted_data, encrypted_size) != 1) {
            printf("AES encryption failed\n");
            EVP_CIPHER_CTX_free(cipher_ctx);
            break;
        }

        if (EVP_EncryptFinal_ex(cipher_ctx, encrypted_data + out_len, &out_len) != 1) {
            printf("AES final failed\n");
            EVP_CIPHER_CTX_free(cipher_ctx);
            break;
        }

        EVP_CIPHER_CTX_free(cipher_ctx);

        printf("Encrypted payload: %zu bytes\n", encrypted_size);

        // 5. Calculate SHA-256 hash of encrypted data
        uint8_t hash[32];
        SHA256(encrypted_data, encrypted_size, hash);

        printf("Calculated SHA-256 hash\n");

        // 6. Load private key and sign hash using OpenSSL
        FILE *key_fp = fopen(private_key_file, "r");
        if (!key_fp) {
            printf("Cannot open private key file: %s\n", private_key_file);
            break;
        }

        EVP_PKEY *private_key = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
        fclose(key_fp);

        if (!private_key) {
            printf("Private key loading failed\n");
            break;
        }

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            printf("EVP_MD_CTX creation failed\n");
            EVP_PKEY_free(private_key);
            break;
        }

        if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) != 1) {
            printf("DigestSignInit failed\n");
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(private_key);
            break;
        }

        size_t sig_len;
        if (EVP_DigestSign(md_ctx, NULL, &sig_len, hash, 32) != 1) {
            printf("DigestSign (get length) failed\n");
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(private_key);
            break;
        }

        signature = malloc(sig_len);
        if (!signature) {
            printf("Memory allocation failed\n");
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(private_key);
            break;
        }

        if (EVP_DigestSign(md_ctx, signature, &sig_len, hash, 32) != 1) {
            printf("DigestSign failed\n");
            free(signature);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(private_key);
            break;
        }

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(private_key);

        printf("Generated RSA signature: %zu bytes\n", sig_len);

        // 7. Create image header (same format as BootROM expects)
        image_header_t header;
        memset(&header, 0, sizeof(header));
        header.magic = IMAGE_MAGIC;
        header.version = IMAGE_VERSION;
        header.image_size = encrypted_size;
        header.image_version = 1; // Can be parameterized
        memcpy(header.iv, iv, 16);
        memcpy(header.signature, signature, 256); // RSA-2048 = 256 bytes

        printf("Created image header\n");

        // 8. Write output file: header + encrypted data
        fp = fopen(output_file, "wb");
        if (!fp) {
            printf("Cannot create output file: %s\n", output_file);
            free(signature);
            break;
        }

        size_t written = fwrite(&header, 1, sizeof(header), fp);
        if (written != sizeof(header)) {
            printf("Failed to write header\n");
            fclose(fp);
            free(signature);
            break;
        }

        written = fwrite(encrypted_data, 1, encrypted_size, fp);
        if (written != encrypted_size) {
            printf("Failed to write encrypted data\n");
            fclose(fp);
            free(signature);
            break;
        }

        fclose(fp);
        free(signature);

        printf("Wrote signed image: %s\n", output_file);
        ret = 0;

    } while(0);

    // Cleanup
    if (input_data) free(input_data);
    if (encrypted_data) free(encrypted_data);

    return ret;
}