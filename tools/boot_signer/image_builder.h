#ifndef IMAGE_BUILDER_H
#define IMAGE_BUILDER_H

#include <stdint.h>

// Same as in secure_boot_core.c
typedef struct {
    uint32_t magic;              // "MBRT"
    uint32_t version;            // Header version
    uint32_t image_size;         // Size of encrypted image
    uint32_t image_version;      // Image version (anti-rollback)
    uint32_t signature_offset;   // Offset to signature (unused)
    uint32_t iv_offset;          // Offset to IV (unused)
    uint32_t reserved[2];        // Reserved
    uint8_t  iv[16];             // AES initialization vector
    uint8_t  signature[256];     // RSA-2048 signature
} image_header_t;

#define IMAGE_MAGIC 0x5442524D  // "MBRT" in little-endian
#define IMAGE_VERSION 1

int build_signed_image(const char *input_file, const char *output_file,
                      const char *private_key_file, const char *aes_key_file);

#endif