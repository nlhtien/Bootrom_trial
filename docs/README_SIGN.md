# BootROM Signing Infrastructure

## Overview

The current BootROM implementation only supports **signature verification** for secure boot. To create signed boot images, you need a separate **signing infrastructure** that runs on the host PC (development machine). This document describes how to implement the signing process and what components are missing for a complete secure boot solution.

## Current State

### What BootROM Has (Built with MbedTLS)
- RSA-2048 signature verification
- AES-256 CBC decryption
- SHA-256 hashing
- Image header parsing
- Anti-rollback protection (stub)

### What's Missing for Complete Solution
- Boot image signing tool
- Key generation and management
- Image packaging utility
- Secure key provisioning
- Signed image testing
- Production signing workflow

## MbedTLS Role Clarification

### MbedTLS in BootROM (Target/Device Side)
MbedTLS is used **only in the BootROM** (device firmware) for **verification**:
- **SHA-256**: Hash boot images
- **RSA Verify**: Check signatures
- **AES Decrypt**: Decrypt payloads
- **Memory Management**: Static buffer allocation

**Why MbedTLS for BootROM:**
- Bare-metal compatible (no OS dependencies)
- Static memory allocation (no malloc)
- Small footprint (~40KB code)
- Production-ready crypto

### Signing Tool (Host/PC Side)
The signing tool can use **either OpenSSL or MbedTLS**:

#### Option 1: OpenSSL (Recommended for Host)
```c
// Uses OpenSSL for signing (different from MbedTLS)
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
```

#### Option 2: MbedTLS for Consistency
```c
// Uses same MbedTLS library for both sign and verify
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
```

**Why OpenSSL for signing tool:**
- More mature host tooling
- Better key management
- Standard in development workflows
- Cross-platform compatibility

## Development Workflow Timeline

### Phase 1: Build BootROM (Verifier)
```bash
# Build BootROM with MbedTLS
cmake -B build -S .
cmake --build build
# Output: bootrom.elf (with MbedTLS crypto)
```

**MbedTLS Role:** Embedded in device firmware for verification

### Phase 2: Build Signing Tool (Signer)
```bash
# Build signing tool (can use OpenSSL or MbedTLS)
cd tools/boot_signer
cmake -B build -S .
cmake --build build
# Output: boot_signer executable
```

**Signing Tool Role:** Host application for creating signed images

### Phase 3: Generate Keys
```bash
# Generate keys for signing
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
openssl rand -out aes_key.bin 32
```

### Phase 4: Sign Boot Images
```bash
# Sign FSBL or other boot components
./boot_signer fsbl.bin signed_fsbl.img private_key.pem aes_key.bin
```

### Phase 5: Provision Keys to Device
```bash
# In production: Write keys to device OTP/eFuse
# For testing: Load via crypto_set_* functions
```

### Phase 6: Test Complete Chain
```bash
# Run BootROM in QEMU with signed image
qemu-system-arm -M virt -kernel bootrom.elf -device loader,file=signed_fsbl.img,addr=0x10000000
```

## Signing Tool Implementation (Updated)

## 1. Signing Tool Implementation

### Requirements
- Generate RSA keypairs (2048-bit minimum)
- Sign boot images with RSA-PSS or PKCS#1 v1.5
- Create proper image headers
- Encrypt payload with AES-256-CBC
- Output signed boot images

### Host Signing Tool (`tools/boot_signer/`)

Create a new directory structure:
```
tools/
├── boot_signer/
│   ├── CMakeLists.txt
│   ├── main.c
│   ├── image_builder.c
│   ├── crypto_sign.c
│   └── README.md
```

#### `main.c` - Main signing tool
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "image_builder.h"

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <input_binary> <output_image> <private_key> <aes_key>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    const char *private_key_file = argv[3];
    const char *aes_key_file = argv[4];

    return build_signed_image(input_file, output_file, private_key_file, aes_key_file);
}
```

#### `image_builder.h` - Image format definitions
```c
#ifndef IMAGE_BUILDER_H
#define IMAGE_BUILDER_H

#include <stdint.h>

// Same as in secure_boot_core.c
typedef struct {
    uint32_t magic;              // "MBRT"
    uint32_t version;            // Header version
    uint32_t image_size;         // Size of encrypted image
    uint32_t image_version;      // Image version (anti-rollback)
    uint32_t signature_offset;   // Offset to signature
    uint32_t iv_offset;          // Offset to IV
    uint32_t reserved[2];        // Reserved
    uint8_t  iv[16];             // AES IV (128 bits)
    uint8_t  signature[256];     // RSA-2048 signature
} image_header_t;

#define IMAGE_MAGIC 0x5442524D  // "MBRT" in little-endian
#define IMAGE_VERSION 1

int build_signed_image(const char *input_file, const char *output_file,
                      const char *private_key_file, const char *aes_key_file);

#endif
```

#### `image_builder.c` - Image building with MbedTLS
```c
#include "image_builder.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>
#include <stdio.h>

int build_signed_image(const char *input_file, const char *output_file,
                      const char *private_key_file, const char *aes_key_file) {

    // 1. Load input binary
    FILE *fp = fopen(input_file, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    size_t input_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *input_data = malloc(input_size);
    fread(input_data, 1, input_size, fp);
    fclose(fp);

    // 2. Load AES key (32 bytes)
    uint8_t aes_key[32];
    fp = fopen(aes_key_file, "rb");
    fread(aes_key, 1, 32, fp);
    fclose(fp);

    // 3. Generate random IV using MbedTLS
    uint8_t iv[16];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);

    // 4. Encrypt payload with AES-256-CBC using MbedTLS
    size_t encrypted_size = ((input_size + 15) / 16) * 16; // Pad to block size
    uint8_t *encrypted_data = malloc(encrypted_size);

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 256);
    
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, encrypted_size, 
                         iv_copy, input_data, encrypted_data);
    mbedtls_aes_free(&aes_ctx);

    // 5. Calculate SHA-256 hash of encrypted data using MbedTLS
    uint8_t hash[32];
    mbedtls_sha256(encrypted_data, encrypted_size, hash, 0); // 0 = SHA-256

    // 6. Load private key and sign hash using MbedTLS
    fp = fopen(private_key_file, "rb");
    fseek(fp, 0, SEEK_END);
    size_t key_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    uint8_t *key_data = malloc(key_size);
    fread(key_data, 1, key_size, fp);
    fclose(fp);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_parse_key(&pk, key_data, key_size, NULL, 0);

    uint8_t signature[256]; // RSA-2048 signature
    size_t sig_len;
    
    mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, signature, &sig_len, 
                   mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_pk_free(&pk);
    free(key_data);

    // 7. Create image header (same format as BootROM expects)
    image_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = IMAGE_MAGIC;
    header.version = IMAGE_VERSION;
    header.image_size = encrypted_size;
    header.image_version = 1;
    memcpy(header.iv, iv, 16);
    memcpy(header.signature, signature, 256);

    // 8. Write output file: header + encrypted data
    fp = fopen(output_file, "wb");
    fwrite(&header, 1, sizeof(header), fp);
    fwrite(encrypted_data, 1, encrypted_size, fp);
    fclose(fp);

    // Cleanup
    free(input_data);
    free(encrypted_data);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    printf("Signed image created: %s\n", output_file);
    return 0;
}
```

**Pros of using MbedTLS for signing:**
- Same crypto library as BootROM (consistency)
- No external dependencies (OpenSSL)
- Cross-platform compatible
- Same security guarantees

**Cons:**
- More complex setup (need MbedTLS on host)
- Less mature host tooling than OpenSSL

## 2. Key Generation

### For MbedTLS Signing Tool
```bash
# Generate RSA private key (DER format for MbedTLS)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -outform DER -out private_key.der

# Extract public key in DER format (for BootROM)
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

# Generate AES key (binary format)
openssl rand -out aes_key.bin 32
```

### For OpenSSL Signing Tool
```bash
# Generate RSA keypair in PEM format
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

# Generate AES key
openssl rand -out aes_key.bin 32
```

## 3. Build and Usage

### Build Signing Tool with MbedTLS
```bash
cd tools/boot_signer
mkdir build && cd build

# Use same MbedTLS as BootROM
cmake -DUSE_MBEDTLS=ON \
      -DMBEDTLS_ROOT=../../bootrom/external/mbedtls \
      -B . -S ..

make
```

### Build Signing Tool with OpenSSL
```bash
cd tools/boot_signer
mkdir build && cd build

# Use system OpenSSL
cmake -DUSE_OPENSSL=ON -B . -S ..
make
```

### Sign a Boot Image
```bash
# Sign FSBL binary
./boot_signer fsbl.bin signed_fsbl.img private_key.der aes_key.bin

# For OpenSSL version:
./boot_signer fsbl.bin signed_fsbl.img private_key.pem aes_key.bin
```

## 4. Image Format Specification

### Header Structure (512 bytes)
```
Offset  Size    Field           Description
0       4       magic           "MBRT" (0x5442524D)
4       4       version         Header version (1)
8       4       image_size      Size of encrypted payload
12      4       image_version   Anti-rollback version
16      4       signature_offset (Reserved, always 0)
20      4       iv_offset       (Reserved, always 0)
24      8       reserved        Reserved for future use
32      16      iv              AES initialization vector
48      256     signature       RSA-2048 signature
304     208     padding         Pad to 512 bytes
```

### Payload Format
- **Encrypted with AES-256-CBC**
- **PKCS#7 padding** to block boundary
- **SHA-256 hash** of encrypted data is signed

## 5. Secure Key Provisioning

### Development Keys (Testing)
- Store in version control (encrypted)
- Use for CI/CD testing
- Rotate regularly

### Production Keys
- Generate in secure environment (HSM)
- Provision to device OTP/eFuse during manufacturing
- Never expose private keys
- Implement key revocation mechanism

### BootROM Key Loading
```c
// In production, replace stub with secure storage access
int load_keys_from_secure_storage(void) {
    // Read from OTP/eFuse
    // crypto_set_public_key(otp_public_key);
    // crypto_set_aes_key(otp_aes_key);
    return 0;
}
```

## 6. Testing Infrastructure

### Unit Tests
- Test signature verification with known good/bad signatures
- Test decryption with known plaintext/ciphertext
- Test anti-rollback logic

### Integration Tests
- Sign test images with known keys
- Verify BootROM accepts valid signed images
- Verify BootROM rejects invalid signatures
- Test in QEMU with semihosting

### Fuzz Testing
- Fuzz image headers
- Fuzz signatures
- Fuzz encrypted payloads

## 7. Production Deployment Checklist

### Pre-Deployment
- [ ] Generate production keypair in HSM
- [ ] Implement secure key storage access
- [ ] Test signing workflow
- [ ] Validate BootROM verification
- [ ] Perform security audit

### Manufacturing
- [ ] Provision keys to device OTP/eFuse
- [ ] Program BootROM to ROM
- [ ] Sign all boot images with production keys
- [ ] Verify signed images work on device

### Post-Deployment
- [ ] Monitor for security incidents
- [ ] Plan key rotation strategy
- [ ] Maintain secure key backup
- [ ] Update anti-rollback counters

## 8. Security Considerations

### Key Management
- **Private keys**: Never in BootROM or device flash
- **Public keys**: Provisioned securely to device
- **AES keys**: Unique per device or image set

### Threat Mitigation
- **Rollback protection**: Version checking
- **Replay attacks**: Include timestamp/nonce in images
- **Side-channel attacks**: Implement constant-time crypto
- **Fault injection**: Hardware security features

### Compliance
- **Secure boot standard**: Follow industry standards
- **Key ceremony**: Documented key generation process
- **Audit trail**: Log all signing operations

## 9. Missing Components Implementation Priority

### High Priority (Must Have)
1. Signing tool implementation
2. Key generation scripts
3. Secure key provisioning
4. Image format documentation
5. Testing with real signatures

### Medium Priority (Should Have)
1. HSM integration
2. Key rotation mechanism
3. Audit logging
4. Fuzz testing
5. Performance optimization

### Low Priority (Nice to Have)
1. Multiple key support
2. Certificate chains
3. Remote attestation
4. Secure update mechanism

## 10. Next Steps

1. **Implement signing tool** in `tools/boot_signer/`
2. **Generate test keys** and document process
3. **Test end-to-end** signing and verification
4. **Implement secure storage** access in BootROM
5. **Add production key management** workflow

This signing infrastructure completes the secure boot chain: **Sign → Verify → Boot**</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/README_SIGN.md