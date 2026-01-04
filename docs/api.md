# BootROM API Reference

## Data Structures

### `image_header_t`

**Definition:**
```c
typedef struct {
    uint32_t magic;              /* Magic number: 0x4D425254 ("MBRT") */
    uint32_t version;            /* Header version */
    uint32_t image_size;         /* Size of encrypted image */
    uint32_t image_version;      /* Image version (for anti-rollback) */
    uint32_t signature_offset;   /* Offset to signature */
    uint32_t iv_offset;          /* Offset to IV */
    uint32_t reserved[2];        /* Reserved */
    uint8_t  iv[16];             /* AES IV (128 bits) */
    uint8_t  signature[256];     /* RSA-2048 signature */
} image_header_t;
```

**Description:**
Image header structure for signed boot images.

**Fields:**
- `magic`: Magic number (0x4D425254 = "MBRT")
- `version`: Header version (currently 1)
- `image_size`: Size of encrypted image in bytes
- `image_version`: Image version for anti-rollback
- `signature_offset`: Offset to signature within image
- `iv_offset`: Offset to initialization vector
- `iv`: AES initialization vector (16 bytes)
- `signature`: RSA-2048 signature (256 bytes)

## Secure Boot Core API

### `secure_boot_load_and_verify()`

**Prototype:**
```c
int secure_boot_load_and_verify(uint32_t image_addr,
                                 uint8_t *decrypted_buffer,
                                 uint32_t buffer_size,
                                 uint32_t *decrypted_size);
```

**Description:**
Loads and verifies a signed boot image from flash memory. Performs signature verification, decryption, and anti-rollback checks.

**Parameters:**
- `image_addr`: Address of image in flash (0 = auto-detect)
- `decrypted_buffer`: Buffer to store decrypted image
- `buffer_size`: Size of buffer in bytes
- `decrypted_size`: Output: actual size of decrypted image

**Return Values:**
- `0`: Success
- `-1`: Invalid parameters
- `-2`: Image loading failed
- `-3`: Verification failed

### `secure_boot_cleanup_and_handoff()`

**Prototype:**
```c
void secure_boot_cleanup_and_handoff(uint32_t fsbl_entry);
```

**Description:**
Cleans up sensitive data and hands off execution to First Stage Boot Loader (FSBL).

**Parameters:**
- `fsbl_entry`: Entry point address of FSBL

### `secure_boot_cleanup()`

**Prototype:**
```c
void secure_boot_cleanup(void);
```

**Description:**
Zeroizes sensitive cryptographic data from memory.

## Crypto Wrapper API

### `crypto_init()`

**Prototype:**
```c
int crypto_init(void);
```

**Description:**
Initializes crypto subsystem and loads keys from secure storage.

**Return Values:**
- `0`: Success
- `-1`: Initialization failed

### `crypto_verify_signature()`

**Prototype:**
```c
int crypto_verify_signature(const uint8_t *hash,
                             size_t hash_len,
                             const uint8_t *signature,
                             size_t signature_len);
```

**Description:**
RSA signature verification wrapper.

**Parameters:**
- `hash`: SHA-256 hash to verify
- `hash_len`: Hash length (32 bytes)
- `signature`: RSA signature
- `signature_len`: Signature length

**Return Values:**
- `0`: Signature valid
- `-1`: Verification failed

### `crypto_set_aes_key()`

**Prototype:**
```c
int crypto_set_aes_key(const uint8_t *key, size_t key_len);
```

**Description:**
Sets AES key for encryption/decryption operations.

**Parameters:**
- `key`: AES key (16, 24, or 32 bytes)
- `key_len`: Key length in bytes

**Return Values:**
- `0`: Success
- `-1`: Invalid key length

### `crypto_aes_decrypt()`

**Prototype:**
```c
int crypto_aes_decrypt(const uint8_t *input, uint8_t *output,
                        size_t size, const uint8_t *iv);
```

**Description:**
AES-CBC decryption with PKCS#7 padding.

**Parameters:**
- `input`: Encrypted data
- `output`: Decryption output buffer
- `size`: Data size
- `iv`: Initialization vector (16 bytes)

**Return Values:**
- `0`: Success
- `-1`: Decryption failed

## Test Framework API

### `test_init()`

**Prototype:**
```c
int test_init(void);
```

**Description:**
Initializes the unit test framework.

**Return Values:**
- `0`: Success

### `test_run_suite()`

**Prototype:**
```c
void test_run_suite(const test_suite_t *suite);
```

**Description:**
Runs a test suite and reports results.

**Parameters:**
- `suite`: Pointer to test suite structure

### `test_report()`

**Prototype:**
```c
void test_report(void);
```

**Description:**
Generates final test report with pass/fail statistics.

**Return Values:**
- `0`: Verification successful
- `-1`: Verification failed

### `crypto_decrypt_aes()`

**Prototype:**
```c
int crypto_decrypt_aes(const uint8_t *encrypted_data, size_t data_len,
                      uint8_t *decrypted_data, const uint8_t *iv);
```

**Description:**
AES-256-CBC decryption with PKCS#7 padding removal.

**Parameters:**
- `encrypted_data`: Encrypted input
- `data_len`: Input length
- `decrypted_data`: Output buffer
- `iv`: Initialization vector (16 bytes)

**Return Values:**
- `>=0`: Decrypted data length
- `-1`: Decryption failed

### `crypto_set_public_key()`

**Prototype:**
```c
int crypto_set_public_key(const uint8_t *key_data, size_t key_len);
```

**Description:**
Loads RSA public key for verification (production: from OTP/eFuse).

**Parameters:**
- `key_data`: DER-encoded public key
- `key_len`: Key data length

**Return Values:**
- `0`: Success
- `-1`: Invalid key format

### `crypto_set_aes_key()`

**Prototype:**
```c
int crypto_set_aes_key(const uint8_t *key_data, size_t key_len);
```

**Description:**
Loads AES key for decryption (production: from secure storage).

**Parameters:**
- `key_data`: AES key (32 bytes)
- `key_len`: Key length

**Return Values:**
- `0`: Success
- `-1`: Invalid key length

## Platform API

### `platform_init()`

**Prototype:**
```c
void platform_init(void);
```

**Description:**
Initializes platform-specific hardware (UART, flash, watchdog).

### `platform_get_boot_source()`

**Prototype:**
```c
boot_source_t platform_get_boot_source(void);
```

**Description:**
Determines boot source (QSPI flash, eMMC, etc.).

**Return Values:**
- `BOOT_SOURCE_QSPI`: QSPI flash
- `BOOT_SOURCE_EMMC`: eMMC
- `BOOT_SOURCE_INVALID`: Invalid source

### `platform_read_flash()`

**Prototype:**
```c
int platform_read_flash(uint32_t address, uint8_t *buffer, size_t size);
```

**Description:**
Reads data from external flash memory.

**Parameters:**
- `address`: Flash address
- `buffer`: Read buffer
- `size`: Bytes to read

**Return Values:**
- `0`: Success
- `-1`: Read failed

### `platform_watchdog_feed()`

**Prototype:**
```c
void platform_watchdog_feed(void);
```

**Description:**
Feeds watchdog timer to prevent system reset.

### `platform_reset()`

**Prototype:**
```c
void platform_reset(void);
```

**Description:**
Performs system reset (warm or cold).

## Data Types

### `image_header_t`

```c
typedef struct {
    uint32_t magic;           // Magic number (0x5442524D)
    uint32_t version;         // Header version
    uint32_t image_size;      // Payload size
    uint32_t image_version;   // Anti-rollback version
    uint8_t  iv[16];          // AES IV
    uint8_t  signature[256];  // RSA signature
} image_header_t;
```

### `boot_source_t`

```c
typedef enum {
    BOOT_SOURCE_QSPI = 0,
    BOOT_SOURCE_EMMC = 1,
    BOOT_SOURCE_INVALID = 0xFF
} boot_source_t;
```

### Error Codes

```c
#define SECURE_BOOT_SUCCESS          0
#define SECURE_BOOT_INVALID_HEADER   -1
#define SECURE_BOOT_SIGNATURE_FAIL   -2
#define SECURE_BOOT_DECRYPT_FAIL     -3
#define SECURE_BOOT_ROLLBACK_DETECTED -4
```

## Configuration Constants

### Memory Sizes
```c
#define IMAGE_HEADER_SIZE        512
#define AES_BLOCK_SIZE           16
#define RSA_KEY_SIZE             2048
#define RSA_SIGNATURE_SIZE       256
#define AES_KEY_SIZE             32
#define SHA256_DIGEST_SIZE       32
```

### Magic Numbers
```c
#define IMAGE_MAGIC              0x5442524D  // "MBRT"
#define IMAGE_VERSION_CURRENT    1
```

### Timeouts
```c
#define WATCHDOG_TIMEOUT_MS      5000
#define BOOT_TIMEOUT_MS          30000
```

## Usage Examples

### Basic Secure Boot Verification

```c
#include "secure_boot_core.h"

int main(void) {
    uint8_t *image_buffer = (uint8_t *)IMAGE_LOAD_ADDR;
    size_t image_size = IMAGE_MAX_SIZE;

    // Load image from flash
    if (platform_read_flash(IMAGE_OFFSET, image_buffer, image_size) != 0) {
        // Handle read error
        platform_reset();
    }

    // Verify and boot
    int result = secure_boot_verify(image_buffer, image_size);
    if (result == SECURE_BOOT_SUCCESS) {
        // Jump to verified image
        jump_to_image(image_buffer + IMAGE_HEADER_SIZE);
    } else {
        // Verification failed - enter failsafe mode
        enter_failsafe_mode();
    }

    return 0;
}
```

### Key Management

```c
#include "crypto_wrapper.h"

void initialize_keys(void) {
    // Load RSA public key (production: from OTP)
    const uint8_t *rsa_key = get_stored_rsa_key();
    crypto_set_public_key(rsa_key, RSA_KEY_SIZE/8);

    // Load AES key (production: from secure storage)
    const uint8_t *aes_key = get_stored_aes_key();
    crypto_set_aes_key(aes_key, AES_KEY_SIZE);
}
```

## Error Handling

All API functions return error codes. Applications should:

1. Check return values
2. Log errors via UART
3. Enter failsafe mode on critical failures
4. Reset system if watchdog expires
5. Never continue boot with invalid images

## Thread Safety

- All functions are single-threaded (bare-metal)
- No reentrancy issues
- Static memory allocation prevents race conditions
- Hardware access is serialized

## Performance Considerations

- Crypto operations are CPU-intensive (~200ms total)
- Flash access should be optimized for speed
- Memory copies should use DMA if available
- Watchdog feeding during long operations</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/docs/api.md