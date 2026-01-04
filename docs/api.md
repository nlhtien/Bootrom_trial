# BootROM API Reference

## Secure Boot Core API

### `secure_boot_verify()`

**Prototype:**
```c
int secure_boot_verify(const uint8_t *image_data, size_t image_size);
```

**Description:**
Main entry point for secure boot verification. Validates image header, verifies RSA signature, decrypts payload, and checks anti-rollback counter.

**Parameters:**
- `image_data`: Pointer to signed image data
- `image_size`: Size of image data in bytes

**Return Values:**
- `SECURE_BOOT_SUCCESS` (0): Verification successful
- `SECURE_BOOT_INVALID_HEADER`: Invalid image header
- `SECURE_BOOT_SIGNATURE_FAIL`: RSA signature verification failed
- `SECURE_BOOT_DECRYPT_FAIL`: AES decryption failed
- `SECURE_BOOT_ROLLBACK_DETECTED`: Anti-rollback check failed

**Notes:**
- Function is blocking and may take up to 200ms
- Uses static memory allocation only
- Logs progress via UART if enabled

### `verify_image_header()`

**Prototype:**
```c
int verify_image_header(const image_header_t *header);
```

**Description:**
Validates image header structure and magic number.

**Parameters:**
- `header`: Pointer to image header structure

**Return Values:**
- `0`: Header valid
- `-1`: Invalid magic number
- `-2`: Unsupported version

### `verify_signature()`

**Prototype:**
```c
int verify_signature(const uint8_t *data, size_t data_len, const uint8_t *signature);
```

**Description:**
Verifies RSA signature of data using configured public key.

**Parameters:**
- `data`: Data to verify
- `data_len`: Length of data
- `signature`: RSA signature (256 bytes)

**Return Values:**
- `0`: Signature valid
- `-1`: Signature invalid
- `-2`: Crypto operation failed

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
- `-1`: Key loading failed

### `crypto_verify_signature()`

**Prototype:**
```c
int crypto_verify_signature(const uint8_t *data, size_t data_len,
                           const uint8_t *signature, size_t sig_len);
```

**Description:**
RSA signature verification wrapper.

**Parameters:**
- `data`: Data to verify
- `data_len`: Data length
- `signature`: Signature bytes
- `sig_len`: Signature length

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