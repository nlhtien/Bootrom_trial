/**
 * @file secure_boot_core.c
 * @brief Secure Boot Core Implementation - Stage 3 & 4
 * 
 * STAGE 3: Load & Verification
 * STAGE 4: Boot Image / Handoff
 */

#include "secure_boot_core.h"
#include "crypto/crypto_wrapper.h"
#include "platform/platform.h"
#include "drivers/flash.h"
#include "drivers/uart.h"
#include <string.h>

/* Image Header Structure */
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

#define IMAGE_MAGIC 0x5442524D  /* "MBRT" in little-endian */
#define IMAGE_VERSION 1

/* Anti-rollback: Store minimum allowed version in NV memory (stub) */
#define NV_COUNTER_ADDR 0x1000  /* Platform-specific NV storage address */
static uint32_t get_nv_counter(void)
{
    /* In production, read from OTP/eFuse/secure storage */
    return 0;  /* Stub - returns minimum allowed version */
}

/**
 * @brief Determine boot source (QSPI/NAND/etc.)
 * @return Boot source address
 */
static uint32_t get_boot_source(void)
{
    /* Platform-specific: Read GPIO/eFuse to determine boot source */
    /* For now, return default QSPI address */
    return 0x10000000;  /* Default boot image address */
}

/**
 * @brief Load image header from flash
 * @param image_addr Address of image in flash
 * @param header Output: image header
 * @return 0 on success, negative on failure
 */
static int load_image_header(uint32_t image_addr, image_header_t *header)
{
    int ret;
    
    ret = flash_read(image_addr, (uint8_t *)header, sizeof(image_header_t));
    if (ret != 0) {
        return -1;
    }
    
    /* Validate magic number */
    if (header->magic != IMAGE_MAGIC) {
        return -2;
    }
    
    /* Validate header version */
    if (header->version != IMAGE_VERSION) {
        return -3;
    }
    
    return 0;
}

/**
 * @brief Check anti-rollback protection
 * @param image_version Version from image header
 * @return 0 on success, negative on failure (rollback detected)
 */
static int check_anti_rollback(uint32_t image_version)
{
    uint32_t min_version = get_nv_counter();
    
    if (image_version < min_version) {
        return -1;  /* Rollback detected */
    }
    
    return 0;
}

/**
 * @brief Verify image signature
 * @param header Pointer to image header
 * @param image_data Pointer to encrypted image data
 * @param image_size Size of image data
 * @return 0 on success, negative on failure
 */
static int verify_image_signature(const image_header_t *header,
                                   const uint8_t *image_data,
                                   uint32_t image_size)
{
    int ret;
    uint8_t hash[32];  /* SHA-256 hash */
    const uint8_t *signature = header->signature;
    
    /* Calculate SHA-256 hash of the image */
    ret = crypto_hash_sha256(image_data, image_size, hash);
    if (ret != 0) {
        return -1;
    }
    
    /* Verify signature using RSA-2048 or ECC */
    ret = crypto_verify_signature(hash, 32, signature, 256);
    if (ret != 0) {
        return -2;  /* Signature verification failed */
    }
    
    return 0;
}

/**
 * @brief Decrypt image using AES-CBC/GCM
 * @param encrypted_data Pointer to encrypted image data
 * @param decrypted_data Pointer to buffer for decrypted data
 * @param data_size Size of data to decrypt
 * @param iv Pointer to initialization vector
 * @return 0 on success, negative on failure
 */
static int decrypt_image_data(const uint8_t *encrypted_data,
                               uint8_t *decrypted_data,
                               uint32_t data_size,
                               const uint8_t *iv)
{
    int ret;
    
    /* Decrypt using AES-CBC (or GCM if required) */
    ret = crypto_aes_decrypt(encrypted_data, decrypted_data, data_size, iv);
    
    return ret;
}

/**
 * @brief STAGE 3: Load and verify boot image
 * @param image_addr Address of image in flash
 * @param decrypted_buffer Buffer to store decrypted image
 * @param buffer_size Size of buffer
 * @param decrypted_size Output: actual size of decrypted image
 * @return 0 on success, negative on failure
 */
int secure_boot_load_and_verify(uint32_t image_addr,
                                 uint8_t *decrypted_buffer,
                                 uint32_t buffer_size,
                                 uint32_t *decrypted_size)
{
    int ret;
    image_header_t header;
    uint8_t *encrypted_data;
    
    /* 1. Boot Source: Determine boot source (stub) */
    if (image_addr == 0) {
        image_addr = get_boot_source();
    }
    
    /* 2. Load Image Header */
    ret = load_image_header(image_addr, &header);
    if (ret != 0) {
        return ret;
    }
    
    /* 3. Anti-Rollback Check */
    ret = check_anti_rollback(header.image_version);
    if (ret != 0) {
        return -10;  /* Rollback detected */
    }
    
    /* Check buffer size */
    if (buffer_size < header.image_size) {
        return -4;  /* Buffer too small */
    }
    
    /* Allocate temporary buffer for encrypted data using static buffer */
    /* Note: Using a static buffer since we can't use malloc */
    #define MAX_ENCRYPTED_SIZE (256 * 1024)  /* 256KB max */
    static uint8_t encrypted_buf[MAX_ENCRYPTED_SIZE];
    
    if (header.image_size > MAX_ENCRYPTED_SIZE) {
        return -5;  /* Image too large */
    }
    
    encrypted_data = encrypted_buf;
    
    /* Read encrypted image data from flash */
    ret = flash_read(image_addr + sizeof(image_header_t),
                     encrypted_data,
                     header.image_size);
    if (ret != 0) {
        return -6;
    }
    
    /* 4. Secure Verification: Verify signature */
    ret = verify_image_signature(&header, encrypted_data, header.image_size);
    if (ret != 0) {
        return -7;  /* Signature verification failed */
    }
    
    /* 5. Decryption: Decrypt payload */
    ret = decrypt_image_data(encrypted_data,
                             decrypted_buffer,
                             header.image_size,
                             header.iv);
    if (ret != 0) {
        return -8;  /* Decryption failed */
    }
    
    *decrypted_size = header.image_size;
    
    /* Zeroize encrypted buffer */
    memset(encrypted_buf, 0, sizeof(encrypted_buf));
    
    return 0;
}

/**
 * @brief STAGE 4: Cleanup and handoff to FSBL
 * @param fsbl_entry Entry point address of FSBL
 */
void secure_boot_cleanup_and_handoff(uint32_t fsbl_entry)
{
    /* 1. Cleanup: Zeroize all crypto keys and sensitive data */
    secure_boot_cleanup();
    
    /* 2. Barriers: Execute ISB and DSB */
    __asm volatile ("isb" ::: "memory");
    __asm volatile ("dsb sy" ::: "memory");
    
    /* 3. Handoff: Jump to FSBL entry point */
    // typedef void (*fsbl_entry_t)(void);  // Commented for testing
    // fsbl_entry_t entry = (fsbl_entry_t)fsbl_entry;  // Commented for testing
    
    /* Disable interrupts */
    __disable_irq();
    
    /* For testing: Print and return instead of jumping */
    uart_puts("Handoff: Simulating jump to FSBL at 0x");
    uart_printf("%x", fsbl_entry);
    uart_puts("\r\nBootROM test completed successfully!\r\n");
    
    /* Simulate handoff by returning (in real code, this would jump) */
    return;
    
    /* Original jump code (commented for testing) */
    /*
    entry();
    
    while (1) {
        __NOP();
    }
    */
}

/**
 * @brief Cleanup: Zeroize sensitive data
 */
void secure_boot_cleanup(void)
{
    /* Zeroize crypto keys and sensitive stack data */
    /* This function is called before handoff to prevent key leakage */
    
    /* Platform-specific cleanup */
    crypto_cleanup();
    
    /* Additional cleanup would go here */
}
