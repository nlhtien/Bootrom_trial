/**
 * @file main.c
 * @brief BootROM Main Entry Point
 * 
 * Implements Stage 3 & 4 of the boot flow
 */

#include "secure_boot/secure_boot_core.h"
#include "crypto/crypto_wrapper.h"
#include "drivers/uart.h"
#include "drivers/flash.h"
#include "platform/platform.h"
#include "platform/platform_mbedtls.h"

#define BOOT_IMAGE_ADDRESS 0x10000000  /* Address of boot image in flash */
#define DECRYPTED_IMAGE_BUFFER_SIZE (256 * 1024)  /* 256KB buffer for decrypted image */

/* Static buffer for decrypted image (no malloc) */
static uint8_t decrypted_image_buffer[DECRYPTED_IMAGE_BUFFER_SIZE] __attribute__((aligned(8)));

/**
 * @brief Error handler - called on boot failure
 */
static void error_handler(void)
{
    /* Platform-specific error handling */
    /* - Blink LED */
    /* - Reset watchdog */
    /* - Log error */
    
    uart_puts("\r\nERROR: Boot failed - entering error handler\r\n");
    
    while (1) {
        /* Blink LED or reset via watchdog */
        platform_delay_ms(1000);
        /* watchdog_reset(); */
    }
}

/**
 * @brief Main entry point (called from startup.S after Stage 1 & 2)
 */
int main(void)
{
    int ret;
    uint32_t decrypted_size;
    uint32_t fsbl_entry;
    
    /* Initialize UART for debugging */
    uart_init(115200);
    uart_puts("DEBUG: UART initialized\n");
    uart_puts("\r\n=== BootROM Starting (Stage 3 & 4) ===\r\n");
    
    /* Initialize crypto subsystem */
    ret = crypto_init();
    if (ret != 0) {
        uart_puts("ERROR: Crypto initialization failed\r\n");
        error_handler();
    }
    uart_puts("Crypto subsystem initialized\r\n");
    
    /* Initialize flash driver */
    ret = flash_init();
    if (ret != 0) {
        uart_puts("ERROR: Flash initialization failed\r\n");
        error_handler();
    }
    
    uart_puts("Flash initialized\r\n");
    
    /* STAGE 3: Load and verify boot image */
    uart_puts("Stage 3: Loading and verifying boot image...\r\n");
    ret = secure_boot_load_and_verify(BOOT_IMAGE_ADDRESS,
                                      decrypted_image_buffer,
                                      DECRYPTED_IMAGE_BUFFER_SIZE,
                                      &decrypted_size);
    
    if (ret != 0) {
        uart_puts("ERROR: Secure boot verification failed (code: ");
        uart_printf("%d", ret);
        uart_puts(")\r\n");
        error_handler();
    }
    
    uart_puts("Boot image verified and decrypted successfully\r\n");
    uart_puts("Image size: ");
    uart_printf("%d", decrypted_size);
    uart_puts(" bytes\r\n");
    
    /* Extract FSBL entry point (first word of decrypted image) */
    fsbl_entry = *(uint32_t *)decrypted_image_buffer;
    
    uart_puts("FSBL entry point: 0x");
    uart_printf("%x", fsbl_entry);
    uart_puts("\r\n");
    
    /* STAGE 4: Cleanup and handoff to FSBL */
    uart_puts("Stage 4: Cleaning up and handing off to FSBL...\r\n");
    
    /* This function will:
     * 1. Zeroize all sensitive data (keys, buffers)
     * 2. Execute ISB/DSB barriers
     * 3. Jump to FSBL entry point
     * It will not return */
    secure_boot_cleanup_and_handoff(fsbl_entry);
    
    /* Handoff completed successfully */
    uart_puts("BootROM: Boot process completed successfully!\r\n");
    
    /* For testing: Exit instead of error_handler */
    return 0;
    
    /* Should never reach here */
    // error_handler();
    
    return 0;
}
