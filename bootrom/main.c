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
    log_error("BOOT FAILED! Entering error handler.");

    while (1) {
        platform_delay_ms(1000);
        /* watchdog_reset(); */
    }
}

/**
 * @brief Main entry point
 */
int main(void)
{
    int ret;
    uint32_t decrypted_size;
    uint32_t fsbl_entry;

    /* =========================
     * Init debug/log system
     * ========================= */
#ifdef BOOTROM_DEV_MODE
    uart_init(115200);
    log_init();
#endif

    log_info("Uart initialized");
    log_info("");
    log_info("====================================");
    log_info(" BootROM Starting (Stage 3 & 4)");
    log_info("====================================");

    /* =========================
     * Init crypto
     * ========================= */
    ret = crypto_init();
    if (ret != 0) {
        log_error("Crypto init failed: %d", ret);
        error_handler();
    }
    log_info("Crypto initialized");

    /* =========================
     * Init flash
     * ========================= */
    ret = flash_init();
    if (ret != 0) {
        log_error("Flash init failed: %d", ret);
        error_handler();
    }
    log_info("Flash initialized");

    /* =========================
     * Stage 3: Load & verify image
     * ========================= */
    log_info("Stage 3: Loading and verifying boot image...");

    ret = secure_boot_load_and_verify(
                BOOT_IMAGE_ADDRESS,
                decrypted_image_buffer,
                DECRYPTED_IMAGE_BUFFER_SIZE,
                &decrypted_size);

    if (ret != 0) {
        log_error("Secure boot verify failed: %d", ret);
        error_handler();
    }

    log_info("Image verified successfully");
    log_info("Image size: %u bytes", decrypted_size);

    /* =========================
     * Get FSBL entry
     * ========================= */
    fsbl_entry = *(uint32_t *)decrypted_image_buffer;

    log_info("FSBL entry point: 0x%08x", fsbl_entry);

    /* =========================
     * Stage 4: Cleanup & handoff
     * ========================= */
    log_info("Stage 4: Cleanup and handoff to FSBL");

    secure_boot_cleanup_and_handoff(fsbl_entry);

    /* Should never reach here */
    log_error("ERROR: Returned from handoff!");

    while (1);
}
