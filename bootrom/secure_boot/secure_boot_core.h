/**
 * @file secure_boot_core.h
 * @brief Secure Boot Core API Header
 */

#ifndef SECURE_BOOT_CORE_H
#define SECURE_BOOT_CORE_H

#include <stdint.h>

/**
 * @brief STAGE 3: Load and verify boot image
 * @param image_addr Address of image in flash (0 = auto-detect)
 * @param decrypted_buffer Buffer to store decrypted image
 * @param buffer_size Size of buffer
 * @param decrypted_size Output: actual size of decrypted image
 * @return 0 on success, negative on failure
 */
int secure_boot_load_and_verify(uint32_t image_addr,
                                 uint8_t *decrypted_buffer,
                                 uint32_t buffer_size,
                                 uint32_t *decrypted_size);

/**
 * @brief STAGE 4: Cleanup and handoff to FSBL
 * @param fsbl_entry Entry point address of FSBL
 */
void secure_boot_cleanup_and_handoff(uint32_t fsbl_entry);

/**
 * @brief Cleanup: Zeroize sensitive data
 */
void secure_boot_cleanup(void);

#endif /* SECURE_BOOT_CORE_H */
