/**
 * @file flash.h
 * @brief Flash Driver Interface (Stub)
 */

#ifndef FLASH_H
#define FLASH_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize flash driver
 * @return 0 on success
 */
int flash_init(void);

/**
 * @brief Read data from flash
 * @param addr Address in flash
 * @param buffer Buffer to store data
 * @param len Number of bytes to read
 * @return 0 on success
 */
int flash_read(uint32_t addr, uint8_t *buffer, size_t len);

/**
 * @brief Get flash size
 * @return Flash size in bytes
 */
uint32_t flash_get_size(void);

#endif /* FLASH_H */
