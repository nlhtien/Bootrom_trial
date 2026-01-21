/**
 * @file sd.h
 * @brief SD Card Driver Interface (Stub)
 */

#ifndef SD_H
#define SD_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize SD card driver
 * @return 0 on success
 */
int sd_init(void);
/**
 * @brief Read data from SD card
 * @param addr Address in SD card
 * @param buffer Buffer to store data
 * @param len Number of bytes to read
 * @return 0 on success
 */
int sd_read(uint32_t addr, uint8_t *buffer, size_t len);
/**
 * @brief Get SD card size
 * @return SD card size in bytes
 */
uint32_t sd_get_size(void);

#endif /* SD_H */