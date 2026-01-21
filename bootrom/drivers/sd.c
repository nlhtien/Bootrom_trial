/**
 * @file sd.c
 * @brief SD Card Driver Implementation (Stub)
 */

#include "sd.h"
#include <string.h>

#define SD_BASE 0x20000000
#define SD_SIZE (2 * 1024 * 1024)  /* 2MB */

int sd_init(void)
{
    /* Stub implementation - platform-specific SD initialization */
    return 0;
}

int sd_read(uint32_t addr, uint8_t *buffer, size_t len)
{
    uint8_t *sd_ptr = (uint8_t *)(SD_BASE + addr);
    
    /* Simple memory copy - in real implementation, this might require
     * special commands to read from SD controller */
    /* Copy by block instead of by byte. */
    memcpy(buffer, sd_ptr, len);
    
    return 0;
}

uint32_t sd_get_size(void)
{
    return SD_SIZE;
}
