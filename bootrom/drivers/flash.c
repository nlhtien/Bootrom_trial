/**
 * @file flash.c
 * @brief Flash Driver Implementation (Stub)
 */

#include "flash.h"
#include <string.h>

#define FLASH_BASE 0x10000000
#define FLASH_SIZE (2 * 1024 * 1024)  /* 2MB */

int flash_init(void)
{
    /* Stub implementation - platform-specific flash initialization */
    return 0;
}

int flash_read(uint32_t addr, uint8_t *buffer, size_t len)
{
    uint8_t *flash_ptr = (uint8_t *)(FLASH_BASE + addr);
    
    /* Simple memory copy - in real implementation, this might require
     * special commands to read from flash controller */
    memcpy(buffer, flash_ptr, len);
    
    return 0;
}

uint32_t flash_get_size(void)
{
    return FLASH_SIZE;
}
