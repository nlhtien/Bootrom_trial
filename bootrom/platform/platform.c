/**
 * @file platform.c
 * @brief Platform Implementation
 */

#include "platform.h"
#include "arch/arm/r5f/sys_registers.h"
#include <string.h>

/* Memory region definitions (from linker script or platform-specific) */
#define ATCM_BASE    0x00000000
#define ATCM_SIZE    0x00008000  /* 32KB */
#define BTCM_BASE    0x20000000
#define BTCM_SIZE    0x00008000  /* 32KB */
#define OCRAM_BASE   0x08000000
#define OCRAM_SIZE   0x00010000  /* 64KB */

/* MPU Region Definitions */
#define MPU_REGION_FLASH      0
#define MPU_REGION_OCRAM      1
#define MPU_REGION_PERIPH     2

#define MPU_RBAR(region, addr) ((addr & 0xFFFFFFE0) | (region & 0xF))
#define MPU_RASR(enable, ap, s, c, b, srd, size) \
    ((enable << 0) | (ap << 8) | (s << 18) | (c << 17) | (b << 16) | \
     (srd << 8) | ((size - 1) << 1) | (1 << 0))

/**
 * @brief Disable watchdog (stub - platform-specific implementation)
 */
void watchdog_disable(void)
{
    /* Platform-specific watchdog disable code */
    /* Example: Write to watchdog control register */
    /* In a real implementation, this would access the watchdog peripheral */
}

/**
 * @brief Get reset cause (stub)
 * @return Reset cause (0 = Cold boot, 1 = Warm boot, etc.)
 */
uint32_t platform_get_reset_cause(void)
{
    /* Platform-specific reset cause detection */
    /* Read reset status register from SoC */
    return 0;  /* Assume cold boot */
}

/**
 * @brief Initialize TCM and zeroize for ECC initialization
 * CRITICAL: Write zeros to entire TCM to initialize ECC logic
 */
void tcm_init_and_zeroize(void)
{
    uint32_t *addr;
    uint32_t i;
    
    /* Enable ATCM via CP15 c9 */
    /* TCMCR - TCM Control Register (platform-specific, this is a stub) */
    /* Example: mcr p15, 0, <val>, c9, c1, 0 */
    
    /* Zeroize ATCM */
    addr = (uint32_t *)ATCM_BASE;
    for (i = 0; i < (ATCM_SIZE / 4); i++) {
        addr[i] = 0;
    }
    
    /* Enable BTCM via CP15 c9 */
    /* Example: mcr p15, 0, <val>, c9, c1, 1 */
    
    /* Zeroize BTCM */
    addr = (uint32_t *)BTCM_BASE;
    for (i = 0; i < (BTCM_SIZE / 4); i++) {
        addr[i] = 0;
    }
    
    /* Zeroize OCRAM (if used) */
    addr = (uint32_t *)OCRAM_BASE;
    for (i = 0; i < (OCRAM_SIZE / 4); i++) {
        addr[i] = 0;
    }
    
    dsb();
    isb();
}

/**
 * @brief Setup MPU regions
 */
void mpu_setup(void)
{
    uint32_t sctlr;
    
    /* Disable MPU temporarily */
    sctlr = read_sctlr();
    sctlr &= ~(1 << 0);  /* Clear M bit */
    write_sctlr(sctlr);
    
    /* Region 0: Flash (BOOT_ROM) - Read/Execute, Normal, Cacheable */
    /* Base: 0x00000000, Size: 64KB (2^16), Region: 0 */
    __asm volatile ("mcr p15, 0, %0, c6, c0, 0" : : "r" (0x00000000));  /* RBAR */
    __asm volatile ("mcr p15, 0, %0, c6, c0, 1" : : "r" (MPU_RASR(1, 0x3, 1, 1, 1, 0, 16)));  /* RASR */
    
    /* Region 1: OCRAM - Read/Write/Execute, Normal, Cacheable */
    /* Base: 0x08000000, Size: 64KB (2^16), Region: 1 */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 0" : : "r" (0x08000000));  /* RBAR */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 1" : : "r" (MPU_RASR(1, 0x3, 1, 1, 1, 0, 16)));  /* RASR */
    
    /* Region 2: Peripherals - Read/Write, Device, Non-cacheable */
    /* Base: 0x40000000, Size: 512MB (2^29), Region: 2 */
    __asm volatile ("mcr p15, 0, %0, c6, c2, 0" : : "r" (0x40000000));  /* RBAR */
    __asm volatile ("mcr p15, 0, %0, c6, c2, 1" : : "r" (MPU_RASR(1, 0x3, 0, 0, 0, 0, 29)));  /* RASR */
    
    /* Enable MPU */
    sctlr = read_sctlr();
    sctlr |= (1 << 0);   /* Set M bit */
    write_sctlr(sctlr);
}

/**
 * @brief Enable I-Cache and D-Cache
 * Must be called AFTER MPU is enabled
 */
void enable_caches(void)
{
    uint32_t sctlr;
    
    /* Enable I-Cache */
    sctlr = read_sctlr();
    sctlr |= (1 << 12);  /* Set I bit */
    write_sctlr(sctlr);
    
    /* Enable D-Cache */
    sctlr = read_sctlr();
    sctlr |= (1 << 2);   /* Set C bit */
    write_sctlr(sctlr);
    
    /* Enable Branch Prediction */
    sctlr = read_sctlr();
    sctlr |= (1 << 11);  /* Set Z bit */
    write_sctlr(sctlr);
}

/**
 * @brief Remap vector table to TCM/OCM
 */
void remap_vector_table(void)
{
    extern const uint32_t _vector_table[];
    uint32_t *vt_tcm = (uint32_t *)0x00000000;
    uint32_t i;
    
    /* Copy vector table from ROM to TCM */
    for (i = 0; i < 8; i++) {
        vt_tcm[i] = _vector_table[i];
    }
    
    dsb();
    isb();
    
    /* Set Vector Base Address Register (VBAR) */
    __asm volatile ("mcr p15, 0, %0, c12, c0, 0" : : "r" (0x00000000));
    isb();
}

/**
 * @brief Platform initialization
 */
void platform_init(void)
{
    /* Platform-specific initialization */
    /* - Clock configuration */
    /* - Peripheral clock gating */
    /* - Pinmux configuration */
}

/**
 * @brief IRQ handler (called from assembly)
 */
void platform_irq_handler(void)
{
    /* Platform-specific IRQ handling */
}

/**
 * @brief FIQ handler (called from assembly)
 */
void platform_fiq_handler(void)
{
    /* Platform-specific FIQ handling */
}

/**
 * @brief Delay in microseconds
 */
void platform_delay_us(uint32_t us)
{
    volatile uint32_t count = us * 10;  /* Adjust multiplier based on CPU frequency */
    while (count--);
}

/**
 * @brief Delay in milliseconds
 */
void platform_delay_ms(uint32_t ms)
{
    platform_delay_us(ms * 1000);
}
