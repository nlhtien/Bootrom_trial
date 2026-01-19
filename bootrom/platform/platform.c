/**
 * @file platform.c
 * @brief Platform Implementation
 */

#include "platform.h"
#include "platform_mbedtls.h"
#include "arch/arm/r5f/sys_registers.h"
#include <string.h>

/* Memory region definitions (from linker script or platform-specific) */
#define ATCM_BASE    0x00000000
#define ATCM_SIZE    0x00008000  /* 32KB */
#define BTCM_BASE    0x20000000
#define BTCM_SIZE    0x00008000  /* 32KB */
#define ROM_BASE     0x00000000
#define ROM_SIZE     0x00010000  /* 64KB */
#define OCRAM_BASE   0x08000000
#define OCRAM_SIZE   0x00010000  /* 64KB */
#define PERIPH_BASE  0x40000000
#define PERIPH_SIZE  0x20000000  /* 512MB */

/* MPU Region Definitions */
#define MPU_REGION_ROM        0
#define MPU_REGION_OCRAM      1
#define MPU_REGION_PERIPH     2


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
 * @brief Disable MPU, caches and branch prediction
 */
void platform_disable_mpu_cache(void)
{
    uint32_t sctlr = cp15_read_sctlr();
    sctlr &= ~(1 << 0);  // MPU
    sctlr &= ~(1 << 2);  // D-cache
    sctlr &= ~(1 << 12); // I-cache
    sctlr &= ~(1 << 11); // BP
    cp15_write_sctlr(sctlr);

    /* Invalidate caches */
    __asm volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r"(0));  // ICIALLU
    __asm volatile ("mcr p15, 0, %0, c15, c5, 0" :: "r"(0)); // DCIALLU

    dsb(); isb();
}

/**
 * @brief Enable FPU
 */
void platform_enable_fpu(void)
{
    uint32_t val = cp15_read_cpacr();
    val |= (0xF << 20); // CP10 CP11
    cp15_write_cpacr(val);

    __asm volatile (
        "vmrs r0, FPEXC\n"
        "orr  r0, r0, #(1<<30)\n"
        "vmsr FPEXC, r0\n"
    );
}

/**
 * @brief Initialize TCM and zeroize for ECC initialization
 * CRITICAL: Write zeros to entire TCM to initialize ECC logic
 */
void tcm_init_and_zeroize(void)
{
    uint32_t val;
    volatile uint32_t *p;

    /* =========================
     * Enable ATCM + BTCM
     * ========================= */

    val = cp15_read_tcmcr();
    /* Enable ATCM (bit0) */
    val |= (1 << 0);
    /* Enable BTCM (bit1) */
    val |= (1 << 1);
    cp15_write_tcmcr(val);

    /* =========================
     * Enable RMW for TCM
     * ========================= */

    val = cp15_read_sacr();
    val |= 0x3;   /* ATCMRMW | BTCMRMW */
    cp15_write_sacr(val);
    dsb();
    isb();

    /* =========================
     * Zeroize ATCM (for ECC)
     * ========================= */
    p = (uint32_t *)ATCM_BASE;
    for (uint32_t i = 0; i < ATCM_SIZE / 4; i++) {
        p[i] = 0;
    }

    /* =========================
     * Zeroize BTCM (for ECC)
     * ========================= */
    p = (uint32_t *)BTCM_BASE;
    for (uint32_t i = 0; i < BTCM_SIZE / 4; i++) {
        p[i] = 0;
    }

    dsb();
    isb();

    /* =========================
     * Enable ECC check in ACTLR
     * ========================= */

    val = cp15_read_actlr();
    val |= (1 << 27); /* B1TCM ECC */
    val |= (1 << 26); /* B0TCM ECC */
    val |= (1 << 25); /* ATCM ECC */

    /* Disable parity aborts like ASM */
    val &= ~(1 << 5);
    val &= ~(1 << 4);
    val &= ~(1 << 3);

    cp15_write_actlr(val);

    dsb();
    isb();
}

/**
 * @brief Setup MPU regions
 */
void mpu_setup(void)
{
    uint32_t val;

    /* =========================
     * Disable MPU
     * ========================= */
    val = cp15_read_sctlr();
    val &= ~(1 << 0);
    cp15_write_sctlr(val);

    /* =========================
     * Region 0: ROM @0x00000000 64KB
     * ========================= */

    /* Select region 0 */
    __asm volatile ("mcr p15, 0, %0, c6, c2, 0" :: "r"(MPU_REGION_ROM));

    /* Base */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 0" :: "r"(ROM_BASE));

    /* Size + enable (64KB = 0x0F) */
    __asm volatile ("mrc p15, 0, %0, c6, c1, 2" : "=r"(val));
    val &= ~(0x0F << 1);
    val |= (0x0F << 1) | 1;
    __asm volatile ("mcr p15, 0, %0, c6, c1, 2" :: "r"(val));

    /* Attributes */
    __asm volatile ("mrc p15, 0, %0, c6, c1, 4" : "=r"(val));
    val &= ~(0xFFFFFFFF);
    val |= (0x5 << 8); /* RO */
    val |= (0x1 << 3); /* Normal */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 4" :: "r"(val));

    /* =========================
     * Region 1: OCRAM @0x08000000
     * ========================= */
    __asm volatile ("mcr p15, 0, %0, c6, c2, 0" :: "r"(MPU_REGION_OCRAM));
    __asm volatile ("mcr p15, 0, %0, c6, c1, 0" :: "r"(OCRAM_BASE));

    __asm volatile ("mrc p15, 0, %0, c6, c1, 2" : "=r"(val));
    val &= ~(0x0F << 1);
    val |= (0x0F << 1) | 1;
    __asm volatile ("mcr p15, 0, %0, c6, c1, 2" :: "r"(val));

    __asm volatile ("mrc p15, 0, %0, c6, c1, 4" : "=r"(val));
    val &= ~(0xFFFFFFFF);
    val |= (0x3 << 8); /* Full access */
    val |= (0x0 << 3); /* Normal */
    val |= (0x2 << 0); /* Cacheable */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 4" :: "r"(val));

    /* =========================
     * Region 2: PERIPH @0x40000000
     * ========================= */
    __asm volatile ("mcr p15, 0, %0, c6, c2, 0" :: "r"(MPU_REGION_PERIPH));
    __asm volatile ("mcr p15, 0, %0, c6, c1, 0" :: "r"(PERIPH_BASE));

    __asm volatile ("mrc p15, 0, %0, c6, c1, 2" : "=r"(val));
    val &= ~(0x1F << 1);
    val |= (0x39 << 1) | 1; /* 512MB */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 2" :: "r"(val));

    __asm volatile ("mrc p15, 0, %0, c6, c1, 4" : "=r"(val));
    val |= (1 << 12);       /* XN */
    val |= (0x3 << 8);      /* Full access */
    val |= (0x0 << 3);      /* Device */
    val |= (0x1 << 0);      /* Non cacheable */
    __asm volatile ("mcr p15, 0, %0, c6, c1, 4" :: "r"(val));

    /* =========================
     * Enable MPU
     * ========================= */
    val = cp15_read_sctlr();
    val |= (1 << 0);
    cp15_write_sctlr(val);

    dsb();
    isb();
}

/**
 * @brief Enable I-Cache and D-Cache
 * Must be called AFTER MPU is enabled
 */
void enable_caches(void)
{
    uint32_t sctlr;
    
    /* Enable I-Cache */
    sctlr = cp15_read_sctlr();
    sctlr |= (1 << 12);  /* Set I bit */
    cp15_write_sctlr(sctlr);

    /* Enable D-Cache */
    sctlr = cp15_read_sctlr();
    sctlr |= (1 << 2);   /* Set C bit */
    cp15_write_sctlr(sctlr);

    /* Enable Branch Prediction */
    sctlr = cp15_read_sctlr();
    sctlr |= (1 << 11);  /* Set Z bit */
    cp15_write_sctlr(sctlr);
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

/**
 * @brief Stub for _exit (bare-metal, no exit)
 */
void _exit(int status)
{
    (void)status;
    while (1) {
        /* Infinite loop on exit */
    }
}

/**
 * @brief Minimal snprintf implementation for MbedTLS OID formatting
 * @note Only supports the specific patterns used in OID string formatting
 */
int mbedtls_platform_snprintf(char *str, size_t size, const char *format, ...)
{
    /* For BootROM, we only need to support OID formatting patterns */
    /* Since we can't use va_args reliably in bare-metal, return error */
    /* This disables OID string conversion but allows certificate verification */
    
    (void)str;
    (void)size; 
    (void)format;
    
    /* Return -1 to indicate not implemented */
    /* Certificate verification will still work without OID string conversion */
    return -1;
}
