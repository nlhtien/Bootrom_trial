/**
 * @file platform.h
 * @brief Platform interface for BootROM / FSBL (Cortex-R5)
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* IRQ control */
static inline void cpu_disable_irq(void)
{
    __asm volatile ("cpsid i" ::: "memory");
}

static inline void cpu_enable_irq(void)
{
    __asm volatile ("cpsie i" ::: "memory");
}

static inline void cpu_nop(void)
{
    __asm volatile ("nop");
}

/* Platform init */
void platform_init(void);

/* Watchdog */
void watchdog_disable(void);

/* Reset cause */
uint32_t platform_get_reset_cause(void);

/* TCM + ECC */
void tcm_init_and_zeroize(void);

/* MPU */
void mpu_setup(void);

/* Cache */
void enable_caches(void);
void platform_disable_mpu_cache(void);

/* Vector table */
void remap_vector_table(void);

/* IRQ / FIQ handlers */
void platform_irq_handler(void);
void platform_fiq_handler(void);

/* Delay */
void platform_delay_us(uint32_t us);
void platform_delay_ms(uint32_t ms);

#endif /* PLATFORM_H */
